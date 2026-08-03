"""
aiosmtpd SMTP handler — intercepts every inbound email,
runs feature extraction + ML scoring + multilingual analysis,
makes accept/quarantine/reject decision.
"""
import email as email_lib
import time
import threading
from email.policy import default as default_policy

from features import extract_features
from scorer import score_email
from db import save_decision
from forwarder import forward_to_downstream

# Try to import multilingual analyzer (graceful degradation)
try:
    from multilingual_analyzer import analyze_email as ml_analyze
    HAS_ML_ANALYZER = True
    print("[Handler] Multilingual analyzer loaded ✓")
except ImportError as e:
    HAS_ML_ANALYZER = False
    print(f"[Handler] Multilingual analyzer not available: {e}")

# Decision thresholds (from design doc)
REJECT_THRESHOLD = 0.90
QUARANTINE_THRESHOLD = 0.65
TAG_THRESHOLD = 0.40


class FraudDetectionHandler:
    """aiosmtpd handler: receives SMTP DATA and scores it."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        start = time.time()

        raw = envelope.content
        if isinstance(raw, bytes):
            raw_str = raw.decode("utf-8", errors="replace")
        else:
            raw_str = raw

        # Parse
        msg = email_lib.message_from_string(raw_str, policy=default_policy)
        sender = envelope.mail_from or msg.get("From", "")
        recipients = list(envelope.rcpt_tos)
        subject = str(msg.get("Subject", ""))

        # Get email body for multilingual analysis
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_content() if hasattr(part, 'get_content') else str(part.get_payload(decode=True) or b"", "utf-8", errors="replace")
                    break
        else:
            body = msg.get_content() if hasattr(msg, 'get_content') else str(msg.get_payload(decode=True) or b"", "utf-8", errors="replace")

        # Feature extraction + ML scoring (existing XGBoost pipeline)
        features = extract_features(msg, sender)
        result = score_email(features)
        fraud_score = result["fraud_score"]
        shap_values = result["shap_values"]
        top_contributors = result["top_contributors"]
        threat_type = result["threat_type"]

        # Multilingual analysis (new engine)
        ml_result = None
        ml_classification = None
        ml_confidence = None
        detected_languages = None
        if HAS_ML_ANALYZER:
            try:
                ml_result = ml_analyze(subject=subject, body=body, sender=sender)
                ml_classification = ml_result.get("classification")
                ml_confidence = ml_result.get("confidence", 0)
                detected_languages = ml_result.get("analysis", {}).get("languages", {}).get("languages_found", ["en"])

                # Enhance decision with multilingual analysis
                fraud_score, decision_override, threat_type = _enhance_decision(
                    fraud_score, threat_type, ml_result
                )
            except Exception as e:
                print(f"[Handler] ML analysis error (non-fatal): {e}")

        elapsed_ms = int((time.time() - start) * 1000)

        # Decision
        if fraud_score >= REJECT_THRESHOLD:
            decision = "REJECT"
        elif fraud_score >= QUARANTINE_THRESHOLD:
            decision = "QUARANTINE"
        elif fraud_score >= TAG_THRESHOLD:
            decision = "TAG"
        else:
            decision = "ACCEPT"

        # Audit log
        save_decision(
            sender=sender,
            recipients=recipients,
            subject=subject,
            fraud_score=fraud_score,
            decision=decision,
            threat_type=threat_type,
            shap_values=shap_values,
            features=features,
            top_contributors=top_contributors,
            processing_ms=elapsed_ms,
            raw_email=raw_str if decision == "QUARANTINE" else None,
            source="SMTP",
            ml_analysis=ml_result,
            ml_classification=ml_classification,
            ml_confidence=ml_confidence,
            detected_languages=detected_languages,
        )

        # Forward clean mail in a background thread so SMTP session
        # completes instantly (Gmail TLS handshake can take several seconds)
        if decision in ("ACCEPT", "TAG"):
            def _forward():
                try:
                    forward_to_downstream(raw_str, sender, recipients)
                except Exception as e:
                    print(f"[Gateway] Forward error: {e}")
            threading.Thread(target=_forward, daemon=True).start()

        tag = {
            "ACCEPT": "\033[92mACCEPT\033[0m",
            "TAG": "\033[93mTAG\033[0m",
            "QUARANTINE": "\033[33mQUARANTINE\033[0m",
            "REJECT": "\033[91mREJECT\033[0m",
        }.get(decision, decision)

        ml_tag = f" [ML:{ml_classification}]" if ml_classification else ""
        lang_tag = f" lang={','.join(detected_languages)}" if detected_languages else ""

        print(
            f"[Gateway] {tag} | score={fraud_score:.3f} | {threat_type:10s}{ml_tag}{lang_tag} "
            f"| from={sender} | subj={subject[:50]} | {elapsed_ms}ms"
        )

        if decision == "REJECT":
            return f"550 5.7.1 Message rejected: fraud score {fraud_score:.2f}"
        return "250 OK"


def _enhance_decision(fraud_score: float, threat_type: str, ml_result: dict) -> tuple:
    """Use multilingual analysis to enhance/override XGBoost decision."""
    ml_class = ml_result.get("classification", "")
    ml_conf = ml_result.get("confidence", 0)
    risks = ml_result.get("risk_scores", {})

    # Homograph attack = definite phishing (XGBoost can't detect Unicode tricks)
    if risks.get("homograph", 0) >= 0.9:
        return (max(fraud_score, 0.98), "REJECT", "PHISHING")

    # Credential exposure = quarantine at minimum
    if risks.get("credential_exposure", 0) >= 0.8:
        return (max(fraud_score, 0.70), "QUARANTINE", "CREDENTIAL_EXPOSURE")

    # 419 scam
    if risks.get("scam_419", 0) >= 0.7:
        return (max(fraud_score, 0.95), "REJECT", "SCAM")

    # BEC from multilingual analyzer
    if risks.get("bec", 0) >= 0.6:
        return (max(fraud_score, 0.93), "REJECT", "BEC")

    # Suspicious domain (e.g., secure-bank-login.xyz)
    if risks.get("url_suspicion", 0) >= 0.6:
        return (max(fraud_score, 0.90), "REJECT", "PHISHING")

    # Dangerous attachment
    if risks.get("attachment", 0) >= 0.7:
        return (max(fraud_score, 0.90), "REJECT", "MALWARE")

    # Multilingual phishing with suspicious signals
    if ml_class == "PHISHING" and ml_conf >= 0.75:
        return (max(fraud_score, 0.90), "REJECT", "PHISHING")

    return (fraud_score, None, threat_type)
