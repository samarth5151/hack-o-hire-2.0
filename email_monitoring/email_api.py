# email_monitoring/email_api.py
# FastAPI server for the Email Monitor service.
# Exposes REST endpoints for the React mailbox frontend.
# Port: 8009

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, List

import uvicorn
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

# ── Path setup so src/ modules are importable ──────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE / "src"))
sys.path.insert(0, str(_HERE))

from email_db import (
    init_db, get_emails, get_email, get_attachment_content,
    update_email_analysis, update_attachment_analysis,
    mark_read, toggle_flag, get_stats,
    save_email_feedback, get_feedback_stats, mark_email_retraining_used,
)
from imap_worker import start_worker

app = FastAPI(title="Email Monitor API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    init_db()
    start_worker()
    print("[EmailAPI] Ready — IMAP worker started")


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "email-monitor"}


# ══════════════════════════════════════════════════════════════════════════════
#  Email Threat Analysis — unified 4-module pipeline
# ══════════════════════════════════════════════════════════════════════════════

class EmailThreatRequest(BaseModel):
    from_name:   str        = Field(default="",  description="Sender display name")
    from_email:  str        = Field(default="",  description="Sender email address")
    subject:     str        = Field(default="",  description="Email subject line")
    body:        str        = Field(default="",  description="Plain-text email body")
    attachments: List[str]  = Field(default_factory=list,
                                    description="Attachment filenames or absolute paths")
    urls:        List[str]  = Field(default_factory=list,
                                    description="URLs found in the email")


@app.post("/analyze/email")
def analyze_email_threat(payload: EmailThreatRequest):
    """
    Unified email threat analysis endpoint (legacy / direct-submit path).

    Runs all 4 modules in parallel/sequence:
      1. Phishing Detection     — DistilBERT on subject + body
      2. Voice Deepfake         — best_eer_v2.pt + XGBoost MFCC ensemble
      3. Sensitive Data         — Regex + spaCy NER
      4. URL Security Scanner   — PhishGuard 6-layer pipeline

    Body (JSON):
      {
        "from_name":   "John Smith",
        "from_email":  "john@example.com",
        "subject":     "Urgent: Verify your account",
        "body":        "Dear customer...",
        "attachments": ["/abs/path/to/call.wav", "invoice.pdf"],
        "urls":        ["https://example.com/login"]
      }

    Returns the unified threat analysis JSON as per the FraudShield spec.
    """
    try:
        from email_threat_analyzer import analyze_email
        result = analyze_email(payload.model_dump())
        return JSONResponse(content=result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")


@app.post("/analyze-email")
def analyze_email_full_pipeline(payload: EmailThreatRequest):
    """
    Full pipeline email analysis via pipeline_controller.

    Runs:
      1. Ollama qwen3:8b      — content understanding, entity extraction
      2. URL Analyzer         — PhishGuard 6-layer (WHOIS/SSL/cookie/XGBoost/HTML/encoding)
      3. Attachment Scanner   — rule-based + microservice check
      4. Voice Analyzer       — dual-model deepfake detection
      5. Credential Scanner   — regex + NER sensitive data extraction
      6. FraudShield ML       — RoBERTa + rule-based phishing score
      7. Risk Aggregation     — unified score, flags, recommendation

    Returns STRICT output JSON per the FraudShield spec.
    """
    try:
        sys.path.insert(0, str(_HERE / "src"))
        from pipeline_controller import run_email_pipeline

        # Build attachment list — payload.attachments may be file paths or names
        att_list = []
        for item in payload.attachments:
            att_list.append({
                "filename": Path(item).name if item else "unknown",
                "path":     item if (item and Path(item).exists()) else None,
                "content":  None,
            })

        result = run_email_pipeline(
            sender=payload.from_email or payload.from_name,
            subject=payload.subject,
            body=payload.body,
            attachments=att_list,
            urls=payload.urls or None,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {exc}")


# ── Email list ────────────────────────────────────────────────────────────────

@app.get("/emails")
def list_emails(
    limit:        int  = Query(50,  ge=1, le=200),
    offset:       int  = Query(0,   ge=0),
    risk_filter:  str  = Query("ALL"),
    search:       Optional[str] = Query(None),
    unread_only:  bool = Query(False),
    flagged_only: bool = Query(False),
):
    rows, total = get_emails(
        limit=limit, offset=offset,
        risk_filter=risk_filter,
        search=search,
        unread_only=unread_only,
        flagged_only=flagged_only,
    )
    for r in rows:
        if r.get("received_at"):
            r["received_at"] = r["received_at"].isoformat()
    return {"emails": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/stats")
def email_stats():
    return get_stats()


# ── Single email ──────────────────────────────────────────────────────────────

@app.get("/emails/{email_id}")
def get_email_detail(email_id: int):
    row = get_email(email_id)
    if not row:
        raise HTTPException(404, "Email not found")
    mark_read(email_id)
    if row.get("received_at"):
        row["received_at"] = row["received_at"].isoformat()
    # Parse JSONB fields returned as strings
    for field in ("headers", "urls", "analysis", "attachments"):
        if isinstance(row.get(field), str):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                pass
    return row


@app.post("/emails/{email_id}/flag")
def flag_email(email_id: int):
    new_state = toggle_flag(email_id)
    return {"email_id": email_id, "is_flagged": new_state}


# ── Attachment download ────────────────────────────────────────────────────────

@app.get("/emails/{email_id}/attachments/{att_id}/download")
def download_attachment(email_id: int, att_id: int):
    att = get_attachment_content(att_id)
    if not att or att.get("email_id") != email_id:
        raise HTTPException(404, "Attachment not found")
    content = bytes(att["content"]) if att["content"] else b""
    return Response(
        content=content,
        media_type=att.get("content_type", "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{att["filename"]}"'},
    )


# ── Full email security analysis ──────────────────────────────────────────────

@app.post("/emails/{email_id}/analyze")
def analyze_email_endpoint(email_id: int, background_tasks: BackgroundTasks):
    row = get_email(email_id)
    if not row:
        raise HTTPException(404, "Email not found")

    for field in ("headers", "urls", "analysis"):
        if isinstance(row.get(field), str):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                pass

    # Return cached if available
    if row.get("analysis") and row["analysis"].get("phishing"):
        return row["analysis"]

    # Run analysis synchronously (results cached after)
    result = _run_full_analysis(row)
    update_email_analysis(email_id, result,
                          result.get("overall_risk_score", 0),
                          result.get("overall_risk_tier", "UNKNOWN"))
    return result


def _run_full_analysis(row: dict) -> dict:
    """Run all analysis modules and return combined result dict."""
    t0 = time.time()

    subject  = row.get("subject", "") or ""
    sender   = row.get("sender", "") or ""
    receiver = row.get("receiver", "") or ""
    reply_to = row.get("reply_to", "") or ""
    body     = row.get("body_text", "") or ""
    headers  = row.get("headers", {}) or {}
    urls     = row.get("urls", []) or []

    spf_pass  = _check_spf(headers)
    dkim_pass = _check_dkim(headers)

    result = {
        "email_id":     row.get("id"),
        "subject":      subject,
        "analyzed_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # ── 1. Phishing / ML Score ────────────────────────────────────────────────
    try:
        from fraudshield_scorer import score_email
        ph = score_email(
            email_text=body, subject=subject, sender=sender,
            receiver=receiver, reply_to=reply_to,
            spf_pass=spf_pass, dkim_pass=dkim_pass,
        )
        result["phishing"] = ph
    except Exception as e:
        result["phishing"] = {
            "risk_score": 0, "verdict": "UNKNOWN", "tier": "LOW",
            "top_indicators": [], "error": str(e)
        }

    # ── 2. AI-generated text detection ───────────────────────────────────────
    try:
        sys.path.insert(0, str(_HERE / "src"))
        from ai_text_detector import detect_ai_text
        ai = detect_ai_text(body[:2000])
        result["ai_detection"] = ai
    except Exception as e:
        result["ai_detection"] = _fallback_ai_detect(body)

    # ── 3. Credential scanner ─────────────────────────────────────────────────
    try:
        _add_cred_scanner_path()
        cred_mod = _get_cred_mod()
        if cred_mod:
            cred = cred_mod.full_scan(f"{subject}\n\n{body}", "email", sender)
        else:
            cred = _fallback_cred_scan(body)
        result["credentials"] = cred
    except Exception as e:
        result["credentials"] = {"total_findings": 0, "findings": [], "error": str(e)}

    # ── 4. URL / web-spoofing scan ────────────────────────────────────────────
    url_results = []
    if urls:
        try:
            from url_scanner import fast_scan
            for url in urls[:10]:   # limit to 10 per email
                try:
                    res = fast_scan(url)
                    url_results.append(res)
                except Exception:
                    url_results.append({"url": url, "verdict": "ERROR", "risk_score_pct": 0})
        except Exception as e:
            url_results = [{"url": u, "verdict": "SKIPPED", "error": str(e)} for u in urls[:10]]
    result["url_scan"] = url_results

    # ── 5. Rule-based check ───────────────────────────────────────────────────
    try:
        from attachment_analyzer import rule_based_fraud_check
        rule = rule_based_fraud_check(body, sender)
        result["rule_check"] = rule
    except Exception as e:
        result["rule_check"] = {"is_suspicious": False, "score": 0, "reasons": []}

    # ── 6. Ollama LLM content analysis ────────────────────────────────────────
    try:
        sys.path.insert(0, str(_HERE / "src"))
        from ollama_service import analyze_email_content
        llm = analyze_email_content(sender, subject, body)
        result["llm_analysis"] = llm
    except Exception as e:
        result["llm_analysis"] = {
            "ollama_available": False,
            "error": str(e),
            "threat_type": "UNKNOWN",
            "summary": "",
            "flags": [],
            "overall_risk_score": 0,
            "recommendation": "REVIEW",
            "extracted_entities": {"emails": [], "accounts": [], "phones": [], "names": []},
        }

    # ── 7. Voice deepfake detection (audio attachments) ───────────────────────
    try:
        # Fetch attachments from DB to check for audio files
        from email_db import get_email as _get_email_row
        email_row = _get_email_row(row.get("id", 0)) or {}
        raw_atts = email_row.get("attachments") or []
        if isinstance(raw_atts, str):
            try:
                import json as _json
                raw_atts = _json.loads(raw_atts)
            except Exception:
                raw_atts = []

        from voice_analyzer import analyze_voice_attachments, AUDIO_EXTENSIONS
        from pathlib import Path as _Path

        voice_att_list = []
        for att in (raw_atts if isinstance(raw_atts, list) else []):
            fname = att.get("filename", "")
            ext   = _Path(fname).suffix.lower()
            if ext in AUDIO_EXTENSIONS:
                # Retrieve content from DB
                try:
                    from email_db import get_attachment_content
                    att_data = get_attachment_content(att.get("id", -1))
                    content  = bytes(att_data["content"]) if att_data and att_data.get("content") else None
                except Exception:
                    content = None
                voice_att_list.append({"filename": fname, "content": content, "path": None})

        voice_results = analyze_voice_attachments(voice_att_list) if voice_att_list else []
        result["voice_analysis"] = {
            "total_audio_files": len(voice_results),
            "scanned":     sum(1 for v in voice_results if "SKIPPED" not in str(v.get("verdict", ""))),
            "skipped":     sum(1 for v in voice_results if "SKIPPED" in str(v.get("verdict", ""))),
            "flagged_as_fake": sum(1 for v in voice_results if "FAKE" in str(v.get("verdict", "")).upper()),
            "results":     voice_results,
        }
    except Exception as e:
        result["voice_analysis"] = {
            "total_audio_files": 0, "scanned": 0, "skipped": 0,
            "flagged_as_fake": 0, "results": [], "error": str(e),
        }

    # ── Overall risk aggregation ──────────────────────────────────────────────
    ph_score   = result["phishing"].get("risk_score", 0)
    url_max    = max((u.get("risk_score_pct", u.get("risk_score", 0) * 100) for u in url_results), default=0)
    cred_hits  = result["credentials"].get("total_findings", 0)
    llm_score  = result["llm_analysis"].get("overall_risk_score", 0)
    voice_max  = max((v.get("risk_score", 0) for v in result["voice_analysis"].get("results", [])), default=0)

    overall = int(
        ph_score  * 0.35 +
        url_max   * 0.25 +
        llm_score * 0.20 +
        min(cred_hits * 10, 100) * 0.10 +
        voice_max * 0.10
    )
    overall = max(overall, int(ph_score * 0.5))
    if cred_hits > 0:
        overall = max(overall, 50 + min(cred_hits * 5, 30))
    overall = min(overall, 100)

    tier = _score_to_tier(overall)
    result["overall_risk_score"] = overall
    result["overall_risk_tier"]  = tier
    result["processing_ms"]      = round((time.time() - t0) * 1000)

    return result


# ── Attachment analysis ────────────────────────────────────────────────────────

@app.post("/emails/{email_id}/attachments/{att_id}/analyze")
def analyze_attachment_endpoint(email_id: int, att_id: int, scan_type: str = "static"):
    att = get_attachment_content(att_id)
    if not att or att.get("email_id") != email_id:
        raise HTTPException(404, "Attachment not found")

    # Return cached
    if isinstance(att.get("analysis"), str):
        try:
            att["analysis"] = json.loads(att["analysis"])
        except Exception:
            pass

    if att.get("analysis") and att["analysis"].get(scan_type):
        return att["analysis"][scan_type]

    content = bytes(att["content"]) if att["content"] else b""
    filename = att.get("filename", "attachment")

    if scan_type == "static":
        res = _run_static_attachment_scan(content, filename)
    else:
        res = _run_deep_attachment_scan(content, filename, att_id)

    # Merge into existing analysis cache
    existing = att.get("analysis") or {}
    existing[scan_type] = res
    update_attachment_analysis(att_id, existing)

    return res


def _run_static_attachment_scan(content: bytes, filename: str) -> dict:
    """Reuse attachment_scanner's 4-phase analysis pipeline."""
    try:
        # Call the attachment scanner service via HTTP (already running at :8007)
        import requests
        files = {"file": (filename, content, "application/octet-stream")}
        resp = requests.post(
            "http://attachment-scanner:8007/analyze",
            files=files,
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"Scanner returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e), "filename": filename}


def _run_deep_attachment_scan(content: bytes, filename: str, att_id: int) -> dict:
    """Deep content analysis: extract text and run full pipeline."""
    t0 = time.time()
    result = {"filename": filename, "scan_type": "deep"}

    ext = Path(filename).suffix.lower()
    extracted_text = _extract_text_from_bytes(content, filename)

    if not extracted_text:
        return {"filename": filename, "scan_type": "deep",
                "error": "Could not extract text content", "processing_ms": 0}

    # Phishing/fraud check on extracted text
    try:
        from attachment_analyzer import rule_based_fraud_check
        rule = rule_based_fraud_check(extracted_text)
        result["fraud_check"] = rule
    except Exception:
        result["fraud_check"] = {}

    # Credential scan
    try:
        _add_cred_scanner_path()
        cred_mod = _get_cred_mod()
        if cred_mod:
            cred = cred_mod.full_scan(extracted_text, "attachment", filename)
            result["credentials"] = cred
    except Exception:
        pass

    # URL extraction + scan
    url_re = __import__("re").compile(r'https?://[^\s<>"\'()\[\]{}|\\^`]*', __import__("re").IGNORECASE)
    urls = list(dict.fromkeys(url_re.findall(extracted_text)))
    result["urls_found"] = urls[:20]

    url_results = []
    if urls:
        try:
            from url_scanner import fast_scan
            for url in urls[:5]:
                try:
                    url_results.append(fast_scan(url))
                except Exception:
                    pass
        except Exception:
            pass
    result["url_scan"] = url_results

    # AI text detection
    try:
        from ai_text_detector import detect_ai_text
        result["ai_detection"] = detect_ai_text(extracted_text[:2000])
    except Exception:
        result["ai_detection"] = _fallback_ai_detect(extracted_text)

    # Score
    rule_score = result.get("fraud_check", {}).get("score", 0)
    url_max = max((u.get("risk_score_pct", 0) for u in url_results), default=0)
    cred_hits = result.get("credentials", {}).get("total_findings", 0)
    overall = max(rule_score, int(url_max * 0.6))
    if cred_hits > 0:
        overall = max(overall, 50 + min(cred_hits * 5, 40))
    result["risk_score"] = overall
    result["risk_tier"] = _score_to_tier(overall)
    result["processing_ms"] = round((time.time() - t0) * 1000)

    return result


# ── Feedback & Retraining Endpoints ──────────────────────────────────────────

from pydantic import BaseModel

class EmailFeedbackBody(BaseModel):
    model_verdict:   str
    correct_verdict: str
    module:          str  = "phishing"
    reviewer_id:     str  = "user"
    notes:           str  = ""


@app.post("/emails/{email_id}/feedback")
def submit_email_feedback(email_id: int, body: EmailFeedbackBody):
    """Submit analyst feedback on an email analysis result."""
    row = get_email(email_id)
    subject = row.get("subject", "") if row else ""
    result = save_email_feedback(
        email_id=email_id,
        model_verdict=body.model_verdict,
        correct_verdict=body.correct_verdict,
        module=body.module,
        reviewer_id=body.reviewer_id,
        notes=body.notes,
        subject=subject,
    )
    return result


@app.get("/feedback/stats")
def email_feedback_stats():
    """Return aggregate email feedback statistics."""
    return get_feedback_stats()


@app.post("/admin/retrain")
def trigger_email_retraining():
    """Admin: trigger retraining on queued email model corrections."""
    stats = get_feedback_stats()
    queue_size = stats.get("retraining_queue_size", 0)

    if queue_size == 0:
        return {"status": "skipped", "reason": "No new corrections in queue", "queue_size": 0}

    mark_email_retraining_used()

    retrain_log = []
    status = "queued"
    try:
        from src.train_bert import retrain_from_feedback
        retrain_log = retrain_from_feedback()
        status = "started"
    except Exception as e:
        retrain_log = [
            f"Retraining queued — {queue_size} email correction(s) saved.",
            f"Run train_bert.py to apply. ({e})",
        ]
        status = "queued"

    return {
        "status": status,
        "queue_size": queue_size,
        "log": retrain_log,
        "message": f"Email model retraining initiated on {queue_size} correction(s).",
    }


@app.get("/admin/retrain/status")
def email_retrain_status():
    """Return email retraining queue status."""
    stats = get_feedback_stats()
    return {
        "queue_size":     stats.get("retraining_queue_size", 0),
        "total_scans":    stats.get("total_scans", 0),
        "total_feedback": stats.get("total_feedback", 0),
        "accuracy":       stats.get("accuracy"),
        "false_positives": stats.get("false_positives", 0),
        "false_negatives": stats.get("false_negatives", 0),
    }


# ── Utility helpers ───────────────────────────────────────────────────────────

def _score_to_tier(score: int) -> str:
    if score >= 70: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"


def _check_spf(headers: dict) -> Optional[bool]:
    for key in ("Authentication-Results", "Received-SPF"):
        val = headers.get(key, "").lower()
        if "spf=pass" in val:
            return True
        if "spf=fail" in val or "spf=softfail" in val:
            return False
    return None


def _check_dkim(headers: dict) -> Optional[bool]:
    val = headers.get("Authentication-Results", "").lower()
    if "dkim=pass" in val:
        return True
    if "dkim=fail" in val:
        return False
    return None


def _fallback_ai_detect(text: str) -> dict:
    import re
    ai_patterns = [
        r"\bcertainly\b", r"\bof course\b", r"\bplease do not hesitate\b",
        r"\bshould you (have|need|require)\b", r"\bfeel free to\b",
        r"\bi hope this (email|message|finds)\b", r"\babsolutely\b",
    ]
    hits = sum(1 for p in ai_patterns if re.search(p, text, re.IGNORECASE))
    prob = min(0.9, hits * 0.15)
    return {
        "ai_generated_probability": prob,
        "is_ai_generated": prob >= 0.5,
        "method": "heuristic",
        "indicators": hits,
    }


_cred_mod = None

def _add_cred_scanner_path():
    cs_dir = str(_HERE.parent / "Credential_Scanner-main")
    if cs_dir not in sys.path:
        sys.path.insert(0, cs_dir)

def _get_cred_mod():
    global _cred_mod
    if _cred_mod is not None:
        return _cred_mod
    try:
        import importlib.util
        cs_path = _HERE.parent / "Credential_Scanner-main" / "main.py"
        spec = importlib.util.spec_from_file_location("_cred_scanner", str(cs_path))
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _cred_mod = mod
        return mod
    except Exception:
        return None


def _fallback_cred_scan(text: str) -> dict:
    import re
    findings = []
    patterns = {
        "EMAIL":       r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "CREDIT_CARD": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "SORT_CODE":   r'\b\d{2}-\d{2}-\d{2}\b',
        "API_KEY":     r'\b[A-Za-z0-9]{32,44}\b',
    }
    for kind, pat in patterns.items():
        for match in re.findall(pat, text):
            findings.append({"type": kind, "value": match, "severity": "medium"})
    return {"total_findings": len(findings), "findings": findings[:20],
            "risk_score": min(len(findings) * 10, 100)}


def _extract_text_from_bytes(content: bytes, filename: str) -> str:
    ext = Path(filename).suffix.lower()
    try:
        if ext == ".pdf":
            import fitz
            doc = fitz.open(stream=content, filetype="pdf")
            return "\n".join(page.get_text() for page in doc)
        elif ext in (".doc", ".docx"):
            from docx import Document
            import io
            doc = Document(io.BytesIO(content))
            return "\n".join(p.text for p in doc.paragraphs)
        elif ext in (".txt", ".csv", ".log", ".py", ".js", ".html", ".xml", ".json"):
            return content.decode("utf-8", errors="replace")
        else:
            return content.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("email_api:app", host="0.0.0.0", port=8009, reload=False)
