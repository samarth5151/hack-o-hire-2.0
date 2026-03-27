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
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

# ── Path setup so src/ modules are importable ──────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE / "src"))
sys.path.insert(0, str(_HERE))

from email_db import (
    init_db, get_emails, get_email, get_attachment_content,
    update_email_analysis, update_attachment_analysis,
    mark_read, toggle_flag, get_stats
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

    # ── Overall risk aggregation ──────────────────────────────────────────────
    ph_score  = result["phishing"].get("risk_score", 0)
    url_max   = max((u.get("risk_score_pct", u.get("risk_score", 0) * 100) for u in url_results), default=0)
    cred_hits = result["credentials"].get("total_findings", 0)

    overall = max(ph_score, int(url_max * 0.6))
    if cred_hits > 0:
        overall = max(overall, 60 + min(cred_hits * 5, 30))

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
