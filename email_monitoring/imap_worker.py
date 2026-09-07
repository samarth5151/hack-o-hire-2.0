# email_monitoring/imap_worker.py
# Background IMAP polling thread — fetches emails every 10 seconds,
# parses full content (headers, body, attachments, URLs) and stores in DB.
#
# Supports:
#   1. IMAP_ENABLED=true  → connects to configured IMAP server (e.g. Gmail)
#   2. IMAP_ENABLED=false → polls MailHog HTTP API (for local dev/demo)

from __future__ import annotations

import email as email_lib
import imaplib
import json
import logging
import os
import re
import select
import threading
import time
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path
from typing import Optional

import requests

from email_db import init_db, save_email, save_attachment, update_email_status

# ── SSE event broadcast queue (shared with email_api.py) ─────────────────────
# Populated by the IMAP worker, consumed by the /events SSE endpoint.
import queue as _queue_module
SSE_EVENT_QUEUE: _queue_module.Queue = _queue_module.Queue(maxsize=500)

EMAIL_API_BASE = os.getenv("EMAIL_API_BASE", "http://127.0.0.1:8009")

# Configure logging so worker messages appear in uvicorn output
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("imap_worker")

# ── Config ────────────────────────────────────────────────────────────────────

IMAP_ENABLED   = os.getenv("IMAP_ENABLED",   "false").lower() == "true"
IMAP_SERVER    = os.getenv("IMAP_SERVER",    "imap.gmail.com")
IMAP_PORT      = int(os.getenv("IMAP_PORT",  "993"))
IMAP_USER      = os.getenv("IMAP_USER",      "")
IMAP_PASSWORD  = os.getenv("IMAP_PASSWORD",  "")
IMAP_USE_SSL   = os.getenv("IMAP_USE_SSL",   "true").lower() == "true"
IMAP_MAILBOX   = os.getenv("IMAP_MAILBOX",   "INBOX")
POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL", "5"))
IMAP_INITIAL_FETCH = int(os.getenv("IMAP_INITIAL_FETCH", "30"))  # how many past emails to load on startup

MAILHOG_URL    = os.getenv("MAILHOG_URL", "http://mailhog:8025")

# ── Helpers ───────────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r'https?://[^\s<>"\'()\[\]{}|\\^`]*',
    re.IGNORECASE
)


def _decode_str(value: str) -> str:
    if not value:
        return ""
    parts = []
    for raw, enc in decode_header(value):
        if isinstance(raw, bytes):
            # Normalise bogus encoding names
            charset = (enc or "utf-8").lower().replace("unknown-8bit", "latin-1")
            parts.append(raw.decode(charset, errors="replace"))
        else:
            parts.append(raw)
    return "".join(parts)


def _extract_body(msg) -> tuple[str, str]:
    """Return (body_text, body_html) from a parsed email.message object."""
    text_parts, html_parts = [], []

    def walk(part):
        ct = part.get_content_type()
        disp = str(part.get("Content-Disposition", ""))
        if "attachment" in disp:
            return
        if ct == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                charset = (part.get_content_charset() or "utf-8").replace("unknown-8bit", "latin-1")
                text_parts.append(payload.decode(charset, errors="replace"))
        elif ct == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                charset = (part.get_content_charset() or "utf-8").replace("unknown-8bit", "latin-1")
                html_parts.append(payload.decode(charset, errors="replace"))
        elif part.is_multipart():
            for sub in part.get_payload():
                walk(sub)

    if msg.is_multipart():
        for part in msg.get_payload():
            walk(part)
    else:
        walk(msg)

    return "\n".join(text_parts), "\n".join(html_parts)


def _extract_attachments(msg) -> list[dict]:
    attachments = []

    def walk(part):
        ct = part.get_content_type()
        disp = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        if filename or "attachment" in disp:
            filename = _decode_str(filename or "attachment")
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename":     filename,
                "content_type": ct,
                "size_bytes":   len(payload),
                "content":      payload,
            })
        elif part.is_multipart():
            for sub in part.get_payload():
                walk(sub)

    if msg.is_multipart():
        for part in msg.get_payload():
            walk(part)

    return attachments


def _extract_urls(text: str, html: str = "") -> list[str]:
    combined = f"{text}\n{html}"
    return list(dict.fromkeys(_URL_RE.findall(combined)))  # deduplicated, order preserved


def _extract_headers(msg) -> dict:
    headers = {}
    for key in msg.keys():
        val = msg.get(key, "")
        headers[key] = _decode_str(str(val))
    return headers


def _parse_email_message(msg, uid: str = "") -> dict:
    """Convert a parsed email.message object → flat dict for DB storage."""
    subject  = _decode_str(msg.get("Subject", "(no subject)"))
    sender   = _decode_str(msg.get("From", ""))
    receiver = _decode_str(msg.get("To", ""))
    reply_to = _decode_str(msg.get("Reply-To", ""))
    date_str = _decode_str(msg.get("Date", ""))
    msg_id   = _decode_str(msg.get("Message-ID", "")) or uid

    body_text, body_html = _extract_body(msg)
    attachments          = _extract_attachments(msg)
    urls                 = _extract_urls(body_text, body_html)
    headers              = _extract_headers(msg)

    return {
        "message_id":       msg_id.strip(),
        "subject":          subject,
        "sender":           sender,
        "receiver":         receiver,
        "reply_to":         reply_to,
        "date_str":         date_str,
        "headers":          headers,
        "body_text":        body_text,
        "body_html":        body_html,
        "urls":             urls,
        "has_attachments":  len(attachments) > 0,
        "attachment_count": len(attachments),
        "_attachments":     attachments,   # not stored in email_inbox directly
    }


# ── Persistent IMAP IDLE Client ───────────────────────────────────────────────

_seen_ids: set[str] = set()
_imap_conn: Optional[imaplib.IMAP4] = None


def _connect_imap():
    global _imap_conn
    try:
        if IMAP_USE_SSL:
            _imap_conn = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        else:
            _imap_conn = imaplib.IMAP4(IMAP_SERVER, IMAP_PORT)
        _imap_conn.login(IMAP_USER, IMAP_PASSWORD)
        logger.info(f"[IMAP IDLE] Successfully authenticated to {IMAP_SERVER}:{IMAP_PORT} as {IMAP_USER}")
        return True
    except Exception as e:
        logger.error(f"[IMAP IDLE] Authentication failed: {e}")
        _imap_conn = None
        return False


def _fetch_new_imap_emails():
    """Fetches newly arrived emails since the last state, parses them,
    writes them immediately to the database with 'PROCESSING' status,
    and kicks off background scoring asynchronously."""
    global _imap_conn, _seen_ids
    if _imap_conn is None:
        return

    try:
        _imap_conn.select(IMAP_MAILBOX)
        typ, data = _imap_conn.uid('SEARCH', None, 'ALL')
        if typ != 'OK' or not data or not data[0]:
            return

        uids = [u.decode() for u in data[0].split()]

        # On the very first run, seed _seen_ids with ALL existing UIDs
        if not _seen_ids:
            _seen_ids.update(uids)
            logger.info(f"[IMAP IDLE] Initialized seen set. Skipped all {len(uids)} historical emails.")
            return

        new_uids = [u for u in uids if u not in _seen_ids]
        if not new_uids:
            return

        logger.info(f"[IMAP IDLE] Ingesting {len(new_uids)} new email(s) via push...")
        for uid in new_uids:
            _seen_ids.add(uid)
            t_start = time.time()
            try:
                typ2, msg_data = _imap_conn.uid('FETCH', uid.encode(), '(RFC822)')
                if typ2 != 'OK' or not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if not isinstance(raw, bytes):
                    continue
                msg = email_lib.message_from_bytes(raw)
                parsed = _parse_email_message(msg, uid=uid)
                _store_parsed(parsed)
                elapsed_ms = int((time.time() - t_start) * 1000)
                logger.info(f"[IMAP IDLE] Processed new email UID={uid} in {elapsed_ms}ms")
            except Exception as e:
                logger.warning(f"[IMAP IDLE] Error fetching UID {uid}: {e}")

    except (imaplib.IMAP4.abort, ConnectionResetError, OSError) as e:
        logger.warning(f"[IMAP IDLE] Connection dropped during fetch: {e}")
        _imap_conn = None
    except Exception as e:
        logger.error(f"[IMAP IDLE] Error in _fetch_new_imap_emails: {e}")
        _imap_conn = None


def _run_imap_idle():
    """Persistent IMAP IDLE loop (RFC 2177 compliant).
    Maintains a single open TLS stream. When Gmail receives an email,
    it pushes an untagged '* <N> EXISTS' notification across the socket.
    The loop terminates IDLE immediately, fetches the email in <1-2s,
    and returns to IDLE mode."""
    global _imap_conn
    logger.info(f"[IMAP IDLE] Starting persistent listener on {IMAP_SERVER}:{IMAP_PORT} (TLS/SSL)...")

    while True:
        try:
            if _imap_conn is None:
                if not _connect_imap():
                    time.sleep(5)
                    continue
                _imap_conn.select(IMAP_MAILBOX)
                _fetch_new_imap_emails()

            # Issue RFC 2177 IDLE command
            tag = _imap_conn._new_tag().decode('latin1')
            _imap_conn.send(f"{tag} IDLE\r\n".encode('latin1'))
            resp = _imap_conn.readline()
            if not resp.startswith(b'+'):
                logger.warning(f"[IMAP IDLE] Server rejected IDLE: {resp}. Retrying in 5s...")
                time.sleep(5)
                continue

            logger.info("[IMAP IDLE] Active and listening for Gmail push notifications (sub-second arrival)...")
            sock = _imap_conn.sock
            idle_start = time.time()
            has_push_event = False

            # RFC 2177 requires clients to re-issue IDLE at least once every 29 minutes.
            # We refresh every 10 minutes (600s) to guarantee NAT / firewall persistence.
            while time.time() - idle_start < 600:
                # Check for buffered bytes in OpenSSL layer first
                if hasattr(sock, "pending") and sock.pending() > 0:
                    readable = True
                else:
                    r, _, _ = select.select([sock], [], [], 2.0)
                    readable = bool(r)

                if readable:
                    line = _imap_conn.readline()
                    if not line:
                        raise ConnectionResetError("IMAP TLS socket disconnected during IDLE")
                    # Untagged notifications: e.g. b'* 1234 EXISTS\r\n' or b'* 1 RECENT\r\n'
                    if b'EXISTS' in line or b'RECENT' in line:
                        logger.info(f"[IMAP IDLE] Push notification received: {line.decode('latin1', errors='ignore').strip()}")
                        has_push_event = True
                        break

            # Terminate IDLE with DONE command
            _imap_conn.send(b"DONE\r\n")
            while True:
                line = _imap_conn.readline()
                if not line or line.startswith(tag.encode('latin1')):
                    break

            if has_push_event:
                _fetch_new_imap_emails()

        except (imaplib.IMAP4.abort, ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.warning(f"[IMAP IDLE] Connection reset: {e}. Reconnecting in 3s...")
            _imap_conn = None
            time.sleep(3)
        except Exception as e:
            logger.error(f"[IMAP IDLE] Unexpected loop error: {e}. Reconnecting in 5s...")
            _imap_conn = None
            time.sleep(5)


# ── MailHog HTTP API polling ───────────────────────────────────────────────────

def _poll_mailhog():
    try:
        resp = requests.get(f"{MAILHOG_URL}/api/v2/messages?limit=100", timeout=5)
        if resp.status_code != 200:
            return
        data = resp.json()
        items = data.get("items", [])

        for item in items:
            mid = item.get("ID", "")
            if mid in _seen_ids:
                continue

            content     = item.get("Content", {})
            headers_raw = content.get("Headers", {})

            def _h(key):
                vals = headers_raw.get(key, [])
                return _decode_str(vals[0]) if vals else ""

            # MailHog Raw.Data contains the full RFC822 message — best source
            raw_data = item.get("Raw", {}).get("Data", "")
            msg = None
            if raw_data:
                try:
                    msg = email_lib.message_from_string(raw_data)
                except Exception:
                    msg = None

            # Fallback: reconstruct from MailHog structured headers + MIME body
            if msg is None or not msg.get("From"):
                header_lines = []
                for k, vals in headers_raw.items():
                    for v in (vals if isinstance(vals, list) else [vals]):
                        header_lines.append(f"{k}: {v}")
                reconstructed = "\r\n".join(header_lines) + "\r\n\r\n" + content.get("Body", "")
                try:
                    msg = email_lib.message_from_string(reconstructed)
                except Exception:
                    msg = None

            if msg and msg.get("Subject"):
                parsed = _parse_email_message(msg, uid=mid)
            else:
                # Last-resort: plain dict from structured fields
                body_text = content.get("Body", "")
                parsed = {
                    "message_id":       mid,
                    "subject":          _h("Subject") or "(no subject)",
                    "sender":           _h("From"),
                    "receiver":         _h("To"),
                    "reply_to":         _h("Reply-To"),
                    "date_str":         _h("Date"),
                    "headers":          {k: (v[0] if isinstance(v, list) else v) for k, v in headers_raw.items()},
                    "body_text":        body_text,
                    "body_html":        "",
                    "urls":             _extract_urls(body_text),
                    "has_attachments":  False,
                    "attachment_count": 0,
                    "_attachments":     [],
                }

            _store_parsed(parsed)
            _seen_ids.add(mid)

    except Exception as e:
        logger.warning(f"[MailHog] Poll error: {e}")


# ── Analysis background thread ────────────────────────────────────────────────

ANALYSIS_TIMEOUT = int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "120"))


def _score_to_tier(score: float) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _broadcast(event: dict):
    """Put an event on the SSE queue; drop oldest if full."""
    try:
        SSE_EVENT_QUEUE.put_nowait(event)
    except _queue_module.Full:
        try:
            SSE_EVENT_QUEUE.get_nowait()
        except _queue_module.Empty:
            pass
        try:
            SSE_EVENT_QUEUE.put_nowait(event)
        except _queue_module.Full:
            pass


def _analyze_and_update_email(email_id: int, parsed: dict):
    """Run in a daemon thread. Calls the phishing analysis endpoint,
    maps score → verdict, updates the DB, and broadcasts SSE events.
    The full 7-module result is stored in the analysis JSONB column so
    EmailDetail can display all panels without re-running the pipeline."""
    try:
        from email_api import analyze_phishing_full, PhishingAnalysisRequest
        import json
        
        req = PhishingAnalysisRequest(
            from_name=parsed.get("sender", ""),
            from_email=parsed.get("sender", ""),
            reply_to=parsed.get("reply_to", ""),
            subject=parsed.get("subject", ""),
            raw_headers="",
            body=(parsed.get("body_text") or "")[:3000],
        )

        # Bypass the HTTP layer to avoid deadlocking the FastAPI thread pool
        # when many emails arrive simultaneously.
        response = analyze_phishing_full(req)
        result = json.loads(response.body.decode("utf-8"))

        # Extract composite score from overall_score field
        score = float(
            result.get("overall_score")
            or result.get("composite_score")
            or result.get("phishing_score")
            or result.get("combined_score")
            or 0
        )
        # Normalise: scores sometimes come as 0-1 fractions
        if score <= 1.0:
            score *= 100

        risk_tier = _score_to_tier(score)
        verdict   = "SPAM" if risk_tier in ("CRITICAL", "HIGH") else "INBOX"

        # Build a normalized analysis object that EmailDetail.jsx can read
        # directly — keys match exactly what the frontend panels expect.
        # The /analyze/phishing response already contains all 7 module keys:
        # distilbert, roberta_ml, rule_based, ai_text, header_analysis,
        # llm_threat_analysis, credentials  — we add top-level convenience keys.
        normalized_analysis = {
            "source":              "IMAP",
            "overall_score":       round(score, 1),
            "overall_risk_score":  round(score, 1),   # alias for EmailDetail
            "overall_risk_tier":   risk_tier,          # alias for EmailDetail
            "risk_level":          result.get("risk_level", ""),
            "risk_emoji":          result.get("risk_emoji", ""),
            "recommendation":      result.get("recommendation", "REVIEW"),
            "processing_ms":       result.get("processing_ms", 0),
            # ── 7 module results (stored verbatim from /analyze/phishing) ──
            "distilbert":          result.get("distilbert", {}),
            "roberta_ml":          result.get("roberta_ml", {}),
            "rule_based":          result.get("rule_based", {}),
            "ai_text":             result.get("ai_text", {}),
            "header_analysis":     result.get("header_analysis", {}),
            "llm_threat_analysis": result.get("llm_threat_analysis", {}),
            "credentials":         result.get("credentials", {}),
        }

        folder    = "spam" if verdict == "SPAM" else "inbox"

        update_email_status(
            email_id   = email_id,
            status     = "COMPLETED",
            verdict    = verdict,
            folder     = folder,
            risk_score = int(round(score)),
            risk_tier  = risk_tier,
            analysis   = normalized_analysis,
        )

        logger.info(
            f"[IMAP Analysis] id={email_id} score={score:.1f} "
            f"tier={risk_tier} verdict={verdict} folder={folder}"
        )

        _broadcast({
            "type":        "email_completed",
            "email_id":    email_id,
            "status":      "COMPLETED",
            "verdict":     verdict,
            "folder":      folder,
            "risk_tier":   risk_tier,
            "risk_score":  int(round(score)),
            "subject":     parsed.get("subject", ""),
            "sender":      parsed.get("sender", ""),
            "received_at": parsed.get("date_str", "") or datetime.now(timezone.utc).isoformat(),
        })

    except Exception as e:
        logger.error(f"[IMAP Analysis] Failed for id={email_id}: {e}")
        # Fallback: basic rule-based scoring so email doesn't stay stuck as PROCESSING/UNKNOWN.
        subject_lower = (parsed.get("subject") or "").lower()
        sender_lower  = (parsed.get("sender")  or "").lower()
        spam_keywords = [
            "urgent", "act now", "click here", "verify your account",
            "winner", "congratulations", "free", "limited time",
            "bitcoin", "crypto", "lottery", "prize",
        ]
        spam_hits = sum(1 for kw in spam_keywords if kw in subject_lower or kw in sender_lower)
        fallback_score = min(spam_hits * 15, 65)  # cap at 65 (never auto-CRITICAL)
        fallback_tier  = _score_to_tier(fallback_score)
        fallback_verdict = "SPAM" if fallback_tier in ("HIGH",) else "INBOX"
        fallback_folder  = "spam" if fallback_verdict == "SPAM" else "inbox"

        fallback_analysis = {
            "source":             "IMAP_FALLBACK",
            "error":              str(e),
            "overall_score":      fallback_score,
            "overall_risk_score": fallback_score,
            "overall_risk_tier":  fallback_tier,
            "risk_level":         fallback_tier,
            "recommendation":     "REVIEW",
        }

        update_email_status(
            email_id  = email_id,
            status    = "COMPLETED",
            verdict   = fallback_verdict,
            folder    = fallback_folder,
            risk_score= fallback_score,
            risk_tier = fallback_tier,
            analysis  = fallback_analysis,
        )
        _broadcast({
            "type":        "email_completed",
            "email_id":    email_id,
            "status":      "COMPLETED",
            "verdict":     fallback_verdict,
            "folder":      fallback_folder,
            "risk_tier":   fallback_tier,
            "risk_score":  fallback_score,
            "subject":     parsed.get("subject", ""),
            "sender":      parsed.get("sender", ""),
            "received_at": parsed.get("date_str", "") or datetime.now(timezone.utc).isoformat(),
        })


# ── Storage helper ────────────────────────────────────────────────────────────

def _store_parsed(parsed: dict):
    attachments = parsed.pop("_attachments", [])
    parsed_copy = dict(parsed)

    # Initial ingestion state: Non-blocking write to DB with 'PROCESSING' state
    parsed["processing_status"] = "PROCESSING"
    parsed["folder"]            = "inbox"
    parsed["verdict"]           = None

    result = save_email(parsed)
    if result:
        email_id = result["id"]
        for att in attachments:
            save_attachment(email_id, att)
        logger.info(f"[EmailWorker] Fast-inserted: {parsed.get('subject','?')!r} (id={email_id}) status=PROCESSING")

        # Broadcast PROCESSING event immediately: UI displays blurred card within sub-3-5s
        _broadcast({
            "type":        "email_processing",
            "email_id":    email_id,
            "status":      "PROCESSING",
            "folder":      "inbox",
            "subject":     parsed_copy.get("subject", ""),
            "sender":      parsed_copy.get("sender", ""),
            "received_at": parsed_copy.get("date_str", "") or datetime.now(timezone.utc).isoformat(),
        })

        # Launch decoupled background analysis thread immediately
        t = threading.Thread(
            target=_analyze_and_update_email,
            args=(email_id, parsed_copy),
            daemon=True,
            name=f"imap-analysis-{email_id}",
        )
        t.start()


# ── Main Worker Entry Point ───────────────────────────────────────────────────

def _worker_loop():
    logger.info(f"[EmailWorker] Starting — mode={'IMAP IDLE (persistent TLS)' if IMAP_ENABLED else 'MailHog'}")
    if IMAP_ENABLED:
        _run_imap_idle()
    else:
        while True:
            try:
                _poll_mailhog()
            except Exception as e:
                logger.error(f"[EmailWorker] MailHog error: {e}")
            time.sleep(POLL_INTERVAL)


_worker_thread: Optional[threading.Thread] = None


def start_worker():
    global _worker_thread
    init_db()
    _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name="imap-worker")
    _worker_thread.start()
    logger.info("[EmailWorker] Thread started")
