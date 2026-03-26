/**
 * Barclays DLP Guardian — Content Script v3
 *
 * KEY DESIGN:
 *  – Safe prompt  → event is NEVER stopped. Zero UI, zero delay. No flicker.
 *  – Unsafe prompt → event stopped quietly, server called, popup shown on BLOCK/WARN.
 *  – No loading/scanning overlay, ever.
 *  – CSP-safe: no inline onclick attributes.
 */

const DLP_API = 'http://localhost:8001/gateway/analyze';
const GUARD_FLAG = '__dlp_safe_pass__';  // marks re-fired events to skip

// ── Site configs ──────────────────────────────────────────────────────────────
const SITE_CONFIG = {
  'chatgpt.com': {
    inputSelectors: ['#prompt-textarea', 'div[contenteditable="true"][data-id]', 'textarea'],
    submitSelectors: ['button[data-testid="send-button"]', 'button[aria-label="Send prompt"]', 'button[aria-label="Send message"]'],
    destination: 'ChatGPT',
  },
  'chat.openai.com': {
    inputSelectors: ['#prompt-textarea', 'textarea'],
    submitSelectors: ['button[data-testid="send-button"]', 'button[aria-label="Send prompt"]'],
    destination: 'ChatGPT',
  },
  'gemini.google.com': {
    inputSelectors: ['div.ql-editor[contenteditable="true"]', 'rich-textarea div[contenteditable]', 'div[contenteditable="true"]'],
    submitSelectors: ['button[aria-label="Send message"]', 'button.send-button', 'button[mattooltip="Send message"]'],
    destination: 'Gemini',
  },
  'chat.deepseek.com': {
    inputSelectors: ['textarea#chat-input', 'textarea[placeholder]', 'div[contenteditable="true"]'],
    submitSelectors: ['button[aria-label="Send"]', 'div[role="button"].send-button', 'button.send-btn'],
    destination: 'DeepSeek',
  },
  'claude.ai': {
    inputSelectors: ['div[contenteditable="true"].ProseMirror', 'div.ProseMirror', 'div[contenteditable="true"]'],
    submitSelectors: ['button[aria-label="Send Message"]', 'button[aria-label="Send message"]', 'button[type="submit"]'],
    destination: 'Claude',
  },
};

// ── Fast local pre-check (pure regex, synchronous, <1ms) ─────────────────────
// ONLY returns true if it finds something that looks genuinely suspicious.
// Intentionally conservative to avoid false positives.
const FAST_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/,                                                          // AWS key
  /\bASIA[0-9A-Z]{16}\b/,                                                          // AWS session
  /\bsk-[A-Za-z0-9]{32,}\b/,                                                       // OpenAI key
  /\bsk-ant-[A-Za-z0-9\-]{32,}\b/,                                                 // Anthropic key
  /\bghp_[A-Za-z0-9]{36}\b/,                                                       // GitHub PAT
  /\bglpat-[A-Za-z0-9\-_]{20,}\b/,                                                 // GitLab token
  /\bAIza[0-9A-Za-z\-_]{35}\b/,                                                    // GCP key
  /\bxoxb-[0-9A-Za-z\-]{50,}\b/,                                                   // Slack token
  /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/,                               // SendGrid
  /\bsk_live_[A-Za-z0-9]{24,}\b/,                                                  // Stripe
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,                        // PEM key
  /eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}/,            // JWT
  /(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[=:]\s*\S{6,}/i,          // credential assignment
  /\b\d{3}-\d{2}-\d{4}\b/,                                                         // SSN
  /\b[A-Z]{2}[0-9]{6}[A-Z]\b/,                                                     // UK NI number
  /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}\b/,                                           // IBAN
  /(?:cvv|cvc|pin)\s*[=:]\s*\d{3,6}/i,                                             // CVV/PIN
  /account\s*(?:number|no|#)?\s*[=:]?\s*\d{8,12}/i,                               // bank account
  /\b(?:STRICTLY\s+CONFIDENTIAL|BARCLAYS\s+INTERNAL|BARCLAYS\s+CONFIDENTIAL)\b/i,  // markers
  // Password heuristic: 8-20 char token with upper+lower+digit+special
  // Uses a very specific pattern to avoid matching normal English words
  /(?<![A-Za-z])(?=[A-Za-z0-9!@#$%^&*\-_+=]{8,20}(?![A-Za-z0-9!@#$%^&*\-_+=]))(?=[^!@#$%^&*\-_+=]*[!@#$%^&*\-_+=])(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])(?=[^0-9]*[0-9])[A-Za-z0-9!@#$%^&*\-_+=]{8,20}/,
];

function localPreCheck(text) {
  return FAST_PATTERNS.some(pat => pat.test(text));
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function getHostConfig() {
  const host = window.location.hostname.replace('www.', '');
  return SITE_CONFIG[host] || null;
}

function getPromptText(config) {
  for (const sel of config.inputSelectors) {
    const el = document.querySelector(sel);
    if (!el) continue;
    const txt = (el.innerText || el.textContent || el.value || '').trim();
    if (txt) return txt;
  }
  return '';
}

// ── Server scan with 60s timeout, fail-open ─────────────────────────────────
async function scanWithServer(text, destination) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 60000);  // 60s matches server LLM timeout
  try {
    const res = await fetch(DLP_API, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: 'browser-user',
        department: 'general',
        role: 'employee',
        prompt: text,
        destination_model: destination.toLowerCase(),
      }),
    });
    clearTimeout(t);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch {
    clearTimeout(t);
    return { decision: 'PASS', risk_score: 0, risk_tier: 'low', block_reason: '', detected_types: [] };
  }
}

// ── Overlay helpers (CSP-safe, no inline onclick) ─────────────────────────────
function removeOverlay() {
  const el = document.getElementById('dlp-guardian-overlay');
  if (el) el.remove();
}

function makeOverlay(html) {
  removeOverlay();
  const wrap = document.createElement('div');
  wrap.id = 'dlp-guardian-overlay';
  wrap.innerHTML = html;
  document.body.appendChild(wrap);
  return wrap;
}

function showScanningOverlay(filename) {
  removeOverlay();
  const wrap = document.createElement('div');
  wrap.id = 'dlp-guardian-overlay';
  Object.assign(wrap.style, {
    position: 'fixed', inset: '0', zIndex: '2147483647',
    background: 'rgba(248,250,252,0.2)',
    backdropFilter: 'blur(4px)', WebkitBackdropFilter: 'blur(4px)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontFamily: "'Inter',-apple-system,BlinkMacSystemFont,sans-serif",
  });
  wrap.innerHTML = `
    <style>
      @keyframes dlp-spin-doc { to { transform: rotate(360deg); } }
      @keyframes dlp-bar { 0% { left:-55%; } 100% { left:100%; } }
      @keyframes dlp-scale-in { from{opacity:0;transform:scale(0.92);} to{opacity:1;transform:scale(1);} }
    </style>
    <div style="position:fixed;top:0;left:0;right:0;height:3px;overflow:hidden;background:rgba(14,165,233,0.15);">
      <div style="position:absolute;top:0;bottom:0;width:55%;background:linear-gradient(90deg,transparent,#0EA5E9,#38BDF8,transparent);animation:dlp-bar 1.2s ease-in-out infinite;"></div>
    </div>
    <div style="background:#fff;border-radius:20px;max-width:380px;width:90%;padding:28px 24px;text-align:center;box-shadow:0 8px 48px rgba(14,165,233,0.18),0 2px 8px rgba(0,0,0,0.07);border:1px solid #E0F2FE;animation:dlp-scale-in 0.22s ease;">
      <div style="width:56px;height:56px;border-radius:50%;border:3px solid #E0F2FE;border-top-color:#0EA5E9;animation:dlp-spin-doc 0.8s linear infinite;margin:0 auto 18px;"></div>
      <div style="font-size:16px;font-weight:700;color:#0F172A;letter-spacing:-0.01em;font-family:inherit;">Scanning Document…</div>
      <div style="font-size:12px;color:#0EA5E9;font-weight:600;margin-top:4px;font-family:inherit;">AegisAI DLP Guardian</div>
      <div style="margin-top:12px;background:#F0F9FF;border-radius:8px;padding:9px 12px;border:1px solid #E0F2FE;">
        <div style="font-size:11px;color:#64748B;font-family:inherit;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">📄 ${filename}</div>
      </div>
      <div style="margin-top:12px;font-size:11.5px;color:#94A3B8;line-height:1.65;font-family:inherit;">Extracting &amp; classifying content…<br><span style="color:#CBD5E1;font-size:10.5px;">This may take up to 60 seconds</span></div>
    </div>`;
  document.body.appendChild(wrap);
}

function showPromptScanningOverlay() {
  removeOverlay();
  const wrap = document.createElement('div');
  wrap.id = 'dlp-guardian-overlay';
  Object.assign(wrap.style, {
    position: 'fixed', inset: '0', zIndex: '2147483647',
    background: 'rgba(248,250,252,0.12)',
    backdropFilter: 'blur(2px)', WebkitBackdropFilter: 'blur(2px)',
    display: 'flex', alignItems: 'flex-end', justifyContent: 'center',
    paddingBottom: '48px', boxSizing: 'border-box',
    fontFamily: "'Inter',-apple-system,BlinkMacSystemFont,sans-serif",
  });
  wrap.innerHTML = `
    <style>
      @keyframes dlp-spin-p { to { transform: rotate(360deg); } }
      @keyframes dlp-bar-p { 0% { left:-50%; } 100% { left:100%; } }
      @keyframes dlp-fade-up { from{opacity:0;transform:translateY(10px);} to{opacity:1;transform:translateY(0);} }
      @keyframes dlp-bar-beat { 0%,100%{opacity:.25;transform:scaleY(.55);} 50%{opacity:1;transform:scaleY(1);} }
    </style>
    <div style="position:fixed;top:0;left:0;right:0;height:3px;overflow:hidden;background:rgba(14,165,233,0.12);">
      <div style="position:absolute;top:0;bottom:0;width:50%;background:linear-gradient(90deg,transparent,#0EA5E9,#38BDF8,transparent);animation:dlp-bar-p 1.1s ease-in-out infinite;"></div>
    </div>
    <div style="background:#fff;border-radius:18px;padding:14px 18px 14px 16px;display:flex;align-items:center;gap:14px;box-shadow:0 4px 28px rgba(14,165,233,0.2),0 1px 4px rgba(0,0,0,0.06);border:1px solid #E0F2FE;animation:dlp-fade-up 0.2s ease;min-width:268px;max-width:360px;">
      <div style="width:34px;height:34px;border-radius:50%;border:2.5px solid #E0F2FE;border-top-color:#0EA5E9;animation:dlp-spin-p 0.75s linear infinite;flex-shrink:0;"></div>
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:700;color:#0F172A;letter-spacing:-0.01em;font-family:inherit;">Scanning Prompt…</div>
        <div style="font-size:11px;color:#94A3B8;margin-top:2px;font-weight:500;font-family:inherit;">AegisAI DLP — Checking for sensitive data</div>
      </div>
      <div style="display:flex;gap:3px;align-items:center;flex-shrink:0;">
        <div style="width:4px;height:14px;background:#0EA5E9;border-radius:2px;animation:dlp-bar-beat 0.9s ease-in-out infinite;"></div>
        <div style="width:4px;height:14px;background:#38BDF8;border-radius:2px;animation:dlp-bar-beat 0.9s ease-in-out 0.15s infinite;"></div>
        <div style="width:4px;height:14px;background:#7DD3FC;border-radius:2px;animation:dlp-bar-beat 0.9s ease-in-out 0.3s infinite;"></div>
      </div>
    </div>`;
  document.body.appendChild(wrap);
}

function showBlockOverlay(result, destination) {
  const types = (result.detected_types || []);
  const tagsHtml = types.length
    ? `<div class="dlp-types"><div class="dlp-types-label">Detected categories</div>
       <div class="dlp-tags">${types.map(t => `<span class="dlp-tag">${t}</span>`).join('')}</div></div>`
    : '';

  const wrap = makeOverlay(`
    <div class="dlp-modal dlp-modal-block">
      <div class="dlp-stripe"></div>
      <div class="dlp-header">
        <div class="dlp-header-left">
          <div class="dlp-shield">🛡️</div>
          <div>
            <div class="dlp-title">Prompt Blocked</div>
            <div class="dlp-subtitle">Barclays DLP Guardian</div>
          </div>
        </div>
        <button class="dlp-x" id="dlp-close-btn" aria-label="Close">✕</button>
      </div>
      <div class="dlp-body">
        <div class="dlp-hero dlp-hero-block">
          <div class="dlp-hero-icon">⛔</div>
          <div class="dlp-hero-text">Your message was blocked and <strong>never sent</strong> to ${destination}.</div>
        </div>
        <div class="dlp-reason-box">
          <div class="dlp-reason-label">Reason</div>
          <div class="dlp-reason-text">${result.block_reason || 'Sensitive data detected in your message.'}</div>
        </div>
        <div class="dlp-stats">
          <div class="dlp-stat-pill dlp-pill-block">⛔ BLOCKED</div>
          <div class="dlp-stat-pill dlp-pill-score">Risk: <b>${result.risk_score}/100</b></div>
          <div class="dlp-stat-pill dlp-pill-tier">${(result.risk_tier || 'high').toUpperCase()}</div>
        </div>
        ${tagsHtml}
        <div class="dlp-footer">
          This event has been recorded in the <strong>Barclays DLP Audit System</strong>.
          Contact your security team if this is a false positive.
        </div>
      </div>
    </div>
  `);

  wrap.querySelector('#dlp-close-btn').addEventListener('click', removeOverlay);
  wrap.addEventListener('click', (e) => { if (e.target === wrap) removeOverlay(); });
}

function showWarnOverlay(result, onProceed, onCancel) {
  const types = (result.detected_types || []);
  const tagsHtml = types.length
    ? `<div class="dlp-types"><div class="dlp-types-label">Detected categories</div>
       <div class="dlp-tags">${types.map(t => `<span class="dlp-tag">${t}</span>`).join('')}</div></div>`
    : '';

  const wrap = makeOverlay(`
    <div class="dlp-modal dlp-modal-warn">
      <div class="dlp-stripe dlp-stripe-warn"></div>
      <div class="dlp-header">
        <div class="dlp-header-left">
          <div class="dlp-shield">⚠️</div>
          <div>
            <div class="dlp-title">Caution: Sensitive Content</div>
            <div class="dlp-subtitle">Barclays DLP Guardian</div>
          </div>
        </div>
        <button class="dlp-x" id="dlp-close-btn" aria-label="Close">✕</button>
      </div>
      <div class="dlp-body">
        <div class="dlp-hero dlp-hero-warn">
          <div class="dlp-hero-icon">⚠️</div>
          <div class="dlp-hero-text">Potentially sensitive content detected. Please review before sending.</div>
        </div>
        <div class="dlp-reason-box">
          <div class="dlp-reason-label">Details</div>
          <div class="dlp-reason-text">${result.block_reason || 'Your message may contain sensitive information.'}</div>
        </div>
        <div class="dlp-stats">
          <div class="dlp-stat-pill dlp-pill-warn">⚠️ WARNING</div>
          <div class="dlp-stat-pill dlp-pill-score">Risk: <b>${result.risk_score}/100</b></div>
        </div>
        ${tagsHtml}
        <div class="dlp-actions">
          <button class="dlp-btn-cancel" id="dlp-cancel-btn">Cancel (Recommended)</button>
          <button class="dlp-btn-proceed" id="dlp-proceed-btn">Send Anyway</button>
        </div>
        <div class="dlp-footer">This event has been recorded in the <strong>Barclays DLP Audit System</strong>.</div>
      </div>
    </div>
  `);

  wrap.querySelector('#dlp-close-btn').addEventListener('click', () => { removeOverlay(); onCancel(); });
  wrap.querySelector('#dlp-cancel-btn').addEventListener('click', () => { removeOverlay(); onCancel(); });
  wrap.querySelector('#dlp-proceed-btn').addEventListener('click', () => { removeOverlay(); onProceed(); });
  wrap.addEventListener('click', (e) => { if (e.target === wrap) { removeOverlay(); onCancel(); } });
}

// ── Core decision flow ────────────────────────────────────────────────────────
let scanning = false;

async function runDlpCheck(text, config, submitFn) {
  console.log(`[DLP Guardian] 🛡️ Intercepted prompt to ${config.destination} (${text.length} chars)`);
  console.log(`[DLP Guardian] Prompt preview: "${text.substring(0, 60)}..."`);

  // Step 1: fast local check — catches obvious threats with <1ms regex
  const localHit = localPreCheck(text);
  if (localHit) {
    console.log(`[DLP Guardian] ⚠️ Local Regex flagged suspicious pattern. Sending to API...`);
  } else {
    console.log(`[DLP Guardian] 🔍 Local regex clean — sending to API for deep scan (PII/Intent/Context)...`);
  }

  // Step 2: ALWAYS call the server — it runs 10-layer regex + entropy for complete coverage
  // (this replaces the old fail-open for undetected patterns)
  scanning = true;
  showPromptScanningOverlay();
  const result = await scanWithServer(text, config.destination);
  removeOverlay();
  scanning = false;

  console.log(`[DLP Guardian] 📊 API Scan Result:`, result);

  if (result.decision === 'BLOCK') {
    console.warn(`[DLP Guardian] 🛑 BLOCKED! Risk: ${result.risk_score}`);
    if (result.findings && result.findings.length > 0) {
      result.findings.forEach(f => {
        console.warn(`   ↳ 🎯 Layer: [${f.layer.toUpperCase()}] | Category: ${f.category} | Severity: ${f.severity}`);
      });
    }
    showBlockOverlay(result, config.destination);
    return false;
  }

  if (result.decision === 'WARN') {
    console.warn(`[DLP Guardian] ⚠️ WARN! Risk: ${result.risk_score}`);
    if (result.findings && result.findings.length > 0) {
      result.findings.forEach(f => {
        console.warn(`   ↳ 🔍 Layer: [${f.layer.toUpperCase()}] | Category: ${f.category} | Severity: ${f.severity}`);
      });
    }
    showWarnOverlay(result, submitFn, () => { });
    return false;
  }

  // PASS from server
  console.log(`[DLP Guardian] ✅ API cleared prompt. Risk: ${result.risk_score}/100 — Sending to ${config.destination}.`);
  removeOverlay(); // Clear scanning overlay on success
  return true;
}

// ── Keyboard interceptor ──────────────────────────────────────────────────────
function attachKeyInterceptor(config) {
  document.addEventListener('keydown', async (e) => {
    // Skip if already scanning, shift+enter (newline), or marked as safe
    if (e[GUARD_FLAG] || e.shiftKey || e.key !== 'Enter' || scanning) return;

    const active = document.activeElement;
    const inInput = config.inputSelectors.some(sel => {
      const el = document.querySelector(sel);
      return el && (el === active || el.contains(active));
    });
    if (!inInput) return;

    const text = getPromptText(config);
    if (!text) return;

    // ALWAYS scan every prompt — server has comprehensive regex even for 'clean' looking text
    e.preventDefault();
    e.stopImmediatePropagation();

    const pass = await runDlpCheck(text, config, () => {
      // Fire a marked Enter that we won't intercept again
      const safeEvt = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true, cancelable: true });
      safeEvt[GUARD_FLAG] = true;
      active.dispatchEvent(safeEvt);
    });

    if (pass) {
      const safeEvt = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true, cancelable: true });
      safeEvt[GUARD_FLAG] = true;
      active.dispatchEvent(safeEvt);
    }
  }, true);
}

// ── Button interceptor ────────────────────────────────────────────────────────
function bindSubmitButton(btn, config) {
  if (btn.dataset.dlpBound === 'true') return;
  btn.dataset.dlpBound = 'true';

  btn.addEventListener('click', async (e) => {
    if (e[GUARD_FLAG] || scanning) return;

    const text = getPromptText(config);
    if (!text) return;

    // ALWAYS send to server — don't rely solely on local regex
    e.preventDefault();
    e.stopImmediatePropagation();

    const pass = await runDlpCheck(text, config, () => {
      const safeClick = new MouseEvent('click', { bubbles: true, cancelable: true });
      safeClick[GUARD_FLAG] = true;
      btn.dispatchEvent(safeClick);
    });

    if (pass) {
      const safeClick = new MouseEvent('click', { bubbles: true, cancelable: true });
      safeClick[GUARD_FLAG] = true;
      btn.dispatchEvent(safeClick);
    }
  }, true);
}

function attachButtonInterceptor(config) {
  function tryBind() {
    config.submitSelectors.forEach(sel => {
      const btn = document.querySelector(sel);
      if (btn) bindSubmitButton(btn, config);
    });
  }
  tryBind();
  new MutationObserver(tryBind).observe(document.body, { childList: true, subtree: true });
}

// ── File Upload Interceptor ───────────────────────────────────────────────────
// Catches files selected via <input type="file"> before they are uploaded to LLMs.
// Supported: .pdf, .docx, .txt, .csv, .xlsx, .json, .md, .py, .env, .sql, .log
const DLP_SCAN_FILE_API = 'http://localhost:8001/gateway/scan-file';
const SUPPORTED_EXTENSIONS = new Set([
  'pdf', 'docx', 'doc', 'txt', 'csv', 'xlsx', 'xls', 'json', 'md',
  'py', 'js', 'env', 'sql', 'log', 'yaml', 'yml', 'xml', 'html',
]);

async function scanFileWithServer(file, destination) {
  const formData = new FormData();
  formData.append('file', file, file.name);
  formData.append('user_id', 'browser-user');
  formData.append('department', 'general');
  formData.append('role', 'employee');
  formData.append('destination', destination.toLowerCase());

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 60000); // Wait up to 60 seconds for PDFs/Word
  try {
    const res = await fetch(DLP_SCAN_FILE_API, {
      method: 'POST',
      signal: ctrl.signal,
      body: formData,
    });
    clearTimeout(t);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch (err) {
    clearTimeout(t);
    console.warn('[DLP Guardian] File scan failed (fail-open):', err.message);
    return { decision: 'PASS', risk_score: 0, doc_classification: 'UNKNOWN', block_reason: '' };
  }
}

function showFileBlockOverlay(result, filename, destination) {
  removeOverlay();
  const classLevel = result.doc_classification || 'CONFIDENTIAL';
  const classColor = {
    RESTRICTED: '#dc2626', CONFIDENTIAL: '#ea580c',
    INTERNAL: '#d97706', PUBLIC: '#16a34a',
  }[classLevel] || '#dc2626';

  const reasons = (result.reasons || []).filter(r => r).slice(0, 4);
  const reasonsHtml = reasons.length
    ? `<div style="margin-top:2px"><div style="font-size:10px;font-weight:700;color:#94A3B8;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px">Classification Reasons</div><ul style="margin:0 0 0 16px;padding:0;color:#475569;font-size:12px;line-height:1.8">${reasons.map(r => `<li>${r}</li>`).join('')}</ul></div>` : '';

  const pii = (result.pii_findings || []).slice(0, 5);
  const piiHtml = pii.length
    ? `<div style="margin-top:2px"><div style="font-size:10px;font-weight:700;color:#94A3B8;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px">Detected in Document</div><div style="display:flex;flex-wrap:wrap;gap:5px">${pii.map(p => `<span style="background:#F0F9FF;color:#0284C7;border:1px solid #BAE6FD;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600">${p.category}</span>`).join('')}</div></div>` : '';

  const wrap = document.createElement('div');
  wrap.id = 'dlp-guardian-overlay';
  wrap.innerHTML = `
    <div style="position:fixed;inset:0;background:rgba(15,23,42,0.55);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;backdrop-filter:blur(8px)">
      <div style="background:#fff;border:1px solid #FECACA;border-radius:20px;max-width:480px;width:92%;padding:0;overflow:hidden;box-shadow:0 0 0 1px rgba(239,68,68,0.1),0 20px 60px rgba(0,0,0,0.2)">
        <div style="height:4px;background:linear-gradient(90deg,#dc2626,#f97316)"></div>
        <div style="background:linear-gradient(135deg,#FFF5F5 0%,#fff 60%);padding:18px 20px 14px;border-bottom:1px solid #F1F5F9;display:flex;justify-content:space-between;align-items:flex-start">
          <div style="display:flex;align-items:center;gap:12px">
            <div style="font-size:26px;filter:drop-shadow(0 0 6px rgba(239,68,68,0.4))">🚫</div>
            <div>
              <div style="font-size:15px;font-weight:700;color:#0F172A;letter-spacing:-0.01em">File Upload Blocked</div>
              <div style="font-size:11px;color:#0EA5E9;font-weight:600;margin-top:2px">AegisAI DLP Guardian</div>
            </div>
          </div>
          <button id="dlp-file-close" style="background:#F1F5F9;border:none;color:#94A3B8;font-size:13px;cursor:pointer;padding:0;width:30px;height:30px;border-radius:8px;display:grid;place-items:center;transition:all 0.15s;font-family:inherit">✕</button>
        </div>
        <div style="padding:18px 20px;display:flex;flex-direction:column;gap:12px;">
          <div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:12px;padding:13px 15px">
            <div style="font-size:10px;font-weight:700;color:#94A3B8;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px">Blocked File</div>
            <div style="font-size:13px;font-weight:600;color:#DC2626;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">📄 ${filename}</div>
            <div style="font-size:13px;color:#374151;margin-top:8px;line-height:1.55">${result.block_reason || 'This document contains sensitive or classified information.'}</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <div style="padding:4px 12px;border-radius:8px;font-size:11px;font-weight:700;background:#FEF2F2;color:#DC2626;border:1px solid #FECACA">🔴 ${classLevel}</div>
            <div style="padding:4px 12px;border-radius:8px;font-size:11px;font-weight:700;background:#F0F9FF;color:#0369A1;border:1px solid #BAE6FD">Risk: ${result.risk_score}/100</div>
            <div style="padding:4px 12px;border-radius:8px;font-size:11px;font-weight:700;background:#F5F3FF;color:#7C3AED;border:1px solid #DDD6FE">${result.doc_type || classLevel}</div>
          </div>
          ${piiHtml}${reasonsHtml}
          <div style="font-size:11px;color:#94A3B8;line-height:1.6;border-top:1px solid #F1F5F9;padding-top:12px">
            This event has been recorded in the <strong style="color:#64748B">AegisAI DLP Audit System</strong>. Contact your security team if this is incorrect.
          </div>
        </div>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  wrap.querySelector('#dlp-file-close').addEventListener('click', removeOverlay);
  wrap.addEventListener('click', (e) => { if (e.target === wrap.firstElementChild) removeOverlay(); });
}

function attachFileInterceptor(config) {

  async function handleFiles(files, eventToCancel) {
    if (!files || files.length === 0) return true;

    // Check if any file is supported
    const filesToScan = Array.from(files).filter(f => {
      const ext = f.name.split('.').pop().toLowerCase();
      return SUPPORTED_EXTENSIONS.has(ext);
    });

    if (filesToScan.length === 0) return true; // Let images pass

    // Stop LLM site from getting the file immediately
    if (eventToCancel) {
      eventToCancel.preventDefault();
      eventToCancel.stopImmediatePropagation();
    }

    const file = filesToScan[0]; // Scan first file
    console.log(`[DLP Guardian] 📎 File intercepted: "${file.name}" (${(file.size / 1024).toFixed(1)}KB)`);

    // Show waiting UI
    showScanningOverlay(file.name);

    const result = await scanFileWithServer(file, config.destination);

    if (result.decision === 'BLOCK') {
      console.warn(`[DLP Guardian] 🛑 FILE BLOCKED: "${file.name}" -> ${result.doc_classification}`);
      showFileBlockOverlay(result, file.name, config.destination);
      return false; // Blocking
    } else if (result.decision === 'WARN') {
      showWarnOverlay(result, () => { removeOverlay(); }, removeOverlay);
      return false;
    } else {
      removeOverlay();
      return true; // Pass
    }
  }

  // 1. Intercept Drag & Drop
  document.addEventListener('drop', async (e) => {
    if (e[GUARD_FLAG] || scanning) return;
    const files = e.dataTransfer && e.dataTransfer.files;
    if (!files || files.length === 0) return;

    scanning = true;
    const allowed = await handleFiles(files, e);
    scanning = false;

    // If allowed, we re-fire the drop event so the site can process it
    if (allowed) {
      const dropEvent = new DragEvent('drop', {
        bubbles: true, cancelable: true,
        dataTransfer: e.dataTransfer // preserve the files
      });
      dropEvent[GUARD_FLAG] = true;
      e.target.dispatchEvent(dropEvent);
    }
  }, true);

  // 2. Intercept <input type="file"> via capture phase
  function interceptFileInput(input) {
    if (input.dataset.dlpFileBound === 'true') return;
    input.dataset.dlpFileBound = 'true';

    input.addEventListener('change', async (e) => {
      if (e[GUARD_FLAG] || scanning) return;
      const files = input.files;
      if (!files || files.length === 0) return;

      scanning = true;
      const allowed = await handleFiles(files, e);
      scanning = false;

      if (allowed) {
        const changeEvent = new Event('change', { bubbles: true, cancelable: true });
        changeEvent[GUARD_FLAG] = true;
        input.dispatchEvent(changeEvent);
      } else {
        input.value = ''; // clear the input completely so the site gets nothing
      }
    }, true);
  }

  // Bind to all current and future file inputs
  document.querySelectorAll('input[type="file"]').forEach(interceptFileInput);
  new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1) {
          if (node.tagName === 'INPUT' && node.type === 'file') interceptFileInput(node);
          node.querySelectorAll?.('input[type="file"]').forEach(interceptFileInput);
        }
      }
    }
  }).observe(document.body, { childList: true, subtree: true });
}

// ── Init ──────────────────────────────────────────────────────────────────────
(function init() {
  const config = getHostConfig();
  if (!config) return;
  console.log('[DLP Guardian v3] Active on', window.location.hostname, '→', config.destination);
  attachKeyInterceptor(config);
  attachButtonInterceptor(config);
  attachFileInterceptor(config);   // 🆕 intercept file uploads
  console.log('[DLP Guardian] 📎 File upload interception active for:', config.destination);
})();

