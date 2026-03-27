import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiArrowLeftLine, RiLoader4Line, RiShieldCheckLine, RiAlertLine,
  RiErrorWarningLine, RiCheckboxCircleLine, RiExternalLinkLine,
  RiAttachment2, RiLockLine, RiGlobalLine, RiRobot2Line,
  RiMailLine, RiArrowDownSLine, RiArrowUpSLine, RiFileCopyLine,
  RiShieldLine, RiDatabase2Line, RiSearchLine, RiFileDamageLine,
  RiCheckLine, RiCloseLine, RiTimeLine, RiInformationLine,
  RiFilePdfLine, RiFileCodeLine, RiFileTextLine, RiFileZipLine,
  RiFileWarningLine, RiEyeLine, RiFlagLine, RiRefreshLine,
  RiBarChartLine, RiSpam2Line, RiCakeLine,
  RiServerLine, RiCalendarLine, RiFingerprint2Line,
  RiLinksLine, RiShieldKeyholeLine, RiBrainLine, RiCodeSSlashLine,
} from 'react-icons/ri'
import { PageWrapper, ScoreMeter } from '../components/ui'

// ── Risk tier helpers ──────────────────────────────────────────────────────────
const TIER_CFG = {
  CRITICAL: { bg: 'bg-red-50',    border: 'border-red-200',   text: 'text-red-700',    dot: 'bg-red-500',    label: 'Critical'  },
  HIGH:     { bg: 'bg-amber-50',  border: 'border-amber-200', text: 'text-amber-700',  dot: 'bg-amber-500',  label: 'High'      },
  MEDIUM:   { bg: 'bg-sky-50',    border: 'border-sky-200',   text: 'text-sky-700',    dot: 'bg-sky-400',    label: 'Medium'    },
  LOW:      { bg: 'bg-slate-50',  border: 'border-slate-200', text: 'text-slate-600',  dot: 'bg-slate-400',  label: 'Low'       },
  UNKNOWN:  { bg: 'bg-slate-50',  border: 'border-slate-200', text: 'text-slate-500',  dot: 'bg-slate-300',  label: 'Unknown'   },
}

function tierCfg(tier) { return TIER_CFG[tier] || TIER_CFG.UNKNOWN }

function TierBadge({ tier, size = 'sm' }) {
  const cfg = tierCfg(tier)
  const cls = size === 'lg'
    ? `px-3 py-1 text-[12px] font-bold`
    : `px-2 py-0.5 text-[10px] font-bold`
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border ${cls} ${cfg.bg} ${cfg.border} ${cfg.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

// ── Section card ───────────────────────────────────────────────────────────────
function AnalysisSection({ icon, title, badge, children, defaultOpen = false, loading = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-slate-50/60 transition-colors"
      >
        <span className="text-sky-500 text-lg flex-shrink-0">{icon}</span>
        <span className="flex-1 text-[14px] font-bold text-slate-800">{title}</span>
        {badge}
        {loading
          ? <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
              <RiLoader4Line className="text-slate-400" />
            </motion.span>
          : <span className="text-slate-300">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
        }
      </button>
      <AnimatePresence>
        {open && !loading && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="border-t border-slate-100"
          >
            <div className="px-5 py-4">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Score bar ──────────────────────────────────────────────────────────────────
function ScoreBar({ label, value, max = 100, color = 'bg-sky-500', delay = 0 }) {
  const pct = Math.min(100, Math.round((value / max) * 100))
  return (
    <div className="flex items-center gap-3">
      <span className="text-[12px] text-slate-500 w-40 flex-shrink-0">{label}</span>
      <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <motion.div
          className={`h-full rounded-full ${color}`}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, delay, ease: [0.34, 1.2, 0.64, 1] }}
        />
      </div>
      <span className="text-[12px] font-bold text-slate-700 w-10 text-right">{value}</span>
    </div>
  )
}

// ── Indicator chip ─────────────────────────────────────────────────────────────
function IndicatorChip({ text, level = 'warn' }) {
  const cfg = {
    warn:  'bg-amber-50 border-amber-200 text-amber-700',
    danger:'bg-red-50 border-red-200 text-red-700',
    info:  'bg-sky-50 border-sky-200 text-sky-700',
    ok:    'bg-emerald-50 border-emerald-200 text-emerald-700',
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-medium ${cfg[level] || cfg.info}`}>
      {text}
    </span>
  )
}

// ── Finding row ────────────────────────────────────────────────────────────────
function FindingRow({ finding }) {
  const [open, setOpen] = useState(false)
  const severity = (finding.severity || finding.type || '').toLowerCase()
  const dotColor = {
    critical: 'bg-red-500', high: 'bg-amber-500', medium: 'bg-sky-400',
    low: 'bg-slate-400', info: 'bg-blue-400',
  }[severity] || 'bg-slate-300'

  return (
    <div className="border border-slate-100 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-slate-50 transition-colors"
      >
        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dotColor}`} />
        <span className="flex-1 text-[12px] text-slate-700 text-left">
          {finding.description || finding.value || finding.type || '—'}
        </span>
        {finding.type && (
          <span className="text-[10px] text-slate-400 font-mono bg-slate-100 px-1.5 py-0.5 rounded">
            {finding.type}
          </span>
        )}
        <span className="text-slate-300 text-xs">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
      </button>
      {open && finding.value && (
        <div className="px-4 py-2 bg-slate-50 border-t border-slate-100">
          <code className="text-[11px] text-slate-600 break-all">{finding.value}</code>
        </div>
      )}
    </div>
  )
}

// ── File icon ──────────────────────────────────────────────────────────────────
function FileIcon({ filename, className = 'text-base' }) {
  const ext = (filename?.split('.').pop() || '').toLowerCase()
  if (['pdf'].includes(ext)) return <RiFilePdfLine className={`text-red-400 ${className}`} />
  if (['zip','rar','7z','gz'].includes(ext)) return <RiFileZipLine className={`text-amber-400 ${className}`} />
  if (['js','py','rb','sh','vbs','ps1','bat'].includes(ext)) return <RiFileCodeLine className={`text-purple-400 ${className}`} />
  if (['doc','docx','xls','xlsx','ppt','pptx'].includes(ext)) return <RiFileTextLine className={`text-blue-400 ${className}`} />
  if (['exe','dll','msi','sys'].includes(ext)) return <RiFileWarningLine className={`text-red-500 ${className}`} />
  return <RiAttachment2 className={`text-slate-400 ${className}`} />
}

function formatBytes(b) {
  if (!b || b === 0) return '0 B'
  const k = 1024
  const sizes = ['B','KB','MB','GB']
  const i = Math.floor(Math.log(b) / Math.log(k))
  return `${parseFloat((b / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

// ── Phase card (from attachment scanner) ──────────────────────────────────────
function PhaseCard({ phase, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  if (!phase) return null

  const STATUS_CFG = {
    clean:    { bar: 'bg-emerald-500', text: 'text-emerald-700', bg: 'bg-emerald-50', label: 'Clean'    },
    low:      { bar: 'bg-sky-400',     text: 'text-sky-700',     bg: 'bg-sky-50',     label: 'Low'      },
    medium:   { bar: 'bg-amber-400',   text: 'text-amber-700',   bg: 'bg-amber-50',   label: 'Medium'   },
    high:     { bar: 'bg-red-400',     text: 'text-red-700',     bg: 'bg-red-50',     label: 'High'     },
    critical: { bar: 'bg-red-600',     text: 'text-red-800',     bg: 'bg-red-50',     label: 'Critical' },
    info:     { bar: 'bg-slate-400',   text: 'text-slate-600',   bg: 'bg-slate-50',   label: 'Info'     },
    pending:  { bar: 'bg-slate-300',   text: 'text-slate-500',   bg: 'bg-slate-50',   label: 'Pending'  },
  }
  const sc = STATUS_CFG[phase.status] || STATUS_CFG.info

  return (
    <div className="border border-slate-100 rounded-xl overflow-hidden bg-white">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-slate-50 transition-colors"
      >
        <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 ${sc.bg}`}>
          <span className={`text-[10px] font-bold ${sc.text}`}>{phase.id}</span>
        </div>
        <span className="flex-1 text-[13px] font-semibold text-slate-700">
          {phase.name}
        </span>
        <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${sc.bg} ${sc.text} border-transparent`}>
          {sc.label}
        </span>
        {phase.summary && (
          <span className="text-[11px] text-slate-400 hidden sm:block max-w-[200px] truncate">{phase.summary}</span>
        )}
        <span className="text-slate-300">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }}
            transition={{ duration: 0.15 }}
            className="border-t border-slate-100 bg-slate-50/40 px-4 py-3"
          >
            {phase.details && phase.id === 1 && (
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(phase.details).map(([k, v]) => v && (
                  <div key={k} className="flex flex-col gap-0.5">
                    <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">{k.replace(/_/g,' ')}</span>
                    <span className="text-[12px] text-slate-700 font-medium break-all">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}
            {phase.analyzers && phase.id === 2 && (
              <div className="space-y-2">
                {phase.analyzers.map((a, i) => (
                  <div key={i} className="p-3 rounded-lg bg-white border border-slate-100">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[12px] font-semibold text-slate-700">{a.name}</span>
                      <span className="text-[10px] text-slate-400">{a.findings?.length || 0} findings</span>
                    </div>
                    {a.findings?.map((f, j) => (
                      <div key={j} className="flex items-center gap-2 mt-1">
                        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                          f.severity === 'critical' ? 'bg-red-500' : f.severity === 'high' ? 'bg-amber-500' : 'bg-sky-400'
                        }`} />
                        <span className="text-[11px] text-slate-600">{f.description || f.rule_name}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
            {phase.details && phase.id === 3 && (
              <div className="space-y-1">
                {['md5', 'sha1', 'sha256'].map(h => phase.details[h] && (
                  <div key={h} className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold text-slate-400 w-12">{h.toUpperCase()}</span>
                    <code className="text-[10px] text-slate-600 font-mono break-all">{phase.details[h]}</code>
                  </div>
                ))}
              </div>
            )}
            {phase.id === 4 && (
              <div>
                <p className="text-[12px] text-slate-700">{phase.human_summary}</p>
                {phase.recommended_action && (
                  <p className="text-[11px] font-semibold text-sky-600 mt-1">{phase.recommended_action}</p>
                )}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Attachment scanner panel ───────────────────────────────────────────────────
function AttachmentPanel({ emailId, att }) {
  const [scanType, setScanType]     = useState('static')
  const [scanResult, setScanResult] = useState(null)
  const [scanning, setScanning]     = useState(false)
  const [scanned, setScanned]       = useState(false)

  const runScan = async (type) => {
    setScanType(type)
    setScanning(true)
    try {
      const res = await fetch(`/api/email/emails/${emailId}/attachments/${att.id}/analyze?scan_type=${type}`, {
        method: 'POST'
      })
      if (res.ok) {
        setScanResult(await res.json())
        setScanned(true)
      }
    } catch (e) {
      console.warn('Scan failed:', e)
    } finally {
      setScanning(false)
    }
  }

  // Use cached result if available
  const cached = att.analysis?.[scanType]

  return (
    <div className="border border-slate-200 rounded-xl overflow-hidden bg-white">
      <div className="px-4 py-3 flex items-center gap-3 bg-slate-50 border-b border-slate-100">
        <FileIcon filename={att.filename} className="text-lg" />
        <div className="flex-1 min-w-0">
          <p className="text-[12px] font-semibold text-slate-800 truncate">{att.filename}</p>
          <p className="text-[10px] text-slate-400">{formatBytes(att.size_bytes)} · {att.content_type}</p>
        </div>
        <div className="flex items-center gap-1">
          {['static', 'deep'].map(t => (
            <button
              key={t}
              onClick={() => setScanType(t)}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded-lg transition-colors ${
                scanType === t
                  ? 'bg-sky-500 text-white'
                  : 'bg-white text-slate-600 border border-slate-200 hover:border-sky-300'
              }`}
            >
              {t === 'static' ? 'Static' : 'Deep Scan'}
            </button>
          ))}
        </div>
      </div>

      <div className="p-4">
        {cached ? (
          <AttachmentResult result={cached} scanType={scanType} />
        ) : scanned && scanResult ? (
          <AttachmentResult result={scanResult} scanType={scanType} />
        ) : (
          <div className="flex flex-col items-center gap-3 py-4">
            <p className="text-[12px] text-slate-500">
              {scanType === 'static'
                ? 'Run 4-phase static analysis using YARA rules, magic bytes, and hash reputation.'
                : 'Extract content and run credential scan, URL scan, AI detection, and fraud checks.'}
            </p>
            <button
              onClick={() => runScan(scanType)}
              disabled={scanning}
              className="flex items-center gap-2 px-4 py-2 bg-sky-500 text-white text-[12px] font-semibold rounded-lg hover:bg-sky-600 disabled:opacity-50 transition-colors"
            >
              {scanning
                ? <><motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}><RiLoader4Line /></motion.span> Scanning…</>
                : <><RiSearchLine /> Run {scanType === 'static' ? 'Static' : 'Deep'} Scan</>
              }
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function AttachmentResult({ result, scanType }) {
  if (result.error) {
    return <p className="text-[12px] text-slate-500 italic">{result.error}</p>
  }

  if (scanType === 'static' && result.phases) {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-3 mb-3">
          <div className="flex-shrink-0">
            <ScoreMeter score={result.risk_score || 0} size={64} />
          </div>
          <div>
            <p className="text-[13px] font-bold text-slate-800">{result.risk_label || 'Unknown'}</p>
            <p className="text-[11px] text-slate-500">{result.human_summary || ''}</p>
          </div>
        </div>
        {result.phases.map(p => <PhaseCard key={p.id} phase={p} defaultOpen={p.id === 4} />)}
      </div>
    )
  }

  if (scanType === 'deep') {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <ScoreMeter score={result.risk_score || 0} size={56} />
          <div>
            <TierBadge tier={result.risk_tier || 'UNKNOWN'} size="lg" />
            <p className="text-[11px] text-slate-500 mt-1">{result.processing_ms}ms</p>
          </div>
        </div>

        {result.fraud_check?.reasons?.length > 0 && (
          <div>
            <p className="text-[11px] font-bold text-slate-600 mb-1 uppercase tracking-wide">Fraud Indicators</p>
            <div className="flex flex-wrap gap-1">
              {result.fraud_check.reasons.map((r, i) => <IndicatorChip key={i} text={r} level="warn" />)}
            </div>
          </div>
        )}

        {result.credentials?.total_findings > 0 && (
          <div>
            <p className="text-[11px] font-bold text-slate-600 mb-1 uppercase tracking-wide">
              Credentials Found ({result.credentials.total_findings})
            </p>
            <div className="space-y-1">
              {result.credentials.findings?.slice(0, 5).map((f, i) => <FindingRow key={i} finding={f} />)}
            </div>
          </div>
        )}

        {result.urls_found?.length > 0 && (
          <div>
            <p className="text-[11px] font-bold text-slate-600 mb-1 uppercase tracking-wide">
              URLs Found ({result.urls_found.length})
            </p>
            <div className="space-y-1">
              {result.url_scan?.map((u, i) => (
                <URLResultRow key={i} result={u} />
              ))}
            </div>
          </div>
        )}

        {result.ai_detection && (
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-100">
            <p className="text-[11px] font-bold text-slate-600 uppercase tracking-wide mb-1">AI Detection</p>
            <p className="text-[12px] text-slate-700">
              Probability: <strong>{Math.round((result.ai_detection.ai_generated_probability || 0) * 100)}%</strong>
              {result.ai_detection.is_ai_generated && <span className="ml-2 text-amber-600 font-semibold">Likely AI-generated</span>}
            </p>
          </div>
        )}
      </div>
    )
  }

  // Fallback flat view
  return (
    <pre className="text-[10px] text-slate-600 overflow-auto max-h-48">{JSON.stringify(result, null, 2)}</pre>
  )
}

// ── URL result row — full detail matching Streamlit UI ────────────────────────
function SubSection({ icon, title, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-slate-100 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 bg-slate-50/60 hover:bg-slate-100/60 transition-colors text-left"
      >
        <span className="text-sky-400 text-sm flex-shrink-0">{icon}</span>
        <span className="flex-1 text-[11px] font-bold text-slate-600 uppercase tracking-wide">{title}</span>
        <span className="text-slate-300 text-xs">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.15 }}
            className="px-3 py-3 space-y-1.5"
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function MetaRow({ label, value, mono = false, ok, warn, danger }) {
  const valCls = ok ? 'text-emerald-600 font-semibold'
    : danger ? 'text-red-600 font-semibold'
    : warn   ? 'text-amber-600 font-semibold'
    : 'text-slate-700'
  return (
    <div className="flex items-start gap-2">
      <span className="text-[10px] text-slate-400 w-36 flex-shrink-0 pt-0.5">{label}</span>
      <span className={`text-[11px] break-all ${mono ? 'font-mono' : ''} ${valCls}`}>{value ?? '—'}</span>
    </div>
  )
}

function BoolRow({ label, value, trueOk = false }) {
  const yes = value === true
  const color = trueOk
    ? (yes ? 'text-emerald-600' : 'text-slate-400')
    : (yes ? 'text-red-600'     : 'text-emerald-600')
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-slate-400 w-36 flex-shrink-0">{label}</span>
      <span className={`text-[11px] font-semibold flex items-center gap-0.5 ${color}`}>
        {yes ? <RiCheckLine className="text-xs" /> : <RiCloseLine className="text-xs" />}
        {yes ? 'Yes' : 'No'}
      </span>
    </div>
  )
}

function URLResultRow({ result }) {
  const [open, setOpen] = useState(false)
  const score   = Math.round(result.risk_score_pct ?? (result.risk_score || 0) * 100)
  const verdict = (result.verdict || 'UNKNOWN').toUpperCase()
  const vCfg = {
    SAFE:       { text: 'text-emerald-700', bg: 'bg-emerald-50', border: 'border-emerald-200', bar: 'bg-emerald-500' },
    SUSPICIOUS: { text: 'text-amber-700',   bg: 'bg-amber-50',   border: 'border-amber-200',   bar: 'bg-amber-500'   },
    DANGEROUS:  { text: 'text-red-700',     bg: 'bg-red-50',     border: 'border-red-200',     bar: 'bg-red-500'     },
    ERROR:      { text: 'text-slate-500',   bg: 'bg-slate-50',   border: 'border-slate-200',   bar: 'bg-slate-400'   },
    UNKNOWN:    { text: 'text-slate-500',   bg: 'bg-slate-50',   border: 'border-slate-200',   bar: 'bg-slate-400'   },
  }
  const vc = vCfg[verdict] || vCfg.UNKNOWN

  const d  = result.details || {}
  const m  = result.metrics || {}
  const ml = d.ml_model || {}
  const ssl = d.ssl || {}
  const whois = d.whois || {}
  const cookies = d.cookies || {}
  const encoding = d.encoding || {}
  const html = d.html || {}
  const fmt = m.url_format || {}
  const sslBadge = ssl.status
    ? ssl.valid
      ? <span className="text-[10px] font-bold text-emerald-600 bg-emerald-50 border border-emerald-200 rounded px-1.5 py-0.5">SSL Valid</span>
      : <span className="text-[10px] font-bold text-amber-600 bg-amber-50 border border-amber-200 rounded px-1.5 py-0.5">{ssl.status?.toUpperCase()}</span>
    : null

  const ageBadge = (whois.age_days != null && whois.age_days < 90)
    ? <span className="text-[10px] font-bold text-red-600 bg-red-50 border border-red-200 rounded px-1.5 py-0.5">New Domain ({whois.age_days}d)</span>
    : null

  const cookieBadge = (cookies.issues?.length > 0)
    ? <span className="text-[10px] font-bold text-amber-600 bg-amber-50 border border-amber-200 rounded px-1.5 py-0.5">{cookies.issues.length} Cookie Issues</span>
    : null

  return (
    <div className={`rounded-xl border ${vc.border} ${vc.bg} overflow-hidden`}>
      {/* ── collapsed header ── */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left"
      >
        <span className={`text-[11px] font-bold ${vc.text} flex-shrink-0 w-20`}>{verdict}</span>
        <span className="flex-1 text-[11px] text-slate-600 font-mono truncate">{result.url}</span>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {sslBadge}
          {ageBadge}
          {cookieBadge}
          <div className="w-16 h-1 bg-white/60 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${vc.bar}`} style={{ width: `${score}%` }} />
          </div>
          <span className={`text-[10px] font-bold ${vc.text} w-8 text-right`}>{score}%</span>
        </div>
        <span className="text-slate-400 ml-1">{open ? <RiArrowUpSLine className="text-xs" /> : <RiArrowDownSLine className="text-xs" />}</span>
      </button>

      {/* ── expanded detail ── */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.18 }}
            className="border-t border-current/10 bg-white/60 px-3 pb-3 pt-2 space-y-2"
          >
            {/* Full URL */}
            <div className="flex items-center gap-2 p-2 bg-slate-50 rounded-lg border border-slate-100">
              <RiLinksLine className="text-slate-400 text-xs flex-shrink-0" />
              <span className="text-[10px] font-mono text-slate-600 break-all">{result.url}</span>
              <a href={result.url} target="_blank" rel="noopener noreferrer" className="ml-auto flex-shrink-0 text-sky-400 hover:text-sky-600">
                <RiExternalLinkLine className="text-xs" />
              </a>
            </div>

            {/* Summary grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {[
                { label: 'ML Verdict',    value: ml.label?.toUpperCase() || '—' },
                { label: 'ML Confidence', value: ml.probability != null ? `${Math.round(ml.probability)}%` : '—' },
                { label: 'SSL',           value: ssl.status ? ssl.status.toUpperCase() : '—' },
                { label: 'Domain Age',    value: whois.age_days != null ? `${whois.age_days}d` : '—' },
                { label: 'URL Length',    value: (fmt.url_length || m.url_length) ?? '—' },
                { label: 'Path Depth',    value: (fmt.path_depth || m.path_depth) ?? '—' },
                { label: 'Query Params',  value: (fmt.query_param_count || m.query_params) ?? '—' },
                { label: 'Readability',   value: fmt.readability_score != null ? `${fmt.readability_score}/10` : (m.readability || '—') },
              ].map(({ label, value }) => (
                <div key={label} className="p-2 bg-slate-50 border border-slate-100 rounded-lg text-center">
                  <p className="text-[9px] font-bold text-slate-400 uppercase tracking-wide">{label}</p>
                  <p className="text-[12px] font-bold text-slate-700 mt-0.5 truncate">{String(value)}</p>
                </div>
              ))}
            </div>

            {/* Risk reasons */}
            {result.risk_reasons?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                <p className="w-full text-[10px] font-bold text-slate-400 uppercase tracking-wide">Risk Reasons</p>
                {result.risk_reasons.map((r, i) => (
                  <span key={i} className="text-[10px] bg-red-50 border border-red-100 rounded-full px-2 py-0.5 text-red-600">{r}</span>
                ))}
              </div>
            )}

            {/* ── ML Model ── */}
            {(ml.label || ml.risk_factors?.length > 0) && (
              <SubSection icon={<RiBrainLine />} title="ML Model Analysis">
                <MetaRow label="Label"       value={ml.label} />
                <MetaRow label="Probability" value={ml.probability != null ? `${Math.round(ml.probability)}%` : '—'} />
                {ml.summary_report && <MetaRow label="Summary" value={ml.summary_report} />}
                {ml.risk_factors?.length > 0 && (
                  <div className="mt-1.5">
                    <p className="text-[10px] font-bold text-slate-400 mb-1">Risk Factors</p>
                    {ml.risk_factors.map((f, i) => <p key={i} className="text-[10px] text-red-600 pl-2">· {f}</p>)}
                  </div>
                )}
                {ml.safe_factors?.length > 0 && (
                  <div className="mt-1">
                    <p className="text-[10px] font-bold text-slate-400 mb-1">Safe Factors</p>
                    {ml.safe_factors.map((f, i) => <p key={i} className="text-[10px] text-emerald-600 pl-2">· {f}</p>)}
                  </div>
                )}
              </SubSection>
            )}

            {/* ── SSL Certificate ── */}
            {ssl.status && (
              <SubSection icon={<RiShieldKeyholeLine />} title="SSL Certificate">
                <MetaRow label="Status"      value={ssl.status?.toUpperCase()} ok={ssl.valid} danger={!ssl.valid && ssl.status !== 'no_https'} />
                <BoolRow label="Valid & Trusted" value={ssl.valid} trueOk />
                {ssl.expires_in_days != null && (
                  <MetaRow label="Expires In" value={`${ssl.expires_in_days} days`}
                    ok={ssl.expires_in_days > 30} warn={ssl.expires_in_days > 0 && ssl.expires_in_days <= 30} danger={ssl.expires_in_days <= 0}
                  />
                )}
                {ssl.issuer   && <MetaRow label="Issuer"  value={ssl.issuer} />}
                {ssl.subject  && <MetaRow label="Subject" value={ssl.subject} />}
                {ssl.error    && <MetaRow label="Error"   value={ssl.error} warn />}
              </SubSection>
            )}

            {/* ── WHOIS / Domain Age ── */}
            {(whois.age_days != null || whois.registrar) && (
              <SubSection icon={<RiCalendarLine />} title="WHOIS & Domain Age">
                {whois.age_days != null && (
                  <MetaRow label="Domain Age"  value={`${whois.age_days} days`}
                    ok={whois.age_days > 365} warn={whois.age_days >= 90} danger={whois.age_days < 90}
                  />
                )}
                {whois.status         && <MetaRow label="Status"      value={whois.status} />}
                {whois.creation_date  && <MetaRow label="Registered"  value={whois.creation_date} />}
                {whois.expiration_date && <MetaRow label="Expires"    value={whois.expiration_date} />}
                {whois.registrar      && <MetaRow label="Registrar"   value={whois.registrar} />}
                {whois.country        && <MetaRow label="Country"     value={whois.country} />}
                <BoolRow label="Domain Resolvable" value={whois.domain_resolvable} trueOk />
                {whois.error          && <MetaRow label="Error"       value={whois.error} warn />}
              </SubSection>
            )}

            {/* ── URL Format Analysis ── */}
            {(fmt.url_length || m.url_length) && (
              <SubSection icon={<RiLinksLine />} title="URL Format Analysis">
                <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                  <MetaRow label="Scheme"       value={fmt.scheme || m.url_scheme} />
                  <MetaRow label="URL Length"   value={fmt.url_length || m.url_length} />
                  <MetaRow label="Path Depth"   value={fmt.path_depth || m.path_depth} />
                  <MetaRow label="Query Params" value={fmt.query_param_count || m.query_params} />
                  <MetaRow label="Readability"  value={fmt.readability_score != null ? `${fmt.readability_score}/10` : m.readability} />
                  {fmt.path_word_count != null && <MetaRow label="Path Words" value={fmt.path_word_count} />}
                </div>
                <div className="mt-1.5 space-y-1">
                  <BoolRow label="Is IP Address"    value={fmt.is_ip_address  || m.is_ip_address}  />
                  <BoolRow label="Uses HTTPS"       value={fmt.uses_https     || m.uses_https}      trueOk />
                  <BoolRow label="Has Port"         value={fmt.has_port} />
                  <BoolRow label="Has Fragment"     value={fmt.has_fragment    || m.has_fragment} />
                  <BoolRow label="Brand Keywords"   value={fmt.has_brand_keywords || m.has_brand_words} />
                  {(m.url_encoded != null) && <BoolRow label="URL Encoded"  value={m.url_encoded} />}
                  {(m.double_encoded != null) && <BoolRow label="Double Encoded" value={m.double_encoded} />}
                </div>
              </SubSection>
            )}

            {/* ── HTML Analysis ── */}
            {html.status !== undefined && html.status !== 'skipped' && (
              <SubSection icon={<RiCodeSSlashLine />} title="HTML Analysis">
                <BoolRow label="Login Form"         value={html.has_login_form} />
                <BoolRow label="Password Input"     value={html.has_password_input} />
                <BoolRow label="External Form"      value={html.external_form_action} />
                <BoolRow label="iFrames"            value={html.has_iframe} />
                <BoolRow label="Hidden Elements"    value={html.has_hidden_elements} />
                <MetaRow label="Suspicious Scripts" value={html.suspicious_scripts ?? 0}
                  warn={(html.suspicious_scripts || 0) > 0}
                />
                <BoolRow label="Favicon Mismatch"   value={html.favicon_mismatch} />
                {html.risk_flags?.length > 0 && (
                  <div className="mt-1">
                    <p className="text-[10px] font-bold text-slate-400 mb-0.5">Risk Flags</p>
                    {html.risk_flags.map((f, i) => <p key={i} className="text-[10px] text-red-600 pl-2">· {f}</p>)}
                  </div>
                )}
                {html.status === 'skipped' && <MetaRow label="Status" value="Skipped (unreachable)" />}
                {html.error  && <MetaRow label="Error" value={html.error} warn />}
              </SubSection>
            )}

            {/* ── Cookie Security ── */}
            {(cookies.total_cookies != null || cookies.status) && (
              <SubSection icon={<RiCakeLine />} title="Cookie Security">
                <MetaRow label="Total Cookies" value={cookies.total_cookies ?? 0} />
                <MetaRow label="Security Issues" value={cookies.issues?.length ?? 0}
                  ok={(cookies.issues?.length || 0) === 0} warn={(cookies.issues?.length || 0) > 0}
                />
                {cookies.issues?.length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {cookies.issues.map((iss, i) => (
                      <p key={i} className="text-[10px] text-amber-600 pl-2">· {iss}</p>
                    ))}
                  </div>
                )}
                {cookies.cookie_details?.length > 0 && (
                  <div className="mt-2 overflow-x-auto">
                    <table className="w-full text-[10px]">
                      <thead>
                        <tr className="border-b border-slate-100">
                          {['Name','Secure','HttpOnly','SameSite'].map(h => (
                            <th key={h} className="text-left pb-1 font-bold text-slate-400 pr-3">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {cookies.cookie_details.map((c, i) => (
                          <tr key={i} className="border-b border-slate-50">
                            <td className="py-1 pr-3 font-mono text-slate-700">{c.name}</td>
                            <td className="py-1 pr-3">
                              {c.secure
                                ? <RiCheckLine className="text-emerald-500" />
                                : <RiCloseLine className="text-red-400" />}
                            </td>
                            <td className="py-1 pr-3">
                              {c.httponly
                                ? <RiCheckLine className="text-emerald-500" />
                                : <RiCloseLine className="text-red-400" />}
                            </td>
                            <td className="py-1 text-slate-600">{c.samesite || 'Not Set'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {cookies.error && <MetaRow label="Error" value={cookies.error} warn />}
              </SubSection>
            )}

            {/* ── URL Encoding ── */}
            {(encoding.is_encoded != null) && (
              <SubSection icon={<RiServerLine />} title="URL Encoding Analysis">
                <BoolRow label="Percent Encoded"  value={encoding.is_encoded} />
                <BoolRow label="Double Encoded"   value={encoding.is_double_encoded} />
                {encoding.decoded_url && (
                  <div className="mt-1">
                    <p className="text-[10px] font-bold text-slate-400 mb-0.5">Decoded URL</p>
                    <p className="text-[10px] font-mono text-slate-600 break-all pl-2">{encoding.decoded_url.substring(0, 120)}</p>
                  </div>
                )}
                {encoding.issues?.length > 0 && (
                  <div className="mt-1">
                    {encoding.issues.map((iss, i) => <p key={i} className="text-[10px] text-amber-600 pl-2">· {iss}</p>)}
                  </div>
                )}
              </SubSection>
            )}

            {/* ── Campaign Fingerprint ── */}
            {m.fingerprint && (
              <div className="flex items-center gap-2 p-2 bg-slate-50 rounded-lg border border-slate-100">
                <RiFingerprint2Line className="text-slate-400 text-xs flex-shrink-0" />
                <span className="text-[10px] font-bold text-slate-400 flex-shrink-0">Fingerprint</span>
                <code className="text-[10px] text-slate-600 font-mono break-all">{m.fingerprint.substring(0, 48)}</code>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Main EmailDetail component ─────────────────────────────────────────────────
export default function EmailDetail({ emailId, onBack }) {
  const [email, setEmail]           = useState(null)
  const [analysis, setAnalysis]     = useState(null)
  const [loading, setLoading]       = useState(true)
  const [analyzing, setAnalyzing]   = useState(false)
  const [activeBodyTab, setActiveBodyTab] = useState('text')

  const fetchEmail = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch(`/api/email/emails/${emailId}`)
      if (res.ok) {
        const data = await res.json()
        setEmail(data)
        if (data.analysis) {
          setAnalysis(data.analysis)
        }
      }
    } catch (e) {
      console.warn('Email fetch error:', e)
    } finally {
      setLoading(false)
    }
  }, [emailId])

  const runAnalysis = useCallback(async () => {
    setAnalyzing(true)
    try {
      const res = await fetch(`/api/email/emails/${emailId}/analyze`, { method: 'POST' })
      if (res.ok) {
        setAnalysis(await res.json())
      }
    } catch (e) {
      console.warn('Analysis error:', e)
    } finally {
      setAnalyzing(false)
    }
  }, [emailId])

  useEffect(() => {
    fetchEmail()
  }, [fetchEmail])

  // Auto-run analysis on load
  useEffect(() => {
    if (email && !analysis && !analyzing) {
      runAnalysis()
    }
  }, [email, analysis, analyzing, runAnalysis])

  if (loading) {
    return (
      <PageWrapper>
        <div className="flex items-center justify-center py-24 gap-3 text-slate-400">
          <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
            <RiLoader4Line className="text-2xl" />
          </motion.span>
          Loading email…
        </div>
      </PageWrapper>
    )
  }

  if (!email) {
    return (
      <PageWrapper>
        <div className="flex flex-col items-center gap-3 py-24 text-slate-400">
          <RiMailLine className="text-4xl text-slate-200" />
          <p>Email not found</p>
          <button onClick={onBack} className="text-sky-500 text-[13px] font-semibold hover:underline">← Back to mailbox</button>
        </div>
      </PageWrapper>
    )
  }

  const overallScore = analysis?.overall_risk_score ?? 0
  const overallTier  = analysis?.overall_risk_tier ?? 'UNKNOWN'
  const urls         = Array.isArray(email.urls) ? email.urls : []
  const attachments  = Array.isArray(email.attachments) ? email.attachments : []

  return (
    <PageWrapper>
      {/* Back + header */}
      <div className="flex items-start gap-4 mb-6">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-[13px] text-slate-500 hover:text-sky-500 transition-colors font-medium mt-0.5 flex-shrink-0"
        >
          <RiArrowLeftLine /> Back
        </button>
        <div className="flex-1 min-w-0">
          <h1 className="text-[20px] font-bold text-slate-900 leading-tight">{email.subject || '(no subject)'}</h1>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <span className="text-[12px] text-slate-500">From <strong className="text-slate-700">{email.sender}</strong></span>
            <span className="text-slate-300">·</span>
            <span className="text-[12px] text-slate-500">{email.date_str || new Date(email.received_at).toLocaleString()}</span>
            {email.has_attachments && (
              <span className="flex items-center gap-1 text-[11px] text-slate-500">
                <RiAttachment2 className="text-xs" /> {email.attachment_count} attachment{email.attachment_count !== 1 ? 's' : ''}
              </span>
            )}
          </div>
        </div>

        {/* Overall risk */}
        {analysis && (
          <div className="flex-shrink-0 text-center">
            <ScoreMeter score={overallScore} size={72} />
            <TierBadge tier={overallTier} size="sm" />
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Left column — email body */}
        <div className="xl:col-span-1 space-y-4">

          {/* Email content card */}
          <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
            <div className="px-5 py-3 border-b border-slate-100 flex items-center gap-2">
              <RiMailLine className="text-sky-500" />
              <span className="text-[14px] font-bold text-slate-800">Email Content</span>
            </div>

            {/* Header info */}
            <div className="px-5 py-3 bg-slate-50/40 border-b border-slate-100 space-y-1">
              {[
                { label: 'From', value: email.sender },
                { label: 'To',   value: email.receiver },
                email.reply_to ? { label: 'Reply-To', value: email.reply_to } : null,
              ].filter(Boolean).map(({ label, value }) => (
                <div key={label} className="flex items-start gap-2">
                  <span className="text-[10px] font-bold text-slate-400 uppercase w-14 pt-0.5 flex-shrink-0">{label}</span>
                  <span className="text-[12px] text-slate-700 break-all">{value}</span>
                </div>
              ))}
            </div>

            {/* Body tabs */}
            {(email.body_text || email.body_html) && (
              <>
                <div className="flex border-b border-slate-100">
                  {[['text', 'Plain Text'], ['html', 'HTML']].map(([id, label]) => (
                    <button
                      key={id}
                      onClick={() => setActiveBodyTab(id)}
                      className={`px-4 py-2 text-[12px] font-semibold transition-colors ${
                        activeBodyTab === id
                          ? 'text-sky-600 border-b-2 border-sky-500 bg-sky-50/40'
                          : 'text-slate-500 hover:text-slate-700'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <div className="px-5 py-4 max-h-72 overflow-y-auto">
                  {activeBodyTab === 'text' ? (
                    <pre className="text-[12px] text-slate-700 whitespace-pre-wrap font-sans leading-relaxed">
                      {email.body_text || '(no plain text body)'}
                    </pre>
                  ) : (
                    <div
                      className="text-[12px] leading-relaxed"
                      dangerouslySetInnerHTML={{ __html: email.body_html || email.body_text || '' }}
                    />
                  )}
                </div>
              </>
            )}
          </div>

          {/* URLs */}
          {urls.length > 0 && (
            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
              <div className="px-5 py-3 border-b border-slate-100 flex items-center gap-2">
                <RiGlobalLine className="text-sky-500" />
                <span className="text-[14px] font-bold text-slate-800">Links Found ({urls.length})</span>
              </div>
              <div className="px-4 py-3 space-y-1 max-h-48 overflow-y-auto">
                {(analysis?.url_scan || []).length > 0 ? (
                  analysis.url_scan.map((u, i) => <URLResultRow key={i} result={u} />)
                ) : (
                  urls.slice(0, 8).map((url, i) => (
                    <div key={i} className="flex items-center gap-2 py-1">
                      <RiGlobalLine className="text-slate-300 text-xs flex-shrink-0" />
                      <span className="text-[11px] text-slate-600 font-mono truncate">{url}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right column — security analysis */}
        <div className="xl:col-span-2 space-y-3">

          {/* Analysis status bar */}
          <div className={`flex items-center gap-3 px-4 py-3 rounded-xl border ${
            analyzing ? 'bg-sky-50 border-sky-200' :
            analysis  ? 'bg-slate-50 border-slate-200' :
            'bg-slate-50 border-slate-200'
          }`}>
            {analyzing
              ? <>
                  <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
                    <RiLoader4Line className="text-sky-500 text-lg" />
                  </motion.span>
                  <span className="text-[13px] text-sky-700 font-semibold">Running security analysis pipeline…</span>
                </>
              : analysis
              ? <>
                  <RiShieldCheckLine className="text-sky-500 text-lg" />
                  <span className="text-[13px] text-slate-700 font-semibold">Analysis complete</span>
                  <span className="text-[11px] text-slate-400 ml-1">{analysis.processing_ms}ms</span>
                  <button
                    onClick={runAnalysis}
                    className="ml-auto text-[11px] text-slate-400 hover:text-sky-500 flex items-center gap-1"
                  >
                    <RiRefreshLine /> Re-run
                  </button>
                </>
              : <>
                  <RiShieldLine className="text-slate-400 text-lg" />
                  <span className="text-[13px] text-slate-500">Analysis pending</span>
                  <button
                    onClick={runAnalysis}
                    className="ml-auto text-[12px] font-semibold text-sky-500 hover:text-sky-600 flex items-center gap-1.5 px-3 py-1 bg-sky-50 rounded-lg border border-sky-200"
                  >
                    <RiSearchLine /> Analyze Now
                  </button>
                </>
            }
          </div>

          {/* ── 1. Phishing Detection ── */}
          <AnalysisSection
            icon={<RiSpam2Line />}
            title="Phishing & Malicious Content"
            loading={analyzing && !analysis?.phishing}
            defaultOpen
            badge={analysis?.phishing && (
              <TierBadge tier={analysis.phishing.tier} />
            )}
          >
            {analysis?.phishing ? (
              <div className="space-y-4">
                {/* Score grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: 'Risk Score',   value: `${analysis.phishing.risk_score}`, sub: '/100' },
                    { label: 'Verdict',      value: analysis.phishing.verdict,           sub: ''    },
                    { label: 'Tier',         value: analysis.phishing.tier,              sub: ''    },
                    { label: 'Action',       value: analysis.phishing.outlook_action,    sub: ''    },
                  ].map(({ label, value, sub }) => (
                    <div key={label} className="p-3 bg-slate-50 rounded-xl border border-slate-100 text-center">
                      <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">{label}</p>
                      <p className="text-[15px] font-bold text-slate-800 mt-0.5">{value}<span className="text-[10px] text-slate-400">{sub}</span></p>
                    </div>
                  ))}
                </div>

                {/* Score breakdown */}
                <div className="space-y-2">
                  <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Score Breakdown</p>
                  <ScoreBar label="RoBERTa / ML Model"  value={Math.round((analysis.phishing.roberta_prob || 0) * 100)} color="bg-sky-500" delay={0.1} />
                  <ScoreBar label="Rule-based Check"    value={Math.round(analysis.phishing.rule_score || 0)} color="bg-indigo-400" delay={0.2} />
                  <ScoreBar label="AI-text Probability" value={Math.round((analysis.phishing.ai_prob || 0) * 100)} color="bg-violet-400" delay={0.3} />
                  <ScoreBar label="Header Analysis"     value={analysis.phishing.header_score || 0} color="bg-cyan-500" delay={0.4} />
                </div>

                {/* Header flags */}
                {analysis.phishing.header_flags?.length > 0 && (
                  <div>
                    <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Header Flags</p>
                    <div className="flex flex-wrap gap-1">
                      {analysis.phishing.header_flags.map((f, i) => <IndicatorChip key={i} text={f} level="warn" />)}
                    </div>
                  </div>
                )}

                {/* Top indicators */}
                {analysis.phishing.top_indicators?.length > 0 && (
                  <div>
                    <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Top Indicators</p>
                    <div className="flex flex-wrap gap-1">
                      {analysis.phishing.top_indicators.map((ind, i) => (
                        <IndicatorChip key={i} text={ind}
                          level={analysis.phishing.tier === 'CRITICAL' ? 'danger' : analysis.phishing.tier === 'HIGH' ? 'warn' : 'info'}
                        />
                      ))}
                    </div>
                  </div>
                )}

                <p className="text-[10px] text-slate-400">Model: {analysis.phishing.scorer_used} · {analysis.phishing.processing_ms}ms</p>
              </div>
            ) : (
              <p className="text-[12px] text-slate-400 italic">Awaiting analysis…</p>
            )}
          </AnalysisSection>

          {/* ── 2. AI-Generated Content ── */}
          <AnalysisSection
            icon={<RiRobot2Line />}
            title="AI-Generated Content Detection"
            loading={analyzing && !analysis?.ai_detection}
            badge={analysis?.ai_detection && (
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${
                analysis.ai_detection.is_ai_generated
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}>
                {analysis.ai_detection.is_ai_generated ? 'Likely AI' : 'Likely Human'}
              </span>
            )}
          >
            {analysis?.ai_detection ? (
              <div className="space-y-3">
                <div className="flex items-center gap-4">
                  <div className="flex-shrink-0">
                    <ScoreMeter score={Math.round((analysis.ai_detection.ai_generated_probability || 0) * 100)} size={72} />
                  </div>
                  <div className="space-y-1">
                    <p className="text-[13px] font-semibold text-slate-800">
                      {analysis.ai_detection.is_ai_generated
                        ? 'This email appears to be AI-generated.'
                        : 'This email appears to be human-written.'}
                    </p>
                    <p className="text-[12px] text-slate-500">
                      AI probability: <strong>{Math.round((analysis.ai_detection.ai_generated_probability || 0) * 100)}%</strong>
                    </p>
                    {analysis.ai_detection.method && (
                      <p className="text-[10px] text-slate-400">Method: {analysis.ai_detection.method}</p>
                    )}
                    {analysis.ai_detection.model && (
                      <p className="text-[10px] text-slate-400">Model: {analysis.ai_detection.model}</p>
                    )}
                  </div>
                </div>
                {analysis.ai_detection.indicators?.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    <p className="w-full text-[11px] font-bold text-slate-400 uppercase tracking-wide mb-0.5">AI Patterns Detected</p>
                    {analysis.ai_detection.indicators.map((ind, i) => <IndicatorChip key={i} text={ind} level="info" />)}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-[12px] text-slate-400 italic">Awaiting analysis…</p>
            )}
          </AnalysisSection>

          {/* ── 3. Credential Leakage ── */}
          <AnalysisSection
            icon={<RiLockLine />}
            title="Credential Leakage Detection"
            loading={analyzing && !analysis?.credentials}
            badge={analysis?.credentials && (
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${
                (analysis.credentials.total_findings || 0) > 0
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}>
                {analysis.credentials.total_findings || 0} found
              </span>
            )}
          >
            {analysis?.credentials ? (
              <div className="space-y-3">
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: 'Total Found',  value: analysis.credentials.total_findings || 0 },
                    { label: 'Risk Score',   value: `${analysis.credentials.risk_score || 0}/100` },
                    { label: 'Risk Label',   value: analysis.credentials.risk_label || '—' },
                  ].map(({ label, value }) => (
                    <div key={label} className="p-2.5 bg-slate-50 rounded-xl border border-slate-100 text-center">
                      <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">{label}</p>
                      <p className="text-[14px] font-bold text-slate-800 mt-0.5">{value}</p>
                    </div>
                  ))}
                </div>

                {analysis.credentials.findings?.length > 0 ? (
                  <div className="space-y-1">
                    <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Findings</p>
                    {analysis.credentials.findings.slice(0, 8).map((f, i) => <FindingRow key={i} finding={f} />)}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 p-3 bg-emerald-50 border border-emerald-100 rounded-xl">
                    <RiCheckboxCircleLine className="text-emerald-500 text-lg flex-shrink-0" />
                    <p className="text-[12px] text-emerald-700">No credentials or sensitive data detected.</p>
                  </div>
                )}

                {analysis.credentials.human_summary && (
                  <p className="text-[12px] text-slate-500">{analysis.credentials.human_summary}</p>
                )}
              </div>
            ) : (
              <p className="text-[12px] text-slate-400 italic">Awaiting analysis…</p>
            )}
          </AnalysisSection>

          {/* ── 4. URL / Web Spoofing ── */}
          <AnalysisSection
            icon={<RiGlobalLine />}
            title={`Web Spoofing & URL Analysis (${urls.length} URLs)`}
            loading={analyzing && !analysis?.url_scan}
            badge={analysis?.url_scan && (() => {
              const dangerous = analysis.url_scan.filter(u => u.verdict?.toUpperCase() === 'DANGEROUS').length
              const suspicious = analysis.url_scan.filter(u => u.verdict?.toUpperCase() === 'SUSPICIOUS').length
              return dangerous > 0
                ? <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-red-50 text-red-700 border border-red-200">{dangerous} Dangerous</span>
                : suspicious > 0
                ? <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-amber-50 text-amber-700 border border-amber-200">{suspicious} Suspicious</span>
                : <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">All Safe</span>
            })()}
          >
            {analysis?.url_scan?.length > 0 ? (
              <div className="space-y-2">
                {analysis.url_scan.map((u, i) => <URLResultRow key={i} result={u} />)}
              </div>
            ) : urls.length === 0 ? (
              <div className="flex items-center gap-2 p-3 bg-slate-50 rounded-xl border border-slate-100">
                <RiCheckboxCircleLine className="text-slate-400 flex-shrink-0" />
                <p className="text-[12px] text-slate-500">No URLs found in this email.</p>
              </div>
            ) : (
              <p className="text-[12px] text-slate-400 italic">{urls.length} URLs pending scan…</p>
            )}
          </AnalysisSection>

          {/* ── 5. Attachments ── */}
          {attachments.length > 0 && (
            <AnalysisSection
              icon={<RiAttachment2 />}
              title={`Attachment Analysis (${attachments.length})`}
              defaultOpen
            >
              <div className="space-y-3">
                {attachments.map(att => (
                  <AttachmentPanel key={att.id} emailId={emailId} att={att} />
                ))}
              </div>
            </AnalysisSection>
          )}

          {/* ── 6. Rule Check ── */}
          {analysis?.rule_check && (
            <AnalysisSection
              icon={<RiBarChartLine />}
              title="Rule-Based Fraud Detection"
              badge={
                <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${
                  analysis.rule_check.is_suspicious
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}>
                  {analysis.rule_check.is_suspicious ? 'Suspicious' : 'Clean'}
                </span>
              }
            >
              <div className="space-y-3">
                <ScoreBar label="Rule Score" value={analysis.rule_check.score || 0} color="bg-indigo-400" />
                {analysis.rule_check.reasons?.length > 0 ? (
                  <div>
                    <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Triggered Rules</p>
                    <div className="flex flex-wrap gap-1">
                      {analysis.rule_check.reasons.map((r, i) => <IndicatorChip key={i} text={r} level="warn" />)}
                    </div>
                  </div>
                ) : (
                  <p className="text-[12px] text-slate-500">No fraud keywords or suspicious patterns detected.</p>
                )}
              </div>
            </AnalysisSection>
          )}
        </div>
      </div>
    </PageWrapper>
  )
}
