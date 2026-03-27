import { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiMailLine, RiMailOpenLine, RiAttachment2, RiSearchLine,
  RiRefreshLine, RiFilterLine, RiArrowDownSLine, RiArrowUpSLine,
  RiFlagLine, RiFlagFill, RiLoader4Line, RiInboxLine,
  RiShieldCheckLine, RiAlertLine, RiCheckboxCircleLine,
  RiErrorWarningLine, RiTimeLine, RiSortAsc, RiSortDesc,
  RiArrowLeftLine, RiArrowRightLine, RiMailSendLine,
  RiSpam2Line, RiCheckDoubleLine,
} from 'react-icons/ri'
import { PageWrapper } from '../components/ui'

// ── Risk tier config ───────────────────────────────────────────────────────────
const RISK_CFG = {
  CRITICAL: { label: 'Critical', dot: 'bg-red-500',     pill: 'bg-red-50 text-red-700 border-red-200',    bar: 'bg-red-500'     },
  HIGH:     { label: 'High',     dot: 'bg-amber-500',   pill: 'bg-amber-50 text-amber-700 border-amber-200', bar: 'bg-amber-500'  },
  MEDIUM:   { label: 'Medium',   dot: 'bg-sky-400',     pill: 'bg-sky-50 text-sky-700 border-sky-200',    bar: 'bg-sky-400'     },
  LOW:      { label: 'Low',      dot: 'bg-slate-400',   pill: 'bg-slate-100 text-slate-600 border-slate-200', bar: 'bg-slate-400' },
  UNKNOWN:  { label: '—',        dot: 'bg-slate-300',   pill: 'bg-slate-50 text-slate-500 border-slate-200',  bar: 'bg-slate-300' },
}

function riskCfg(tier) {
  return RISK_CFG[tier] || RISK_CFG.UNKNOWN
}

// ── Relative timestamp ─────────────────────────────────────────────────────────
function relTime(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60)  return 'just now'
  const m = Math.floor(s / 60)
  if (m < 60)  return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24)  return `${h}h ago`
  const d = Math.floor(h / 24)
  if (d < 7)   return `${d}d ago`
  return new Date(iso).toLocaleDateString()
}

function fullDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
}

// ── Sender display name ────────────────────────────────────────────────────────
function parseSender(raw) {
  if (!raw) return { name: 'Unknown', email: '' }
  const m = raw.match(/^"?([^"<]+)"?\s*<?([^>]*)>?$/)
  if (m) {
    const name = m[1].trim()
    const email = m[2].trim()
    return { name: name || email, email }
  }
  return { name: raw, email: raw }
}

function SenderAvatar({ sender }) {
  const { name } = parseSender(sender)
  const initials = name.split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase() || '?'
  const colors = [
    'bg-sky-500', 'bg-indigo-500', 'bg-violet-500',
    'bg-teal-500', 'bg-cyan-600', 'bg-blue-600',
  ]
  const idx = name.charCodeAt(0) % colors.length
  return (
    <div className={`w-9 h-9 rounded-full ${colors[idx]} flex items-center justify-center flex-shrink-0`}>
      <span className="text-[11px] font-bold text-white">{initials}</span>
    </div>
  )
}

// ── Risk pill ──────────────────────────────────────────────────────────────────
function RiskPill({ tier }) {
  const cfg = riskCfg(tier)
  if (!tier || tier === 'UNKNOWN') return null
  return (
    <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${cfg.pill}`}>
      {cfg.label}
    </span>
  )
}

// ── Email row ──────────────────────────────────────────────────────────────────
function EmailRow({ email, onOpen, onFlag }) {
  const { name, email: addr } = parseSender(email.sender)
  const cfg   = riskCfg(email.risk_tier)
  const unread = !email.is_read

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.15 }}
      onClick={() => onOpen(email.id)}
      className={`flex items-center gap-3 px-4 py-3 cursor-pointer border-b border-slate-100 last:border-0 transition-colors group ${
        unread ? 'bg-white hover:bg-sky-50/40' : 'bg-slate-50/40 hover:bg-sky-50/30'
      }`}
    >
      {/* Risk accent */}
      <div className={`w-0.5 h-10 rounded-full flex-shrink-0 ${cfg.bar} ${email.risk_tier === 'UNKNOWN' ? 'opacity-0' : ''}`} />

      {/* Avatar */}
      <SenderAvatar sender={email.sender} />

      {/* Main content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className={`text-[13px] truncate ${unread ? 'font-semibold text-slate-900' : 'font-medium text-slate-700'}`}>
            {name}
          </span>
          {email.has_attachments && (
            <RiAttachment2 className="text-slate-400 text-xs flex-shrink-0" />
          )}
          <RiskPill tier={email.risk_tier} />
        </div>
        <div className="flex items-baseline gap-1.5">
          <span className={`text-[12px] truncate ${unread ? 'text-slate-700' : 'text-slate-500'}`}>
            {email.subject || '(no subject)'}
          </span>
          {email.body_preview && (
            <span className="text-[11px] text-slate-400 truncate hidden sm:block">
              — {email.body_preview}
            </span>
          )}
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <span className="text-[11px] text-slate-400 whitespace-nowrap" title={fullDate(email.received_at)}>
          {relTime(email.received_at)}
        </span>
        <button
          onClick={(e) => { e.stopPropagation(); onFlag(email.id) }}
          className={`p-1 rounded transition-colors ${
            email.is_flagged ? 'text-amber-500' : 'text-slate-300 opacity-0 group-hover:opacity-100 hover:text-amber-400'
          }`}
        >
          {email.is_flagged ? <RiFlagFill className="text-sm" /> : <RiFlagLine className="text-sm" />}
        </button>
        {unread && <div className="w-2 h-2 rounded-full bg-sky-500 flex-shrink-0" />}
      </div>
    </motion.div>
  )
}

// ── Empty state ────────────────────────────────────────────────────────────────
function EmptyState({ filtered }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-400 gap-3">
      <RiInboxLine className="text-5xl text-slate-200" />
      <p className="text-[14px] font-semibold text-slate-500">
        {filtered ? 'No emails match your filters' : 'Your inbox is empty'}
      </p>
      <p className="text-[12px]">
        {filtered ? 'Try adjusting the filter or search query.' : 'Emails will appear here as they arrive.'}
      </p>
    </div>
  )
}

// ── Toolbar ────────────────────────────────────────────────────────────────────
const FILTERS = [
  { id: 'ALL',      label: 'All Mail' },
  { id: 'CRITICAL', label: 'Critical' },
  { id: 'HIGH',     label: 'High' },
  { id: 'MEDIUM',   label: 'Medium' },
  { id: 'LOW',      label: 'Low' },
]

// ── Main Mailbox component ─────────────────────────────────────────────────────
export default function Mailbox({ onOpenEmail }) {
  const [emails, setEmails]           = useState([])
  const [total, setTotal]             = useState(0)
  const [loading, setLoading]         = useState(true)   // start true – avoid flash of "empty"
  const [refreshing, setRefreshing]   = useState(false)
  const [error, setError]             = useState(null)
  const [stats, setStats]             = useState({})
  const [search, setSearch]           = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [riskFilter, setRiskFilter]   = useState('ALL')
  const [unreadOnly, setUnreadOnly]   = useState(false)
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [page, setPage]               = useState(0)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [initialLoaded, setInitialLoaded] = useState(false)

  const PAGE_SIZE = 20
  const inputRef = useRef(null)

  const fetchEmails = useCallback(async (opts = {}) => {
    const isRefresh = opts.refresh || false
    if (isRefresh) setRefreshing(true)
    else if (!initialLoaded) setLoading(true)

    const params = new URLSearchParams({
      limit:       PAGE_SIZE,
      offset:      (opts.page ?? page) * PAGE_SIZE,
      risk_filter: opts.riskFilter ?? riskFilter,
    })
    if (opts.search ?? search) params.set('search', opts.search ?? search)
    if (opts.unreadOnly ?? unreadOnly) params.set('unread_only', 'true')
    if (opts.flaggedOnly ?? flaggedOnly) params.set('flagged_only', 'true')

    try {
      const [emailRes, statsRes] = await Promise.all([
        fetch(`/api/email/emails?${params}`),
        fetch('/api/email/stats'),
      ])
      if (!emailRes.ok) throw new Error(`API error ${emailRes.status}`)
      const data = await emailRes.json()
      setEmails(data.emails || [])
      setTotal(data.total || 0)
      setLastRefresh(new Date())
      setError(null)
      setInitialLoaded(true)
      if (statsRes.ok) {
        setStats(await statsRes.json())
      }
    } catch (e) {
      console.warn('Mailbox fetch failed:', e)
      setError('Could not load emails. Retrying…')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [page, riskFilter, search, unreadOnly, flaggedOnly, initialLoaded])

  // Initial fetch + auto-refresh every 10s
  useEffect(() => {
    fetchEmails()
    const interval = setInterval(() => fetchEmails({ refresh: true }), 10000)
    return () => clearInterval(interval)
  }, [fetchEmails])

  const handleSearch = (e) => {
    e.preventDefault()
    setSearch(searchInput)
    setPage(0)
    fetchEmails({ search: searchInput, page: 0 })
  }

  const handleFilter = (f) => {
    setRiskFilter(f)
    setPage(0)
    fetchEmails({ riskFilter: f, page: 0 })
  }

  const handlePageChange = (newPage) => {
    setPage(newPage)
    fetchEmails({ page: newPage })
  }

  const handleFlag = async (id) => {
    await fetch(`/api/email/emails/${id}/flag`, { method: 'POST' })
    setEmails(prev => prev.map(e => e.id === id ? { ...e, is_flagged: !e.is_flagged } : e))
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)
  const hasFilters = riskFilter !== 'ALL' || search || unreadOnly || flaggedOnly

  return (
    <PageWrapper>
      <div className="flex flex-col h-full">

        {/* Page header */}
        <div className="mb-5">
          <h1 className="text-[22px] font-bold text-slate-900">Mailbox</h1>
          <p className="text-[13px] text-slate-500 mt-0.5">
            Real-time email monitoring · Security analysis · Threat detection
          </p>
        </div>

        {/* Stats strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
          {[
            { label: 'Total',          value: stats.total || 0,           icon: <RiMailLine />,          color: 'text-slate-600 bg-slate-50 border-slate-200'  },
            { label: 'Unread',         value: stats.unread || 0,          icon: <RiMailOpenLine />,       color: 'text-sky-600 bg-sky-50 border-sky-200'        },
            { label: 'High Risk',      value: stats.high_risk || 0,       icon: <RiAlertLine />,          color: 'text-amber-700 bg-amber-50 border-amber-200'  },
            { label: 'With Attachments', value: stats.with_attachments || 0, icon: <RiAttachment2 />,    color: 'text-indigo-600 bg-indigo-50 border-indigo-200'},
          ].map(({ label, value, icon, color }) => (
            <div key={label} className={`p-3 rounded-xl border flex items-center gap-3 ${color}`}>
              <span className="text-lg opacity-70">{icon}</span>
              <div>
                <p className="text-xl font-bold leading-none">{value}</p>
                <p className="text-[11px] font-medium opacity-70 mt-0.5">{label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Toolbar */}
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          {/* Search */}
          <form onSubmit={handleSearch} className="flex items-center gap-1 flex-1 min-w-[200px] max-w-sm">
            <div className="relative flex-1">
              <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm" />
              <input
                ref={inputRef}
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
                placeholder="Search emails…"
                className="w-full pl-8 pr-3 py-2 text-[13px] bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-sky-300 focus:border-sky-400"
              />
            </div>
            {searchInput && (
              <button type="button" onClick={() => { setSearchInput(''); setSearch(''); fetchEmails({ search: '', page: 0 }) }}
                className="text-[11px] text-slate-400 hover:text-slate-600">✕</button>
            )}
          </form>

          {/* Toggles */}
          <button
            onClick={() => { setUnreadOnly(v => !v); fetchEmails({ unreadOnly: !unreadOnly, page: 0 }) }}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-[12px] font-semibold border transition-colors ${
              unreadOnly ? 'bg-sky-500 text-white border-sky-500' : 'bg-white text-slate-600 border-slate-200 hover:border-sky-300'
            }`}
          >
            <RiMailLine className="text-sm" /> Unread
          </button>
          <button
            onClick={() => { setFlaggedOnly(v => !v); fetchEmails({ flaggedOnly: !flaggedOnly, page: 0 }) }}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-[12px] font-semibold border transition-colors ${
              flaggedOnly ? 'bg-amber-500 text-white border-amber-500' : 'bg-white text-slate-600 border-slate-200 hover:border-amber-300'
            }`}
          >
            <RiFlagLine className="text-sm" /> Flagged
          </button>

          {/* Refresh */}
          <button
            onClick={() => fetchEmails({ refresh: true })}
            disabled={refreshing}
            className="ml-auto flex items-center gap-1.5 text-[12px] text-slate-500 hover:text-sky-500 transition-colors disabled:opacity-40"
          >
            <motion.span animate={refreshing ? { rotate: 360 } : {}} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
              <RiRefreshLine />
            </motion.span>
            {lastRefresh ? relTime(lastRefresh.toISOString()) : 'Refresh'}
          </button>
        </div>

        {/* Risk filter tabs */}
        <div className="flex items-center gap-1 mb-3">
          {FILTERS.map(f => (
            <button
              key={f.id}
              onClick={() => handleFilter(f.id)}
              className={`px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-colors ${
                riskFilter === f.id
                  ? 'bg-sky-500 text-white shadow-sm'
                  : 'bg-white text-slate-600 border border-slate-200 hover:border-sky-300 hover:text-sky-600'
              }`}
            >
              {f.label}
              {f.id !== 'ALL' && (
                <span className="ml-1.5 opacity-60 font-normal text-[10px]">
                  {emails.filter(e => e.risk_tier === f.id).length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Email list card */}
        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-16 gap-2 text-slate-400">
              <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
                <RiLoader4Line className="text-xl" />
              </motion.span>
              <span className="text-[13px]">Loading emails…</span>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3 text-slate-400">
              <RiAlertLine className="text-4xl text-amber-400" />
              <p className="text-[13px] font-semibold text-slate-600">{error}</p>
              <button
                onClick={() => fetchEmails()}
                className="flex items-center gap-1.5 px-4 py-2 bg-sky-500 text-white text-[12px] font-semibold rounded-lg hover:bg-sky-600 transition-colors"
              >
                <RiRefreshLine /> Try Again
              </button>
            </div>
          ) : emails.length === 0 ? (
            <EmptyState filtered={hasFilters} />
          ) : (
            <div>
              {emails.map((email) => (
                <EmailRow
                  key={email.id}
                  email={email}
                  onOpen={onOpenEmail}
                  onFlag={handleFlag}
                />
              ))}
            </div>
          )}
        </div>

        {/* Pagination */}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between mt-3">
            <span className="text-[12px] text-slate-400">
              Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => handlePageChange(page - 1)}
                disabled={page === 0}
                className="p-1.5 rounded-lg border border-slate-200 text-slate-500 hover:border-sky-300 hover:text-sky-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <RiArrowLeftLine className="text-sm" />
              </button>
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                const p = i
                return (
                  <button
                    key={p}
                    onClick={() => handlePageChange(p)}
                    className={`w-7 h-7 rounded-lg text-[12px] font-semibold transition-colors ${
                      page === p ? 'bg-sky-500 text-white' : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    {p + 1}
                  </button>
                )
              })}
              <button
                onClick={() => handlePageChange(page + 1)}
                disabled={page >= totalPages - 1}
                className="p-1.5 rounded-lg border border-slate-200 text-slate-500 hover:border-sky-300 hover:text-sky-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <RiArrowRightLine className="text-sm" />
              </button>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
