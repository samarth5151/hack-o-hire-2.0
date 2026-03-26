import { motion } from 'framer-motion'
import { RiBellLine, RiSettings3Line, RiSearchLine, RiArrowDownSLine, RiNotificationLine } from 'react-icons/ri'
import { PAGE_META } from '../../constants/navigation.jsx'

export default function Topbar({ activePage }) {
  const meta = PAGE_META[activePage] ?? { title: '', sub: '' }

  return (
    <header className="h-16 sticky top-0 z-40 bg-white border-b border-slate-100 flex items-center px-6 gap-4">
      {/* Title area */}
      <motion.div
        key={activePage}
        initial={{ opacity: 0, x: -8 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.25 }}
        className="flex-1 min-w-0"
      >
        <h1 className="text-[16px] font-bold text-gray-900 leading-tight">{meta.title}</h1>
        <p className="text-[11px] text-gray-400 mt-0.5 truncate hidden md:block">{meta.sub}</p>
      </motion.div>

      {/* Right controls */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <div className="hidden lg:flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 w-48">
          <RiSearchLine className="text-gray-400 text-sm flex-shrink-0" />
          <input
            placeholder="Search..."
            className="bg-transparent text-[12px] text-gray-700 placeholder-gray-400 outline-none w-full font-medium"
          />
        </div>



        {/* Bell - notifications */}
        <button
          title="Notifications"
          className="w-9 h-9 rounded-full border border-slate-200 bg-white flex items-center justify-center text-gray-500 hover:text-sky-500 hover:border-sky-200 hover:bg-sky-50 transition-all"
        >
          <RiNotificationLine className="text-[17px]" />
        </button>

        {/* Settings */}
        <button
          title="Settings"
          className="w-9 h-9 rounded-full border border-slate-200 bg-white flex items-center justify-center text-gray-500 hover:text-sky-500 hover:border-sky-200 hover:bg-sky-50 transition-all"
        >
          <RiSettings3Line className="text-[16px]" />
        </button>

        {/* Round user avatar only */}
        <div className="relative cursor-pointer group" title="Analyst Kumar — Security Admin">
          <div className="w-9 h-9 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center ring-2 ring-white hover:ring-sky-200 transition-all shadow-sm">
            <span className="text-white text-[12px] font-bold">AK</span>
          </div>
          <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-400 rounded-full border-2 border-white" />
        </div>
      </div>
    </header>
  )
}
