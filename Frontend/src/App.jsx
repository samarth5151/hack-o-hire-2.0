import { useState } from 'react'

// Layout & Core
import Sidebar from './components/layout/Sidebar'
import Topbar  from './components/layout/Topbar'

// Auth
import Login from './pages/Login'

// Employee Pages
import Dashboard          from './pages/Dashboard'
import EmailPhishing      from './pages/EmailPhishing'
import CredentialScanner  from './pages/CredentialScanner'
import AttachmentAnalyzer from './pages/AttachmentAnalyzer'
import WebsiteSpoofing    from './pages/WebsiteSpoofing'
import DeepfakeVoice      from './pages/DeepfakeVoice'
import FeedbackRetraining from './pages/FeedbackRetraining'

// Full Admin Portal
import AdminPortal from './pages/AdminPortal'

const EMPLOYEE_PAGES = {
  dashboard:  <Dashboard />,
  email:      <EmailPhishing />,
  credential: <CredentialScanner />,
  attachment: <AttachmentAnalyzer />,
  website:    <WebsiteSpoofing />,
  voice:      <DeepfakeVoice />,
  feedback:   <FeedbackRetraining />,
}

function App() {
  const [user, setUser]           = useState(null)          // null → show login
  const [activePage, setActivePage] = useState('dashboard')

  // ── LOGIN GATE ────────────────────────────────────────────────────────────
  if (!user) {
    return (
      <Login
        onLogin={(u) => {
          setUser(u)
          setActivePage(u.role === 'admin' ? 'admin' : 'dashboard')
        }}
      />
    )
  }

  // ── ADMIN MODE ────────────────────────────────────────────────────────────
  if (user.role === 'admin') {
    return (
      <AdminPortal
        user={user}
        onExit={() => {
          setUser(null)   // back to login
        }}
      />
    )
  }

  // ── EMPLOYEE MODE ─────────────────────────────────────────────────────────
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar
        activePage={activePage}
        setActivePage={(p) => {
          if (p === 'admin') {
            // Prompt re-login as admin instead of directly switching
            setUser(null)
          } else {
            setActivePage(p)
          }
        }}
      />
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar activePage={activePage} />
        <main className="flex-1 overflow-y-auto">
          {EMPLOYEE_PAGES[activePage]}
        </main>
      </div>
    </div>
  )
}

export default App
