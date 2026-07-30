import { useEffect, useState } from 'react'
import { Navigate, NavLink, Route, Routes, useNavigate } from 'react-router-dom'
import { loadSession, login, saveSession, Session, Role } from './api'
import { AUTH_MODE, beginOidcLogin, completeOidcLogin, oidcLogout, onOidcToken } from './oidc'
import NrsDashboard from './pages/NrsDashboard'
import CaseFeed from './pages/CaseFeed'
import NswDeclarations from './pages/NswDeclarations'
import JrbAuthorities from './pages/JrbAuthorities'
import EoiInbox from './pages/EoiInbox'
import AttributionFeeds from './pages/AttributionFeeds'
import StatePortal from './pages/StatePortal'
import OmbudCases from './pages/OmbudCases'

const NAV = [
  { section: 'NRS console' },
  { to: '/nrs/scoring', label: 'Scoring dashboard' },
  { to: '/nrs/cases', label: 'Case feed' },
  { to: '/nrs/nsw', label: 'NSW declarations' },
  { section: 'JRB console' },
  { to: '/jrb/authorities', label: 'Authorities' },
  { to: '/jrb/eoi', label: 'EOI inbox' },
  { to: '/jrb/attribution', label: 'Attribution feeds' },
  { section: 'State IRS portal' },
  { to: '/state', label: 'State portal view' },
  { section: 'Ombud registry' },
  { to: '/ombud/cases', label: 'Cases & deposits' },
]

function LoginPage({ onLogin }: { onLogin: (s: Session) => void }) {
  if (AUTH_MODE === 'keycloak') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-sand-100">
        <div className="card w-full max-w-sm p-8">
          <div className="mb-1 text-xs font-semibold uppercase tracking-widest text-clay-600">
            Meridian · Sovereign Zone
          </div>
          <h1 className="mb-6 text-2xl font-bold text-sand-900">Gov Console</h1>
          <button className="btn btn-primary w-full justify-center" onClick={() => void beginOidcLogin()}>
            Sign in with Keycloak
          </button>
          <p className="mt-4 text-xs text-sand-500">
            Production profile: Keycloak OIDC (authorization code + PKCE). Tokens in memory only.
          </p>
        </div>
      </div>
    )
  }
  const [role, setRole] = useState<Role>('admin')
  const [authority, setAuthority] = useState('JRB-SEC')
  const [busy, setBusy] = useState(false)
  const nav = useNavigate()
  return (
    <div className="flex min-h-screen items-center justify-center bg-sand-100">
      <div className="card w-full max-w-sm p-8">
        <div className="mb-1 text-xs font-semibold uppercase tracking-widest text-clay-600">
          Meridian · Sovereign Zone
        </div>
        <h1 className="mb-6 text-2xl font-bold text-sand-900">Gov Console</h1>
        <label className="mb-1 block text-sm font-medium text-sand-700">Dev role</label>
        <select className="input mb-4" value={role} onChange={(e) => setRole(e.target.value as Role)}>
          <option value="admin">admin (registry)</option>
          <option value="operator">operator (clerk)</option>
          <option value="auditor">auditor (member)</option>
        </select>
        <label className="mb-1 block text-sm font-medium text-sand-700">Authority (JRB identity)</label>
        <select className="input mb-6" value={authority} onChange={(e) => setAuthority(e.target.value)}>
          <option value="JRB-SEC">JRB Secretariat</option>
          <option value="NRS">NRS</option>
          <option value="NG-LA">Lagos LIRS</option>
          <option value="NG-FC">FCT-IRS</option>
          <option value="NG-KN">Kano IRS</option>
          <option value="NG-RI">Rivers IRS</option>
        </select>
        <button
          className="btn btn-primary w-full justify-center"
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            try {
              const s = await login(role, authority)
              onLogin(s)
              nav('/nrs/scoring')
            } finally {
              setBusy(false)
            }
          }}
        >
          {busy ? 'Signing in…' : 'Sign in (dev JWT)'}
        </button>
        <p className="mt-4 text-xs text-sand-500">
          Dev mode: HS256 JWT minted locally (MERIDIAN_DEV_JWT_SECRET). Production uses Keycloak OIDC.
        </p>
      </div>
    </div>
  )
}

export default function App() {
  const [session, setSession] = useState<Session | null>(loadSession())
  const [oidcBusy, setOidcBusy] = useState(AUTH_MODE === 'keycloak')

  // Keycloak profile: finish the PKCE redirect / restore the in-memory user,
  // and keep the session token fresh via silent renew.
  useEffect(() => {
    if (AUTH_MODE !== 'keycloak') return
    let live = true
    completeOidcLogin()
      .then((s) => {
        if (live && s) setSession(s)
      })
      .finally(() => live && setOidcBusy(false))
    onOidcToken((s) => live && setSession(s))
    return () => {
      live = false
    }
  }, [])

  if (AUTH_MODE === 'keycloak' && oidcBusy && !session) {
    return <div className="flex min-h-screen items-center justify-center bg-sand-100 text-sand-500">Signing in…</div>
  }
  if (!session) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage onLogin={setSession} />} />
      </Routes>
    )
  }
  return (
    <div className="flex min-h-screen">
      <aside className="w-60 shrink-0 border-r border-sand-200 bg-sand-100 p-4">
        <div className="mb-1 text-xs font-semibold uppercase tracking-widest text-clay-600">Meridian</div>
        <div className="mb-6 text-lg font-bold text-sand-900">Gov Console</div>
        <nav className="space-y-1">
          {NAV.map((item, i) =>
            'section' in item && item.section ? (
              <div key={i} className="mt-4 px-3 text-xs font-semibold uppercase tracking-wide text-sand-400">
                {item.section}
              </div>
            ) : (
              <NavLink
                key={item.to}
                to={item.to!}
                className={({ isActive }) => `navlink ${isActive ? 'navlink-active' : ''}`}
              >
                {item.label}
              </NavLink>
            ),
          )}
        </nav>
      </aside>
      <main className="flex-1 overflow-y-auto">
        <header className="flex items-center justify-between border-b border-sand-200 bg-white px-6 py-3">
          <div className="text-sm text-sand-500">
            Sovereign enclave · audited cross-zone gateway · pseudonymised analytics
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span className="badge bg-moss-100 text-moss-700">{session.role}</span>
            <span className="badge bg-sand-200 text-sand-700">{session.authorityId}</span>
            <button
              className="btn"
              onClick={() => {
                if (AUTH_MODE === 'keycloak') void oidcLogout()
                saveSession(null)
                setSession(null)
              }}
            >
              Sign out
            </button>
          </div>
        </header>
        <div className="p-6">
          <Routes>
            <Route path="/" element={<Navigate to="/nrs/scoring" replace />} />
            <Route path="/nrs/scoring" element={<NrsDashboard session={session} />} />
            <Route path="/nrs/cases" element={<CaseFeed session={session} />} />
            <Route path="/nrs/nsw" element={<NswDeclarations session={session} />} />
            <Route path="/jrb/authorities" element={<JrbAuthorities session={session} />} />
            <Route path="/jrb/eoi" element={<EoiInbox session={session} />} />
            <Route path="/jrb/attribution" element={<AttributionFeeds session={session} />} />
            <Route path="/state" element={<StatePortal session={session} />} />
            <Route path="/ombud/cases" element={<OmbudCases session={session} />} />
            <Route path="*" element={<Navigate to="/nrs/scoring" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}
