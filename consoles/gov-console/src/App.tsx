import { useEffect, useState } from 'react'
import { Navigate, NavLink, Route, Routes, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Landmark } from 'lucide-react'
import { loadSession, login, saveSession, Session, Role } from './api'
import { AUTH_MODE, beginOidcLogin, completeOidcLogin, oidcLogout, onOidcToken } from './oidc'
import Field from './components/Field'
import LangSwitcher from './components/LangSwitcher'
import { Chip } from './components/ui'
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

function LoginCard({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation('common')
  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-100">
      <div className="card w-full max-w-sm p-8">
        <div className="mb-1 flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-brand-700">
          <Landmark aria-hidden="true" className="h-4 w-4" />
          {t('app.zone')}
        </div>
        <h1 className="mb-6 text-2xl font-bold text-stone-900">{t('app.name')}</h1>
        {children}
        <div className="mt-6">
          <LangSwitcher />
        </div>
      </div>
    </div>
  )
}

function LoginPage({ onLogin }: { onLogin: (s: Session) => void }) {
  const { t } = useTranslation('common')
  if (AUTH_MODE === 'keycloak') {
    return (
      <LoginCard>
        <button className="btn btn-primary w-full justify-center" onClick={() => void beginOidcLogin()}>
          {t('auth.signin.keycloak')}
        </button>
        <p className="mt-4 text-xs text-stone-600">
          Production profile: Keycloak OIDC (authorization code + PKCE). Tokens in memory only.
        </p>
      </LoginCard>
    )
  }
  return <DevLogin onLogin={onLogin} />
}

function DevLogin({ onLogin }: { onLogin: (s: Session) => void }) {
  const { t } = useTranslation('common')
  const [role, setRole] = useState<Role>('admin')
  const [authority, setAuthority] = useState('JRB-SEC')
  const [busy, setBusy] = useState(false)
  const nav = useNavigate()
  return (
    <LoginCard>
      <div className="mb-4">
        <Field label="Dev role" id="dev-role">
          <select id="dev-role" className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            <option value="admin">admin (registry)</option>
            <option value="operator">operator (clerk)</option>
            <option value="auditor">auditor (member)</option>
          </select>
        </Field>
      </div>
      <div className="mb-6">
        <Field label="Authority (JRB identity)" id="dev-authority">
          <select id="dev-authority" className="input" value={authority} onChange={(e) => setAuthority(e.target.value)}>
            <option value="JRB-SEC">JRB Secretariat</option>
            <option value="NRS">NRS</option>
            <option value="NG-LA">Lagos LIRS</option>
            <option value="NG-FC">FCT-IRS</option>
            <option value="NG-KN">Kano IRS</option>
            <option value="NG-RI">Rivers IRS</option>
          </select>
        </Field>
      </div>
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
        {busy ? t('auth.signingIn') : t('auth.signin.dev')}
      </button>
      <p className="mt-4 text-xs text-stone-600">
        Dev mode: HS256 JWT minted locally (MERIDIAN_DEV_JWT_SECRET). Production uses Keycloak OIDC.
      </p>
    </LoginCard>
  )
}

export default function App() {
  const { t } = useTranslation('common')
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
    return (
      <div className="flex min-h-screen items-center justify-center bg-neutral-100 text-stone-600" role="status">
        {t('auth.signingIn')}
      </div>
    )
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
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded-md focus:bg-brand-700 focus:px-3 focus:py-2 focus:text-white"
      >
        Skip to content
      </a>
      <aside className="flex w-60 shrink-0 flex-col bg-brand-800 p-4">
        <div className="mb-1 flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-brand-200">
          <Landmark aria-hidden="true" className="h-4 w-4" />
          Meridian
        </div>
        <div className="mb-6 text-lg font-bold text-white">Meridian Gov Console</div>
        <nav className="flex-1 space-y-1" aria-label="Primary">
          {NAV.map((item, i) =>
            'section' in item && item.section ? (
              <div key={i} className="mt-4 px-3 text-xs font-semibold uppercase tracking-wide text-brand-300">
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
        <div className="mt-4 border-t border-brand-700 pt-3">
          <LangSwitcher dark />
        </div>
      </aside>
      <main id="main" className="flex-1 overflow-y-auto">
        <header className="flex items-center justify-between border-b border-neutral-200 bg-white px-6 py-3 shadow-sm">
          <div className="text-sm text-stone-600">{t('app.tagline')}</div>
          <div className="flex items-center gap-3 text-sm">
            <Chip status="info">{session.role}</Chip>
            <Chip status="demo">{session.authorityId}</Chip>
            <button
              className="btn"
              onClick={() => {
                if (AUTH_MODE === 'keycloak') void oidcLogout()
                saveSession(null)
                setSession(null)
              }}
            >
              {t('auth.signout')}
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
