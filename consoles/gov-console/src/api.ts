// API client for the gov-console. Dev mode uses X-Dev-Role headers or a dev
// JWT issued from the login page (HS256, MERIDIAN_DEV_JWT_SECRET).

export type Role = 'admin' | 'operator' | 'auditor'

export interface Session {
  token: string | null
  role: Role
  authorityId: string // for JRB EOI visibility (dev: X-Authority-Id)
}

const KEY = 'gov-console-session'
const AUTH_MODE = (import.meta.env.VITE_AUTH_MODE as string) || 'dev'

export function loadSession(): Session | null {
  // Prod (keycloak) profile: sessions live in memory only (HARDENING H2) —
  // never restore from localStorage.
  if (AUTH_MODE === 'keycloak') return null
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? (JSON.parse(raw) as Session) : null
  } catch {
    return null
  }
}

export function saveSession(s: Session | null) {
  if (AUTH_MODE === 'keycloak') return // in-memory only in prod profile
  if (s) localStorage.setItem(KEY, JSON.stringify(s))
  else localStorage.removeItem(KEY)
}

// Dev JWT minter (HS256) — mirrors the platform dev auth contract (SPEC 1.3).
async function mintDevJwt(sub: string, roles: string[]): Promise<string> {
  const secret = import.meta.env.VITE_DEV_JWT_SECRET || 'meridian-dev-secret'
  const enc = new TextEncoder()
  const b64 = (buf: ArrayBuffer | Uint8Array | string) => {
    const bytes = typeof buf === 'string' ? enc.encode(buf) : new Uint8Array(buf as ArrayBuffer)
    let s = ''
    bytes.forEach((b) => (s += String.fromCharCode(b)))
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  const header = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = b64(
    JSON.stringify({ sub, roles, tenant_id: 'dev', exp: Math.floor(Date.now() / 1000) + 8 * 3600 }),
  )
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${payload}`))
  return `${header}.${payload}.${b64(sig)}`
}

// login: dev profile mints a local HS256 dev JWT. When VITE_AUTH_MODE=keycloak
// the PKCE redirect flow (oidc.ts) owns sign-in and this is not called.
export async function login(role: Role, authorityId: string): Promise<Session> {
  const token = await mintDevJwt(`console-${role}`, [role])
  const session = { token, role, authorityId }
  saveSession(session)
  return session
}

const GATEWAY = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8400'
const ANALYTICS = import.meta.env.VITE_ANALYTICS_URL || 'http://localhost:8401'
const JRB = import.meta.env.VITE_JRB_URL || 'http://localhost:8402'
const OMBUD = import.meta.env.VITE_OMBUD_URL || 'http://localhost:8403'

async function api<T>(base: string, path: string, s: Session, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (s.token) headers['Authorization'] = `Bearer ${s.token}`
  else headers['X-Dev-Role'] = s.role
  if (base === JRB) headers['X-Authority-Id'] = s.authorityId
  const res = await fetch(base + path, { ...init, headers: { ...headers, ...(init?.headers || {}) } })
  if (!res.ok) {
    const prob = await res.json().catch(() => ({}))
    throw new Error(prob.detail || `${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<T>
}

// ---- analytics (T4/T15) ----
export interface ScoreRow {
  pseudo_tin: string
  score: number
  band: string
  explanation: { feature: string; contribution: number }[]
}
export const getScores = (s: Session) => api<{ scores: ScoreRow[] }>(ANALYTICS, '/v1/scores', s)
export const getCases = (s: Session) => api<{ cases: unknown[] }>(ANALYTICS, '/v1/cases', s)
export const getDeclarations = (s: Session) => api<{ declarations: unknown[] }>(ANALYTICS, '/v1/nsw/declarations', s)

// ---- jrb (T11) ----
export interface Authority {
  id: string
  kind: string
  name: string
  state_code?: string
  status: string
  cert_fingerprint?: string
}
export const getAuthorities = (s: Session) => api<{ authorities: Authority[] }>(JRB, '/v1/authorities', s)
export const getEOIs = (s: Session) => api<{ items: unknown[]; visibility_banner: string }>(JRB, '/v1/eoi', s)
export const getAttribution = (s: Session) =>
  api<Record<string, unknown>>(GATEWAY, '/flows/f7/attribution-feeds/NG-LA', s)

// ---- ombud (T13i) ----
export const getOmbudCases = (s: Session) => api<{ cases: unknown[] }>(OMBUD, '/v1/cases', s)

// ---- gateway receipts ----
export const getReceipts = (s: Session) =>
  api<{ worm_mode: string; receipts: unknown[]; manifest: unknown[] }>(GATEWAY, '/v1/receipts', s)
