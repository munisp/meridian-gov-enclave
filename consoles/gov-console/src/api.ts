// API client for the gov-console. Dev mode uses X-Dev-Role headers or a dev
// JWT issued from the login page (HS256, MERIDIAN_DEV_JWT_SECRET).

export type Role = 'admin' | 'operator' | 'auditor'

export interface Session {
  token: string | null
  role: Role
  authorityId: string // for JRB EOI visibility (dev: X-Authority-Id)
}

const KEY = 'gov-console-session'

export function loadSession(): Session | null {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? (JSON.parse(raw) as Session) : null
  } catch {
    return null
  }
}

export function saveSession(s: Session | null) {
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

export async function login(role: Role, authorityId: string): Promise<Session> {
  const token = await mintDevJwt(`console-${role}`, [role])
  const session = { token, role, authorityId }
  saveSession(session)
  return session
}

export type Service = 'analytics' | 'jrb' | 'ombud' | 'gateway'

const BASE: Record<Service, string> = {
  analytics: import.meta.env.VITE_ANALYTICS_URL || '/api/analytics',
  jrb: import.meta.env.VITE_JRB_URL || '/api/jrb',
  ombud: import.meta.env.VITE_OMBUD_URL || '/api/ombud',
  gateway: import.meta.env.VITE_GATEWAY_URL || '/api/gateway',
}

export async function api<T = unknown>(
  service: Service,
  path: string,
  opts: { method?: string; body?: unknown; session?: Session | null } = {},
): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const s = opts.session ?? loadSession()
  if (s?.token) headers['Authorization'] = `Bearer ${s.token}`
  else if (s?.role) headers['X-Dev-Role'] = s.role
  if (s?.authorityId) headers['X-Authority-Id'] = s.authorityId
  const res = await fetch(`${BASE[service]}${path}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) {
    const detail = data?.detail || data?.title || res.statusText
    throw new Error(`${res.status}: ${detail}`)
  }
  return data as T
}

export function fmtKobo(kobo: number | null | undefined): string {
  if (kobo === null || kobo === undefined) return '—'
  return '₦' + (kobo / 100).toLocaleString('en-NG', { minimumFractionDigits: 2 })
}

export function short(id: string | null | undefined, n = 12): string {
  if (!id) return '—'
  return id.length > n ? id.slice(0, n) + '…' : id
}
