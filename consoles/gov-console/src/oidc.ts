// Keycloak OIDC login (authorization code + PKCE) for the gov-console
// (HARDENING H2). Active only when VITE_AUTH_MODE=keycloak; the dev-token
// login in api.ts stays the default. Tokens are held IN MEMORY (never
// localStorage) and renewed silently.
import { InMemoryWebStorage, User, UserManager, WebStorageStateStore } from 'oidc-client-ts'
import type { Role, Session } from './api'

export const AUTH_MODE: string = (import.meta.env.VITE_AUTH_MODE as string) || 'dev'

let manager: UserManager | null = null

export function oidcManager(): UserManager {
  if (manager) return manager
  const issuer = (import.meta.env.VITE_KEYCLOAK_ISSUER as string) || ''
  if (!issuer) throw new Error('VITE_KEYCLOAK_ISSUER required when VITE_AUTH_MODE=keycloak')
  manager = new UserManager({
    authority: issuer.replace(/\/$/, ''),
    client_id: (import.meta.env.VITE_KEYCLOAK_CLIENT_ID as string) || 'gov-console',
    redirect_uri: window.location.origin + '/',
    post_logout_redirect_uri: window.location.origin + '/',
    response_type: 'code', // authorization code + PKCE (S256 by default)
    scope: 'openid profile email roles',
    automaticSilentRenew: true,
    // In-memory stores only: tokens never touch localStorage/sessionStorage.
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
  })
  return manager
}

function roleFromProfile(profile: Record<string, unknown>): Role {
  const ra = profile['realm_access'] as { roles?: string[] } | undefined
  const roles: string[] = [
    ...(ra?.roles ?? []),
    ...((profile['roles'] as string[] | undefined) ?? []),
  ]
  for (const r of ['admin', 'operator', 'auditor'] as const) {
    if (roles.includes(r)) return r
  }
  return 'auditor'
}

export function sessionFromUser(user: User): Session {
  const profile = (user.profile ?? {}) as Record<string, unknown>
  return {
    token: user.access_token,
    role: roleFromProfile(profile),
    authorityId: (profile['authority_id'] as string) || 'JRB-SEC',
  }
}

// beginLogin starts the PKCE redirect to Keycloak.
export async function beginOidcLogin(): Promise<void> {
  await oidcManager().signinRedirect()
}

// completeOidcLogin finishes the redirect flow (when the URL carries the
// authorization response) or restores an in-memory user. Null when no user.
export async function completeOidcLogin(): Promise<Session | null> {
  const mgr = oidcManager()
  try {
    if (window.location.search.includes('code=') && window.location.search.includes('state=')) {
      const user = await mgr.signinRedirectCallback(window.location.href)
      window.history.replaceState({}, document.title, window.location.pathname)
      return sessionFromUser(user)
    }
  } catch {
    // fall through to stored user
  }
  const user = await mgr.getUser()
  return user && !user.expired ? sessionFromUser(user) : null
}

// onOidcToken refreshes propagate renewed access tokens (silent renew) so the
// api client always sends a fresh Bearer token.
export function onOidcToken(cb: (s: Session) => void): void {
  oidcManager().events.addUserLoaded((user) => cb(sessionFromUser(user)))
}

export async function oidcLogout(): Promise<void> {
  try {
    await oidcManager().removeUser()
  } catch {
    /* noop */
  }
}
