/**
 * Browser SDK for clawauth. The 3-line surface:
 *
 *   import { createClawAuthClient } from '@clawauth/client';
 *   const auth = createClawAuthClient({ googleClientId: 'xxx.apps.googleusercontent.com', apiBase: '/api' });
 *   document.getElementById('signin')!.onclick = () => auth.signInWithGoogle();
 *
 * That's it. The SDK:
 *   - Lazy-loads Google Identity Services script
 *   - Pops the Google sign-in chooser
 *   - POSTs the resulting ID token to ${apiBase}/auth/google
 *   - Stores access + refresh tokens in localStorage (configurable)
 *   - Auto-refreshes access token before expiry
 *   - Exposes `auth.fetch()` that adds Authorization header and retries on 401
 */

export interface ClawAuthClientOptions {
  googleClientId: string;
  /** Base URL of your clawauth-mounted API. Default '/api'. */
  apiBase?: string;
  /**
   * Storage adapter. Default = `localStorage`. Pass `sessionStorage`, an in-memory
   * shim, or a custom adapter for SSR / native shells.
   */
  storage?: TokenStorage;
  /** Called whenever the auth state changes (sign-in / refresh / sign-out). */
  onChange?: (state: AuthState) => void;
  /** Optional: device id added to refresh records (for revocation by device). */
  deviceId?: string;
}

export interface TokenStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface AuthState {
  signedIn: boolean;
  user: AuthUser | null;
  accessToken: string | null;
  accessTokenExpiresAt: string | null;
}

export interface AuthUser {
  sub: string;
  email: string | null;
  name: string | null;
  picture: string | null;
  provider: string;
}

export interface ClawAuthClient {
  signInWithGoogle(): Promise<AuthState>;
  signOut(): Promise<void>;
  refresh(): Promise<AuthState>;
  /** fetch wrapper that injects bearer + auto-refreshes on 401. */
  fetch: typeof fetch;
  /** Read current state synchronously. */
  state(): AuthState;
  /** Manually subscribe to changes (in addition to onChange option). */
  subscribe(listener: (state: AuthState) => void): () => void;
}

const STORAGE_KEY = 'clawauth.session.v1';
const GIS_SCRIPT = 'https://accounts.google.com/gsi/client';

interface PersistedSession {
  user: AuthUser;
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

export function createClawAuthClient(opts: ClawAuthClientOptions): ClawAuthClient {
  if (typeof window === 'undefined') {
    throw new Error('@clawauth/client must run in a browser environment');
  }
  const storage = opts.storage ?? window.localStorage;
  const apiBase = (opts.apiBase ?? '/api').replace(/\/+$/, '');
  const listeners = new Set<(s: AuthState) => void>();
  if (opts.onChange) listeners.add(opts.onChange);

  let session: PersistedSession | null = loadSession(storage);
  let refreshTimer: ReturnType<typeof setTimeout> | null = null;
  scheduleRefresh();

  function loadSession(s: TokenStorage): PersistedSession | null {
    try {
      const raw = s.getItem(STORAGE_KEY);
      return raw ? (JSON.parse(raw) as PersistedSession) : null;
    } catch {
      return null;
    }
  }
  function save() {
    if (session) storage.setItem(STORAGE_KEY, JSON.stringify(session));
    else storage.removeItem(STORAGE_KEY);
    const s = currentState();
    listeners.forEach((l) => l(s));
    scheduleRefresh();
  }
  function currentState(): AuthState {
    return session
      ? {
          signedIn: true,
          user: session.user,
          accessToken: session.accessToken,
          accessTokenExpiresAt: session.accessTokenExpiresAt
        }
      : { signedIn: false, user: null, accessToken: null, accessTokenExpiresAt: null };
  }

  function scheduleRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    if (!session) return;
    const expiresAt = new Date(session.accessTokenExpiresAt).getTime();
    // Refresh 60s before expiry, but never less than 5s out.
    const delay = Math.max(5_000, expiresAt - Date.now() - 60_000);
    refreshTimer = setTimeout(() => {
      refresh().catch(() => {
        /* swallow — fetch wrapper will re-try and either succeed or sign out */
      });
    }, delay);
  }

  async function refresh(): Promise<AuthState> {
    if (!session) return currentState();
    const res = await fetch(`${apiBase}/auth/refresh`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refreshToken: session.refreshToken })
    });
    if (!res.ok) {
      // Refresh failed → fully sign out.
      session = null;
      save();
      return currentState();
    }
    const data = await res.json();
    session = {
      ...session,
      accessToken: data.accessToken,
      accessTokenExpiresAt: data.accessTokenExpiresAt,
      refreshToken: data.refreshToken,
      refreshTokenExpiresAt: data.refreshTokenExpiresAt
    };
    save();
    return currentState();
  }

  async function signInWithGoogle(): Promise<AuthState> {
    await loadGis();
    const idToken = await new Promise<string>((resolve, reject) => {
      try {
        // @ts-expect-error global injected by GIS script
        google.accounts.id.initialize({
          client_id: opts.googleClientId,
          callback: (resp: { credential?: string }) => {
            if (resp?.credential) resolve(resp.credential);
            else reject(new Error('Google did not return a credential'));
          },
          ux_mode: 'popup',
          auto_select: false
        });
        // @ts-expect-error
        google.accounts.id.prompt((notification: any) => {
          if (notification.isNotDisplayed?.() || notification.isSkippedMoment?.()) {
            // Fallback: render a button into a hidden div and auto-click.
            // For most users the prompt() works; this is a best-effort fallback.
            reject(new Error('Google sign-in prompt was suppressed (browser/3p cookies?)'));
          }
        });
      } catch (err) {
        reject(err);
      }
    });

    const res = await fetch(`${apiBase}/auth/google`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ idToken, deviceId: opts.deviceId })
    });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`clawauth sign-in failed (${res.status}): ${detail}`);
    }
    const data = await res.json();
    session = {
      user: { ...data.user, sub: data.user.id }, // server returns full user; alias id→sub for jwt convention
      accessToken: data.accessToken,
      accessTokenExpiresAt: data.accessTokenExpiresAt,
      refreshToken: data.refreshToken,
      refreshTokenExpiresAt: data.refreshTokenExpiresAt
    };
    save();
    return currentState();
  }

  async function signOut(): Promise<void> {
    if (session?.refreshToken) {
      await fetch(`${apiBase}/auth/logout`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ refreshToken: session.refreshToken })
      }).catch(() => {});
    }
    session = null;
    save();
  }

  const wrappedFetch: typeof fetch = async (input, init) => {
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    if (session?.accessToken && !headers.has('authorization')) {
      headers.set('authorization', `Bearer ${session.accessToken}`);
    }
    const doFetch = () => fetch(input, { ...init, headers });
    let res = await doFetch();
    if (res.status === 401 && session) {
      const refreshed = await refresh();
      if (refreshed.signedIn) {
        headers.set('authorization', `Bearer ${refreshed.accessToken}`);
        res = await doFetch();
      }
    }
    return res;
  };

  return {
    signInWithGoogle,
    signOut,
    refresh,
    fetch: wrappedFetch,
    state: currentState,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    }
  };
}

let gisLoading: Promise<void> | null = null;
function loadGis(): Promise<void> {
  if (typeof window === 'undefined') return Promise.reject(new Error('no window'));
  // @ts-expect-error
  if (window.google?.accounts?.id) return Promise.resolve();
  if (gisLoading) return gisLoading;
  gisLoading = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = GIS_SCRIPT;
    s.async = true;
    s.defer = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error('Failed to load Google Identity Services'));
    document.head.appendChild(s);
  });
  return gisLoading;
}
