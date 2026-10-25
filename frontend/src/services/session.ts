import axios from 'axios';

/**
 * The console session, outside of any store so the axios boot and the auth
 * store can both reach it without importing each other.
 *
 * The access token lives here, in memory only: it lasts a quarter-hour and is
 * renewed from the refresh cookie, which is HttpOnly — no script, an injected
 * one included, can read either from storage. A reload starts with no access
 * token and renews one from the cookie.
 */
let accessToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

// A bare instance: the renewal must not go through the interceptors that
// trigger it, or a failed renewal would try to renew itself.
const bare = axios.create({
  baseURL: (import.meta.env.API_BASE_URL as string | undefined) || '/api/v1',
});

let renewal: Promise<string | null> | null = null;

/** HTTP status of an axios error, if it has one. */
function statusOf(e: unknown): number | undefined {
  return (e as { response?: { status?: number } })?.response?.status;
}

async function renewOnce(): Promise<string | null> {
  for (let attempt = 0; ; attempt++) {
    try {
      const { data } = await bare.post<{ access_token: string }>('/auth/refresh');
      accessToken = data.access_token;
      return accessToken;
    } catch (e) {
      // 409: another tab renewed with the same cookie a moment ago and the
      // browser now holds the next one — retry once with it.
      if (statusOf(e) === 409 && attempt === 0) {
        await new Promise((resolve) => setTimeout(resolve, 300));
        continue;
      }
      accessToken = null;
      return null;
    }
  }
}

/**
 * Renew the access token from the refresh cookie; null when the session is
 * over. Concurrent callers share one request: ten calls failing with 401 at
 * once must not spend ten refresh tokens, nine of which would read as reuse.
 */
export function renewAccessToken(): Promise<string | null> {
  if (!renewal) {
    renewal = renewOnce().finally(() => {
      renewal = null;
    });
  }
  return renewal;
}

/** End the session server-side (the refresh family) and forget the token. */
export async function endSession(): Promise<void> {
  accessToken = null;
  try {
    await bare.post('/auth/logout');
  } catch {
    // Logging out of a server that is down still logs this console out.
  }
}
