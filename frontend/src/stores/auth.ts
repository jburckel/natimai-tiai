import { defineStore } from 'pinia';

import { getMe, login as loginRequest, type User } from 'src/services/auth';
import { endSession, getAccessToken, renewAccessToken, setAccessToken } from 'src/services/session';

interface AuthState {
  user: User | null;
}

// Shared by every navigation that arrives before the first restore settles.
let restoring: Promise<boolean> | null = null;

export const useAuthStore = defineStore('auth', {
  state: (): AuthState => ({
    user: null,
  }),
  getters: {
    isAuthenticated: (state): boolean => state.user !== null,
    isAdmin: (state): boolean => state.user?.role === 'admin',
  },
  actions: {
    async login(email: string, password: string) {
      const { access_token } = await loginRequest(email, password);
      setAccessToken(access_token);
      await this.fetchMe();
    },
    async fetchMe() {
      this.user = await getMe();
    },
    /**
     * Make sure a session is loaded: after a reload the access token is gone
     * (it lives in memory) and the refresh cookie brings it back. False when
     * there is no session to restore.
     */
    async restore(): Promise<boolean> {
      if (this.user) return true;
      if (!restoring) {
        restoring = (async () => {
          const token = getAccessToken() ?? (await renewAccessToken());
          if (!token) return false;
          try {
            await this.fetchMe();
            return true;
          } catch {
            return false;
          }
        })().finally(() => {
          restoring = null;
        });
      }
      return restoring;
    },
    /** The server said the session is over: forget it locally. */
    clear() {
      this.user = null;
      setAccessToken(null);
    },
    async logout() {
      this.user = null;
      await endSession();
    },
  },
});
