import { defineStore } from 'pinia';

import { getMe, login as loginRequest, type User } from 'src/services/auth';

// Same key the axios boot reads to attach the Bearer header (kept in sync via
// localStorage rather than a cross-import to avoid a boot/store import cycle).
const TOKEN_KEY = 'tiai_token';

interface AuthState {
  token: string | null;
  user: User | null;
}

export const useAuthStore = defineStore('auth', {
  state: (): AuthState => ({
    token: localStorage.getItem(TOKEN_KEY),
    user: null,
  }),
  getters: {
    isAuthenticated: (state): boolean => !!state.token,
  },
  actions: {
    setToken(token: string | null) {
      this.token = token;
      if (token) {
        localStorage.setItem(TOKEN_KEY, token);
      } else {
        localStorage.removeItem(TOKEN_KEY);
      }
    },
    async login(email: string, password: string) {
      const { access_token } = await loginRequest(email, password);
      this.setToken(access_token);
      await this.fetchMe();
    },
    async fetchMe() {
      this.user = await getMe();
    },
    logout() {
      this.setToken(null);
      this.user = null;
    },
  },
});
