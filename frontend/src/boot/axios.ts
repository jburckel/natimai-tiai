import { defineBoot } from '#q-app';
import axios, { type AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from 'axios';

import { getAccessToken, renewAccessToken } from 'src/services/session';

declare module 'vue' {
  interface ComponentCustomProperties {
    $api: AxiosInstance;
  }
}

const api = axios.create({
  // `build.env` reaches the client as `import.meta.env` since app-vite 3.
  baseURL: (import.meta.env.API_BASE_URL as string | undefined) || '/api/v1',
});

// Attach the in-memory access token (if any) to every request.
api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

type RetriableConfig = InternalAxiosRequestConfig & { _renewed?: boolean };

export default defineBoot(({ app, router }) => {
  app.config.globalProperties.$api = api;

  // On 401, renew the access token once from the refresh cookie and replay the
  // request; when the session is really over, back to the login page. The
  // auth routes are left alone: a 401 there is a wrong password, not an
  // expired session.
  api.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const config = error.config as RetriableConfig | undefined;
      const isAuthRoute = config?.url?.startsWith('/auth/') ?? false;
      if (error.response?.status !== 401 || !config || isAuthRoute) {
        return Promise.reject(error);
      }
      if (!config._renewed) {
        const token = await renewAccessToken();
        if (token) {
          config._renewed = true;
          config.headers.Authorization = `Bearer ${token}`;
          return api.request(config);
        }
      }
      const { useAuthStore } = await import('src/stores/auth');
      useAuthStore().clear();
      if (router.currentRoute.value.name !== 'login') {
        void router.push({
          name: 'login',
          query: { redirect: router.currentRoute.value.fullPath },
        });
      }
      return Promise.reject(error);
    },
  );
});

export { api };
