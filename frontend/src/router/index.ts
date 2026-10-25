import { defineRouter } from '#q-app';
import {
  createMemoryHistory,
  createRouter,
  createWebHashHistory,
  createWebHistory,
} from 'vue-router';
import routes from './routes';
import { useAuthStore } from 'src/stores/auth';
import { documentTitle } from 'src/utils/format';

export default defineRouter(() => {
  // app-vite 3 exposes these as `import.meta.env.QUASAR_*`; the `process.env`
  // spelling of app-vite 1/2 is undefined in dev (the page stayed blank) and
  // emptied in the build, which silently fell back to hash mode — and broke the
  // e-mailed `/reset-password?token=…` link, a history-mode URL.
  const createHistory = import.meta.env.QUASAR_SERVER
    ? createMemoryHistory
    : import.meta.env.QUASAR_VUE_ROUTER_MODE === 'history'
      ? createWebHistory
      : createWebHashHistory;

  const router = createRouter({
    scrollBehavior: () => ({ left: 0, top: 0 }),
    routes,
    history: createHistory(import.meta.env.QUASAR_VUE_ROUTER_BASE),
  });

  router.beforeEach(async (to) => {
    const auth = useAuthStore();
    // The session lives in memory and in an HttpOnly cookie: after a reload,
    // only asking the server tells whether it is still open.
    const needsSession = to.meta.requiresAuth || to.name === 'login';
    const isAuthed = needsSession ? await auth.restore() : auth.isAuthenticated;
    if (to.meta.requiresAuth && !isAuthed) {
      return { name: 'login', query: { redirect: to.fullPath } };
    }
    if (to.name === 'login' && isAuthed) {
      return { name: 'dashboard' };
    }
    // Admin-only pages. The guard only decides what to render — the backend
    // authorizes every call independently, so this cannot be bypassed for real.
    if (to.meta.requiresAdmin && !auth.isAdmin) {
      return { name: 'dashboard' };
    }
    return true;
  });

  // One title per page: it is what a screen reader announces on navigation,
  // and what tells twelve open tabs apart.
  router.afterEach((to) => {
    document.title = documentTitle(to.meta.title as string | undefined);
  });

  return router;
});
