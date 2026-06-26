import { defineConfig } from '#q-app/wrappers';

export default defineConfig(() => {
  return {
    boot: ['pinia', 'axios'],
    css: ['app.scss'],
    extras: ['material-icons'],

    build: {
      target: { browser: ['es2022'], node: 'node20' },
      typescript: { strict: true, vueShim: true },
      vueRouterMode: 'history',
      // API base URL injected at build time (overridable via env).
      env: {
        API_BASE_URL: process.env.API_BASE_URL || '/api/v1',
      },
    },

    devServer: {
      port: 9000,
      open: true,
      proxy: {
        '/api': { target: 'http://localhost:8000', changeOrigin: true },
      },
    },

    framework: {
      plugins: ['Notify', 'Dialog'],
    },
  };
});
