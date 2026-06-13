import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      boot: fileURLToPath(new URL('./src/boot', import.meta.url)),
      src: fileURLToPath(new URL('./src', import.meta.url)),
      pages: fileURLToPath(new URL('./src/pages', import.meta.url)),
      layouts: fileURLToPath(new URL('./src/layouts', import.meta.url)),
    },
  },
  // Tests are self-contained: don't inherit the Quasar tsconfig preset.
  esbuild: {
    tsconfigRaw: '{}',
  },
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.spec.ts'],
  },
});
