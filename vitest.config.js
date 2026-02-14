import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: ['vscode-extension/**', 'node_modules/**'],
  },
});
