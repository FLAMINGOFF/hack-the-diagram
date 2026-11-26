import { defineConfig } from '@playwright/test';

// Runs against the production build served by `vite preview`.
export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: { baseURL: 'http://localhost:4173/hack-the-diagram/', trace: 'off' },
  webServer: { command: 'npm run preview -- --port 4173 --strictPort', url: 'http://localhost:4173/hack-the-diagram/', reuseExistingServer: !process.env.CI },
});
