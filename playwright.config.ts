import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  use: { baseURL: 'http://127.0.0.1:4173', browserName: 'chromium', viewport: { width: 1440, height: 1000 }, actionTimeout: 10_000, trace: 'retain-on-failure' },
  webServer: {
    command: 'node --experimental-strip-types tests/browser/server.ts',
    url: 'http://127.0.0.1:4173/api/health',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
