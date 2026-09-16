import { defineConfig, devices } from '@playwright/test';

// Flows F1–F7 run against the dev stack and the Express example, at phone and desktop sizes,
// in light and dark (REQ-076, REQ-133). `pnpm e2e` starts both from the repo root.

const EXAMPLE_URL = process.env.EXAMPLE_URL ?? 'http://localhost:4000';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: EXAMPLE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    // Chromium at phone size: real iOS Safari is on the manual QA list (Test Strategy).
    { name: 'phone-dark', use: { ...devices['Pixel 7'], colorScheme: 'dark' } },
    { name: 'desktop-light', use: { ...devices['Desktop Chrome'], colorScheme: 'light' } },
  ],
  // Set E2E_NO_SERVER when the example app is already running.
  ...(process.env.E2E_NO_SERVER
    ? {}
    : {
        webServer: {
          command: 'pnpm --filter d3auth-express start',
          url: EXAMPLE_URL,
          cwd: '..',
          reuseExistingServer: !process.env.CI,
          timeout: 60_000,
        },
      }),
});
