import { defineConfig, devices } from '@playwright/test';

/**
 * Every browser test runs against the PRODUCTION build served by `vite preview`,
 * so what passes here is what ships. Two projects:
 *   - a11y   : e2e/a11y.spec.ts, the WCAG A/AA gate (template §4).
 *   - claims : e2e/claims.spec.ts, what the page SAYS, recomputed (template §4.1b,
 *              §4.1d), plus the verdict-marker sink that the global teardown
 *              audits against e2e/verdict-mutations.json (§4.1c).
 *
 * Port 4239 was assigned by the catalog's `node tools/port-sync.js` on
 * 2026-11-15 (never the Vite default 4173, and `--strictPort` so a collision
 * fails loudly instead of silently testing another lab's preview).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 120_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: 'http://localhost:4239/crypto-lab-subverted-cipher/',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'claims',
      testMatch: /claims\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
  ],
  webServer: {
    // Build BEFORE serving. `vite preview` serves whatever is already in dist/,
    // so without the build in front a failing build would leave the previous
    // good bundle in place and the suite would pass green against source that
    // no longer compiles -- which also silently invalidates mutation checking.
    command: 'npm run build && npm run preview -- --port 4239 --strictPort',
    url: 'http://localhost:4239/crypto-lab-subverted-cipher/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
