import { configDefaults, defineConfig } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-subverted-cipher/
export default defineConfig({
  base: '/crypto-lab-subverted-cipher/',
  test: {
    // Colocated unit tests only; the Playwright specs in e2e/ must not be
    // collected as unit tests (template §1).
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
    // The statistics suite runs ~150k real HMAC calls; it is tagged [slow] in
    // its names and runs in every CI run rather than being skipped.
    testTimeout: 120_000,
  },
});
