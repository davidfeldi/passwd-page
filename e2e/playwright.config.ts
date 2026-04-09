import { defineConfig } from '@playwright/test';

const testDbPath = `/tmp/passwd-test-${Date.now()}.db`;

export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  retries: 0,
  use: {
    baseURL: 'http://localhost:9876',
    headless: true,
  },
  webServer: {
    command: `../passwd-page -port 9876 -db ${testDbPath}`,
    url: 'http://localhost:9876/health',
    timeout: 15000,
    reuseExistingServer: true,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
