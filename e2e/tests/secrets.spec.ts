import { test, expect } from '@playwright/test';

test.describe('passwd.page E2E', () => {

  test('Create and reveal secret', async ({ page }) => {
    await page.goto('/');

    // Fill in the secret
    await page.locator('#secret-input').fill('test-password-123');

    // Select 1 hour expiry (already default, but be explicit)
    await page.locator('#expiry-select').selectOption('1h');

    // Ensure burn-after-read is checked (default is true)
    const burnCheckbox = page.locator('.toggle-input');
    if (!(await burnCheckbox.isChecked())) {
      await burnCheckbox.check();
    }

    // Click create
    await page.getByRole('button', { name: 'Create Secret Link' }).click();

    // Wait for result URL to appear
    const resultInput = page.locator('#result-url');
    await expect(resultInput).toBeVisible({ timeout: 10000 });

    // Extract the generated URL
    const secretUrl = await resultInput.inputValue();
    expect(secretUrl).toContain('/s/');
    expect(secretUrl).toContain('#');

    // Navigate to the secret URL
    const urlObj = new URL(secretUrl);
    const pathWithHash = urlObj.pathname + urlObj.hash;
    await page.goto(pathWithHash);

    // Click Reveal Secret
    await page.getByRole('button', { name: 'Reveal Secret' }).click();

    // Verify the revealed text
    const secretText = page.locator('.secret-text');
    await expect(secretText).toBeVisible({ timeout: 10000 });
    await expect(secretText).toHaveText('test-password-123');
  });

  test('Burn after read', async ({ page }) => {
    // Create a secret with burn-after-read ON
    await page.goto('/');
    await page.locator('#secret-input').fill('burn-me-secret');
    await page.locator('#expiry-select').selectOption('1h');

    const burnCheckbox = page.locator('.toggle-input');
    if (!(await burnCheckbox.isChecked())) {
      await burnCheckbox.check();
    }

    await page.getByRole('button', { name: 'Create Secret Link' }).click();

    const resultInput = page.locator('#result-url');
    await expect(resultInput).toBeVisible({ timeout: 10000 });
    const secretUrl = await resultInput.inputValue();

    // Parse path+hash for navigation
    const urlObj = new URL(secretUrl);
    const pathWithHash = urlObj.pathname + urlObj.hash;

    // First visit: reveal the secret
    await page.goto(pathWithHash);
    await page.getByRole('button', { name: 'Reveal Secret' }).click();
    await expect(page.locator('.secret-text')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.secret-text')).toHaveText('burn-me-secret');

    // Second visit: navigate away first, then back (SPA won't re-render same URL)
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.goto(pathWithHash);
    await page.getByRole('button', { name: 'Reveal Secret' }).click();

    // Should show error state (not found since it was burned)
    const errorState = page.locator('.error-state');
    await expect(errorState).toBeVisible({ timeout: 10000 });
    // Verify error is displayed (could be "not found" or "no longer exists")
    await expect(errorState).toContainText(/not found|no longer exists|not available/i);
  });

  test('Secret not found', async ({ page }) => {
    // Use a valid-looking 32-char hex ID that doesn't exist
    // We need a proper base64url key for base64urlToKey to succeed
    // Generate a fake but valid-format key (32 bytes = 43 chars base64url)
    const fakeKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    await page.goto(`/s/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#${fakeKey}`);

    await page.getByRole('button', { name: 'Reveal Secret' }).click();

    // Should show error (secret doesn't exist)
    const errorState = page.locator('.error-state');
    await expect(errorState).toBeVisible({ timeout: 10000 });
    await expect(errorState).toContainText(/not found|no longer exists/i);
  });

  test('Missing key in URL', async ({ page }) => {
    await page.goto('/s/someid');

    // With no hash fragment, clicking reveal should show invalid-link error
    await page.getByRole('button', { name: 'Reveal Secret' }).click();

    const errorTitle = page.locator('.error-title');
    await expect(errorTitle).toBeVisible({ timeout: 10000 });
    await expect(errorTitle).toHaveText('Invalid link');
  });

});
