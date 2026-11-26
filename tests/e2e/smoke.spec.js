import { expect, test } from '@playwright/test';
import { TOPICS } from '../../src/topics/registry.js';

/** Fail the test on any uncaught error in the page. */
function watchErrors(page) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  return errors;
}

test('home page lists every topic and search filters them', async ({ page }) => {
  const errors = watchErrors(page);
  await page.goto('./');
  await expect(page.locator('a.card')).toHaveCount(TOPICS.length);
  await page.getByRole('searchbox').fill('jwt');
  await expect(page.locator('a.card')).toHaveCount(1);
  expect(errors).toEqual([]);
});

test('language toggle switches the interface to Chinese', async ({ page }) => {
  await page.goto('./');
  await page.getByRole('group', { name: 'Language' }).getByRole('button', { name: '中文' }).click();
  await expect(page.getByRole('searchbox')).toHaveAttribute('placeholder', /搜索主题/);
});

for (const t of TOPICS) {
  test(`topic page renders: ${t.id}`, async ({ page }) => {
    const errors = watchErrors(page);
    await page.goto(`./#/${t.id}`);
    await expect(page.locator('h1')).toBeVisible();
    await expect(page.locator('.challenge').first()).toBeVisible();
    const width = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(width).toBeLessThanOrEqual(0);
    expect(errors).toEqual([]);
  });
}

test('solving a challenge is remembered on the guide page', async ({ page }) => {
  await page.goto('./#/ssrf');
  const card = page.locator('.challenge').first();
  await card.getByRole('button', { name: 'Hint' }).click();
  await card.getByRole('button', { name: 'Show solution' }).click();
  const solution = await card.locator('.hint code').textContent();
  await card.locator('input').first().fill(solution);
  await card.getByRole('button', { name: 'Send' }).click();
  await expect(card.locator('.unlock')).toBeVisible();
  await page.goto('./#/start');
  await expect(page.locator('.challenge-bar')).toHaveAttribute('aria-valuenow', '1');
});

test('keyboard users can skip straight to the content', async ({ page }) => {
  await page.goto('./#/xss');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Skip to content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('main')).toBeFocused();
});
