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

test('cheat sheet lists every topic and filters by category', async ({ page }) => {
  await page.goto('./#/cheatsheet');
  await expect(page.locator('.cs-card')).toHaveCount(TOPICS.length);
  await page.getByRole('button', { name: 'Foundations' }).click();
  await expect(page.locator('.cs-card')).toHaveCount(TOPICS.filter((t) => t.category === 'foundations').length);
});

test('SSRF map: an open redirect beats a host allowlist', async ({ page }) => {
  await page.goto('./#/ssrf');
  const viz = page.locator('.ssrf-viz');
  await viz.getByRole('radio', { name: 'Host allowlist' }).click();
  await viz.getByRole('button', { name: 'Bypass: open redirect' }).click();
  await viz.getByRole('button', { name: 'Send' }).click();
  await expect(viz.locator('.verdict.bad')).toBeVisible({ timeout: 8000 });
});

test('JWT inspector: alg none is accepted by the naive server only', async ({ page }) => {
  await page.goto('./#/jwt');
  const viz = page.locator('.jwt-viz');
  await viz.getByRole('button', { name: 'alg: none' }).click();
  await viz.getByRole('button', { name: 'Send token' }).click();
  await expect(viz.locator('.verdict.bad')).toContainText('admin', { timeout: 8000 });
  await viz.getByRole('radio', { name: 'Hardened server' }).click();
  await viz.getByRole('button', { name: 'alg: none' }).click();
  await viz.getByRole('button', { name: 'Send token' }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('smuggling stream: CL.TE leaves bytes that poison the victim request', async ({ page }) => {
  await page.goto('./#/smuggling');
  const viz = page.locator('.smug-viz');
  for (let i = 0; i < 4; i++) await viz.getByRole('button', { name: /Next/ }).click();
  await expect(viz.locator('.narration')).toContainText('victim-8f3a');
});

test('every topic has a share page with its own title', async ({ request }) => {
  const res = await request.get('./t/jwt/');
  expect(res.ok()).toBe(true);
  const html = await res.text();
  expect(html).toContain('<meta property="og:title" content="JWT Attacks · Hack the Diagram">');
  expect(html).toContain('#/jwt');
});
