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

test('theme toggle switches and is remembered after reload', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('./');
  await page.getByRole('button', { name: 'Switch to dark mode' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.getByRole('button', { name: 'Switch to light mode' })).toBeVisible();
});

test('phone menu fits on one row and holds the main links', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  await page.goto('./#/xss');
  expect(await page.locator('.nav').evaluate((e) => e.offsetHeight)).toBeLessThan(64);
  await page.locator('.topic-menu summary').click();
  await page.locator('.menu-quick').getByRole('link', { name: 'Cheat sheet' }).click();
  await expect(page.locator('h1')).toHaveText('Cheat sheet');
});

test('CORS gate: a prefix check leaks to a look-alike domain', async ({ page }) => {
  await page.goto('./#/cors');
  const viz = page.locator('.cors-viz');
  await viz.getByRole('radio', { name: 'Prefix check' }).click();
  await viz.getByRole('button', { name: 'bank.example.evil.example' }).click();
  await viz.getByRole('button', { name: 'Run the script' }).click();
  await expect(viz.locator('.verdict.bad')).toBeVisible({ timeout: 8000 });
});

test('OAuth flow: exact redirect_uri matching blocks the stolen code', async ({ page }) => {
  await page.goto('./#/oauth');
  const viz = page.locator('.oauth-viz');
  await viz.getByText('Exact redirect_uri match').click();
  for (let i = 0; i < 3; i++) await viz.getByRole('button', { name: /Next/ }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible();
});

test('clickjacking layers: the click lands on the framed bank page', async ({ page }) => {
  await page.goto('./#/clickjacking');
  const viz = page.locator('.cj3-viz');
  await viz.getByRole('button', { name: 'Play the click' }).click();
  await expect(viz.locator('.verdict.bad')).toBeVisible({ timeout: 6000 });
});

test('path traversal: nested ../ beats a one-pass strip, resolving stops it', async ({ page }) => {
  await page.goto('./#/path-traversal');
  const viz = page.locator('.pt-viz');
  await viz.getByRole('radio', { name: 'Strip "../" once' }).click();
  await viz.getByRole('button', { name: '....//....//....//etc/passwd' }).click();
  await viz.getByRole('button', { name: 'Read file' }).click();
  await expect(viz.locator('.verdict.bad')).toContainText('/etc/passwd', { timeout: 8000 });
  await viz.getByRole('radio', { name: 'Resolve, then check the prefix' }).click();
  await viz.getByRole('button', { name: '../../../etc/passwd', exact: true }).click();
  await viz.getByRole('button', { name: 'Read file' }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('command injection: argv removes the shell', async ({ page }) => {
  await page.goto('./#/cmdi');
  const viz = page.locator('.sh-viz');
  await viz.getByRole('button', { name: 'Run it' }).click();
  await expect(viz.locator('.verdict.bad')).toBeVisible({ timeout: 8000 });
  await expect(viz.locator('.sh-out').last()).toHaveText('www-data');
  await viz.getByRole('radio', { name: /execFile/ }).click();
  await viz.getByRole('button', { name: 'Run it' }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('IDOR grid: scanning leaks invoices until the owner is checked', async ({ page }) => {
  await page.goto('./#/access-control');
  const viz = page.locator('.idor-viz');
  await viz.getByRole('button', { name: /^Scan/ }).click();
  await expect(viz.locator('.verdict.bad')).toContainText('10 other', { timeout: 8000 });
  await viz.getByRole('radio', { name: 'Checks invoice.owner' }).click();
  await viz.getByRole('button', { name: /^Scan/ }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('auth timing: the slow reply gives carlos away, lockout stops the guess', async ({ page }) => {
  await page.goto('./#/auth');
  const viz = page.locator('.auth-viz');
  await viz.getByRole('radio', { name: 'Same message, different timing' }).click();
  await viz.getByRole('button', { name: 'Try 8 usernames' }).click();
  await expect(viz.locator('.verdict.bad').first()).toContainText('carlos', { timeout: 8000 });
  await viz.getByText('Lock the account after 5 failures').click();
  await viz.getByRole('button', { name: 'Guess passwords' }).click();
  await expect(viz.locator('.verdict.good')).toContainText('Locked out', { timeout: 8000 });
});

test('race lanes: a single-packet attack applies the coupon every time', async ({ page }) => {
  await page.goto('./#/race');
  const viz = page.locator('.race-viz');
  await viz.getByRole('radio', { name: 'Single-packet attack' }).click();
  await viz.getByRole('button', { name: 'Send 10 requests' }).click();
  await expect(viz.locator('.verdict.bad')).toContainText('Applied 10 times', { timeout: 8000 });
});

test('file upload: a polyglot gets past the signature check', async ({ page }) => {
  await page.goto('./#/file-upload');
  const viz = page.locator('.up-viz');
  await viz.getByRole('button', { name: 'GIF89a + PHP (polyglot)' }).click();
  await viz.getByText('First bytes must be an image signature').click();
  await viz.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(viz.locator('.verdict.bad')).toContainText('web shell', { timeout: 8000 });
  await viz.getByText('Allowlist: .jpg .png .gif (any case)').click();
  await viz.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('XXE: disallowing DOCTYPE leaves XInclude open', async ({ page }) => {
  await page.goto('./#/xxe');
  const viz = page.locator('.xxe-viz');
  await viz.getByRole('button', { name: 'Send' }).click();
  await expect(viz.locator('.verdict.bad')).toBeVisible({ timeout: 8000 });
  await viz.getByRole('radio', { name: 'DOCTYPE disallowed', exact: true }).click();
  await viz.getByRole('button', { name: 'XInclude' }).click();
  await viz.getByRole('button', { name: 'Send' }).click();
  await expect(viz.locator('.verdict.bad')).toBeVisible({ timeout: 8000 });
});

test('NoSQL: $ne logs in as admin until fields must be strings', async ({ page }) => {
  await page.goto('./#/nosqli');
  const viz = page.locator('.nosql-viz');
  await viz.getByRole('button', { name: 'Log in' }).click();
  await expect(viz.locator('.verdict.bad')).toContainText('admin', { timeout: 8000 });
  await viz.getByRole('radio', { name: 'Both fields must be strings' }).click();
  await viz.getByRole('button', { name: 'Log in' }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('mass assignment: isAdmin lands on the record', async ({ page }) => {
  await page.goto('./#/api');
  const viz = page.locator('.ma-viz');
  await viz.getByRole('button', { name: 'Send PATCH' }).click();
  await expect(viz.locator('.ma-field.priv')).toContainText('isAdmin', { timeout: 8000 });
});

test('business logic: a negative quantity fits the credit', async ({ page }) => {
  await page.goto('./#/logic');
  const viz = page.locator('.logic-viz');
  await viz.getByRole('button', { name: 'Check out' }).click();
  await expect(viz.locator('.verdict.bad')).toContainText('$90.21', { timeout: 8000 });
  await viz.getByText('Quantity must be 1 or more').click();
  await viz.getByRole('button', { name: 'Check out' }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('information disclosure: production settings leak nothing', async ({ page }) => {
  await page.goto('./#/info-disclosure');
  const viz = page.locator('.info-viz');
  await viz.getByRole('radio', { name: 'Production settings' }).click();
  await viz.getByRole('button', { name: 'Run recon' }).click();
  await expect(viz.locator('.verdict.good')).toBeVisible({ timeout: 8000 });
});

test('cache deception: the cache serves the victim page to the attacker', async ({ page }) => {
  await page.goto('./#/cache-deception');
  const viz = page.locator('.cd-viz');
  for (let i = 0; i < 9; i++) {
    const next = viz.getByRole('button', { name: /Next/ });
    if (await next.isDisabled()) break;
    await next.click();
  }
  await expect(viz.locator('.verdict.bad')).toBeVisible();
});
