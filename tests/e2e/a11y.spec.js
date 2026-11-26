import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { TOPICS } from '../../src/topics/registry.js';

// Automated WCAG 2.1 A/AA checks with axe-core, in both colour schemes.
const PAGES = ['', '#/start', ...TOPICS.map((t) => `#/${t.id}`)];

for (const scheme of ['light', 'dark']) {
  test.describe(scheme, () => {
    test.use({ colorScheme: scheme });
    for (const path of PAGES) {
      test(`no axe violations: /${path || 'home'}`, async ({ page }) => {
        await page.goto(`./${path}`);
        await page.locator('h1').first().waitFor();
        if (path.startsWith('#/') && path !== '#/start') await page.locator('.challenge').first().waitFor();
        const { violations } = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
        const summary = violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length}× e.g. ${v.nodes[0].target.join(' ')}`);
        expect(summary).toEqual([]);
      });
    }
  });
}
