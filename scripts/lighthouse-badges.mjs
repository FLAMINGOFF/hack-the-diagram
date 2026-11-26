// Turn the Lighthouse CI results into shields.io "endpoint" badges, written into dist/badges/
// so they are deployed with the site. Each badge shows the lowest score across the audited URLs.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const runs = JSON.parse(readFileSync('.lighthouseci/manifest.json', 'utf8')).filter((r) => r.isRepresentativeRun);
if (!runs.length) throw new Error('No Lighthouse results found. Run `npx lhci autorun` first.');

const CATS = { performance: 'performance', accessibility: 'accessibility', 'best-practices': 'best practices', seo: 'SEO' };
const color = (s) => (s >= 90 ? 'brightgreen' : s >= 50 ? 'orange' : 'red');

// Log the key metrics per page so a low score can be diagnosed from the CI log alone.
for (const r of runs) {
  const a = JSON.parse(readFileSync(r.jsonPath, 'utf8')).audits;
  const m = ['first-contentful-paint', 'largest-contentful-paint', 'total-blocking-time', 'cumulative-layout-shift', 'speed-index'].map((k) => `${k.split('-').map((w) => w[0]).join('').toUpperCase()} ${a[k].displayValue}`);
  console.log(`${r.url}  ${m.join('  ')}`);
  for (const it of a['layout-shifts']?.details?.items || []) console.log(`  layout shift ${it.score?.toFixed(3)}: ${it.node?.snippet ?? 'unknown element'}`);
}

mkdirSync('dist/badges', { recursive: true });
for (const [key, label] of Object.entries(CATS)) {
  const score = Math.round(Math.min(...runs.map((r) => r.summary[key])) * 100);
  writeFileSync(`dist/badges/lighthouse-${key}.json`, JSON.stringify({ schemaVersion: 1, label: `lighthouse ${label}`, message: String(score), color: color(score) }));
  console.log(`${label}: ${score}`);
}
