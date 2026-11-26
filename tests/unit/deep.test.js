import { describe, expect, it } from 'vitest';
import { DEEP } from '../../src/topics/deep/index.js';
import { TOPICS } from '../../src/topics/registry.js';
import { solutionFor } from './solutions.js';

const defaults = (fields) => Object.fromEntries(fields.map((f) => [f.id, f.default ?? '']));

/** Every {en, zh} pair in a tree of data, with the path that leads to it. */
function* pairs(node, path = '') {
  if (!node || typeof node !== 'object') return;
  if ('en' in node || 'zh' in node) yield [path, node];
  for (const [k, v] of Object.entries(node)) if (typeof v === 'object') yield* pairs(v, `${path}.${k}`);
}

describe('deep-dive data', () => {
  it('covers every topic in the catalogue', () => {
    const missing = TOPICS.map((t) => t.id).filter((id) => !DEEP[id]);
    expect(missing).toEqual([]);
  });

  it('has English and Chinese text everywhere', () => {
    const bad = [];
    for (const [id, d] of Object.entries(DEEP))
      for (const [p, v] of pairs(d, id)) if (typeof v.en !== 'string' || !v.en.trim() || typeof v.zh !== 'string' || !v.zh.trim()) bad.push(p);
    expect(bad).toEqual([]);
  });
});

for (const [id, d] of Object.entries(DEEP)) {
  describe(id, () => {
    it('has 3+ variants and 2+ challenges with unique variant ids', () => {
      expect(d.variants.length).toBeGreaterThanOrEqual(3);
      expect(d.challenges.length).toBeGreaterThanOrEqual(2);
      expect(new Set(d.variants.map((v) => v.id)).size).toBe(d.variants.length);
    });

    for (const v of d.variants) {
      it(`variant "${v.id}": every preset gives a verdict, and the defence always holds`, () => {
        const base = defaults(v.lab.fields);
        for (const p of [{ values: {} }, ...(v.lab.presets || [])]) {
          const values = { ...base, ...p.values };
          const open = v.lab.run({ values, defended: false });
          const shut = v.lab.run({ values, defended: true });
          expect(open.verdict, JSON.stringify(values)).toMatch(/^(good|bad|neutral)$/);
          expect(shut.verdict, JSON.stringify(values)).not.toBe('bad');
        }
      });
      it(`variant "${v.id}": at least one preset shows the attack working`, () => {
        const base = defaults(v.lab.fields);
        const hits = (v.lab.presets || []).filter((p) => v.lab.run({ values: { ...base, ...p.values }, defended: false }).verdict === 'bad');
        expect(hits.length).toBeGreaterThan(0);
      });
    }

    d.challenges.forEach((ch, i) => {
      const n = i + 1;
      it(`challenge ${n}: the starting input does not pass`, () => {
        const init = defaults(ch.fields);
        expect(ch.check(init, ch.run(init))).toBeFalsy();
      });
      it(`challenge ${n}: the published solution passes`, () => {
        const vals = solutionFor(id, n, ch);
        const out = ch.run(vals);
        expect(ch.check(vals, out), JSON.stringify(out.response)).toBe(true);
      });
    });

    it('cases have a year, a title, a story and a lesson', () => {
      for (const c of d.cases || []) {
        expect(String(c.year)).toMatch(/^(19|20)\d\d/);
        expect(c.title && c.what && c.lesson).toBeTruthy();
        if (typeof c.ref === 'string' && c.ref.startsWith('CVE-')) expect(c.ref).toMatch(/^CVE-\d{4}-\d{4,}$/);
      }
    });
  });
}
