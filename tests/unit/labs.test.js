import { describe, expect, it } from 'vitest';
import { SERVER } from '../../src/topics/content/server.js';
import { CLIENT } from '../../src/topics/content/client.jsx';
import { ADVANCED } from '../../src/topics/content/advanced.js';

const DEFS = { ...SERVER, ...CLIENT, ...ADVANCED };

describe('main topic labs', () => {
  for (const [id, def] of Object.entries(DEFS)) {
    if (!def.lab) continue;
    it(`${id}: presets give a verdict and the fixed version never fails`, () => {
      const base = Object.fromEntries(def.lab.fields.map((f) => [f.id, f.default ?? '']));
      for (const p of [{ values: {} }, ...(def.lab.presets || [])]) {
        const values = { ...base, ...p.values };
        expect(def.lab.run({ values, defended: false }).verdict).toMatch(/^(good|bad|neutral)$/);
        expect(def.lab.run({ values, defended: true }).verdict).not.toBe('bad');
      }
    });
  }
});
