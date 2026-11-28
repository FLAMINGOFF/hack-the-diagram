import { describe, expect, it } from 'vitest';
import { CHEATSHEET } from '../../src/topics/cheatsheet.js';
import { TOPICS } from '../../src/topics/registry.js';

describe('cheat sheet', () => {
  it('has exactly one entry per topic', () => {
    expect(CHEATSHEET.map((e) => e.id).sort()).toEqual(TOPICS.map((t) => t.id).sort());
  });
  it('every entry has bilingual text and at least three things to try', () => {
    for (const e of CHEATSHEET) {
      for (const f of [e.spot, e.fix]) expect(f.en.trim() && f.zh.trim(), e.id).toBeTruthy();
      expect(e.payloads.length, e.id).toBeGreaterThanOrEqual(3);
    }
  });
});
