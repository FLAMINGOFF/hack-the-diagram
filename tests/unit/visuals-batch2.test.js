import { describe, expect, it } from 'vitest';
import * as b from '../../src/visuals/batch2.js';

describe('XXE parser', () => {
  const out = (id, d) => b.parseXxe(id, d).outcome;
  it('the default parser falls to every entity payload', () => {
    for (const id of ['file', 'ssrf', 'blind', 'xinclude']) expect(out(id, 'none')).toBe('pwned');
  });
  it('disallowing DOCTYPE does not stop XInclude, turning XInclude off does', () => {
    for (const id of ['file', 'ssrf', 'blind']) expect(out(id, 'nodtd')).toBe('blocked');
    expect(out('xinclude', 'nodtd')).toBe('pwned');
    expect(out('xinclude', 'both')).toBe('blocked');
  });
  it('blind XXE leaks out of band, not in the response', () => {
    const r = b.parseXxe('blind', 'none');
    expect(r.response).not.toContain('shop-web-01');
    expect(r.oob.join(' ')).toContain('shop-web-01');
  });
  it('a normal request is untouched by any setting', () => {
    for (const d of Object.keys(b.XXE_DEFENCES)) expect(out('normal', d)).toBe('normal');
  });
});

describe('NoSQL login', () => {
  const login = (id, d) => b.nosqlLogin(b.NOSQL_PRESETS.find((p) => p.id === id).body, d);
  it('operators log in without a password', () => {
    expect(login('ne', 'none').login).toBe('admin');
    expect(login('regex', 'none').login).toBe('carlos');
    expect(login('gt', 'none').login).toBe('admin');
    expect(login('ne', 'none').injected).toBe(true);
  });
  it('plain strings behave like a normal login', () => {
    expect(login('normal', 'none').login).toBe('wiener');
    expect(login('normal', 'none').injected).toBe(false);
    expect(login('wrong', 'none').login).toBe(null);
  });
  it('requiring strings stops every operator but not a real login', () => {
    for (const id of ['ne', 'regex', 'gt']) expect(login(id, 'cast').error).toBeTruthy();
    expect(login('normal', 'cast').login).toBe('wiener');
  });
  it('bad JSON is reported, not thrown', () => {
    expect(b.nosqlLogin('{', 'none').error).toBeTruthy();
  });
});

describe('mass assignment', () => {
  it('copying the whole body escalates, an allowlist does not', () => {
    for (const p of b.MA_PRESETS.filter((x) => x.id !== 'normal')) {
      expect(b.massAssign(p.body, 'spread').escalated).toBe(true);
      expect(b.massAssign(p.body, 'allow').escalated).toBe(false);
    }
    expect(b.massAssign('{"isAdmin":true}', 'spread').after.isAdmin).toBe(true);
    expect(b.massAssign('{"email":"a@b.c"}', 'allow').after.email).toBe('a@b.c');
  });
});

describe('checkout logic', () => {
  const none = { qty: false, price: false, coupon: false };
  it('every attack fits the $100 credit when nothing is checked', () => {
    for (const a of ['negative', 'price', 'coupons']) {
      const r = b.checkout(a, none);
      expect(r.cheated).toBe(true);
      expect(r.total).toBeGreaterThanOrEqual(0);
      expect(r.total).toBeLessThanOrEqual(b.CREDIT);
    }
    expect(b.checkout('normal', none).ok).toBe(false);
  });
  it('each check closes exactly its own hole', () => {
    expect(b.checkout('negative', { ...none, qty: true }).cheated).toBe(false);
    expect(b.checkout('price', { ...none, price: true }).cheated).toBe(false);
    expect(b.checkout('coupons', { ...none, coupon: true }).cheated).toBe(false);
    expect(b.checkout('negative', { ...none, price: true, coupon: true }).cheated).toBe(true);
    expect(b.checkout('price', { ...none, qty: true, coupon: true }).cheated).toBe(true);
  });
});

describe('information disclosure', () => {
  it('debug settings leak on every probe, production on none', () => {
    expect(b.recon('dev').every((p) => p.loot)).toBe(true);
    expect(b.recon('prod').some((p) => p.loot)).toBe(false);
  });
});

describe('web cache deception', () => {
  const out = (id, o, c) => b.deception(id, o, c).outcome;
  it('needs both a lenient origin and an extension-based cache', () => {
    for (const id of ['mapping', 'semi', 'enc']) {
      expect(out(id, 'loose', 'ext')).toBe('pwned');
      expect(out(id, 'strict', 'ext')).toBe('blocked');
      expect(out(id, 'loose', 'respect')).toBe('blocked');
    }
  });
  it('the plain account URL is never cached', () => {
    expect(out('normal', 'loose', 'ext')).toBe('normal');
  });
});
