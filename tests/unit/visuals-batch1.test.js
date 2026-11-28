import { describe, expect, it } from 'vitest';
import * as b from '../../src/visuals/batch1.js';

const pt = (id, d) => b.walkPath(b.PT_PRESETS.find((p) => p.id === id).value, d);
const leaks = (r) => !r.blocked && !!r.content && r.escaped;

describe('path traversal walk', () => {
  it('a plain filename stays in the images folder', () => {
    const r = pt('ok', 'none');
    expect(r.full).toBe('/var/www/images/1.jpg');
    expect(r.escaped).toBe(false);
  });
  it('each defence falls to the bypass it is known for', () => {
    expect(leaks(pt('up', 'none'))).toBe(true);
    expect(leaks(pt('abs', 'none'))).toBe(true);
    expect(leaks(pt('up', 'strip'))).toBe(false);
    expect(leaks(pt('nest', 'strip'))).toBe(true);
    expect(pt('up', 'reject').blocked).toBe(true);
    expect(leaks(pt('enc', 'reject'))).toBe(true);
  });
  it('resolving before the prefix check stops every preset', () => {
    for (const p of b.PT_PRESETS) expect(leaks(b.walkPath(p.value, 'canon'))).toBe(false);
    expect(b.walkPath('../../../etc/passwd', 'canon').blocked).toBe(true);
  });
  it('each ".." climbs exactly one folder', () => {
    const r = pt('up', 'none');
    expect(r.steps.map((s) => s.at.length)).toEqual([3, 2, 1, 0, 1, 2]);
  });
});

describe('shell parsing', () => {
  const ran = (id, d) => b.runShell(b.SH_PRESETS.find((p) => p.id === id).value, d).parts.filter((p) => p.ran && p.injected).length;
  it('the benign host runs only ping', () => {
    expect(ran('ok', 'shell')).toBe(0);
  });
  it('every operator injects when a shell is used', () => {
    for (const id of ['semi', 'and', 'or', 'sub', 'pipe']) expect(ran(id, 'shell')).toBeGreaterThan(0);
  });
  it('&& and || respect the exit status', () => {
    expect(b.runShell('nohost && whoami', 'shell').parts[1].ran).toBe(false);
    expect(b.runShell('nohost || id', 'shell').parts[1].ran).toBe(true);
  });
  it('double quotes stop operators but not command substitution', () => {
    expect(ran('semi', 'quoted')).toBe(0);
    expect(ran('sub', 'quoted')).toBeGreaterThan(0);
  });
  it('no shell means nothing is injected', () => {
    for (const p of b.SH_PRESETS) expect(b.runShell(p.value, 'argv').parts).toHaveLength(1);
    expect(ran('sub', 'argv')).toBe(0);
  });
});

describe('IDOR', () => {
  it('without an owner check, every other invoice leaks', () => {
    const rows = b.invoiceRows();
    const leaked = rows.filter((r) => b.fetchInvoice(r.id, 'none').leak).length;
    expect(leaked).toBe(rows.filter((r) => r.owner !== 'alice').length);
  });
  it('with an owner check, only alice’s invoices come back', () => {
    for (const r of b.invoiceRows()) expect(b.fetchInvoice(r.id, 'owner').status).toBe(r.owner === 'alice' ? 200 : 403);
    expect(b.fetchInvoice(9999, 'owner').status).toBe(404);
  });
});

describe('username enumeration and brute force', () => {
  const view = (mode) => b.CANDIDATES.map((n, i) => b.tryUser(n, mode, i));
  it('verbose errors give the user away by message', () => {
    expect(new Set(view('verbose').map((r) => r.msg.en)).size).toBe(2);
  });
  it('timing gives the user away even with one message', () => {
    const v = view('timing');
    expect(new Set(v.map((r) => r.msg.en)).size).toBe(1);
    const realMin = Math.min(...v.filter((r) => r.real).map((r) => r.ms));
    const fakeMax = Math.max(...v.filter((r) => !r.real).map((r) => r.ms));
    expect(realMin).toBeGreaterThan(fakeMax);
  });
  it('the hardened form looks the same for every user', () => {
    const v = view('hardened');
    expect(new Set(v.map((r) => r.msg.en)).size).toBe(1);
    expect(Math.max(...v.map((r) => r.ms)) - Math.min(...v.map((r) => r.ms))).toBeLessThan(10);
  });
  it('lockout stops the guess before the seventh password', () => {
    expect(b.bruteForce('carlos', false).at(-1).result).toBe('ok');
    expect(b.bruteForce('carlos', true).some((t) => t.result === 'ok')).toBe(false);
  });
});

describe('race condition', () => {
  it('more overlap means more coupons applied', () => {
    expect(b.raceRun(10, 'sequential', false).applied).toBe(1);
    expect(b.raceRun(10, 'parallel', false).applied).toBeGreaterThan(1);
    expect(b.raceRun(10, 'packet', false).applied).toBe(10);
  });
  it('an atomic update applies once whatever the timing', () => {
    for (const m of Object.keys(b.RACE_MODES)) expect(b.raceRun(10, m, true).applied).toBe(1);
  });
});

describe('file upload gates', () => {
  const all = { block: false, ctype: false, magic: false, allow: false, store: false };
  const runs = (id, g) => !!b.upload(b.FILES.find((f) => f.id === id), { ...all, ...g }).runs;
  it('no checks: a PHP file runs', () => {
    expect(runs('php', {})).toBe(true);
    expect(runs('png', {})).toBe(false);
  });
  it('blocklist and Content-Type checks are bypassed', () => {
    expect(runs('php', { block: true })).toBe(false);
    expect(runs('case', { block: true, ctype: true })).toBe(true);
    expect(runs('poly', { block: true, ctype: true, magic: true })).toBe(true);
  });
  it('the double extension does not run on this server', () => {
    expect(runs('dbl', {})).toBe(false);
  });
  it('an allowlist or random-name storage stops execution', () => {
    for (const f of b.FILES) {
      expect(runs(f.id, { allow: true })).toBe(false);
      expect(runs(f.id, { store: true })).toBe(false);
    }
  });
});
