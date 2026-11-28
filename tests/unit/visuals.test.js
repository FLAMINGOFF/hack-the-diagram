import { describe, expect, it } from 'vitest';
import * as ssrf from '../../src/visuals/ssrf.js';
import * as jwt from '../../src/visuals/jwt.js';
import * as sm from '../../src/visuals/smuggling.js';

describe('SSRF map', () => {
  it('normalises IPv4 shorthand the way URL parsers do', () => {
    expect(ssrf.resolve('http://127.1/').ip).toBe('127.0.0.1');
    expect(ssrf.resolve('http://2852039166/').ip).toBe('169.254.169.254');
    expect(ssrf.resolve('http://[::1]/').ip).toBe('127.0.0.1');
  });
  const outcome = (label, d) => ssrf.simulate(ssrf.PRESETS.find((p) => (p.label.en ?? p.label) === label).url, d).outcome;
  it('each defence stops what it should and nothing more', () => {
    expect(outcome('Normal stock check', 'allowlist')).toBe('normal');
    expect(outcome('Cloud metadata', 'none')).toBe('pwned');
    expect(outcome('Cloud metadata', 'blocklist')).toBe('blocked');
    expect(outcome('Bypass: decimal IP', 'blocklist')).toBe('pwned');
    expect(outcome('Bypass: 127.1', 'blocklist')).toBe('pwned');
    expect(outcome('Bypass: 127.1', 'hostallow')).toBe('blocked');
    expect(outcome('Bypass: open redirect', 'hostallow')).toBe('pwned');
    for (const p of ssrf.PRESETS) expect(ssrf.simulate(p.url, 'allowlist').outcome).not.toBe('pwned');
  });
});

describe('JWT inspector', () => {
  const H = JSON.stringify(jwt.ISSUED_HEADER);
  const admin = JSON.stringify({ ...jwt.ISSUED_PAYLOAD, role: 'admin' });
  it('base64url round-trips UTF-8', () => {
    expect(jwt.unb64url(jwt.b64urlText('{"n":"王"}'))).toBe('{"n":"王"}');
  });
  it('matches the published HMAC-SHA256 test vector', async () => {
    // HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog") = f7bc83f4…2d1a3cd8
    expect(await jwt.hs256('key', 'The quick brown fox jumps over the lazy dog')).toBe('97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg');
  });
  it('the naive server falls for none, weak keys and kid traversal; the hardened one does not', async () => {
    for (const server of ['naive', 'hardened']) {
      const issued = await jwt.issuedToken(server);
      const forged = {
        tamper: await jwt.makeToken(H, admin, { mode: 'keep', signature: issued.split('.')[2] }),
        none: await jwt.makeToken(JSON.stringify({ ...jwt.ISSUED_HEADER, alg: 'none' }), admin, { mode: 'none' }),
        weak: await jwt.makeToken(H, admin, { mode: 'sign', key: 'secret1' }),
        kid: await jwt.makeToken(JSON.stringify({ ...jwt.ISSUED_HEADER, kid: '../../../../dev/null' }), admin, { mode: 'sign', key: '' }),
      };
      expect((await jwt.verify(issued, server)).ok).toBe(true);
      expect((await jwt.verify(forged.tamper, server)).ok).toBe(false);
      for (const k of ['none', 'weak', 'kid']) expect((await jwt.verify(forged[k], server)).admin ?? false, `${server} ${k}`).toBe(server === 'naive');
    }
  });
  it('cracks the weak key and not the strong one', async () => {
    expect((await jwt.crack(await jwt.issuedToken('naive'))).found).toBe('secret1');
    expect((await jwt.crack(await jwt.issuedToken('hardened'))).found).toBe(null);
  });
});

describe('request smuggling', () => {
  for (const kind of ['clte', 'tecl']) {
    it(`${kind}: lengths are right and the victim request is poisoned`, () => {
      const [f, b] = sm.FRONT_BACK[kind];
      const r = sm.run(sm.build(kind, sm.SMUGGLED[kind]), f, b, false);
      expect(r.f.end).toBe(r.wire.length);
      expect(r.poisoned).toBe(true);
      expect(`${r.method} ${r.path}`).toBe('GET /admin');
    });
    it(`${kind}: servers that agree, or the defence, stop it`, () => {
      const text = sm.build(kind, sm.SMUGGLED[kind]);
      expect(sm.run(text, 'CL', 'CL', false).poisoned).toBe(false);
      expect(sm.run(text, 'TE', 'TE', false).poisoned).toBe(false);
      expect(sm.run(text, ...sm.FRONT_BACK[kind], true).rejected).toBe(true);
    });
  }
  it('CL.TE carries the victim cookie onto the smuggled request', () => {
    expect(sm.run(sm.build('clte', sm.SMUGGLED.clte), 'CL', 'TE', false).cookie).toBe('session=victim-8f3a');
  });
  it('a normal request leaves nothing behind', () => {
    expect(sm.run(sm.build('normal'), 'CL', 'TE', false).poisoned).toBe(false);
  });
});

import * as cors from '../../src/visuals/cors.js';
import * as oauth from '../../src/visuals/oauth.js';

describe('CORS gate', () => {
  const stolen = (config, origin) => cors.run(config, origin).stolen;
  it('follows the browser rules for credentialed requests', () => {
    expect(cors.browserCheck('https://a.example', { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }).ok).toBe(false);
    expect(cors.browserCheck('https://a.example', { 'Access-Control-Allow-Origin': 'https://a.example' }).ok).toBe(false);
    expect(cors.browserCheck('https://a.example', {}).ok).toBe(false);
  });
  it('each broken policy leaks to the origin that abuses it, and the exact allowlist to none', () => {
    expect(stolen('reflect', 'https://evil.example')).toBe(true);
    expect(stolen('prefix', 'https://bank.example.evil.example')).toBe(true);
    expect(stolen('prefix', 'https://evil.example')).toBe(false);
    expect(stolen('null', 'null')).toBe(true);
    for (const o of cors.ORIGINS) expect(stolen('wildcard', o.value) || stolen('exact', o.value)).toBe(false);
    expect(cors.run('exact', 'https://bank.example').legit).toBe(true);
  });
});

describe('OAuth flow', () => {
  const out = (attack, d) => oauth.flow(attack, { exact: false, state: false, pkce: false, ...d }).outcome;
  it('only exact redirect_uri matching stops code theft via redirect_uri', () => {
    expect(out('redirect', {})).toBe('pwned');
    expect(out('redirect', { state: true, pkce: true })).toBe('pwned');
    expect(out('redirect', { exact: true })).toBe('blocked');
  });
  it('state or PKCE stops login CSRF; redirect matching does not', () => {
    expect(out('csrf', {})).toBe('pwned');
    expect(out('csrf', { exact: true })).toBe('pwned');
    expect(out('csrf', { state: true })).toBe('blocked');
    expect(out('csrf', { pkce: true })).toBe('blocked');
  });
  it('every message names known actors', () => {
    const ids = new Set(oauth.ACTORS.map((a) => a.id));
    for (const a of Object.keys(oauth.ATTACKS)) for (const m of oauth.flow(a, { exact: false, state: false, pkce: false }).messages) expect(ids.has(m.from) && ids.has(m.to)).toBe(true);
  });
});
