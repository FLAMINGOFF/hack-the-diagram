import { describe, expect, it } from 'vitest';
import * as b from '../../src/visuals/batch3.js';

const run = (id, sink) => b.domRun(b.DOM_PAYLOADS.find((p) => p.id === id).value, sink).executes;

describe('DOM XSS sinks', () => {
  it('innerHTML runs event handlers but not inserted <script>', () => {
    expect(run('img', 'innerHTML')).toBe(true);
    expect(run('script', 'innerHTML')).toBe(false);
  });
  it('document.write runs both', () => {
    expect(run('img', 'write')).toBe(true);
    expect(run('script', 'write')).toBe(true);
  });
  it('href only runs javascript: URLs', () => {
    expect(run('js', 'href')).toBe(true);
    expect(run('img', 'href')).toBe(false);
  });
  it('textContent never runs anything', () => {
    for (const p of b.DOM_PAYLOADS) expect(run(p.id, 'textContent')).toBe(false);
  });
  it('the fragment never reaches the server', () => {
    expect(b.serverSees('<x>', 'hash')).toBe('GET /');
    expect(b.serverSees('<x>', 'search')).toContain('%3Cx%3E');
  });
});

describe('cross-site WebSocket hijacking', () => {
  it('works with no defences and leaks messages', () => {
    const r = b.wsHijack({});
    expect(r.outcome).toBe('pwned');
    expect(r.handshake).toContain('Cookie');
  });
  it('each defence on its own stops it', () => {
    for (const k of Object.keys(b.WS_DEFENCES)) expect(b.wsHijack({ [k]: true }).outcome).toBe('blocked');
    expect(b.wsHijack({ samesite: true }).handshake).not.toContain('Cookie');
  });
});

describe('deserialization', () => {
  it('signing stops both attacks', () => {
    expect(b.deserialize('tamper', 'sign').outcome).toBe('blocked');
    expect(b.deserialize('gadget', 'sign').outcome).toBe('blocked');
  });
  it('a data-only format stops gadgets but not tampering', () => {
    expect(b.deserialize('gadget', 'json').outcome).toBe('blocked');
    expect(b.deserialize('tamper', 'json').outcome).toBe('pwned');
  });
  it('the cookies are well-formed PHP serialization', () => {
    for (const c of Object.values(b.DS_COOKIE)) {
      for (const [, n, s] of c.matchAll(/s:(\d+):"([^"]*)"/g)) expect(s.length).toBe(Number(n));
      const [, n, cls] = c.match(/^O:(\d+):"([^"]+)"/);
      expect(cls.length).toBe(Number(n));
    }
  });
});

describe('SSTI fingerprinting', () => {
  it("{{7*'7'}} separates Jinja2 from Twig", () => {
    expect(b.render('jinja2', "{{7*'7'}}")).toBe('7777777');
    expect(b.render('twig', "{{7*'7'}}")).toBe('49');
  });
  it('the decision tree identifies every engine', () => {
    for (const e of Object.keys(b.ENGINES)) expect(b.fingerprint(e).verdict).toBe(e);
  });
  it('passing input as data defeats every probe', () => {
    for (const e of Object.keys(b.ENGINES)) expect(b.fingerprint(e, 'data').verdict).toBe('none');
  });
});

describe('GraphQL', () => {
  const none = { introspection: false, suggestions: false, cost: false };
  it('suggestions leak fields even with introspection off', () => {
    expect(b.graphql('introspect', none).outcome).toBe('pwned');
    expect(b.graphql('introspect', { ...none, introspection: true }).outcome).toBe('pwned');
    expect(b.graphql('introspect', { ...none, introspection: true, suggestions: true }).outcome).toBe('blocked');
  });
  it('aliases pack 100 guesses into one request unless operations are limited', () => {
    const r = b.graphql('aliases', none);
    expect(r.results.filter(Boolean)).toHaveLength(1);
    expect(r.results.indexOf(true)).toBe(63);
    expect(b.graphql('aliases', { ...none, cost: true }).outcome).toBe('blocked');
  });
});
