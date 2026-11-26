import { describe, expect, it } from 'vitest';
import { decodeOnce, escHtml, htmlExec, jsExec, parseReq } from '../../src/topics/deep/lib.js';

describe('htmlExec (inert HTML check)', () => {
  it('spots event handlers, javascript: URLs and inline scripts', () => {
    expect(htmlExec('<img src=x onerror=alert(1)>')).toHaveLength(1);
    expect(htmlExec('<a href="javascript:alert(1)">x</a>')).toHaveLength(1);
    expect(htmlExec('<script>alert(document.domain)</script>')).toHaveLength(1);
  });
  it('ignores escaped or harmless markup', () => {
    expect(htmlExec(escHtml('<img src=x onerror=alert(1)>'))).toEqual([]);
    expect(htmlExec('<b>hello</b><script>var a = 1</script>')).toEqual([]);
  });
});

describe('jsExec', () => {
  it('flags calls outside strings only', () => {
    expect(jsExec("var a = ''; alert(1); //").runs).toBe(true);
    expect(jsExec("var a = 'alert(1) // not code';").runs).toBe(false);
    expect(jsExec('var a = "x" + ;').ok).toBe(false);
  });
});

describe('escHtml / decodeOnce', () => {
  it('escapes all five HTML metacharacters', () => {
    expect(escHtml(`<a href="x" title='y'>&</a>`)).toBe('&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  });
  it('decodes once and survives bad input', () => {
    expect(decodeOnce('%252e')).toBe('%2e');
    expect(decodeOnce('%E0%A4%A')).toBe('%E0%A4%A');
  });
});

describe('parseReq', () => {
  it('reads a raw request like Burp Repeater', () => {
    const r = parseReq('POST /login?next=%2Fhome HTTP/1.1\nHost: shop.example\nCookie: session=abc; role=user\nContent-Type: application/x-www-form-urlencoded\n\nuser=carlos&pass=x');
    expect(r.method).toBe('POST');
    expect(r.path).toBe('/login');
    expect(r.query.get('next')).toBe('/home');
    expect(r.headers.host).toBe('shop.example');
    expect(r.cookies.role).toBe('user');
    expect(r.form.get('user')).toBe('carlos');
  });
});
