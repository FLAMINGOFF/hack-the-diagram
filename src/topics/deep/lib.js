export { L, verdict } from '../content/helpers.js';

const EVIL_JS = /\b(alert|prompt|confirm|print|fetch|eval)\s*\(|document\.cookie|location\s*=/;

/**
 * Parse HTML inertly (DOMParser never runs scripts) and report what would execute
 * if a browser rendered it. Falls back to regexes outside the browser.
 */
export function htmlExec(html) {
  const found = [];
  if (typeof DOMParser !== 'undefined') {
    const doc = new DOMParser().parseFromString(`<!doctype html><body>${html}`, 'text/html');
    for (const el of doc.querySelectorAll('*')) {
      for (const a of el.attributes) {
        if (/^on/i.test(a.name)) found.push(`<${el.tagName.toLowerCase()} ${a.name}="${a.value}">`);
        if (/^(href|src|action|formaction)$/i.test(a.name) && /^\s*javascript:/i.test(a.value)) found.push(`${a.name}=${a.value}`);
      }
      if (el.tagName === 'SCRIPT' && !el.hasAttribute('src') && jsExec(el.textContent).runs) found.push(`<script>${el.textContent.trim().slice(0, 60)}</script>`);
      if (el.tagName === 'SCRIPT' && el.hasAttribute('src')) found.push(`<script src=${el.getAttribute('src')}>`);
    }
  } else {
    const m = html.match(/<[a-z][^>]*\son\w+\s*=[^>]*>|<script[\s>][\s\S]*?<\/script>|javascript:/gi);
    if (m) found.push(...m);
  }
  return found;
}

/** Does this JavaScript source parse, and does it call something interesting outside a string? */
export function jsExec(code) {
  let ok = true;
  try {
    // eslint-disable-next-line no-new-func
    new Function(code); // compile only, never called
  } catch {
    ok = false;
  }
  // Strings and line comments in one pass, so a // inside a string is not mistaken for a comment.
  const outside = code.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`|\/\/.*$/gm, (m) => (m.startsWith('//') ? '' : '""'));
  return { ok, runs: ok && EVIL_JS.test(outside) };
}

export const escHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

export const decodeOnce = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

/**
 * Parse a small raw HTTP request typed by the learner (Burp Repeater style).
 * Returns { method, target, path, query (URLSearchParams), headers (lowercased keys), cookies, body, form }.
 */
export function parseReq(text) {
  const norm = text.replace(/\r/g, '');
  const [head, ...rest] = norm.split(/\n\s*\n/);
  const lines = head.split('\n').filter((l) => l.trim() !== '');
  const [method = 'GET', target = '/'] = (lines.shift() || '').trim().split(/\s+/);
  const headers = {};
  for (const l of lines) {
    const i = l.indexOf(':');
    if (i > 0) headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  }
  const cookies = {};
  for (const part of (headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) cookies[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  const body = rest.join('\n\n').trim();
  const q = target.indexOf('?');
  const path = q < 0 ? target : target.slice(0, q);
  const query = new URLSearchParams(q < 0 ? '' : target.slice(q + 1));
  let form = new URLSearchParams();
  let json = null;
  if (body.startsWith('{')) {
    try {
      json = JSON.parse(body);
    } catch {
      json = null;
    }
  } else form = new URLSearchParams(body);
  return { method: method.toUpperCase(), target, path, query, headers, cookies, body, form, json };
}
