// CORS: what the server answers, and what the browser then lets the attacker's script read.
// The browser check follows the Fetch standard's CORS check for a credentialed request.
const L = (en, zh) => ({ en, zh });

export const API = 'https://api.bank.example';

export const ORIGINS = [
  { value: 'https://evil.example', label: 'evil.example', note: L('The attacker’s own site', '攻击者自己的网站') },
  { value: 'null', label: 'null', note: L('A sandboxed iframe or a data: URL sends Origin: null', '沙箱 iframe 或 data: URL 会发送 Origin: null') },
  { value: 'https://bank.example.evil.example', label: 'bank.example.evil.example', note: L('A domain the attacker registers to beat a prefix check', '攻击者注册的域名，用来绕过前缀检查') },
  { value: 'https://bank.example', label: 'bank.example', note: L('The real site (legitimate use)', '真正的网站（正常使用）') },
];

export const CONFIGS = {
  reflect: { label: L('Reflects any Origin', '回显任意 Origin'), code: 'res.set("Access-Control-Allow-Origin", req.headers.origin)\nres.set("Access-Control-Allow-Credentials", "true")' },
  prefix: { label: L('Prefix check', '前缀检查'), code: 'if (origin.startsWith("https://bank.example"))\n  allow(origin)  // + credentials' },
  null: { label: L('Allows "null"', '允许 "null"'), code: 'const ok = ["https://bank.example", "null"]\nif (ok.includes(origin)) allow(origin)  // + credentials' },
  wildcard: { label: L('Wildcard *', '通配符 *'), code: 'res.set("Access-Control-Allow-Origin", "*")\nres.set("Access-Control-Allow-Credentials", "true")' },
  exact: { label: L('Exact allowlist', '精确白名单'), code: 'const ok = new Set(["https://bank.example"])\nif (ok.has(origin)) allow(origin)  // + credentials\nres.set("Vary", "Origin")' },
};

/** The response headers the API sends for this Origin. */
export function serverHeaders(config, origin) {
  const allow = (o) => ({ 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Credentials': 'true' });
  switch (config) {
    case 'reflect':
      return allow(origin);
    case 'prefix':
      return origin.startsWith('https://bank.example') ? allow(origin) : {};
    case 'null':
      return ['https://bank.example', 'null'].includes(origin) ? allow(origin) : {};
    case 'wildcard':
      return { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' };
    default:
      return origin === 'https://bank.example' ? { ...allow(origin), Vary: 'Origin' } : { Vary: 'Origin' };
  }
}

/** The browser's CORS check for a fetch(..., { credentials: 'include' }). */
export function browserCheck(origin, h) {
  const acao = h['Access-Control-Allow-Origin'];
  if (acao === undefined) return { ok: false, why: L('No Access-Control-Allow-Origin header', '没有 Access-Control-Allow-Origin 头') };
  if (acao === '*') return { ok: false, why: L('"*" is not allowed when credentials are included', '带凭据的请求不允许使用 "*"') };
  if (acao !== origin) return { ok: false, why: L(`Allowed origin "${acao}" is not "${origin}"`, `允许的来源 "${acao}" 不是 "${origin}"`) };
  if (h['Access-Control-Allow-Credentials'] !== 'true') return { ok: false, why: L('Credentials not allowed', '不允许携带凭据') };
  return { ok: true, why: L(`Origin matches exactly and credentials are allowed`, '来源完全匹配，且允许携带凭据') };
}

export const SECRET = '{ "user": "alice", "apiKey": "bk_live_7Q2x…9Fz", "balance": 5000 }';

export function run(config, origin) {
  const headers = serverHeaders(config, origin);
  const check = browserCheck(origin, headers);
  return { headers, check, stolen: check.ok && origin !== 'https://bank.example', legit: check.ok && origin === 'https://bank.example' };
}
