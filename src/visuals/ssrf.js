// Logic for the SSRF network map. Host parsing uses the real WHATWG URL parser, so the IPv4
// shorthand tricks (127.1, 2130706433, 0x7f.1) normalise exactly as they do in a browser or Node.
const L = (en, zh) => ({ en, zh });

export const APP_HOST = 'stock.shop.example';

/** Machines on the simulated network, keyed by the address the URL resolves to. */
export const NODES = {
  stock: { ip: '10.0.0.5', label: L('Stock API', '库存 API'), sub: `${APP_HOST}`, safe: true },
  local: { ip: '127.0.0.1', label: L('App itself', '应用自身'), sub: 'localhost:80 /admin' },
  admin: { ip: '192.168.0.12', label: L('Admin panel', '管理后台'), sub: '192.168.0.12:8080' },
  meta: { ip: '169.254.169.254', label: L('Cloud metadata', '云元数据'), sub: '169.254.169.254' },
};

const DNS = { [APP_HOST]: '10.0.0.5', localhost: '127.0.0.1', 'evil.example': '203.0.113.66' };

export const PRESETS = [
  { label: L('Normal stock check', '正常库存查询'), url: `http://${APP_HOST}/stock?id=1` },
  { label: 'localhost/admin', url: 'http://localhost/admin/delete?username=carlos' },
  { label: L('Internal admin', '内网管理后台'), url: 'http://192.168.0.12:8080/admin' },
  { label: L('Cloud metadata', '云元数据'), url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-role' },
  { label: L('Bypass: 127.1', '绕过：127.1'), url: 'http://127.1/%61dmin/delete?username=carlos' },
  { label: L('Bypass: decimal IP', '绕过：十进制 IP'), url: 'http://2852039166/latest/meta-data/' },
  { label: L('Bypass: open redirect', '绕过：开放重定向'), url: `http://${APP_HOST}/redirect?to=http://192.168.0.12:8080/admin` },
];

export const DEFENCES = {
  none: L('No check', '不检查'),
  blocklist: L('String blocklist', '字符串黑名单'),
  hostallow: L('Host allowlist', '主机白名单'),
  allowlist: L('Allowlist + no redirects', '白名单 + 禁止重定向'),
};

const BLOCKED_WORDS = ['localhost', '127.0.0.1', '169.254.169.254', '192.168.', 'admin'];

function nodeFor(ip) {
  return Object.entries(NODES).find(([, n]) => n.ip === ip)?.[0] ?? null;
}

/** Parse a URL and resolve it to an IP, the way the vulnerable server would. */
export function resolve(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, error: L('Not a valid URL', '不是合法的 URL') };
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const ip = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host : host === '::1' ? '127.0.0.1' : DNS[host] ?? null;
  return { ok: true, url: u, host, ip, node: ip ? nodeFor(ip) : null };
}

/**
 * Run one request through the stock checker.
 * Returns the hops the packet takes and what comes back, for the animation.
 */
export function simulate(raw, defence) {
  const steps = [];
  const first = resolve(raw);
  if (!first.ok) return { steps: [{ at: 'app', kind: 'blocked', text: first.error }], outcome: 'error' };

  steps.push({ at: 'app', kind: 'info', text: L(`URL parser: host "${first.url.host}" → ${first.ip ?? 'unknown'}`, `URL 解析器：主机 "${first.url.host}" → ${first.ip ?? '未知'}`) });

  if (defence === 'blocklist') {
    const hit = BLOCKED_WORDS.find((w) => raw.toLowerCase().includes(w));
    if (hit) {
      steps.push({ at: 'app', kind: 'blocked', text: L(`Blocklist matched "${hit}" → 400`, `黑名单匹配到 "${hit}" → 400`) });
      return { steps, outcome: 'blocked', target: first.node };
    }
    steps.push({ at: 'app', kind: 'info', text: L('Blocklist: no forbidden words in the string, allowed', '黑名单：字符串里没有禁用词，放行') });
  }
  if ((defence === 'allowlist' || defence === 'hostallow') && first.host !== APP_HOST) {
    steps.push({ at: 'app', kind: 'blocked', text: L(`"${first.host}" is not on the allowlist → 400`, `"${first.host}" 不在白名单里 → 400`) });
    return { steps, outcome: 'blocked', target: first.node };
  }
  if (defence === 'hostallow' || defence === 'allowlist') steps.push({ at: 'app', kind: 'info', text: L(`Host "${first.host}" is on the allowlist`, `主机 "${first.host}" 在白名单里`) });

  let hop = first;
  const redirect = first.node === 'stock' && first.url.pathname === '/redirect' ? first.url.searchParams.get('to') : null;
  if (redirect) {
    steps.push({ at: 'stock', kind: 'info', text: L(`Stock API answers 302 → ${redirect}`, `库存 API 返回 302 → ${redirect}`) });
    if (defence === 'allowlist') {
      steps.push({ at: 'app', kind: 'blocked', text: L('Redirects are not followed → request ends here', '不跟随重定向 → 请求到此结束') });
      return { steps, outcome: 'blocked', target: 'stock' };
    }
    hop = resolve(redirect);
    if (!hop.ok) return { steps, outcome: 'error' };
    steps.push({ at: 'app', kind: 'info', text: L(`App follows the redirect to ${hop.ip ?? hop.host}`, `应用跟随重定向到 ${hop.ip ?? hop.host}`) });
  }

  const node = hop.node;
  if (!node) {
    steps.push({ at: 'app', kind: 'blocked', text: L('Connection failed: no such host', '连接失败：没有这个主机') });
    return { steps, outcome: 'error', target: null };
  }
  const path = hop.url.pathname + hop.url.search;
  const resp = respond(node, decodeURIComponent(path));
  steps.push({ at: node, kind: node === 'stock' ? 'good' : 'bad', text: resp.line });
  return { steps, outcome: node === 'stock' ? 'normal' : 'pwned', target: node, via: redirect ? 'stock' : null, body: resp.body };
}

function respond(node, path) {
  if (node === 'stock') return { line: L('200 OK: 42 units in stock', '200 OK：库存 42 件'), body: '{"productId":1,"units":42}' };
  if (node === 'meta')
    return path.includes('security-credentials')
      ? { line: L('200 OK: temporary AWS keys returned', '200 OK：返回了临时 AWS 密钥'), body: '{"AccessKeyId":"ASIA…EXAMPLE","SecretAccessKey":"wJalr…EXAMPLEKEY","Token":"IQoJ…"}' }
      : { line: L('200 OK: metadata index', '200 OK：元数据目录'), body: 'ami-id\nhostname\niam/\ninstance-id\n…' };
  const admin = path.startsWith('/admin');
  if (!admin) return { line: L('200 OK: internal page', '200 OK：内部页面'), body: '<h1>Internal</h1>' };
  return path.includes('delete')
    ? { line: L('200 OK: user carlos deleted (no auth: request came from inside)', '200 OK：用户 carlos 已删除（没有鉴权：请求来自内部）'), body: 'User carlos deleted' }
    : { line: L('200 OK: admin panel, no login needed from inside', '200 OK：管理后台，内部访问无需登录'), body: '<h1>Admin</h1><a href="/admin/delete?username=carlos">Delete carlos</a>' };
}
