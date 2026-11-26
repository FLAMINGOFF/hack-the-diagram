import { useState } from 'react';
import { useLang } from '../../i18n.jsx';
import { Seg } from '../../components/TopicShell.jsx';
import { ATTACKER, L, VICTIM, actor, msg, verdict } from './helpers.js';

/* -------------------------------------------------------------------- CORS */
const cors = {
  tldr: L(
    'CORS lets a server relax the same-origin policy for chosen origins. A misconfigured policy, such as reflecting any Origin while allowing credentials, lets any website read logged-in users’ private API responses.',
    'CORS 允许服务器为指定的源放宽同源策略。配置错误的策略，比如在允许携带凭据的同时反射任意 Origin，会让任何网站都能读取已登录用户的私密 API 响应。',
  ),
  labTitle: L('Which origins can read /api/account?', '哪些源能读取 /api/account？'),
  lab: {
    fields: [{ id: 'o', label: L('Origin of the page making the request', '发起请求的页面 Origin'), default: 'https://evil.example' }],
    presets: [
      { label: L('Same site app', '本站前端'), values: { o: 'https://app.bank.example' } },
      { label: 'evil.example', values: { o: 'https://evil.example' } },
      { label: 'null', values: { o: 'null' } },
      { label: L('Suffix trick', '后缀绕过'), values: { o: 'https://bank.example.evil.example' } },
      { label: L('Prefix trick', '前缀绕过'), values: { o: 'https://evilbank.example' } },
    ],
    defense: { label: L('CORS policy', 'CORS 策略'), off: L('Reflect / regex', '反射 / 正则'), on: L('Exact allow-list', '精确白名单') },
    run({ values, defended }) {
      const o = values.o.trim();
      const request = `GET /api/account HTTP/1.1\nHost: api.bank.example\nOrigin: ${o}\nCookie: session=alice…`;
      let allowed;
      const log = [];
      if (defended) {
        allowed = ['https://app.bank.example', 'https://bank.example'].includes(o);
        log.push(allowed ? L('✓ origin is in the allow-list', '✓ 源在白名单中') : L('🛡 not in allow-list → no ACAO header', '🛡 不在白名单 → 不返回 ACAO 头'));
      } else {
        // a typical buggy policy: trust null, and anything matching /bank\.example/
        allowed = o === 'null' || /bank\.example/.test(o) || o.startsWith('https://');
        log.push(o === 'null' ? L('⚠ "null" is whitelisted (for local files / sandboxed iframes)', '⚠ “null” 在白名单里（为了本地文件 / 沙箱 iframe）') : /bank\.example/.test(o) ? L(`⚠ /bank\\.example/ matches ${o}`, `⚠ /bank\\.example/ 匹配了 ${o}`) : L('⚠ server reflects the Origin header back', '⚠ 服务器把 Origin 头原样反射回来'));
      }
      const headers = allowed ? `Access-Control-Allow-Origin: ${o}\nAccess-Control-Allow-Credentials: true` : '(no Access-Control-Allow-Origin)';
      const trusted = o === 'https://app.bank.example' || o === 'https://bank.example';
      const response = `HTTP/1.1 200 OK\n${headers}\n\n{"user":"alice","apiKey":"ak_live_7f3a…","balance":5000}`;
      if (!allowed) return { request, log: [...log, L('browser blocks JS from reading the response', '浏览器阻止 JS 读取响应')], response, ...verdict(false, `JavaScript on ${o} cannot read the response.`, `${o} 上的 JavaScript 读不到响应。`) };
      return { request, log: [...log, trusted ? L('✓ browser lets the trusted front end read it', '✓ 浏览器允许受信任的前端读取') : L('⚠ browser lets the attacker page read the response', '⚠ 浏览器允许攻击者页面读取响应')], response, ...(trusted ? verdict(false, 'The legitimate front end reads the data, as designed.', '合法前端按设计读取数据。') : verdict(true, `Any page on ${o} can read alice’s API key with fetch(…, {credentials: "include"}).`, `${o} 上的任何页面都能用 fetch(…, {credentials: "include"}) 读到 alice 的 API Key。`)) };
    },
  },
  actors: [VICTIM, actor('evil', 'evil.example', L('attacker page', '攻击者页面'), 'red'), actor('api', 'api.bank.example', 'REST API', 'neutral')],
  flow: [
    msg('vic', 'evil', 'GET /', L('Alice, logged in to her bank, visits the attacker’s page.', '已登录网银的 Alice 访问了攻击者的页面。')),
    msg('evil', 'vic', 'fetch(api, {credentials:"include"})', L('The page’s script asks the browser to call the bank API with cookies.', '页面脚本让浏览器带着 Cookie 调用银行 API。'), 'attack'),
    msg('vic', 'api', 'GET /api/account  Origin: evil.example 🍪', L('The browser always sends the request and the cookie. CORS only decides whether JS may read the answer.', '浏览器总会发出请求并带上 Cookie。CORS 只决定 JS 能不能读到响应。'), 'attack'),
    msg('api', 'vic', 'ACAO: https://evil.example + Credentials: true', L('The server reflects the Origin, telling the browser this site is trusted.', '服务器反射了 Origin，告诉浏览器这个网站是可信的。'), 'attack'),
    msg('vic', 'evil', '{apiKey, balance, …}', L('The browser hands the response to the attacker’s script.', '浏览器把响应交给了攻击者的脚本。'), 'attack'),
  ],
  code: {
    vuln: `app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', req.headers.origin);
  res.set('Access-Control-Allow-Credentials', 'true');
  next();
});`,
    fixed: `const ALLOWED = new Set(['https://app.bank.example']);
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (ALLOWED.has(o)) {
    res.set('Access-Control-Allow-Origin', o);
    res.set('Access-Control-Allow-Credentials', 'true');
    res.set('Vary', 'Origin');
  }
  next();
});`,
  },
  defenses: [
    { title: L('Exact-match allow-list', '精确匹配白名单'), body: L('Compare the full origin string. No regex, no substring, no reflection.', '比较完整的源字符串。不用正则、不用子串匹配、不反射。') },
    { title: L('Never trust “null”', '永远不信任 “null”'), body: L('Sandboxed iframes and data: URLs can send Origin: null on demand.', '沙箱 iframe 和 data: URL 可以随意发送 Origin: null。') },
    { title: L('CORS is not access control', 'CORS 不是访问控制'), body: L('Server-side auth still applies; CORS only protects reads from browsers. Add Vary: Origin to avoid cache issues.', '服务器端认证依然必要；CORS 只保护来自浏览器的读取。加上 Vary: Origin 避免缓存问题。') },
  ],
  qa: [
    { q: L('Why can’t you use “*” with credentials?', '为什么 “*” 不能和凭据一起用？'), a: L('Browsers refuse Access-Control-Allow-Origin: * when credentials are included. That is why buggy servers reflect the Origin instead, which is worse.', '携带凭据时，浏览器拒绝 Access-Control-Allow-Origin: *。所以有缺陷的服务器会改为反射 Origin，结果更糟。') },
    { q: L('Does a strict CORS policy prevent CSRF?', '严格的 CORS 策略能防 CSRF 吗？'), a: L('No. Simple requests are sent regardless; CORS only blocks reading the response.', '不能。简单请求无论如何都会被发出；CORS 只阻止读取响应。') },
  ],
};

/* -------------------------------------------------------------- Clickjacking */
function ClickjackingLab() {
  const { tr } = useLang();
  const [opacity, setOpacity] = useState(0.0001);
  const [xfo, setXfo] = useState('none');
  const [clicked, setClicked] = useState(null);
  const blocked = xfo !== 'none';
  const shown = Math.max(opacity, 0);
  return (
    <div className="lab">
      <div className="panel">
        <Seg
          label={{ en: 'bank.example response header', zh: 'bank.example 的响应头' }}
          value={xfo}
          onChange={(v) => {
            setXfo(v);
            setClicked(null);
          }}
          options={[
            { value: 'none', label: { en: 'None', zh: '无' } },
            { value: 'xfo', label: 'X-Frame-Options: DENY' },
            { value: 'csp', label: "CSP frame-ancestors 'self'" },
          ]}
        />
        <label className="field-label" htmlFor="cj-op">
          {tr({ en: 'Opacity of the framed bank page', zh: '被嵌入的银行页面透明度' })}: {shown < 0.01 ? '0.0001' : shown.toFixed(2)}
        </label>
        <input id="cj-op" type="range" min="0" max="1" step="0.01" value={opacity} onChange={(e) => setOpacity(Math.max(0.0001, Number(e.target.value)))} className="range" />
        <p className="hint">
          {tr({
            en: 'The attacker’s page loads bank.example in an iframe, makes it almost invisible, and positions the real “Delete account” button exactly under a fake “Claim prize” button. Slide to reveal it, then click the button.',
            zh: '攻击者的页面在 iframe 里加载 bank.example，把它设成几乎透明，并把真正的“删除账号”按钮精确地放在假的“领取奖品”按钮正下方。拖动滑块揭开它，然后点击按钮。',
          })}
        </p>
        <pre className="code small">{`<style>
  iframe { opacity: ${shown < 0.01 ? '0.0001' : shown.toFixed(2)}; position: absolute;
           top: 0; left: 0; z-index: 2; }
  .decoy { position: absolute; top: 172px; left: 60px; z-index: 1; }
</style>
<div class="decoy">Claim your prize!</div>
<iframe src="https://bank.example/account"></iframe>`}</pre>
      </div>
      <div className="panel">
        <div className="browser">
          <div className="browser-bar">
            <span className="dots">
              <i /> <i /> <i />
            </span>
            <span className="url">🎁 win-a-prize.example</span>
          </div>
          <div className="cj-stage">
            <div className="cj-decoy">
              <h4>🎉 {tr({ en: 'Congratulations!', zh: '恭喜你！' })}</h4>
              <p>{tr({ en: 'You are visitor #1,000,000.', zh: '你是第 1,000,000 位访客。' })}</p>
              <button className="cj-btn decoy-btn" tabIndex={-1}>
                {tr({ en: 'Claim prize', zh: '领取奖品' })}
              </button>
            </div>
            {blocked ? (
              <div className="cj-frame cj-refused">
                <b>⛔ bank.example</b>
                <span>{tr({ en: 'refused to connect (framing not allowed)', zh: '拒绝连接（不允许被嵌入框架）' })}</span>
              </div>
            ) : (
              <div className="cj-frame" style={{ opacity: shown }}>
                <div className="cj-bank-head">bank.example · {tr({ en: 'Account settings', zh: '账户设置' })}</div>
                <p>alice@uni.example</p>
                <p className="muted">{tr({ en: 'Balance', zh: '余额' })}: $5,000</p>
                <button className="cj-btn danger-btn" onClick={() => setClicked('delete')}>
                  {tr({ en: 'Delete account', zh: '删除账号' })}
                </button>
              </div>
            )}
            {blocked && (
              <button className="cj-btn decoy-click" onClick={() => setClicked('decoy')} aria-label="Claim prize">
                {tr({ en: 'Claim prize', zh: '领取奖品' })}
              </button>
            )}
          </div>
        </div>
        <div className={`verdict ${clicked === 'delete' ? 'bad' : clicked === 'decoy' || blocked ? 'good' : 'neutral-v'}`}>
          {clicked === 'delete'
            ? tr({ en: '💥 You clicked “Delete account” on bank.example. The click went to the invisible frame, with your real session.', zh: '💥 你在 bank.example 上点击了“删除账号”。点击落在了隐形框架上，用的是你真实的会话。' })
            : blocked
              ? tr({ en: '🛡 The browser refuses to render bank.example inside another site’s frame, so there is nothing to click on.', zh: '🛡 浏览器拒绝在其他网站的框架中渲染 bank.example，所以根本没有东西可点。' })
              : tr({ en: 'Click “Claim prize”.', zh: '点击“领取奖品”。' })}
        </div>
      </div>
    </div>
  );
}

const clickjacking = {
  tldr: L(
    'Clickjacking loads a target site in an invisible iframe on top of a decoy page. The victim thinks they click the decoy, but the click lands on the real, logged-in site underneath.',
    '点击劫持把目标网站放在诱饵页面之上的隐形 iframe 里。受害者以为自己点的是诱饵，实际点击落在了下面那个真实、已登录的网站上。',
  ),
  labTitle: L('Reveal the hidden frame', '揭开隐藏的框架'),
  CustomLab: ClickjackingLab,
  actors: [VICTIM, actor('evil', 'win-a-prize.example', L('decoy page', '诱饵页面'), 'red'), actor('bank', 'bank.example', L('target', '目标'), 'neutral')],
  flow: [
    msg('vic', 'evil', 'GET /', L('The victim opens a page promising a prize.', '受害者打开一个声称有奖品的页面。')),
    msg('evil', 'vic', '<iframe src=bank.example style=opacity:0>', L('The page frames the bank, transparent and aligned over a decoy button.', '页面嵌入银行网站，设为透明并对齐到诱饵按钮上。'), 'attack'),
    msg('vic', 'bank', 'GET /account 🍪', L('The frame loads with the victim’s cookies (if SameSite allows it), so they are logged in.', 'iframe 加载时带上了受害者的 Cookie（如果 SameSite 允许），所以处于登录状态。'), 'attack'),
    msg('vic', 'bank', 'POST /account/delete (the “prize” click)', L('The click is a genuine user action inside bank.example. CSRF tokens don’t help: the real form submits them.', '这次点击是 bank.example 里真实的用户操作。CSRF Token 没用：真实表单会自己提交 Token。'), 'attack'),
    msg('bank', 'vic', 'Account deleted', L('Fix: the bank must tell browsers not to render it inside other sites’ frames.', '修复：银行必须告诉浏览器，不要在其他网站的框架中渲染它。'), 'attack'),
  ],
  code: {
    vuln: `HTTP/1.1 200 OK
Content-Type: text/html
(no framing policy)`,
    fixed: `HTTP/1.1 200 OK
Content-Security-Policy: frame-ancestors 'self'
X-Frame-Options: DENY          # for older browsers
Set-Cookie: session=…; SameSite=Lax`,
  },
  defenses: [
    { title: L("CSP frame-ancestors", 'CSP frame-ancestors'), body: L("The modern control: 'none' or 'self' or an explicit list of parent origins.", "现代的控制手段：'none'、'self' 或明确列出允许的父页面源。") },
    { title: L('X-Frame-Options', 'X-Frame-Options'), body: L('DENY or SAMEORIGIN for legacy browsers. Frame-busting JavaScript is unreliable (sandbox breaks it).', '为旧浏览器设置 DENY 或 SAMEORIGIN。用 JavaScript 跳出框架不可靠（sandbox 能让它失效）。') },
    { title: L('SameSite cookies', 'SameSite Cookie'), body: L('Lax/Strict cookies are not sent to cross-site iframes, so the framed page is logged out.', 'Lax/Strict 的 Cookie 不会发送给跨站 iframe，被嵌入的页面会处于未登录状态。') },
  ],
  qa: [
    { q: L('Why don’t CSRF tokens stop clickjacking?', '为什么 CSRF Token 防不住点击劫持？'), a: L('The request comes from the real page inside the frame, which includes a valid token. The attacker only supplies the click.', '请求来自 iframe 中的真实页面，页面本身带有合法 Token。攻击者只是“提供”了点击。') },
    { q: L('Can clickjacking be combined with other bugs?', '点击劫持能和其他漏洞组合吗？'), a: L('Yes: triggering a DOM XSS that needs a click, or prefilling forms via URL parameters then tricking the click on submit.', '能：比如触发需要点击才会生效的 DOM XSS，或通过 URL 参数预填表单后诱骗用户点击提交。') },
  ],
};

/* ---------------------------------------------------------------- DOM-based */
const SINKS = {
  innerHTML: { code: 'document.getElementById("msg").innerHTML = value;', en: 'innerHTML parses markup. <img onerror> runs; <script> does not.', zh: 'innerHTML 会解析 HTML。<img onerror> 会执行，<script> 不会。' },
  location: { code: 'location = value;  // "redirect after login"', en: 'Navigating to a javascript: URL runs code; any other URL is an open redirect.', zh: '跳转到 javascript: URL 会执行代码；其他 URL 则是开放重定向。' },
  eval: { code: 'eval("track(\'" + value + "\')");', en: 'eval executes a string as JavaScript. Breaking out of the quotes is enough.', zh: 'eval 会把字符串当 JavaScript 执行，跳出引号就够了。' },
};
const dom = {
  tldr: L(
    'DOM-based vulnerabilities happen entirely in the browser: client-side JavaScript reads attacker-controllable data (a source, like location.hash) and passes it to a dangerous function (a sink, like innerHTML or eval).',
    '基于 DOM 的漏洞完全发生在浏览器中：前端 JavaScript 读取了攻击者可控的数据（源，比如 location.hash），并把它传给危险函数（汇，比如 innerHTML 或 eval）。',
  ),
  labTitle: L('Trace a source into a sink', '追踪数据从源流向汇'),
  lab: {
    fields: [
      { id: 'sink', label: L('Sink (innerHTML / location / eval)', '汇（innerHTML / location / eval）'), default: 'innerHTML' },
      { id: 'v', label: L('URL fragment after #', '# 之后的 URL 片段'), default: '<img src=x onerror=alert(document.domain)>' },
    ],
    presets: [
      { label: L('Harmless text', '无害文本'), values: { sink: 'innerHTML', v: 'Welcome back!' } },
      { label: 'innerHTML + onerror', values: { sink: 'innerHTML', v: '<img src=x onerror=alert(document.domain)>' } },
      { label: 'innerHTML + <script>', values: { sink: 'innerHTML', v: '<script>alert(1)</script>' } },
      { label: 'location + javascript:', values: { sink: 'location', v: 'javascript:alert(document.cookie)' } },
      { label: L('Open redirect', '开放重定向'), values: { sink: 'location', v: 'https://evil.example/login' } },
      { label: L('eval breakout', 'eval 逃逸'), values: { sink: 'eval', v: "x');alert(1);//" } },
    ],
    defense: { label: L('Sink', '汇'), off: L('Dangerous sink', '危险的汇'), on: L('Safe API', '安全 API') },
    run({ values, defended }) {
      const sink = SINKS[values.sink] ? values.sink : 'innerHTML';
      const v = values.v;
      const request = `https://shop.example/welcome#${v}\n\n// page script\nconst value = decodeURIComponent(location.hash.slice(1));\n${defended ? { innerHTML: 'el.textContent = value;', location: 'if (/^\\/[^/]/.test(value)) location = value;  // same-site paths only', eval: 'track(value);  // no eval' }[sink] : SINKS[sink].code}`;
      const log = [L('source: location.hash (never sent to the server)', '源：location.hash（从不发送给服务器）'), L(`sink: ${sink}`, `汇：${sink}`)];
      let bad = false;
      let note = SINKS[sink];
      if (!defended) {
        if (sink === 'innerHTML') bad = /<[a-z]+[^>]*\son\w+\s*=/i.test(v) || /<iframe|<svg[^>]*onload/i.test(v);
        if (sink === 'location') bad = /^\s*javascript:/i.test(v) || /^https?:\/\/(?!shop\.example)/i.test(v);
        if (sink === 'eval') bad = /'/.test(v);
        if (sink === 'innerHTML' && /<script/i.test(v) && !bad) note = { en: '<script> inserted via innerHTML never executes. Try an event handler.', zh: '通过 innerHTML 插入的 <script> 不会执行，试试事件处理器。' };
      } else {
        note = { en: 'textContent / path checks / no eval: the value is treated as data.', zh: 'textContent / 路径校验 / 不用 eval：值只被当作数据。' };
      }
      if (bad) log.push(L('⚠ attacker-controlled data reached a dangerous sink', '⚠ 攻击者可控的数据到达了危险的汇'));
      else if (defended) log.push(L('🛡 safe sink: no parsing, no navigation off-site', '🛡 安全的汇：不解析、不跳转到站外'));
      return { request, log, response: null, ...(bad ? verdict(true, note.en, note.zh) : defended ? verdict(false, note.en, note.zh) : { verdict: 'neutral', message: note }) };
    },
  },
  actors: [ATTACKER, VICTIM, actor('app', L('Server', '服务器'), 'shop.example', 'neutral')],
  flow: [
    msg('atk', 'vic', 'link: /welcome#<img src=x onerror=…>', L('The payload lives in the URL fragment, which browsers never send to servers.', 'payload 藏在 URL 片段里，浏览器从不会把片段发给服务器。'), 'attack'),
    msg('vic', 'app', 'GET /welcome', L('The server only sees /welcome, so WAFs and server logs see nothing unusual.', '服务器只看到 /welcome，所以 WAF 和服务器日志都看不出异常。')),
    msg('app', 'vic', 'static HTML + JS', L('The response is identical for everyone.', '所有人收到的响应都一样。')),
    msg('vic', 'vic', 'el.innerHTML = location.hash', L('The page’s own JavaScript moves the source into the sink.', '页面自己的 JavaScript 把源送进了汇。'), 'attack'),
    msg('vic', 'atk', 'payload runs in shop.example', L('Same impact as reflected XSS. Find these with DOM Invader, or by grepping JS for sinks.', '影响与反射型 XSS 相同。可以用 DOM Invader，或在 JS 中搜索危险汇来发现。'), 'attack'),
  ],
  concepts: [
    { t: L('Common sources', '常见的源'), b: L('location.search / hash, document.referrer, window.name, postMessage data, localStorage, cookies.', 'location.search / hash、document.referrer、window.name、postMessage 数据、localStorage、Cookie。') },
    { t: L('Common sinks', '常见的汇'), b: L('innerHTML, outerHTML, document.write, eval, setTimeout(string), location, jQuery $() and .html().', 'innerHTML、outerHTML、document.write、eval、setTimeout(字符串)、location、jQuery 的 $() 和 .html()。') },
    { t: L('Beyond XSS', '不止 XSS'), b: L('DOM open redirects, cookie manipulation, web-message bugs and DOM clobbering all follow the source → sink model.', 'DOM 开放重定向、Cookie 篡改、Web 消息漏洞和 DOM Clobbering 都遵循“源 → 汇”模型。') },
  ],
  code: {
    vuln: `const name = new URLSearchParams(location.search).get('name');
document.getElementById('hi').innerHTML = 'Hello ' + name;

window.addEventListener('message', e => eval(e.data));`,
    fixed: `const name = new URLSearchParams(location.search).get('name');
document.getElementById('hi').textContent = 'Hello ' + name;

window.addEventListener('message', e => {
  if (e.origin !== 'https://shop.example') return;
  handle(JSON.parse(e.data));
});
// + CSP: require-trusted-types-for 'script'`,
  },
  defenses: [
    { title: L('Use safe sinks', '使用安全的汇'), body: L('textContent, setAttribute for safe attributes, framework bindings instead of innerHTML.', '用 textContent、对安全属性用 setAttribute、用框架绑定代替 innerHTML。') },
    { title: L('Trusted Types', 'Trusted Types'), body: L("CSP require-trusted-types-for 'script' makes the browser reject strings at dangerous sinks.", "CSP 的 require-trusted-types-for 'script' 会让浏览器拒绝向危险汇传入普通字符串。") },
    { title: L('Validate postMessage origins', '校验 postMessage 来源'), body: L('Check event.origin and treat data as untrusted JSON, never code.', '检查 event.origin，把数据当作不可信的 JSON，绝不当作代码。') },
  ],
  qa: [
    { q: L('Why can’t server-side encoding fix DOM XSS?', '为什么服务器端编码修不了 DOM XSS？'), a: L('The dangerous data may never reach the server (fragments), and the bug is in how client-side code uses it.', '危险数据可能根本不会到达服务器（URL 片段），漏洞在于前端代码如何使用它。') },
    { q: L('What is DOM clobbering?', '什么是 DOM Clobbering？'), a: L('Injecting HTML elements with id/name attributes that override global variables the script relies on, e.g. <a id=config href=…>.', '注入带 id/name 属性的 HTML 元素，覆盖脚本依赖的全局变量，比如 <a id=config href=…>。') },
  ],
};

/* --------------------------------------------------------------- WebSockets */
const websockets = {
  tldr: L(
    'WebSockets keep a two-way channel open after an HTTP upgrade. If the handshake is authenticated only by cookies and doesn’t check Origin, any website can open a socket as the victim (cross-site WebSocket hijacking).',
    'WebSocket 在一次 HTTP 升级后保持双向通道。如果握手只依靠 Cookie 认证、不检查 Origin，任何网站都能以受害者身份打开连接（跨站 WebSocket 劫持）。',
  ),
  labTitle: L('Hijack a support-chat socket', '劫持客服聊天的 WebSocket'),
  lab: {
    fields: [
      { id: 'o', label: L('Origin of the page opening the socket', '打开连接的页面 Origin'), default: 'https://evil.example' },
      { id: 'm', label: L('First message sent', '发送的第一条消息'), default: 'READY' },
    ],
    presets: [
      { label: L('Real chat page', '真实聊天页面'), values: { o: 'https://chat.shop.example', m: 'READY' } },
      { label: L('Attacker page', '攻击者页面'), values: { o: 'https://evil.example', m: 'READY' } },
      { label: L('XSS via message', '通过消息 XSS'), values: { o: 'https://chat.shop.example', m: '<img src=x onerror=alert(1)>' } },
    ],
    defense: { label: L('Handshake checks', '握手检查'), off: L('Cookie only', '只看 Cookie'), on: L('Origin + token', 'Origin + Token') },
    run({ values, defended }) {
      const o = values.o.trim();
      const request = `GET /chat HTTP/1.1\nUpgrade: websocket\nConnection: Upgrade\nOrigin: ${o}\nCookie: session=alice…\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==`;
      const trusted = o === 'https://chat.shop.example';
      if (defended && !trusted) return { request, log: [L(`🛡 Origin ${o} not allowed → 403`, `🛡 Origin ${o} 不被允许 → 403`)], response: 'HTTP/1.1 403 Forbidden', ...verdict(false, 'The handshake is refused for foreign origins, so the attacker never gets a socket.', '来自外部源的握手被拒绝，攻击者拿不到连接。') };
      const log = ['101 Switching Protocols', `→ ${values.m}`];
      const xss = /<[a-z]+[^>]*on\w+=/i.test(values.m);
      if (xss) {
        log.push(defended ? L('🛡 messages rendered with textContent', '🛡 消息用 textContent 渲染') : L('⚠ agent’s browser renders message with innerHTML', '⚠ 客服的浏览器用 innerHTML 渲染消息'));
        return { request, log, response: defended ? '(shown as text to the agent)' : '(script runs in the support agent’s browser)', ...verdict(!defended, defended ? 'WebSocket messages are encoded like any other output.' : 'WebSocket messages are user input too: XSS against the support agent.', defended ? 'WebSocket 消息和其他输出一样被编码。' : 'WebSocket 消息也是用户输入：对客服人员的 XSS。') };
      }
      const history = '← {"user":"alice","content":"My card ends in 4242, the reset code is 839201"}';
      if (!trusted) return { request, log: [...log, L(`⚠ server sent chat history to a socket opened by ${o}`, `⚠ 服务器把聊天记录发给了 ${o} 打开的连接`), history], response: null, ...verdict(true, 'Cross-site WebSocket hijacking: like CSRF, but two-way, so the attacker reads the replies.', '跨站 WebSocket 劫持：类似 CSRF，但它是双向的，攻击者能读到回复。') };
      return { request, log: [...log, history], response: null, ...verdict(false, 'The real chat page loads alice’s history.', '真实聊天页面加载了 alice 的聊天记录。') };
    },
  },
  actors: [VICTIM, actor('evil', 'evil.example', L('attacker page', '攻击者页面'), 'red'), actor('ws', 'chat.shop.example', 'WebSocket', 'neutral')],
  flow: [
    msg('vic', 'evil', 'GET /', L('Alice visits the attacker’s page while logged in to the shop.', 'Alice 在登录商店的状态下访问了攻击者页面。')),
    msg('evil', 'vic', 'new WebSocket("wss://chat.shop.example")', L('WebSockets are not covered by the same-origin policy or CORS.', 'WebSocket 不受同源策略或 CORS 约束。'), 'attack'),
    msg('vic', 'ws', 'Upgrade: websocket  Origin: evil.example 🍪', L('The browser sends Alice’s cookies with the handshake.', '浏览器在握手时带上了 Alice 的 Cookie。'), 'attack'),
    msg('ws', 'vic', '101 Switching Protocols', L('The server only checks the session cookie.', '服务器只检查会话 Cookie。'), 'attack'),
    msg('ws', 'evil', 'chat history (via the socket)', L('The attacker’s script sends READY and receives Alice’s private messages.', '攻击者的脚本发送 READY，收到了 Alice 的私密消息。'), 'attack'),
  ],
  code: {
    vuln: `wss.on('connection', (ws, req) => {
  const user = sessionFromCookie(req.headers.cookie);
  ws.on('message', m => broadcast(user, m));
});`,
    fixed: `wss.on('connection', (ws, req) => {
  if (req.headers.origin !== 'https://chat.shop.example') return ws.close(1008);
  const user = verifyToken(new URL(req.url, 'wss://x').searchParams.get('t'));
  if (!user) return ws.close(1008);
  ws.on('message', m => broadcast(user, String(m).slice(0, 2000)));
});`,
  },
  defenses: [
    { title: L('Check Origin on the handshake', '握手时检查 Origin'), body: L('Reject upgrades from origins you don’t own.', '拒绝来自非自有源的升级请求。') },
    { title: L('Token-based auth', '基于 Token 的认证'), body: L('Use a short-lived token in the first message or URL instead of relying only on ambient cookies.', '在第一条消息或 URL 中使用短期 Token，而不是只依赖自动携带的 Cookie。') },
    { title: L('Treat messages as input', '把消息当作输入'), body: L('Validate, rate-limit and output-encode them like any HTTP parameter.', '像对待任何 HTTP 参数一样对它们做校验、限速和输出编码。') },
  ],
  qa: [
    { q: L('How is CSWSH different from CSRF?', 'CSWSH 与 CSRF 有什么不同？'), a: L('CSRF is one-way: the attacker cannot read the response. A hijacked WebSocket is two-way, so data flows back to the attacker.', 'CSRF 是单向的：攻击者读不到响应。被劫持的 WebSocket 是双向的，数据会回流给攻击者。') },
    { q: L('Do SameSite cookies help?', 'SameSite Cookie 有帮助吗？'), a: L('Yes. With Lax or Strict, cookies are not sent on the cross-site handshake. Still check Origin.', '有。Lax 或 Strict 下，跨站握手不会携带 Cookie。但仍要检查 Origin。') },
  ],
};

export const CLIENT = { cors, clickjacking, dom, websockets };
