// Logic for the first batch of server-side visuals. Pure functions, unit-tested.
const L = (en, zh) => ({ en, zh });

/* ───────────────────────── path traversal ───────────────────────── */
export const BASE = '/var/www/images/';
export const TREE = {
  etc: { passwd: 'root:x:0:0:root:/root:/bin/bash\ncarlos:x:1001:1001::/home/carlos:/bin/sh', hostname: 'shop-web-01' },
  home: { carlos: { secret: 'Zq8Lm2Vt' } },
  var: { www: { images: { '1.jpg': '<JPEG bytes>', '2.jpg': '<JPEG bytes>' }, app: { 'config.yml': 'db_password: Tr4versal-0k!' } } },
};

export const PT_DEFENCES = {
  none: L('No check', '不检查'),
  strip: L('Strip "../" once', '去掉一次 "../"'),
  reject: L('Reject "../", then URL-decode', '拒绝 "../"，然后再 URL 解码'),
  canon: L('Resolve, then check the prefix', '先解析路径，再检查前缀'),
};

export const PT_PRESETS = [
  { id: 'ok', label: '1.jpg', value: '1.jpg' },
  { id: 'up', label: '../../../etc/passwd', value: '../../../etc/passwd' },
  { id: 'nest', label: '....//....//....//etc/passwd', value: '....//....//....//etc/passwd' },
  { id: 'enc', label: '..%2f..%2f..%2fetc/passwd', value: '..%2f..%2f..%2fetc/passwd' },
  { id: 'abs', label: '/etc/passwd', value: '/etc/passwd' },
];

const lookup = (parts) => parts.reduce((n, p) => (n && typeof n === 'object' ? n[p] : undefined), TREE);

/** Walk the path segment by segment from the images folder. */
export function walkPath(input, defence) {
  let name = input;
  const notes = [];
  if (defence === 'strip') {
    name = input.replace(/\.\.\//g, '');
    notes.push(L(`After stripping: "${name}"`, `去掉之后："${name}"`));
  }
  if (defence === 'reject') {
    if (name.includes('../')) return { blocked: true, notes: [L('Contains "../" → 400', '包含 "../" → 400')], steps: [] };
    try {
      name = decodeURIComponent(name);
    } catch {
      /* leave as is */
    }
    notes.push(L(`Decoded after the check: "${name}"`, `检查之后才解码："${name}"`));
  }
  const start = name.startsWith('/') ? [] : BASE.split('/').filter(Boolean);
  const dir = [...start];
  const steps = [{ seg: name.startsWith('/') ? '/' : 'images/', at: [...dir] }];
  for (const seg of name.split('/').filter(Boolean)) {
    if (seg === '..') dir.pop();
    else if (seg !== '.') dir.push(seg);
    steps.push({ seg, at: [...dir] });
  }
  const full = '/' + dir.join('/');
  if (defence === 'canon' && !full.startsWith(BASE)) return { blocked: true, notes: [L(`Resolves to ${full}, outside ${BASE} → 403`, `解析为 ${full}，在 ${BASE} 之外 → 403`)], steps, full };
  const content = lookup(dir);
  return { blocked: false, notes, steps, full, content: typeof content === 'string' ? content : null, escaped: !full.startsWith(BASE) };
}

/* ───────────────────────── OS command injection ───────────────────────── */
export const SH_PRESETS = [
  { id: 'ok', label: 'example.com', value: 'example.com' },
  { id: 'semi', label: '; whoami', value: 'example.com; whoami' },
  { id: 'and', label: '&& cat secret', value: 'example.com && cat /home/carlos/secret' },
  { id: 'or', label: '|| id', value: 'nohost || id' },
  { id: 'sub', label: '$(whoami)', value: '$(whoami).example.com' },
  { id: 'pipe', label: '| ls', value: 'x | ls /home/carlos' },
];

export const SH_DEFENCES = {
  shell: L('sh -c "ping -c 1 " + host', 'sh -c "ping -c 1 " + host'),
  quoted: L('Wrapped in "double quotes"', '用 "双引号" 包起来'),
  argv: L('execFile("ping", ["-c","1", host])', 'execFile("ping", ["-c","1", host])'),
};

function cmd1(words) {
  const [c, ...a] = words;
  switch (c) {
    case 'ping': {
      const host = a.filter((x, i) => !(x === '-c' || a[i - 1] === '-c'))[0] ?? '';
      return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host) ? { out: `PING ${host}: 1 packets transmitted, 1 received`, ok: true } : { out: `ping: ${host || '(empty)'}: Name or service not known`, ok: false };
    }
    case 'whoami':
      return { out: 'www-data', ok: true };
    case 'id':
      return { out: 'uid=33(www-data) gid=33(www-data)', ok: true };
    case 'cat':
      return a[0] === '/home/carlos/secret' ? { out: 'Zq8Lm2Vt', ok: true } : { out: `cat: ${a[0]}: No such file`, ok: false };
    case 'ls':
      return { out: a[0] === '/home/carlos' ? 'secret  notes.txt' : 'index.php  images', ok: true };
    default:
      return { out: `sh: ${c}: not found`, ok: false };
  }
}

const OPS = /(;|&&|\|\||\||&|\n)/;

/** Split a command line the way sh does (simplified): operators, then $(…) / `…` substitution. */
export function runShell(host, defence) {
  if (defence === 'argv') {
    const r = cmd1(['ping', '-c', '1', host]);
    return { line: `execFile("ping", ["-c", "1", ${JSON.stringify(host)}])`, parts: [{ text: `ping -c 1 ${JSON.stringify(host)}`, op: null, ran: true, out: r.out, injected: false, oneArg: true }] };
  }
  const line = defence === 'quoted' ? `ping -c 1 "${host}"` : `ping -c 1 ${host}`;
  const tokens = defence === 'quoted' && !host.includes('"') ? [line] : line.split(OPS);
  const parts = [];
  let lastOk = true;
  for (let i = 0; i < tokens.length; i += 2) {
    const op = i === 0 ? null : tokens[i - 1];
    let text = tokens[i].trim();
    if (!text) continue;
    const skip = (op === '&&' && !lastOk) || (op === '||' && lastOk);
    const subs = [];
    const expanded = text.replace(/\$\(([^)]*)\)|`([^`]*)`/g, (_, a, b) => {
      const r = cmd1((a ?? b).trim().split(/\s+/));
      subs.push({ cmd: (a ?? b).trim(), out: r.out });
      return r.out;
    });
    const words = expanded.replace(/"/g, '').split(/\s+/);
    const r = skip ? { out: '', ok: lastOk } : cmd1(words);
    parts.push({ text, op, ran: !skip, out: r.out, subs, injected: i > 0 || subs.length > 0 });
    if (!skip) lastOk = r.ok;
  }
  return { line, parts };
}

/* ───────────────────────── IDOR ───────────────────────── */
export const OWNERS = ['bob', 'carol', 'dave', 'alice', 'erin', 'bob', 'carol', 'frank', 'alice', 'dave', 'erin', 'carol'];
export const FIRST_ID = 1001;
export const invoiceRows = () => OWNERS.map((owner, i) => ({ id: FIRST_ID + i, owner, amount: 40 + ((i * 37) % 160) }));

/** What GET /api/invoices/:id returns to alice. */
export function fetchInvoice(id, mode) {
  const row = invoiceRows().find((r) => r.id === id);
  if (!row) return { status: 404 };
  if (mode === 'owner' && row.owner !== 'alice') return { status: 403, row };
  return { status: 200, row, leak: row.owner !== 'alice' };
}

/* ───────────────────────── auth: username enumeration ───────────────────────── */
export const USERS = { carlos: 'montana', alice: 'wonderland' };
export const CANDIDATES = ['admin', 'root', 'test', 'carlos', 'guest', 'info', 'adm', 'oracle'];
export const PASSWORDS = ['123456', 'password', 'qwerty', 'letmein', 'monkey', 'dragon', 'montana', 'shadow'];
export const AUTH_MODES = {
  verbose: L('Different error messages', '不同的错误提示'),
  timing: L('Same message, different timing', '提示相同，耗时不同'),
  hardened: L('Same message and timing', '提示和耗时都相同'),
};

/** Response to a login attempt with a wrong password. Times in ms; deterministic jitter. */
export function tryUser(name, mode, i = 0) {
  const real = name in USERS;
  const jitter = (i * 7) % 9;
  if (mode === 'verbose') return { msg: real ? L('Incorrect password', '密码错误') : L('Invalid username', '用户名不存在'), ms: 18 + jitter, real };
  if (mode === 'timing') return { msg: L('Invalid username or password', '用户名或密码错误'), ms: real ? 142 + jitter : 18 + jitter, real };
  return { msg: L('Invalid username or password', '用户名或密码错误'), ms: 140 + jitter, real };
}

/** Brute-force a known user's password. lockout: lock after 5 failures. */
export function bruteForce(user, lockout) {
  const tries = [];
  for (let i = 0; i < PASSWORDS.length; i++) {
    if (lockout && i >= 5) {
      tries.push({ pw: PASSWORDS[i], result: 'locked' });
      continue;
    }
    tries.push({ pw: PASSWORDS[i], result: USERS[user] === PASSWORDS[i] ? 'ok' : 'fail' });
    if (USERS[user] === PASSWORDS[i]) break;
  }
  return tries;
}

/* ───────────────────────── race condition ───────────────────────── */
export const RACE_MODES = {
  sequential: L('One after another', '一个接一个'),
  parallel: L('In parallel (network jitter)', '并发（有网络抖动）'),
  packet: L('Single-packet attack', '单包攻击'),
};
export const CHECK_TO_WRITE = 30; // ms between reading "coupon unused" and writing "used"

/** Arrival, check and write times per request, and whether each applied the coupon. */
export function raceRun(n, mode, atomic) {
  const reqs = [];
  for (let i = 0; i < n; i++) {
    const arrive = mode === 'sequential' ? i * 60 : mode === 'parallel' ? ((i * 37) % 11) * 8 : i * 0.3;
    reqs.push({ i, arrive, check: arrive + 2, write: arrive + 2 + CHECK_TO_WRITE });
  }
  const order = [...reqs].sort((a, b) => a.check - b.check);
  let firstWrite = Infinity;
  let used = false;
  for (const r of order) {
    if (atomic) {
      // UPDATE coupons SET used = 1 WHERE code = ? AND used = 0 — only one row update can win
      r.ok = !used;
      used = true;
    } else {
      r.ok = r.check < firstWrite;
      if (r.ok) firstWrite = Math.min(firstWrite, r.write);
    }
  }
  return { reqs, applied: reqs.filter((r) => r.ok).length, end: Math.max(...reqs.map((r) => r.write)) + 10 };
}

/* ───────────────────────── file upload ───────────────────────── */
const PHP = "<?php system($_GET['cmd']); ?>";
export const FILES = [
  { id: 'png', label: 'avatar.png', name: 'avatar.png', type: 'image/png', body: '\x89PNG…(image data)' },
  { id: 'php', label: 'shell.php', name: 'shell.php', type: 'application/x-php', body: PHP },
  { id: 'ctype', label: L('shell.php as image/png', 'shell.php（伪装成 image/png）'), name: 'shell.php', type: 'image/png', body: PHP },
  { id: 'case', label: 'shell.pHp', name: 'shell.pHp', type: 'image/png', body: PHP },
  { id: 'poly', label: L('GIF89a + PHP (polyglot)', 'GIF89a + PHP（多语言文件）'), name: 'shell.phtml', type: 'image/gif', body: 'GIF89a' + PHP },
  { id: 'dbl', label: 'shell.php.jpg', name: 'shell.php.jpg', type: 'image/jpeg', body: PHP },
];

export const GATES = {
  block: L('Block the extension ".php"', '拦截 ".php" 扩展名'),
  ctype: L('Content-Type must be image/*', 'Content-Type 必须是 image/*'),
  magic: L('First bytes must be an image signature', '文件开头必须是图片签名'),
  allow: L('Allowlist: .jpg .png .gif (any case)', '白名单：.jpg .png .gif（不分大小写）'),
  store: L('Random name, served as a download', '随机文件名，以下载方式提供'),
};

const ext = (n) => (n.match(/\.([^.]+)$/)?.[1] ?? '');

/** Push a file through the enabled gates. The server runs .php/.phtml files in /uploads (any case). */
export function upload(file, gates) {
  const checks = [];
  const fail = (k, why) => ({ checks: [...checks, { k, pass: false, why }], stored: null });
  if (gates.block) {
    if (ext(file.name) === 'php') return fail('block', L('".php" is on the blocklist', '".php" 在黑名单里'));
    checks.push({ k: 'block', pass: true, why: L(`".${ext(file.name)}" is not exactly ".php"`, `".${ext(file.name)}" 不完全等于 ".php"`) });
  }
  if (gates.ctype) {
    if (!file.type.startsWith('image/')) return fail('ctype', L(`Content-Type ${file.type}`, `Content-Type 是 ${file.type}`));
    checks.push({ k: 'ctype', pass: true, why: L(`Says ${file.type} (the client chose that)`, `声称是 ${file.type}（这是客户端自己填的）`) });
  }
  if (gates.magic) {
    if (!/^(\x89PNG|GIF8|\xff\xd8)/.test(file.body)) return fail('magic', L('No image signature', '没有图片签名'));
    checks.push({ k: 'magic', pass: true, why: L('Starts like an image', '开头像一张图片') });
  }
  if (gates.allow) {
    if (!/^(jpe?g|png|gif)$/i.test(ext(file.name))) return fail('allow', L(`".${ext(file.name)}" is not an image extension`, `".${ext(file.name)}" 不是图片扩展名`));
    checks.push({ k: 'allow', pass: true, why: L('Image extension', '图片扩展名') });
  }
  const stored = gates.store ? `/uploads/7f3a9c2e.${(ext(file.name) || 'bin').toLowerCase()}` : `/uploads/${file.name}`;
  const runs = !gates.store && /^(php|phtml)$/i.test(ext(file.name)) && file.body.includes('<?php');
  if (gates.store) checks.push({ k: 'store', pass: true, why: L('Saved under a random name, sent with Content-Disposition: attachment', '以随机文件名保存，并以 Content-Disposition: attachment 返回') });
  return { checks, stored, runs };
}
