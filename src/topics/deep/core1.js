import { L, decodeOnce, escHtml, htmlExec, jsExec, verdict } from './lib.js';

/* =============================================================== SQLi */
const ADMIN_PW = 'k7x2q9';
const USERS = [
  ['administrator', ADMIN_PW],
  ['wiener', 'peter'],
  ['carlos', 'montoya'],
];

// Evaluate the conditions attackers typically use in blind SQLi.
function blindCondition(sqlTail) {
  const t = sqlTail;
  const sub = /substring\(\s*\(\s*select\s+password\s+from\s+users\s+where\s+username\s*=\s*'administrator'\s*\)\s*,\s*(\d+)\s*,\s*1\s*\)\s*([=<>])\s*'(.)'/i.exec(t);
  if (sub) {
    const c = ADMIN_PW[Number(sub[1]) - 1] ?? '';
    const v = sub[3];
    return { known: true, value: sub[2] === '=' ? c === v : sub[2] === '>' ? c > v : c < v };
  }
  const len = /length\(\s*\(\s*select\s+password\s+from\s+users\s+where\s+username\s*=\s*'administrator'\s*\)\s*\)\s*([=<>])\s*(\d+)/i.exec(t);
  if (len) {
    const n = ADMIN_PW.length;
    const v = Number(len[2]);
    return { known: true, value: len[1] === '=' ? n === v : len[1] === '>' ? n > v : n < v };
  }
  const lit = /'(\w*)'\s*=\s*'(\w*)/i.exec(t) || /(\d+)\s*=\s*(\d+)/.exec(t);
  if (lit) return { known: true, value: lit[1] === lit[2] };
  return { known: false, value: false };
}

const PARAM = { label: L('Query building', '查询构造'), off: L('Concatenation', '字符串拼接'), on: L('Parameterised', '参数化') };

function unionRun(input, { blockUpper = false } = {}) {
  const sql = `SELECT name, price FROM products WHERE category = '${input}'`;
  const log = [sql];
  const products = [['Lightweight jacket', '$1337'], ['Beach ball', '$12']];
  if (blockUpper && /UNION|SELECT/.test(input)) return { sql, log: [...log, L('WAF: blocked keyword', 'WAF：拦截到关键字')], response: 'HTTP/1.1 403 "Attack detected"', rows: null };
  const u = /'\s*union\s+(all\s+)?select\s+(.+?)\s+from\s+(\w+)\s*(--.*)?$/i.exec(input);
  const ob = /'\s*order\s+by\s+(\d+)\s*--/i.exec(input);
  if (ob) {
    const n = Number(ob[1]);
    return n > 2 ? { sql, log, response: `HTTP/1.1 500\n\nERROR: ORDER BY position ${n} is not in select list`, rows: null } : { sql, log, response: 'HTTP/1.1 200 (sorted)', rows: products };
  }
  if (u) {
    const cols = u[2].split(',').map((c) => c.trim());
    if (cols.length !== 2) return { sql, log, response: 'HTTP/1.1 500\n\nERROR: each UNION query must have the same number of columns', rows: null };
    if (u[3].toLowerCase() !== 'users') return { sql, log, response: `HTTP/1.1 500\n\nERROR: relation "${u[3]}" does not exist`, rows: null };
    const pick = (c, row) => (c.toLowerCase() === 'username' ? row[0] : c.toLowerCase() === 'password' ? row[1] : c.replace(/'/g, ''));
    return { sql, log, response: null, rows: [...(input.startsWith("Gifts'") ? products : []), ...USERS.map((r) => [pick(cols[0], r), pick(cols[1], r)])], union: true };
  }
  if (input.includes("'") && !/'\s*--\s*$/.test(input) && (input.match(/'/g).length % 2 === 1)) return { sql, log, response: 'HTTP/1.1 500\n\nERROR: unterminated quoted string', rows: null };
  return { sql, log, response: null, rows: input === 'Gifts' ? products : [] };
}
const rowsText = (rows) => rows.map((r) => r.join('  |  ')).join('\n') || '(no products)';

const sqli = {
  variants: [
    {
      id: 'union',
      title: L('UNION-based', '联合查询（UNION）'),
      summary: L(
        'When query results are shown on the page, UNION SELECT appends rows from any other table. First find the number of columns (ORDER BY n until it errors), then pull data through them.',
        '当查询结果会显示在页面上时，UNION SELECT 可以把其他表的行拼接进来。先用 ORDER BY n 试出列数（直到报错），再通过这些列取出数据。',
      ),
      lab: {
        fields: [{ id: 'c', label: L('category parameter', 'category 参数'), default: "Gifts' ORDER BY 3--" }],
        presets: [
          { label: 'Gifts', values: { c: 'Gifts' } },
          { label: 'ORDER BY 2', values: { c: "Gifts' ORDER BY 2--" } },
          { label: 'ORDER BY 3', values: { c: "Gifts' ORDER BY 3--" } },
          { label: L('3 columns (wrong)', '3 列（错误）'), values: { c: "' UNION SELECT NULL, NULL, NULL FROM users--" } },
          { label: L('Dump users', '导出 users 表'), values: { c: "' UNION SELECT username, password FROM users--" } },
        ],
        defense: PARAM,
        run({ values, defended }) {
          const request = `GET /filter?category=${encodeURIComponent(values.c)} HTTP/1.1`;
          if (defended) return { request, log: ["SELECT name, price FROM products WHERE category = $1", `$1 = ${JSON.stringify(values.c)}`], response: '(no products)', ...verdict(false, 'The whole string is one value. No category is literally called that.', '整个字符串只是一个值，没有哪个分类真的叫这个名字。') };
          const r = unionRun(values.c);
          if (!r.rows) return { request, log: r.log, response: r.response, verdict: 'neutral', message: L('An error. With ORDER BY, the first failing n tells you the column count (here: 2).', '报错了。用 ORDER BY 时，第一个报错的 n 就告诉你列数（这里是 2）。') };
          return { request, log: r.log, response: `HTTP/1.1 200 OK\n\n${rowsText(r.rows)}`, ...(r.union ? verdict(true, 'Usernames and passwords are rendered as if they were products.', '用户名和密码被当作商品显示了出来。') : { verdict: 'neutral', message: L('Normal listing.', '正常列表。') }) };
        },
      },
      takeaway: L('Column count and types must match. ORDER BY or UNION SELECT NULL,… finds the count.', '列数和类型必须匹配。用 ORDER BY 或 UNION SELECT NULL,… 来确定列数。'),
    },
    {
      id: 'error',
      title: L('Error-based', '报错注入'),
      summary: L(
        'If the app shows database errors, you can force an error whose message contains data, e.g. by casting a password to an integer.',
        '如果应用会显示数据库错误，就可以故意制造一个错误，让错误信息里带出数据，比如把密码强制转换成整数。',
      ),
      lab: {
        fields: [{ id: 't', label: L('TrackingId cookie value', 'TrackingId Cookie 值'), default: "x' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--" }],
        presets: [
          { label: L('Normal', '正常'), values: { t: 'xyz' } },
          { label: L('Syntax error', '语法错误'), values: { t: "xyz'" } },
          { label: L('CAST leak', 'CAST 泄露'), values: { t: "x' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--" } },
        ],
        defense: { label: L('Errors', '错误处理'), off: L('Verbose', '详细错误'), on: L('Parameterised + generic', '参数化 + 通用错误') },
        run({ values, defended }) {
          const t = values.t;
          const request = `GET / HTTP/1.1\nCookie: TrackingId=${t}`;
          const sql = `SELECT id FROM tracking WHERE id = '${t}'`;
          if (defended) return { request, log: ['SELECT id FROM tracking WHERE id = $1'], response: 'HTTP/1.1 200 OK', ...verdict(false, 'No injection and no error details.', '没有注入，也没有错误细节。') };
          const cast = /cast\(\s*\(\s*select\s+(username|password)\s+from\s+users\s+limit\s+1\s*\)\s+as\s+int\s*\)/i.exec(t);
          if (cast) {
            const v = cast[1].toLowerCase() === 'password' ? ADMIN_PW : 'administrator';
            return { request, log: [sql], response: `HTTP/1.1 500\n\nERROR: invalid input syntax for type integer: "${v}"`, ...verdict(true, 'The database helpfully printed the value it failed to convert.', '数据库“贴心地”把转换失败的值打印了出来。') };
          }
          if ((t.match(/'/g) || []).length % 2 === 1 && !/--/.test(t)) return { request, log: [sql], response: 'HTTP/1.1 500\n\nERROR: unterminated quoted string at or near "\'"', verdict: 'neutral', message: L('Errors are visible: now make one that carries data.', '错误是可见的：现在构造一个能带出数据的错误。') };
          return { request, log: [sql], response: 'HTTP/1.1 200 OK', verdict: 'neutral', message: L('Normal.', '正常。') };
        },
      },
      takeaway: L('Never show raw database errors; they turn a blind bug into a visible one.', '永远不要显示原始数据库错误，它会把盲注变成可见的注入。'),
    },
    {
      id: 'boolean',
      title: L('Blind: boolean', '布尔盲注'),
      summary: L(
        'No data and no errors are shown, but the page changes slightly when the query returns a row (“Welcome back!”). Ask yes/no questions and read the answer from that difference, one character at a time.',
        '页面既不显示数据也不显示错误，但查询返回结果时页面会有细微差别（“Welcome back!”）。提出是/否问题，通过这个差别读出答案，一次一个字符。',
      ),
      lab: {
        fields: [{ id: 't', label: L('TrackingId cookie value', 'TrackingId Cookie 值'), default: "xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='k'--" }],
        presets: [
          { label: "AND '1'='1", values: { t: "xyz' AND '1'='1" } },
          { label: "AND '1'='2", values: { t: "xyz' AND '1'='2" } },
          { label: L('Length > 5?', '长度 > 5？'), values: { t: "xyz' AND LENGTH((SELECT password FROM users WHERE username='administrator'))>5--" } },
          { label: L('1st char = a?', '第 1 位 = a？'), values: { t: "xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--" } },
          { label: L('1st char = k?', '第 1 位 = k？'), values: { t: "xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='k'--" } },
        ],
        defense: PARAM,
        run({ values, defended }) {
          const t = values.t;
          const request = `GET / HTTP/1.1\nCookie: TrackingId=${t}`;
          if (defended) return { request, log: ['SELECT … WHERE id = $1'], response: 'HTTP/1.1 200 OK\n\n(no "Welcome back")', ...verdict(false, 'Every injected condition is just part of an unknown ID.', '所有注入的条件都只是一个未知 ID 的一部分。') };
          const base = t.startsWith('xyz');
          const c = blindCondition(t.slice(3));
          const yes = base && (!c.known || c.value);
          return { request, log: [`SELECT … WHERE id = '${t}'`, c.known ? L(`condition evaluates to ${c.value}`, `条件结果为 ${c.value}`) : ''].filter(Boolean), response: `HTTP/1.1 200 OK\n\n${yes ? '<p>Welcome back!</p>' : '(no message)'}`, ...(c.known && c.value && /substring|length/i.test(t) ? verdict(true, '“Welcome back” = yes. Repeat for each position to rebuild the password.', '出现“Welcome back”就表示“是”。对每个位置重复，就能还原整个密码。') : { verdict: 'neutral', message: L(yes ? 'Message shown: condition true.' : 'No message: condition false.', yes ? '显示了欢迎语：条件为真。' : '没有欢迎语：条件为假。') }) };
        },
      },
      takeaway: L('Tools like Burp Intruder or sqlmap automate the hundreds of requests this takes.', 'Burp Intruder 或 sqlmap 这类工具能自动完成所需的数百个请求。'),
    },
    {
      id: 'time',
      title: L('Blind: time-based', '时间盲注'),
      summary: L(
        'When the page looks identical either way, make the database pause only if a condition is true. The response time is the oracle.',
        '当页面无论如何都一模一样时，可以让数据库只在条件为真时暂停。响应时间就是“预言机”。',
      ),
      lab: {
        fields: [{ id: 't', label: L('TrackingId cookie value', 'TrackingId Cookie 值'), default: "x'; SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='k') THEN pg_sleep(5) ELSE pg_sleep(0) END--" }],
        presets: [
          { label: 'pg_sleep(5)', values: { t: "x'; SELECT pg_sleep(5)--" } },
          { label: L('Conditional: true', '条件为真'), values: { t: "x'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--" } },
          { label: L('Conditional: false', '条件为假'), values: { t: "x'; SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END--" } },
          { label: L('1st char = k?', '第 1 位 = k？'), values: { t: "x'; SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='k') THEN pg_sleep(5) ELSE pg_sleep(0) END--" } },
        ],
        defense: PARAM,
        run({ values, defended }) {
          const t = values.t;
          const request = `GET / HTTP/1.1\nCookie: TrackingId=${t}`;
          if (defended) return { request, log: ['SELECT … WHERE id = $1'], response: 'HTTP/1.1 200 OK  (82 ms)', ...verdict(false, 'pg_sleep is just text inside a value.', 'pg_sleep 只是值里的一段文本。') };
          const sleep = /pg_sleep\((\d+)\)/i.exec(t);
          let secs = 0;
          const cw = /case\s+when\s*\((.+?)\)\s*then\s+pg_sleep\((\d+)\)\s*else\s+pg_sleep\((\d+)\)/i.exec(t);
          if (cw) {
            const c = blindCondition(cw[1]);
            secs = c.value ? Number(cw[2]) : Number(cw[3]);
          } else if (sleep) secs = Number(sleep[1]);
          const ms = 80 + secs * 1000;
          return { request, log: [L(`stacked query runs; database sleeps ${secs}s`, `堆叠查询被执行；数据库暂停 ${secs} 秒`)], response: `HTTP/1.1 200 OK  (${ms} ms)`, ...(secs > 0 ? verdict(true, `A ${secs}s delay answers “yes”.`, `${secs} 秒的延迟回答了“是”。`) : { verdict: 'neutral', message: L('Fast response: the answer is “no” (or no injection).', '响应很快：答案是“否”（或者没有注入）。') }) };
        },
      },
      takeaway: L('Time-based payloads differ per database: SLEEP() in MySQL, WAITFOR DELAY in SQL Server, pg_sleep() in PostgreSQL.', '不同数据库的时间延迟函数不同：MySQL 用 SLEEP()，SQL Server 用 WAITFOR DELAY，PostgreSQL 用 pg_sleep()。'),
    },
    {
      id: 'second',
      title: L('Second-order', '二次注入'),
      summary: L(
        'Input is stored safely, but later read back from the database and trusted, then concatenated into a new query somewhere else.',
        '输入在存储时是安全的，但之后从数据库读出来时被当成可信数据，又在别处被拼进了新的查询。',
      ),
      lab: {
        fields: [{ id: 'u', label: L('Username you register', '你注册的用户名'), default: "administrator'--" }],
        presets: [
          { label: L('Normal name', '正常名字'), values: { u: 'mallory' } },
          { label: "administrator'--", values: { u: "administrator'--" } },
        ],
        defense: { label: L('Password change query', '修改密码的查询'), off: L('Concatenates stored username', '拼接已存储的用户名'), on: L('Parameterised everywhere', '处处参数化') },
        run({ values, defended }) {
          const u = values.u;
          const request = `1) POST /register  username=${u}  (stored with a parameterised INSERT ✓)\n2) POST /change-password  new=hacked  (as ${u})`;
          if (defended) return { request, log: ['UPDATE users SET password = $1 WHERE username = $2', `$2 = ${JSON.stringify(u)}`], response: `Password changed for "${u}"`, ...verdict(false, 'Data from your own database is still untrusted input.', '来自自己数据库的数据，仍然是不可信输入。') };
          const sql = `UPDATE users SET password = 'hacked' WHERE username = '${u}'`;
          const target = /^(\w+)'\s*--/.exec(u);
          return { request, log: [sql, target ? L(`⚠ WHERE clause now targets "${target[1]}"`, `⚠ WHERE 子句现在指向 "${target[1]}"`) : ''].filter(Boolean), response: `Password changed`, ...(target ? verdict(true, `You changed ${target[1]}’s password, not your own.`, `你修改的是 ${target[1]} 的密码，而不是你自己的。`) : { verdict: 'neutral', message: L('Normal.', '正常。') }) };
        },
      },
      takeaway: L('Every query must be parameterised, not just the ones that touch request data directly.', '所有查询都必须参数化，而不仅仅是直接接触请求数据的那些。'),
    },
  ],
  challenges: [
    {
      title: L('Log in as administrator', '以 administrator 身份登录'),
      goal: L('The login query is SELECT * FROM users WHERE username = \'U\' AND password = \'P\'. Log in as administrator without knowing the password.', '登录查询为 SELECT * FROM users WHERE username = \'U\' AND password = \'P\'。不知道密码，以 administrator 登录。'),
      fields: [
        { id: 'u', label: L('Username', '用户名') },
        { id: 'p', label: L('Password', '密码') },
      ],
      run({ u, p }) {
        const sql = `SELECT * FROM users WHERE username = '${u}' AND password = '${p}'`;
        const m = /^(\w+)'\s*(--|#)/.exec(u);
        let who = null;
        if (m) who = USERS.find((x) => x[0] === m[1])?.[0];
        else if (/'\s*or\s*'?1'?\s*=\s*'?1/i.test(u)) who = 'administrator';
        else who = USERS.find((x) => x[0] === u && x[1] === p)?.[0];
        return { log: [sql], response: who ? `302 → /my-account  (logged in as ${who})` : '200 "Invalid username or password"', who };
      },
      check: (v, o) => o.who === 'administrator',
      hint: L('Can you end the username string early and make the rest of the line a comment?', '能不能提前结束用户名字符串，再把这一行剩下的部分变成注释？'),
      solution: "username: administrator'--   password: anything",
      explain: L("The quote closes the string and -- comments out AND password = '…', so the query only checks the username.", "引号闭合了字符串，-- 把 AND password = '…' 注释掉了，于是查询只检查用户名。"),
    },
    {
      title: L('Steal the administrator password with UNION', '用 UNION 偷出 administrator 的密码'),
      goal: L('The product filter runs SELECT name, price FROM products WHERE category = \'X\' and shows the rows. Make the administrator’s password appear on the page.', '商品筛选执行 SELECT name, price FROM products WHERE category = \'X\'，并显示结果行。让 administrator 的密码出现在页面上。'),
      fields: [{ id: 'c', label: L('category parameter', 'category 参数') }],
      run({ c }) {
        const r = unionRun(c);
        return { log: r.log, response: r.rows ? rowsText(r.rows) : r.response };
      },
      check: (v, o) => String(o.response).includes(ADMIN_PW),
      hint: L('Two columns. The table is users, with columns username and password.', '两列。表名是 users，列名是 username 和 password。'),
      solution: "' UNION SELECT username, password FROM users--",
      explain: L('UNION appends a second result set with the same number of columns. The page cannot tell product rows from user rows.', 'UNION 追加了一个列数相同的结果集。页面分不清哪些是商品行、哪些是用户行。'),
    },
    {
      title: L('Beat the keyword filter', '绕过关键字过滤'),
      goal: L('Same query, but a WAF now blocks any request containing UNION or SELECT. Get the password anyway.', '同样的查询，但现在 WAF 会拦截任何包含 UNION 或 SELECT 的请求。照样拿到密码。'),
      fields: [{ id: 'c', label: L('category parameter', 'category 参数') }],
      run({ c }) {
        const r = unionRun(c, { blockUpper: true });
        return { log: r.log, response: r.rows ? rowsText(r.rows) : r.response };
      },
      check: (v, o) => String(o.response).includes(ADMIN_PW),
      hint: L('Is SQL case-sensitive about keywords? Is the filter?', 'SQL 关键字区分大小写吗？这个过滤器呢？'),
      solution: "' union select username, password from users--",
      explain: L('SQL keywords are case-insensitive, but the blocklist only matched uppercase. Blocklists fail against encodings, case, comments (UN/**/ION) and more; only parameterisation fixes the root cause.', 'SQL 关键字不区分大小写，而黑名单只匹配了大写。黑名单挡不住编码、大小写、注释（UN/**/ION）等各种变形；只有参数化才能从根本上解决问题。'),
    },
  ],
  cases: [
    { year: '2008', ref: L('Heartland Payment Systems', 'Heartland 支付系统'), title: L('Card data for ~130 million cards', '约 1.3 亿张银行卡数据'), what: L('Attackers led by Albert Gonzalez used SQL injection to get a foothold in Heartland’s network, then installed sniffers that captured payment card data in transit. It was among the largest card breaches ever reported.', '以 Albert Gonzalez 为首的攻击者利用 SQL 注入进入 Heartland 的网络，随后安装嗅探程序，截获传输中的银行卡数据。这是史上报道过的最大规模银行卡泄露事件之一。'), lesson: L('One injectable web form can be the entry point to an entire payment network.', '一个可注入的网页表单，就可能成为进入整个支付网络的入口。') },
    { year: '2015', ref: L('TalkTalk (UK)', 'TalkTalk（英国）'), title: L('Telecom customer data via legacy pages', '通过遗留页面泄露的电信客户数据'), what: L('Attackers used SQL injection against legacy web pages to access personal data of about 157,000 customers. The UK ICO fined TalkTalk £400,000, noting the technique was well known and easy to prevent.', '攻击者对遗留网页使用 SQL 注入，获取了约 15.7 万名客户的个人数据。英国信息专员办公室（ICO）对 TalkTalk 罚款 40 万英镑，并指出这种手法广为人知、很容易防范。'), lesson: L('Forgotten legacy pages count as attack surface.', '被遗忘的遗留页面同样是攻击面。') },
    { year: '2023', ref: 'CVE-2023-34362', title: L('MOVEit Transfer mass exploitation', 'MOVEit Transfer 被大规模利用'), what: L('A SQL injection in Progress MOVEit Transfer, a file-transfer product, was exploited by the Cl0p ransomware group as a zero-day to steal data from many organisations worldwide.', '文件传输产品 Progress MOVEit Transfer 中的一个 SQL 注入，被 Cl0p 勒索软件团伙当作零日漏洞利用，从全球众多机构窃取了数据。'), lesson: L('SQLi is not just a beginner bug; it still drives major incidents.', 'SQL 注入不只是新手漏洞，至今仍在引发重大安全事件。') },
  ],
};

/* =============================================================== XSS */
function xssResult(html, extra = []) {
  const ex = htmlExec(html);
  return { ex, log: [...extra, ex.length ? L(`⚠ would execute: ${ex[0]}`, `⚠ 将会执行：${ex[0]}`) : L('nothing executable in the output', '输出中没有可执行内容')] };
}
const ENC = { label: L('Output', '输出方式'), off: L('Raw', '原样输出'), on: L('Context-aware encoding', '按上下文编码') };
const jsStr = (s) => s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/</g, '\\u003c').replace(/>/g, '\\u003e');

const xss = {
  variants: [
    {
      id: 'reflected',
      title: L('Reflected', '反射型'),
      summary: L('The payload travels in the request (often a URL) and comes straight back in the response. The attacker has to get the victim to open a crafted link.', 'payload 位于请求中（通常是 URL），并直接出现在响应里。攻击者需要诱使受害者打开构造好的链接。'),
      lab: {
        fields: [{ id: 'q', label: 'search ?q=', default: '<img src=x onerror=alert(document.domain)>' }],
        presets: [
          { label: L('Plain text', '普通文本'), values: { q: 'red shoes' } },
          { label: '<script>', values: { q: '<script>alert(1)</script>' } },
          { label: '<img onerror>', values: { q: '<img src=x onerror=alert(document.domain)>' } },
          { label: '<svg onload>', values: { q: '<svg onload=alert(1)>' } },
        ],
        defense: ENC,
        run({ values, defended }) {
          const q = defended ? escHtml(values.q) : values.q;
          const html = `<h1>Results for: ${q}</h1>`;
          const r = xssResult(html);
          return { request: `GET /search?q=${encodeURIComponent(values.q)}`, log: r.log, response: html, ...(r.ex.length ? verdict(true, 'Anyone who opens this link runs the script on the site.', '任何打开这个链接的人都会在该站点上运行这段脚本。') : verdict(false, 'Rendered as text.', '被当作文本显示。')) };
        },
      },
    },
    {
      id: 'attr',
      title: L('Attribute context', '属性上下文'),
      summary: L('Input lands inside a quoted attribute. Angle brackets don’t matter here; a quote ends the attribute and lets you add your own, like an event handler.', '输入位于带引号的属性中。这里尖括号无关紧要；一个引号就能结束属性，然后加上你自己的属性，比如事件处理器。'),
      lab: {
        fields: [{ id: 'q', label: L('Value reflected in <input value="…">', '反射到 <input value="…"> 中的值'), default: '" autofocus onfocus=alert(1) x="' }],
        presets: [
          { label: L('Plain', '普通'), values: { q: 'shoes' } },
          { label: L('Tag (doesn’t work)', '标签（无效）'), values: { q: '<script>alert(1)</script>' } },
          { label: L('Quote breakout', '引号逃逸'), values: { q: '" autofocus onfocus=alert(1) x="' } },
        ],
        defense: ENC,
        run({ values, defended }) {
          const q = defended ? escHtml(values.q) : values.q.replace(/</g, '&lt;').replace(/>/g, '&gt;');
          const html = `<input name="q" value="${q}">`;
          const r = xssResult(html, [L(defended ? 'all of < > " \' & encoded' : 'only < and > are encoded', defended ? '< > " \' & 全部编码' : '只编码了 < 和 >')]);
          return { request: `GET /search?q=${encodeURIComponent(values.q)}`, log: r.log, response: html, ...(r.ex.length ? verdict(true, 'The quote ended value="…" and added an onfocus handler; autofocus fires it.', '引号结束了 value="…"，并加上了 onfocus 处理器；autofocus 会触发它。') : verdict(false, 'Stayed inside the attribute value.', '仍停留在属性值内部。')) };
        },
      },
      takeaway: L('Encoding must match the context: HTML body, attribute, JS, URL, CSS each need different rules.', '编码必须与上下文匹配：HTML 正文、属性、JS、URL、CSS 各有不同的规则。'),
    },
    {
      id: 'js',
      title: L('JavaScript string', 'JavaScript 字符串'),
      summary: L('Input is placed inside a JS string in a <script> block. Break out of the string, or close the whole script tag.', '输入被放进 <script> 块中的 JS 字符串里。可以逃出字符串，或者直接闭合整个 script 标签。'),
      lab: {
        fields: [{ id: 'q', label: "var search = '…';", default: "';alert(document.domain)//" }],
        presets: [
          { label: L('Plain', '普通'), values: { q: 'shoes' } },
          { label: "'; alert(1)//", values: { q: "';alert(document.domain)//" } },
          { label: '</script>', values: { q: '</script><img src=x onerror=alert(1)>' } },
        ],
        defense: { label: L('Output', '输出方式'), off: L('Raw', '原样输出'), on: L('JS-string escaping', 'JS 字符串转义') },
        run({ values, defended }) {
          const q = defended ? jsStr(values.q) : values.q;
          const code = `var search = '${q}';`;
          const html = `<script>${code}</script>`;
          const r = xssResult(html, [code]);
          return { request: `GET /search?q=${encodeURIComponent(values.q)}`, log: r.log, response: html, ...(r.ex.length ? verdict(true, 'Your input became JavaScript code.', '你的输入变成了 JavaScript 代码。') : verdict(false, defended ? "' became \\' and < became \\u003c: still one string." : 'Still a string.', defended ? "' 变成 \\'，< 变成 \\u003c：仍然只是一个字符串。" : '仍然只是字符串。')) };
        },
      },
    },
    {
      id: 'href',
      title: L('URL / href context', 'URL / href 上下文'),
      summary: L('A user-supplied link (a website field on a profile) is placed in href. HTML-encoding is not enough: javascript: URLs run when clicked.', '用户提供的链接（比如个人资料里的网站字段）被放进了 href。只做 HTML 编码不够：javascript: URL 被点击时会执行。'),
      lab: {
        fields: [{ id: 'u', label: L('Website field', '网站字段'), default: 'javascript:alert(document.cookie)' }],
        presets: [
          { label: 'https://', values: { u: 'https://alice.example' } },
          { label: 'javascript:', values: { u: 'javascript:alert(document.cookie)' } },
          { label: L('Mixed case + entity', '大小写 + 实体'), values: { u: 'JaVaScRiPt&colon;alert(1)' } },
        ],
        defense: { label: L('URL handling', 'URL 处理'), off: L('HTML-encode only', '仅 HTML 编码'), on: L('Allow http(s) only', '仅允许 http(s)') },
        run({ values, defended }) {
          let u = values.u;
          if (defended && !/^https?:\/\//i.test(u)) u = '#';
          const html = `<a href="${u.replace(/"/g, '&quot;')}">My website</a>`;
          const r = xssResult(html);
          return { request: `POST /profile  website=${values.u}`, log: defended && u === '#' ? [L('🛡 scheme not http/https → replaced with #', '🛡 协议不是 http/https → 替换为 #')] : r.log, response: html, ...(r.ex.length ? verdict(true, 'Clicking the profile link runs the script.', '点击个人资料链接就会运行脚本。') : verdict(false, 'Safe link.', '安全的链接。')) };
        },
      },
    },
    {
      id: 'filter',
      title: L('Filter bypass', '过滤绕过'),
      summary: L('Some apps try to delete dangerous strings instead of encoding output. Blocklists miss case changes, other tags, and payloads that reassemble after one pass of removal.', '有些应用不做输出编码，而是试图删除危险字符串。黑名单挡不住大小写变化、其他标签，以及在一次删除后重新拼合的 payload。'),
      lab: {
        fields: [{ id: 'q', label: L('Comment (filter removes <script> and </script>, once)', '评论（过滤器删除一次 <script> 和 </script>）'), default: '<scr<script>ipt>alert(1)</scr</script>ipt>' }],
        presets: [
          { label: '<script>', values: { q: '<script>alert(1)</script>' } },
          { label: L('Nested', '嵌套'), values: { q: '<scr<script>ipt>alert(1)</scr</script>ipt>' } },
          { label: L('Mixed case', '大小写混合'), values: { q: '<ScRiPt>alert(1)</ScRiPt>' } },
          { label: L('Other tag', '换个标签'), values: { q: '<details open ontoggle=alert(1)>' } },
        ],
        defense: { label: L('Strategy', '策略'), off: L('Blocklist', '黑名单'), on: L('Encode output', '输出编码') },
        run({ values, defended }) {
          const filtered = defended ? escHtml(values.q) : values.q.replace('<script>', '').replace('</script>', '');
          const html = `<p>${filtered}</p>`;
          const r = xssResult(html, [L(`after filter: ${filtered}`, `过滤后：${filtered}`)]);
          return { request: `POST /comment`, log: r.log, response: html, ...(r.ex.length ? verdict(true, 'The filter was bypassed.', '过滤器被绕过了。') : verdict(false, 'Nothing executes.', '没有内容会被执行。')) };
        },
      },
      takeaway: L('Encode on output or use a real sanitiser (DOMPurify). Hand-written filters lose.', '在输出时编码，或使用真正的净化库（DOMPurify）。手写过滤器注定会输。'),
    },
  ],
  challenges: [
    {
      title: L('Escape the attribute', '逃出属性'),
      goal: L('Your search term is reflected as <input value="TERM">. < and > are encoded, quotes are not. Make JavaScript run without any user click.', '你的搜索词被反射为 <input value="TERM">。< 和 > 会被编码，引号不会。让 JavaScript 在无需用户点击的情况下运行。'),
      fields: [{ id: 'q', label: L('Search term', '搜索词') }],
      run({ q }) {
        const html = `<input value="${q.replace(/</g, '&lt;').replace(/>/g, '&gt;')}">`;
        const ex = htmlExec(html);
        return { log: [ex.length ? L(`executes: ${ex[0]}`, `会执行：${ex[0]}`) : L('nothing executes', '没有内容会执行')], response: html, ex };
      },
      check: (v, o) => o.ex.some((e) => /on(focus|blur|load|error|animationstart|transitionend|toggle|pointerover|mouseover)/i.test(e)) && (/autofocus|onmouseover|onpointerover/i.test(v.q) || !/onfocus/i.test(v.q)),
      hint: L('Close value="…" with a quote, then add an event that fires on its own. Inputs can focus themselves.', '用引号闭合 value="…"，再加一个会自动触发的事件。输入框可以自己获得焦点。'),
      solution: '" autofocus onfocus=alert(1) x="',
      explain: L('The quote ends the attribute, autofocus focuses the input on load, and onfocus runs. Encoding quotes (&quot;) in attribute context prevents it.', '引号结束了属性，autofocus 让输入框在加载时获得焦点，于是 onfocus 运行。在属性上下文中编码引号（&quot;）就能防止这一点。'),
    },
    {
      title: L('Break the JS string', '打破 JS 字符串'),
      goal: L("Input goes into var q = '…'; inside a <script>. The app escapes ' as \\' and encodes < >, but forgets about the backslash itself. Call alert().", "输入被放进 <script> 中的 var q = '…';。应用把 ' 转义成 \\'，并编码了 < >，但忘了处理反斜杠本身。调用 alert()。"),
      fields: [{ id: 'q', label: L('Input', '输入') }],
      run({ q }) {
        const s = q.replace(/'/g, "\\'").replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const code = `var q = '${s}';`;
        const j = jsExec(code);
        return { log: [code, j.ok ? (j.runs ? L('⚠ code outside the string', '⚠ 有代码在字符串之外') : L('valid JS, still just a string', '合法 JS，但仍只是字符串')) : L('syntax error: the script would not run at all', '语法错误：整段脚本都不会运行')], response: `<script>${code}</script>`, j };
      },
      check: (v, o) => o.j.runs,
      hint: L("If you send \\' the app turns it into \\\\'. What does a double backslash mean inside a JS string?", "如果你发送 \\'，应用会把它变成 \\\\'。JS 字符串里的双反斜杠是什么意思？"),
      solution: "\\';alert(1)//",
      explain: L("\\' becomes \\\\' : the first backslash escapes the second, so the quote is free and ends the string. Proper JS escaping must escape backslashes first.", "\\' 变成了 \\\\'：第一个反斜杠转义了第二个，于是引号“自由”了并结束了字符串。正确的 JS 转义必须先转义反斜杠。"),
    },
    {
      title: L('Defeat the event-handler filter', '击败事件处理器过滤器'),
      goal: L('The app removes anything matching /on\\w+=/gi once, then renders your comment as HTML. Get an event handler through.', '应用会把匹配 /on\\w+=/gi 的内容删除一次，然后把你的评论当作 HTML 渲染。让一个事件处理器通过。'),
      fields: [{ id: 'q', label: L('Comment', '评论') }],
      run({ q }) {
        const f = q.replace(/on\w+=/gi, '');
        const html = `<p>${f}</p>`;
        const ex = htmlExec(html);
        return { log: [L(`after filter: ${f}`, `过滤后：${f}`), ex.length ? L(`executes: ${ex[0]}`, `会执行：${ex[0]}`) : L('nothing executes', '没有内容会执行')], response: html, ex };
      },
      check: (v, o) => o.ex.some((e) => /\son\w+=/i.test(e)),
      hint: L('The regex needs “=” right after the name. HTML is more relaxed than that. Or: what is left after one removal?', '这个正则要求名字后面紧跟“=”，而 HTML 没那么严格。或者想想：删除一次后剩下什么？'),
      solution: '<img src=x onerror =alert(1)>',
      explain: L('HTML allows whitespace before =, and /on\\w+=/ does not. Nesting works too: oonerror=nerror= collapses into onerror= after one removal. Filters can’t model the parser; encoding can.', 'HTML 允许在 = 前有空白，而 /on\\w+=/ 不允许。嵌套也行：oonerror=nerror= 在删除一次后合并成 onerror=。过滤器无法模拟解析器，而编码可以。'),
    },
  ],
  cases: [
    { year: '2005', ref: L('MySpace “Samy” worm', 'MySpace “Samy” 蠕虫'), title: L('A million friends in a day', '一天内一百万好友'), what: L('Samy Kamkar placed a stored XSS payload in his MySpace profile. Anyone viewing it added Samy as a friend and copied the worm to their own profile. It spread to over a million profiles in about 20 hours, and MySpace went offline to clean it up.', 'Samy Kamkar 在自己的 MySpace 个人资料中植入了存储型 XSS payload。任何人查看它，都会自动加 Samy 为好友，并把蠕虫复制到自己的资料页。它在约 20 小时内传播到一百多万个资料页，MySpace 不得不下线清理。'), lesson: L('Stored XSS on a social site can self-propagate.', '社交网站上的存储型 XSS 可以自我传播。') },
    { year: '2014', ref: L('TweetDeck', 'TweetDeck'), title: L('The self-retweeting tweet', '会自动转发的推文'), what: L('An XSS flaw in TweetDeck let a tweet containing a <script> tag execute in viewers’ clients. One such tweet retweeted itself tens of thousands of times before Twitter temporarily shut TweetDeck down to fix it.', 'TweetDeck 的一个 XSS 漏洞，让包含 <script> 标签的推文在查看者的客户端中执行。其中一条推文自动转发了自己数万次，Twitter 随后暂时关闭了 TweetDeck 进行修复。'), lesson: L('Rich clients that render user content need the same encoding as web pages.', '渲染用户内容的富客户端，需要和网页一样的编码处理。') },
  ],
};

export const CORE1 = { sqli, xss };
