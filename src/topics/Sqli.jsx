import { useCallback, useEffect, useMemo, useState } from 'react';
import initSqlJs from 'sql.js';
import wasmUrl from 'sql.js/dist/sql-wasm.wasm?url';
import { useLang } from '../i18n.jsx';
import SequenceDiagram from '../components/SequenceDiagram.jsx';
import { StepControls, useStepper } from '../components/Stepper.jsx';
import { Defenses, InterviewQs, Section, Seg, TopicShell } from '../components/TopicShell.jsx';

const SEED_SQL = `
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
INSERT INTO users VALUES
  (1, 'admin', 'S3cr3t!Adm1n', 'admin'),
  (2, 'alice', 'wonderland', 'student'),
  (3, 'bob',   'builder42',  'student');`;

let sqlModule;
const loadSql = () => (sqlModule ??= initSqlJs({ locateFile: () => wasmUrl }));

const PRE = "SELECT id, username, role FROM users WHERE username = '";
const MID = "' AND password = '";
const END = "';";
const PARAM_QUERY = 'SELECT id, username, role FROM users WHERE username = ? AND password = ?;';

const PRESETS = [
  { label: { en: 'Normal login', zh: '正常登录' }, u: 'alice', p: 'wonderland' },
  { label: { en: 'Wrong password', zh: '密码错误' }, u: 'alice', p: 'guess123' },
  { label: { en: "Lone quote '", zh: "单引号 '" }, u: "'", p: '' },
  { label: { en: 'Comment out the password', zh: '注释掉密码检查' }, u: "admin' --", p: 'anything' },
  { label: { en: 'Always true', zh: '恒为真' }, u: "' OR 1=1 --", p: '' },
  { label: { en: 'UNION: dump passwords', zh: 'UNION 导出密码' }, u: "' UNION SELECT id, username, password FROM users --", p: '' },
  { label: { en: 'Drop the table', zh: '删表' }, u: "'; DROP TABLE users; --", p: '' },
];

/** Classify each character of the final query as template/input and code/string/comment. */
function analyse(u, p) {
  const parts = [
    [PRE, false],
    [u, true],
    [MID, false],
    [p, true],
    [END, false],
  ];
  const chars = [];
  for (const [text, fromInput] of parts) for (const ch of text) chars.push({ ch, input: fromInput });
  let state = 'code';
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i].ch;
    if (state === 'comment') {
      chars[i].ctx = 'comment';
      if (c === '\n') state = 'code';
    } else if (state === 'string') {
      if (c === "'" && chars[i + 1]?.ch === "'") {
        // An escaped '' pair. If one half came from the user, it still changed the parse.
        const ctx = chars[i].input !== chars[i + 1].input ? 'quote' : 'string';
        chars[i].ctx = chars[i + 1].ctx = ctx;
        i++;
      } else if (c === "'") {
        chars[i].ctx = 'quote';
        state = 'code';
      } else chars[i].ctx = 'string';
    } else if (c === "'") {
      chars[i].ctx = 'quote';
      state = 'string';
    } else if (c === '-' && chars[i + 1]?.ch === '-') {
      chars[i].ctx = chars[i + 1].ctx = 'comment';
      state = 'comment';
      i++;
    } else chars[i].ctx = 'code';
  }
  // group into spans
  const spans = [];
  for (const c of chars) {
    const cls = c.ctx === 'comment' ? (c.input ? 'q-in-comment' : 'q-comment') : c.input ? (c.ctx === 'string' ? 'q-data' : 'q-code') : 'q-tpl';
    const last = spans[spans.length - 1];
    if (last && last.cls === cls) last.text += c.ch;
    else spans.push({ cls, text: c.ch });
  }
  const injected = chars.filter((c) => c.input && (c.ctx === 'code' || c.ctx === 'quote') && c.ch.trim()).length;
  const disabled = chars.some((c) => !c.input && c.ctx === 'comment');
  return { spans, injected, disabled, query: chars.map((c) => c.ch).join('') };
}

function readUsers(db) {
  try {
    const r = db.exec('SELECT * FROM users');
    return r[0] || { columns: ['id', 'username', 'password', 'role'], values: [] };
  } catch (e) {
    return { error: e.message };
  }
}

const ACTORS = [
  { id: 'b', label: { en: 'Browser', zh: '浏览器' }, sub: { en: 'login form', zh: '登录表单' }, tone: 'neutral' },
  { id: 'app', label: { en: 'Web app', zh: 'Web 应用' }, sub: 'login.php', tone: 'neutral' },
  { id: 'db', label: { en: 'Database', zh: '数据库' }, sub: 'SQLite', tone: 'amber' },
];

export default function Sqli() {
  const { tr } = useLang();
  const [db, setDb] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [mode, setMode] = useState('concat');
  const [u, setU] = useState(PRESETS[4].u);
  const [p, setP] = useState(PRESETS[4].p);
  const [result, setResult] = useState(null);
  const [users, setUsers] = useState(null);

  const freshDb = useCallback(async () => {
    try {
      const SQL = await loadSql();
      const d = new SQL.Database();
      d.run(SEED_SQL);
      setDb(d);
      setUsers(readUsers(d));
      setResult(null);
      return d;
    } catch (e) {
      setLoadError(String(e.message || e));
      return null;
    }
  }, []);

  useEffect(() => {
    freshDb();
  }, [freshDb]);

  const a = useMemo(() => analyse(u, p), [u, p]);

  const run = (uu = u, pp = p, d = db) => {
    if (!d) return;
    let res;
    try {
      let rows;
      if (mode === 'concat') {
        const q = analyse(uu, pp).query;
        const out = d.exec(q);
        rows = out[0] || { columns: ['id', 'username', 'role'], values: [] };
      } else {
        const stmt = d.prepare(PARAM_QUERY);
        stmt.bind([uu, pp]);
        const values = [];
        while (stmt.step()) values.push(stmt.get());
        stmt.free();
        rows = { columns: ['id', 'username', 'role'], values };
      }
      res = { rows };
    } catch (e) {
      res = { error: e.message };
    }
    setResult(res);
    setUsers(readUsers(d));
  };

  const applyPreset = (pr) => {
    setU(pr.u);
    setP(pr.p);
    run(pr.u, pr.p);
  };

  const loggedIn = result?.rows?.values?.length ? result.rows.values[0] : null;

  const messages = useMemo(() => {
    const isParam = mode === 'param';
    const outcome = result?.error
      ? { kind: 'attack', label: { en: '500 SQL error leaked', zh: '500 泄露 SQL 错误' } }
      : loggedIn
        ? { kind: mode === 'concat' && a.injected ? 'attack' : 'normal', label: { en: `Welcome, ${loggedIn[1]}`, zh: `欢迎，${loggedIn[1]}` } }
        : { kind: 'secure', label: { en: '401 Invalid credentials', zh: '401 用户名或密码错误' } };
    return [
      {
        from: 'b', to: 'app',
        label: `POST /login  username=${u.length > 18 ? u.slice(0, 18) + '…' : u}`,
        note: { en: 'The form sends whatever the user typed. The server has no way to know if it is a name or a carefully crafted fragment of SQL.', zh: '表单把用户输入原样发出。服务器无从得知这是一个用户名，还是精心构造的 SQL 片段。' },
      },
      {
        from: 'app', to: 'app', kind: isParam ? 'secure' : a.injected ? 'attack' : 'normal',
        label: isParam ? { en: 'prepare(sql) + bind(values)', zh: 'prepare(sql) + bind(值)' } : { en: 'sql = "…" + username + "…"', zh: 'sql = "…" + username + "…"' },
        note: isParam
          ? { en: 'Parameterised query: the SQL text is fixed, and the user input is passed separately as values. It can never change the structure of the statement.', zh: '参数化查询：SQL 文本是固定的，用户输入作为“值”单独传入，永远无法改变语句结构。' }
          : { en: 'String concatenation: the input is glued into the SQL text. A quote in the input closes the string literal early, and everything after it is parsed as SQL code.', zh: '字符串拼接：输入被直接粘进 SQL 文本。输入中的引号会提前闭合字符串，之后的内容都被当作 SQL 代码解析。' },
      },
      {
        from: 'app', to: 'db', kind: isParam ? 'secure' : a.injected ? 'attack' : 'normal',
        label: isParam ? { en: 'statement + [values]', zh: '语句 + [值]' } : { en: 'one combined SQL string', zh: '一整段拼好的 SQL' },
        note: isParam
          ? { en: 'The database compiles the statement first, then plugs in the values as data.', zh: '数据库先编译语句，再把值当作数据填进去。' }
          : { en: `The database parses the whole string. In this query, ${a.injected} character(s) from your input are being executed as SQL code.`, zh: `数据库解析整段字符串。在这条查询里，你的输入中有 ${a.injected} 个字符被当成 SQL 代码执行。` },
      },
      {
        from: 'db', to: 'app', kind: result?.error ? 'attack' : 'normal',
        label: result?.error ? { en: 'error: syntax / no such table', zh: '错误：语法 / 表不存在' } : { en: `${result?.rows?.values?.length ?? '?'} row(s)`, zh: `${result?.rows?.values?.length ?? '?'} 行` },
        note: { en: 'The app treats "at least one row came back" as "credentials are correct". That assumption is what the injection abuses.', zh: '应用把“返回了至少一行”当作“账号密码正确”。注入攻击利用的正是这个假设。' },
      },
      {
        from: 'app', to: 'b', kind: outcome.kind, label: outcome.label,
        note: result?.error
          ? { en: 'Verbose database errors tell the attacker the query structure. Log them, but show users a generic message.', zh: '详细的数据库错误会把查询结构暴露给攻击者。应该记录到日志，但只给用户显示通用信息。' }
          : { en: 'Press "Log in" to update this step with the real result from the database.', zh: '点击“登录”后，这一步会显示数据库返回的真实结果。' },
      },
    ];
  }, [mode, u, a, result, loggedIn]);
  const stepper = useStepper(messages.length);

  return (
    <TopicShell
      id="sqli"
      tldr={{
        en: 'SQL injection happens when user input is glued into a SQL query as text. A single quote lets the input escape its string and rewrite the query, from bypassing a login to dumping the whole database.',
        zh: '当用户输入被当作文本拼进 SQL 查询时，就会发生 SQL 注入。一个单引号就能让输入逃出字符串、改写查询，小到绕过登录，大到导出整个数据库。',
      }}
    >
      <Section kicker={{ en: 'Lab', zh: '实验' }} title={{ en: 'Break into a login form', zh: '攻破一个登录表单' }}>
        <div className="lab">
          <div className="panel">
            <Seg
              label={{ en: 'How the app builds the query', zh: '应用如何构造查询' }}
              value={mode}
              onChange={(m) => {
                setMode(m);
                setResult(null);
              }}
              options={[
                { value: 'concat', label: { en: 'String concatenation', zh: '字符串拼接' } },
                { value: 'param', label: { en: 'Parameterised', zh: '参数化查询' } },
              ]}
            />
            <div className="field-label">{tr({ en: 'Payloads', zh: 'Payload 预设' })}</div>
            <div className="chips">
              {PRESETS.map((pr, i) => (
                <button key={i} className={`chip ${u === pr.u && p === pr.p ? 'on' : ''}`} onClick={() => applyPreset(pr)}>
                  {tr(pr.label)}
                </button>
              ))}
            </div>
            <form
              className="login"
              onSubmit={(e) => {
                e.preventDefault();
                run();
              }}
            >
              <label className="field-label" htmlFor="sq-u">
                {tr({ en: 'Username', zh: '用户名' })}
              </label>
              <input id="sq-u" className="input mono" value={u} onChange={(e) => setU(e.target.value)} spellCheck={false} autoComplete="off" />
              <label className="field-label" htmlFor="sq-p">
                {tr({ en: 'Password', zh: '密码' })}
              </label>
              <input id="sq-p" className="input mono" value={p} onChange={(e) => setP(e.target.value)} spellCheck={false} autoComplete="off" />
              <div className="row">
                <button className="btn danger" type="submit" disabled={!db}>
                  {db ? tr({ en: 'Log in', zh: '登录' }) : tr({ en: 'Loading SQLite…', zh: '正在加载 SQLite…' })}
                </button>
                <button className="btn ghost" type="button" onClick={freshDb}>
                  ↻ {tr({ en: 'Reset database', zh: '重置数据库' })}
                </button>
              </div>
            </form>
            {loadError && <p className="bad-text">SQLite failed to load: {loadError}</p>}
          </div>

          <div className="panel">
            <div className="field-label">{tr({ en: 'Query the database receives', zh: '数据库收到的查询' })}</div>
            {mode === 'concat' ? (
              <>
                <pre className="code query">
                  {a.spans.map((s, i) => (
                    <span key={i} className={s.cls}>
                      {s.text}
                    </span>
                  ))}
                </pre>
                <div className="legend">
                  <span className="q-tpl">{tr({ en: 'app code', zh: '应用代码' })}</span>
                  <span className="q-data">{tr({ en: 'your input as data', zh: '你的输入（数据）' })}</span>
                  <span className="q-code">{tr({ en: 'your input as SQL code', zh: '你的输入（代码！）' })}</span>
                  <span className="q-comment">{tr({ en: 'commented out', zh: '被注释掉' })}</span>
                </div>
                <div className={`verdict ${a.injected ? 'bad' : 'good'}`}>
                  {a.injected
                    ? tr({ en: `⚠ ${a.injected} character(s) of your input escaped the string and became SQL code.`, zh: `⚠ 你的输入中有 ${a.injected} 个字符逃出了字符串，变成了 SQL 代码。` })
                    : tr({ en: '✓ Your input stayed inside the string literal. It is only data.', zh: '✓ 你的输入留在了字符串里，只是数据。' })}
                  {a.disabled && tr({ en: ' The password check is commented out.', zh: ' 密码检查被注释掉了。' })}
                </div>
              </>
            ) : (
              <>
                <pre className="code query">
                  <span className="q-tpl">{PARAM_QUERY}</span>
                  {'\n'}
                  <span className="q-comment">-- bound values:</span>
                  {'\n'}
                  <span className="q-data">{`?1 = ${JSON.stringify(u)}\n?2 = ${JSON.stringify(p)}`}</span>
                </pre>
                <div className="verdict good">
                  {tr({ en: '✓ The SQL text never changes. Your input is sent separately and treated purely as data.', zh: '✓ SQL 文本从不改变。你的输入单独传送，只会被当作数据。' })}
                </div>
              </>
            )}

            <div className="field-label">{tr({ en: 'Result', zh: '结果' })}</div>
            {!result && <div className="result muted">{tr({ en: 'Press "Log in" to run the query against SQLite.', zh: '点击“登录”在 SQLite 上执行查询。' })}</div>}
            {result?.error && (
              <div className="result bad">
                <b>SQL error:</b> <span className="mono">{result.error}</span>
              </div>
            )}
            {result?.rows &&
              (loggedIn ? (
                <div className={`result ${mode === 'concat' && a.injected ? 'bad' : 'good'}`}>
                  {tr({ en: 'Logged in as', zh: '已登录为' })} <b>{loggedIn[1]}</b> ({loggedIn[2]})
                </div>
              ) : (
                <div className="result neutral">{tr({ en: 'Invalid username or password.', zh: '用户名或密码错误。' })}</div>
              ))}
            {result?.rows?.values?.length > 0 && <Table data={result.rows} />}

            <div className="field-label">
              {tr({ en: 'users table (the attacker cannot normally see this)', zh: 'users 表（攻击者本来看不到）' })}
            </div>
            {users?.error ? (
              <div className="result bad mono">{users.error} 💥</div>
            ) : (
              users && <Table data={users} dim />
            )}
          </div>
        </div>
      </Section>

      <Section kicker={{ en: 'Trace', zh: '追踪' }} title={{ en: 'Where the data becomes code', zh: '数据在哪一步变成了代码' }}>
        <SequenceDiagram actors={ACTORS} messages={messages} step={stepper.step} onSelect={stepper.go} title={{ en: 'Login request sequence', zh: '登录请求时序图' }} />
        <StepControls stepper={stepper} messages={messages} />
      </Section>

      <Section kicker={{ en: 'Defend', zh: '防御' }} title={{ en: 'Defences that actually work', zh: '真正有效的防御' }}>
        <Defenses
          items={[
            { title: { en: 'Parameterised queries / prepared statements', zh: '参数化查询 / 预编译语句' }, body: { en: 'The fix. Keep SQL text constant and pass input as bound parameters. Every mainstream driver and ORM supports it.', zh: '根本解决方案。SQL 文本保持不变，输入作为绑定参数传入。所有主流驱动和 ORM 都支持。' } },
            { title: { en: 'Allow-list what cannot be parameterised', zh: '无法参数化的部分用白名单' }, body: { en: 'Table names, column names and ORDER BY direction cannot be bound. Map user choices to a fixed list instead of inserting them.', zh: '表名、列名、ORDER BY 方向无法绑定。把用户的选择映射到固定列表，而不是直接插入。' } },
            { title: { en: 'Least privilege', zh: '最小权限' }, body: { en: 'The web app’s DB account should not be able to DROP tables or read other schemas. It limits the blast radius.', zh: 'Web 应用的数据库账号不应该能 DROP 表或读其他库，用来缩小爆炸半径。' } },
            { title: { en: 'Hash passwords, hide errors', zh: '密码要哈希，错误要隐藏' }, body: { en: 'This lab stores plaintext passwords so the UNION dump is visible. Real apps use bcrypt/Argon2, and never show raw SQL errors to users.', zh: '本实验为了让 UNION 导出看得见才存了明文密码。真实应用要用 bcrypt/Argon2，并且永远不要把原始 SQL 错误展示给用户。' } },
          ]}
        />
      </Section>

      <Section kicker={{ en: 'Interview prep', zh: '面试准备' }} title={{ en: 'Questions you might get', zh: '可能被问到的问题' }}>
        <InterviewQs
          items={[
            { q: { en: 'Why doesn’t escaping quotes fully solve SQL injection?', zh: '为什么转义引号不能彻底解决 SQL 注入？' }, a: { en: 'Escaping depends on the right function, charset and context. Numeric contexts (WHERE id = 1 OR 1=1) need no quote at all, and multi-byte charset tricks have broken escaping before. Parameterisation separates code and data by design.', zh: '转义依赖于正确的函数、字符集和上下文。数字上下文（WHERE id = 1 OR 1=1）根本不需要引号，历史上也出现过利用多字节字符集绕过转义的手法。参数化从设计上就把代码和数据分开了。' } },
            { q: { en: 'What is blind SQL injection?', zh: '什么是盲注？' }, a: { en: 'When the app shows no data or errors, the attacker asks yes/no questions: boolean-based (page changes when a condition is true) or time-based (SLEEP/pg_sleep delays the response).', zh: '当应用既不显示数据也不显示错误时，攻击者就问“是/否”问题：布尔盲注（条件为真时页面不同）或时间盲注（用 SLEEP/pg_sleep 让响应变慢）。' } },
            { q: { en: 'Does using an ORM make you immune?', zh: '用了 ORM 就安全了吗？' }, a: { en: 'Mostly, until you use raw query helpers or string-format into them, e.g. raw(f"... {name}"). Those are the places to review.', zh: '大多数情况下是的，除非你用了原生查询接口，或者把字符串格式化进去，比如 raw(f"... {name}")。这些地方最值得审查。' } },
          ]}
        />
      </Section>
    </TopicShell>
  );
}

function Table({ data, dim }) {
  return (
    <div className={`table-wrap ${dim ? 'dim' : ''}`}>
      <table>
        <thead>
          <tr>
            {data.columns.map((c) => (
              <th key={c}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.values.map((r, i) => (
            <tr key={i}>
              {r.map((v, j) => (
                <td key={j}>{String(v)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
