import { useEffect, useState } from 'react';
import { useLang } from './i18n.jsx';
import { categoryById, topicById } from './topics/registry.js';
import { getSolved, getVisited, resetSolved, resetVisited } from './progress.js';
import { loadDeep } from './components/DeepDive.jsx';

const L = (en, zh) => ({ en, zh });

const BASICS = [
  {
    icon: '📨',
    t: L('HTTP is just text', 'HTTP 本质上就是文本'),
    b: L(
      'A browser sends a request (method, path, headers, maybe a body) and the server sends back a response (status, headers, body). Every lab shows these as plain text. Anything in a request can be changed by the person sending it, so the server must never trust it.',
      '浏览器发送请求（方法、路径、请求头，可能还有请求体），服务器返回响应（状态码、响应头、响应体）。每个实验都会把它们以纯文本显示出来。请求里的任何东西，发送者都可以随意修改，所以服务器永远不能信任它。',
    ),
    code: 'POST /login HTTP/1.1\nHost: shop.example\nCookie: session=7f3a…\n\nusername=alice&password=…',
  },
  {
    icon: '🍪',
    t: L('Cookies and sessions', 'Cookie 与会话'),
    b: L(
      'After you log in, the server gives your browser a session cookie. The browser then attaches it automatically to every request to that site. That automatic behaviour is what CSRF, clickjacking and WebSocket hijacking abuse; stealing the cookie is what XSS often aims for.',
      '登录后，服务器给浏览器发一个会话 Cookie，之后浏览器会在每个发往该站点的请求中自动带上它。CSRF、点击劫持和 WebSocket 劫持利用的正是这种“自动携带”；而偷走这个 Cookie 常常是 XSS 的目标。',
    ),
  },
  {
    icon: '🧱',
    t: L('Same-origin policy', '同源策略'),
    b: L(
      'An origin is scheme + host + port (https://shop.example:443). Scripts from one origin can send requests to another, but usually can’t read the responses. XSS gets around this by running inside the target origin; CORS is how a server deliberately relaxes it.',
      '源 = 协议 + 主机 + 端口（https://shop.example:443）。一个源的脚本可以向另一个源发请求，但通常读不到响应。XSS 通过在目标源内部运行来绕过它；CORS 则是服务器有意放宽它的方式。',
    ),
  },
  {
    icon: '🔀',
    t: L('Data vs code', '数据与代码'),
    b: L(
      'Most injection bugs (SQLi, XSS, command injection, SSTI, XXE…) are the same mistake: user data is glued into something that gets parsed as code. The fix is always to keep them separate: parameters, encoding, argument arrays, template variables.',
      '大多数注入漏洞（SQL 注入、XSS、命令注入、SSTI、XXE……）都是同一个错误：用户数据被拼进了会被当作代码解析的东西里。修复方法永远是把两者分开：参数化、编码、参数数组、模板变量。',
    ),
  },
  {
    icon: '🪪',
    t: L('Authentication vs authorisation', '认证与授权'),
    b: L(
      'Authentication asks “who are you?” (login, tokens). Authorisation asks “are you allowed to do this?” (ownership, roles). Many serious bugs pass the first check and skip the second.',
      '认证问的是“你是谁”（登录、令牌）。授权问的是“你能不能做这件事”（归属、角色）。很多严重漏洞都是过了第一关，却漏了第二关。',
    ),
  },
  {
    icon: '🔐',
    t: L('Encoding ≠ encryption ≠ hashing', '编码 ≠ 加密 ≠ 哈希'),
    b: L(
      'Base64 and URL encoding are reversible by anyone. Encryption is reversible only with a key. Hashing is one-way. Seeing base64 in a cookie or JWT means you can read it, and often edit it.',
      'Base64 和 URL 编码任何人都能还原。加密只有持有密钥才能还原。哈希是单向的。在 Cookie 或 JWT 里看到 base64，意味着你能读懂它，往往还能改它。',
    ),
  },
];

const PATH = [
  {
    t: L('Stage 1 · The classics', '第一阶段 · 经典漏洞'),
    b: L('Start here. These explain the core ideas everything else builds on.', '从这里开始。这些主题讲清了其他所有内容所依赖的核心概念。'),
    ids: ['sqli', 'xss', 'csrf', 'access-control', 'auth', 'path-traversal', 'cmdi', 'info-disclosure'],
  },
  {
    t: L('Stage 2 · Servers talking to things', '第二阶段 · 服务器与外部交互'),
    b: L('What happens when the server fetches URLs, parses files, or exposes APIs.', '当服务器请求 URL、解析文件或对外暴露 API 时会发生什么。'),
    ids: ['ssrf', 'file-upload', 'xxe', 'nosqli', 'api', 'logic', 'race'],
  },
  {
    t: L('Stage 3 · The browser as a battleground', '第三阶段 · 浏览器战场'),
    b: L('Cross-origin rules and client-side code paths.', '跨源规则与前端代码路径。'),
    ids: ['cors', 'clickjacking', 'dom', 'websockets', 'tls'],
  },
  {
    t: L('Stage 4 · Tokens, protocols and caches', '第四阶段 · 令牌、协议与缓存'),
    b: L('Bugs that live between systems: identity protocols, proxies and caches.', '存在于系统之间的漏洞：身份协议、代理和缓存。'),
    ids: ['jwt', 'oauth', 'host-header', 'cache-poisoning', 'cache-deception', 'smuggling'],
  },
  {
    t: L('Stage 5 · Frameworks and AI', '第五阶段 · 框架与 AI'),
    b: L('Language- and framework-specific attacks, plus the newest attack surface.', '与语言和框架相关的攻击，以及最新的攻击面。'),
    ids: ['ssti', 'deserialization', 'prototype-pollution', 'graphql', 'llm', 'mcp'],
  },
];

const GLOSSARY = [
  [L('Payload', 'Payload（载荷）'), L('The input an attacker sends to trigger a bug, e.g. \' OR 1=1 --.', '攻击者为触发漏洞而发送的输入，比如 \' OR 1=1 --。')],
  [L('Source / sink', '源 / 汇'), L('Where untrusted data enters (source) and the dangerous place it ends up (sink).', '不可信数据进入的地方（源）和它最终到达的危险位置（汇）。')],
  [L('Origin', '源（Origin）'), L('Scheme + host + port. The unit of browser isolation.', '协议 + 主机 + 端口，是浏览器隔离的基本单位。')],
  [L('RCE', 'RCE'), L('Remote code execution: running your own commands on the server. Usually the worst outcome.', '远程代码执行：在服务器上运行你自己的命令，通常是最严重的后果。')],
  [L('Blind', '盲注 / 盲打'), L('The bug works but you can’t see the result directly; you infer it from timing, errors or out-of-band requests.', '漏洞存在，但你看不到直接结果，只能通过时间、错误或带外请求来推断。')],
  [L('Defence in depth', '纵深防御'), L('Several independent layers (e.g. encoding + CSP), so one failure isn’t fatal.', '多层相互独立的防护（比如编码 + CSP），一层失效不至于全盘失守。')],
  [L('PoC', 'PoC'), L('Proof of concept: the smallest demonstration that a bug is real.', '概念验证：证明漏洞真实存在的最小演示。')],
  [L('CWE / OWASP', 'CWE / OWASP'), L('Shown under each title. CWE is a catalogue of weakness types; OWASP Top 10 ranks the most common web risks.', '显示在每个标题下方。CWE 是弱点类型目录；OWASP Top 10 列出最常见的 Web 风险。')],
];

function Anatomy() {
  const { tr } = useLang();
  const parts = [
    { n: '1', t: L('Lab', '实验'), b: L('Pick a payload chip or type your own. The right side shows the request, what the server did, the response, and a verdict.', '点一个 payload 预设，或者自己输入。右侧会显示请求、服务器做了什么、响应以及结论。') },
    { n: '2', t: L('Defence toggle', '防御开关'), b: L('Every lab has a switch between the vulnerable and the fixed version. Run the same payload twice and compare.', '每个实验都能在“有漏洞”和“已修复”之间切换。用同一个 payload 跑两次，对比结果。') },
    { n: '3', t: L('Trace diagram', '时序图'), b: L('Press ▶ Play or Next to walk through the attack. Click any arrow to jump to it. The box below explains each step.', '点 ▶ 播放或“下一步”逐步走完攻击，点击任意箭头可直接跳到那一步，下方的文字框会解释每一步。') },
    { n: '4', t: L('Variants, challenges, real cases', '变体、关卡与真实案例'), b: L('Tabs for each sub-type with its own lab, then challenge levels with no presets: build the payload yourself, use a hint if stuck, and the explanation unlocks when you pass. Real incidents show why it matters.', '每种子类型一个标签页，各有自己的实验；之后是没有预设的关卡：自己构造 payload，卡住了可以看提示，通过后解锁讲解。真实事件告诉你它为什么重要。') },
    { n: '5', t: L('Code + defences', '代码与防御'), b: L('A vulnerable snippet next to the fixed one, then the defences that actually work in production.', '有漏洞的代码和修复后的代码并排显示，随后是在生产环境中真正有效的防御。') },
    { n: '6', t: L('Interview questions', '面试题'), b: L('Click a question to reveal the answer. Try answering out loud first.', '点击问题查看答案。建议先自己大声回答一遍。') },
  ];
  return (
    <div className="anatomy">
      <div className="anatomy-legend">
        <div className="field-label">{tr(L('Arrow colours in diagrams', '时序图中箭头的颜色'))}</div>
        <div className="legend-row"><i style={{ background: 'var(--c-normal)' }} /> {tr(L('normal traffic', '正常流量'))}</div>
        <div className="legend-row"><i style={{ background: 'var(--c-attack)' }} /> {tr(L('attacker-controlled / harmful', '攻击者控制 / 有害'))}</div>
        <div className="legend-row"><i style={{ background: 'var(--c-secure)' }} /> {tr(L('a defence doing its job', '防御生效'))}</div>
        <div className="legend-row"><i style={{ background: 'var(--c-blocked)' }} /> {tr(L('blocked / rejected', '被拦截 / 被拒绝'))}</div>
        <div className="field-label">{tr(L('Verdict boxes', '结论框'))}</div>
        <div className="verdict bad">{tr(L('Red: the attack worked.', '红色：攻击成功。'))}</div>
        <div className="verdict good">{tr(L('Green: blocked, or safe behaviour.', '绿色：被拦下，或者行为安全。'))}</div>
        <div className="verdict neutral-v">{tr(L('Grey: nothing happened yet. Try another payload.', '灰色：还没发生什么，换个 payload 试试。'))}</div>
      </div>
      <ol className="anatomy-steps">
        {parts.map((p) => (
          <li key={p.n}>
            <span className="how-n mono">{p.n}</span>
            <div>
              <b>{tr(p.t)}</b>
              <p>{tr(p.b)}</p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

export default function Guide() {
  const { tr } = useLang();
  const [visited, setVisited] = useState(getVisited);
  const total = PATH.reduce((n, s) => n + s.ids.length, 0);
  const done = PATH.reduce((n, s) => n + s.ids.filter((id) => visited.has(id)).length, 0);
  const next = PATH.flatMap((s) => s.ids).find((id) => !visited.has(id));
  const [solved, setSolved] = useState(getSolved);
  const [counts, setCounts] = useState(null);
  useEffect(() => {
    let live = true;
    loadDeep().then((d) => live && setCounts(Object.fromEntries(Object.entries(d).map(([k, v]) => [k, v.challenges?.length || 0]))));
    return () => {
      live = false;
    };
  }, []);
  const solvedIn = (id) => [...solved].filter((k) => k.startsWith(`${id}:`)).length;
  const chTotal = counts ? Object.values(counts).reduce((a, b) => a + b, 0) : 0;
  const chDone = counts ? Object.keys(counts).reduce((n, id) => n + Math.min(solvedIn(id), counts[id]), 0) : 0;

  return (
    <main className="topic tone-green guide">
      <section className="topic-hero">
        <div className="container">
          <a href="#/" className="back">
            ← {tr(L('Home', '首页'))}
          </a>
          <div className="eyebrow">
            <span className="badge tone-green">{tr(L('Start here', '新手指引'))}</span>
            <span className="muted">{tr(L('about 10 minutes', '约 10 分钟'))}</span>
          </div>
          <h1>{tr(L('Beginner’s guide', '新手指引'))}</h1>
          <p className="lede">
            {tr(
              L(
                'New to web security? This page explains how the labs work, the handful of ideas you need before you start, and a suggested order through all 32 topics. No setup, no account: everything runs in your browser against fake targets.',
                '刚接触 Web 安全？这一页会告诉你实验怎么用、开始前需要知道的几个基础概念，以及 32 个主题的推荐学习顺序。不用安装、不用注册：所有内容都在你的浏览器里，针对模拟目标运行。',
              ),
            )}
          </p>
          <div className="hero-cta">
            <a className="btn primary lg" href={`#/${next || 'sqli'}`}>
              {done === 0 ? tr(L('Start with SQL injection →', '从 SQL 注入开始 →')) : next ? tr(L(`Continue: ${topicById(next).title.en} →`, `继续：${topicById(next).title.zh} →`)) : tr(L('All done! Review any topic →', '全部完成！随便复习一个 →'))}
            </a>
          </div>
        </div>
      </section>

      <div className="container topic-body">
        <section className="section">
          <div className="kicker">{tr(L('Step 1', '第 1 步'))}</div>
          <h2>{tr(L('How a topic page works', '主题页面怎么用'))}</h2>
          <Anatomy />
        </section>

        <section className="section">
          <div className="kicker">{tr(L('Step 2', '第 2 步'))}</div>
          <h2>{tr(L('Six ideas to know first', '先了解这六个概念'))}</h2>
          <div className="basics">
            {BASICS.map((x, i) => (
              <div className="mini" key={i}>
                <h3>
                  <span aria-hidden="true">{x.icon}</span> {tr(x.t)}
                </h3>
                <p>{tr(x.b)}</p>
                {x.code && <pre className="code small">{x.code}</pre>}
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <div className="kicker">{tr(L('Step 3', '第 3 步'))}</div>
          <h2>{tr(L('Suggested learning path', '推荐学习路线'))}</h2>
          <div className="progress-row">
            <div className="progress-bar" role="progressbar" aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
              <span style={{ width: `${(done / total) * 100}%` }} />
            </div>
            <span className="mono muted">
              {done} / {total} {tr(L('opened', '已打开'))}
            </span>
            {(done > 0 || chDone > 0) && (
              <button
                className="btn ghost"
                onClick={() => {
                  resetVisited();
                  resetSolved();
                  setVisited(new Set());
                  setSolved(new Set());
                }}
              >
                {tr(L('Reset', '重置'))}
              </button>
            )}
          </div>
          {counts && (
            <div className="progress-row">
              <div className="progress-bar challenge-bar" role="progressbar" aria-valuemin={0} aria-valuemax={chTotal} aria-valuenow={chDone}>
                <span style={{ width: `${(chDone / chTotal) * 100}%` }} />
              </div>
              <span className="mono muted">
                {chDone} / {chTotal} {tr(L('challenges solved', '关卡已通过'))}
              </span>
            </div>
          )}
          <p className="tiny muted">{tr(L('Progress is saved only in this browser. A topic is ticked once you open it; the number shows challenges solved in it.', '进度只保存在当前浏览器中。打开过的主题会被打勾；数字表示该主题已通过的关卡数。'))}</p>
          <div className="path">
            {PATH.map((stage, i) => (
              <div className="stage" key={i}>
                <div className="stage-head">
                  <span className="stage-n mono">{i + 1}</span>
                  <div>
                    <h3>{tr(stage.t)}</h3>
                    <p className="muted">{tr(stage.b)}</p>
                  </div>
                </div>
                <div className="stage-topics">
                  {stage.ids.map((id) => {
                    const t = topicById(id);
                    const c = categoryById(t.category);
                    const seen = visited.has(id);
                    return (
                      <a key={id} href={`#/${id}`} className={`stage-topic tone-${c.tone} ${seen ? 'seen' : ''}`}>
                        <span className="tick" aria-label={seen ? 'opened' : 'not opened'}>
                          {seen ? '✓' : ''}
                        </span>
                        <span className={`badge tone-${c.tone}`}>{t.short}</span>
                        <span>{tr(t.title)}</span>
                        {counts?.[id] > 0 && (
                          <span className={`ch-count mono ${solvedIn(id) >= counts[id] ? 'all' : ''}`} title={tr(L('challenges solved', '已通过关卡'))}>
                            {Math.min(solvedIn(id), counts[id])}/{counts[id]}
                          </span>
                        )}
                      </a>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <div className="kicker">{tr(L('Reference', '参考'))}</div>
          <h2>{tr(L('Glossary', '术语表'))}</h2>
          <dl className="glossary">
            {GLOSSARY.map(([k, v], i) => (
              <div key={i}>
                <dt>{tr(k)}</dt>
                <dd>{tr(v)}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="section">
          <div className="kicker">{tr(L('Next steps', '下一步'))}</div>
          <h2>{tr(L('Rules and where to practise next', '规则与进阶练习'))}</h2>
          <div className="grid3">
            <div className="mini">
              <h3>⚖️ {tr(L('Stay legal', '遵守法律'))}</h3>
              <p>{tr(L('Only test systems you own or have written permission to test. Using these techniques on real sites without permission is illegal in Australia, China and most other countries.', '只测试你拥有或获得书面授权的系统。未经许可对真实网站使用这些技术，在澳大利亚、中国以及大多数国家都是违法的。'))}</p>
            </div>
            <div className="mini">
              <h3>🧪 {tr(L('Practise on real labs', '在真实靶场练习'))}</h3>
              <p>
                {tr(L('When a topic clicks here, try it for real: ', '在这里弄懂一个主题后，去真实环境里试试：'))}
                <a href="https://portswigger.net/web-security" target="_blank" rel="noreferrer">PortSwigger Web Security Academy</a>,{' '}
                <a href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noreferrer">OWASP Juice Shop</a>.
              </p>
            </div>
            <div className="mini">
              <h3>🛠️ {tr(L('Learn the tools', '熟悉工具'))}</h3>
              <p>{tr(L('Browser DevTools (Network tab) and an intercepting proxy such as Burp Suite Community let you see and edit every request, exactly like the lab panels here.', '浏览器开发者工具（Network 面板）和 Burp Suite Community 这类拦截代理，能让你查看和修改每一个请求，就像这里的实验面板一样。'))}</p>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
