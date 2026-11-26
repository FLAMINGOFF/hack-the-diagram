import { useLang } from './i18n.jsx';
import { useState } from 'react';
import { getFlag, setFlag } from './progress.js';
import { CATEGORIES, TOPICS } from './topics/registry.js';

function HeroDiagram() {
  const { tr } = useLang();
  return (
    <svg className="hero-diagram" viewBox="0 0 420 300" role="img" aria-label={tr({ en: 'A request travelling from a browser to a server while an attacker intercepts a copy', zh: '请求从浏览器发往服务器，攻击者截获了一份副本' })}>
      <defs>
        <path id="p-main" d="M80 80 C 170 40, 250 40, 340 80" />
        <path id="p-back" d="M340 96 C 250 136, 170 136, 80 96" />
        <path id="p-evil" d="M80 92 C 120 170, 170 220, 210 236" />
      </defs>
      <use href="#p-main" className="hd-path" />
      <use href="#p-back" className="hd-path" />
      <use href="#p-evil" className="hd-path evil" />
      <circle r="6" visibility="hidden" className="hd-dot ok">
        <set attributeName="visibility" to="visible" begin="0s" />
        <animateMotion dur="3s" repeatCount="indefinite">
          <mpath href="#p-main" />
        </animateMotion>
      </circle>
      <circle r="6" visibility="hidden" className="hd-dot ok2">
        <set attributeName="visibility" to="visible" begin="1.5s" />
        <animateMotion dur="3s" begin="1.5s" repeatCount="indefinite">
          <mpath href="#p-back" />
        </animateMotion>
      </circle>
      <circle r="6" visibility="hidden" className="hd-dot bad">
        <set attributeName="visibility" to="visible" begin="0.7s" />
        <animateMotion dur="3s" begin="0.7s" repeatCount="indefinite">
          <mpath href="#p-evil" />
        </animateMotion>
      </circle>
      <g className="hd-node">
        <rect x="18" y="58" width="112" height="56" rx="12" />
        <text x="74" y="83">Browser</text>
        <text x="74" y="101" className="sub">alice@uni</text>
      </g>
      <g className="hd-node">
        <rect x="290" y="58" width="112" height="56" rx="12" />
        <text x="346" y="83">Server</text>
        <text x="346" y="101" className="sub">bank.example</text>
      </g>
      <g className="hd-node evil">
        <rect x="154" y="214" width="112" height="56" rx="12" />
        <text x="210" y="239">Attacker</text>
        <text x="210" y="257" className="sub">evil.example</text>
      </g>
      <text x="210" y="34" className="hd-caption">GET /account · Cookie: session=7f3a…</text>
    </svg>
  );
}

export default function Home() {
  const { tr } = useLang();
  return (
    <main>
      <section className="hero">
        <div className="container hero-grid">
          <div>
            <div className="kicker">{tr({ en: 'Interactive web security', zh: '交互式 Web 安全' })}</div>
            <h1>
              {tr({ en: 'Understand attacks by ', zh: '亲手' })}
              <span className="glitch">{tr({ en: 'breaking things', zh: '攻破它' })}</span>
              {tr({ en: '.', zh: '，才真正理解它。' })}
            </h1>
            <p className="lede">
              {tr({
                en: 'Hack the Diagram turns classic web vulnerabilities into diagrams you can poke. Fire real payloads at sandboxed targets, watch each packet move, then switch on the defence and see exactly where the attack dies.',
                zh: 'Hack the Diagram 把经典的 Web 漏洞做成可以动手戳的图。向沙箱目标发送真实 payload，看每个数据包怎么流动，再打开防御，看攻击究竟死在哪一步。',
              })}
            </p>
            <div className="hero-cta">
              <a className="btn primary lg" href="#/start">
                {tr({ en: 'New here? Start the guide →', zh: '新手？先看指引 →' })}
              </a>
              <a className="btn ghost lg" href="#/" onClick={(e) => { e.preventDefault(); document.getElementById('topics')?.scrollIntoView({ behavior: 'smooth' }); }}>
                {tr({ en: 'Browse topics', zh: '浏览全部主题' })}
              </a>
            </div>
            <ul className="hero-facts">
              <li>
                <b>{TOPICS.length}</b> {tr({ en: 'topics', zh: '个主题' })}
              </li>
              <li>
                <b>0</b> {tr({ en: 'servers, all in-browser', zh: '个服务器，全部在浏览器里跑' })}
              </li>
              <li>
                <b>EN / 中文</b>
              </li>
            </ul>
          </div>
          <HeroDiagram />
        </div>
      </section>

      <WelcomeBanner />
      <TopicBrowser />

      <section className="container section">
        <div className="kicker">{tr({ en: 'How every lab works', zh: '每个实验的结构' })}</div>
        <h2>{tr({ en: 'Attack, trace, defend', zh: '攻击、追踪、防御' })}</h2>
        <div className="how">
          {[
            {
              n: '01',
              t: { en: 'Attack', zh: '攻击' },
              b: {
                en: 'Use the preset payloads or write your own. Targets are real: an actual HTML parser for XSS and an actual SQLite engine for SQL injection.',
                zh: '用预设 payload 或自己写。目标是真的：XSS 用真实的 HTML 解析器，SQL 注入用真实的 SQLite 引擎。',
              },
            },
            {
              n: '02',
              t: { en: 'Trace', zh: '追踪' },
              b: {
                en: 'A step-by-step sequence diagram shows who sends what to whom, and why each step matters to the attacker.',
                zh: '逐步的时序图展示谁向谁发送了什么，以及每一步对攻击者意味着什么。',
              },
            },
            {
              n: '03',
              t: { en: 'Defend', zh: '防御' },
              b: {
                en: 'Toggle the real-world fix, rerun the same attack, and read the interview-style questions at the end of each lab.',
                zh: '切换真实世界的修复方案，重跑同一个攻击，最后看看每个实验末尾的面试题。',
              },
            },
          ].map((s) => (
            <div className="how-step" key={s.n}>
              <span className="how-n mono">{s.n}</span>
              <h3>{tr(s.t)}</h3>
              <p>{tr(s.b)}</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}

const kindLabel = (t) =>
  t.kind === 'lab' ? { en: 'Interactive lab', zh: '交互实验' } : t.kind === 'steps' ? { en: 'Step-through', zh: '逐步演示' } : t.kind;

function TopicBrowser() {
  const { tr } = useLang();
  const [cat, setCat] = useState('all');
  const [q, setQ] = useState('');
  const query = q.trim().toLowerCase();
  const match = (t) =>
    !query || [t.short, t.title.en, t.title.zh, t.tag, t.blurb.en, t.blurb.zh].some((x) => x.toLowerCase().includes(query));
  const cats = CATEGORIES.filter((c) => cat === 'all' || c.id === cat);
  let shown = 0;
  return (
    <section className="container section" id="topics">
      <div className="kicker">{tr({ en: 'Labs', zh: '实验' })}</div>
      <h2>{tr({ en: 'Pick a vulnerability', zh: '选一个漏洞' })}</h2>
      <div className="browser-tools">
        <div className="chips">
          <button className={`chip ${cat === 'all' ? 'on' : ''}`} onClick={() => setCat('all')}>
            {tr({ en: 'All', zh: '全部' })} · {TOPICS.length}
          </button>
          {CATEGORIES.map((c) => (
            <button key={c.id} className={`chip tone-${c.tone} ${cat === c.id ? 'on' : ''}`} onClick={() => setCat(c.id)}>
              {tr(c.title)} · {TOPICS.filter((t) => t.category === c.id).length}
            </button>
          ))}
        </div>
        <input className="input search" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={tr({ en: 'Search topics… (e.g. jwt, 注入)', zh: '搜索主题…（如 jwt、注入）' })} aria-label={tr({ en: 'Search topics', zh: '搜索主题' })} />
      </div>
      {cats.map((c) => {
        const list = TOPICS.filter((t) => t.category === c.id && match(t));
        shown += list.length;
        if (!list.length) return null;
        return (
          <div key={c.id} className={`cat-group tone-${c.tone}`}>
            <div className="cat-head">
              <h3>{tr(c.title)}</h3>
              <span className="muted">{tr(c.blurb)}</span>
            </div>
            <div className="cards">
              {list.map((t) => (
                <a key={t.id} className={`card tone-${c.tone}`} href={`#/${t.id}`}>
                  <div className="card-top">
                    <span className={`badge tone-${c.tone}`}>{t.short}</span>
                    <span className="card-kind">{tr(kindLabel(t))}</span>
                  </div>
                  <h3>{tr(t.title)}</h3>
                  <p>{tr(t.blurb)}</p>
                  <div className="card-foot">
                    <span className="mono muted">{t.tag}</span>
                    <span className="go">{tr({ en: 'Open →', zh: '打开 →' })}</span>
                  </div>
                </a>
              ))}
            </div>
          </div>
        );
      })}
      {shown === 0 && <p className="muted">{tr({ en: 'No topics match.', zh: '没有匹配的主题。' })}</p>}
    </section>
  );
}

function WelcomeBanner() {
  const { tr } = useLang();
  const [hidden, setHidden] = useState(() => getFlag('htd-welcome-dismissed'));
  if (hidden) return null;
  return (
    <div className="container">
      <div className="welcome" role="note">
        <span aria-hidden="true">👋</span>
        <p>
          {tr({
            en: 'First time here? The 10-minute beginner’s guide explains how the labs work and which topic to open first.',
            zh: '第一次来？花 10 分钟看看新手指引，了解实验怎么用、先学哪个主题。',
          })}
        </p>
        <a className="btn primary" href="#/start">
          {tr({ en: 'Open the guide', zh: '打开指引' })}
        </a>
        <button
          className="x"
          aria-label={tr({ en: 'Dismiss', zh: '关闭' })}
          onClick={() => {
            setFlag('htd-welcome-dismissed');
            setHidden(true);
          }}
        >
          ✕
        </button>
      </div>
    </div>
  );
}
