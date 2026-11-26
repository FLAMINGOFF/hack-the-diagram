import { useEffect, useMemo, useState } from 'react';
import { useLang } from '../i18n.jsx';
import DeepDive from '../components/DeepDive.jsx';
import SequenceDiagram from '../components/SequenceDiagram.jsx';
import { StepControls, useStepper } from '../components/Stepper.jsx';
import { Defenses, InterviewQs, Section, Seg, TopicShell } from '../components/TopicShell.jsx';

const METHODS = {
  form: {
    label: { en: 'Auto-submit POST form', zh: '自动提交 POST 表单' },
    request: 'POST /transfer  to=mallory&amount=1000',
    topLevel: true,
    safe: false,
    html: `<!-- evil.example/cute-cats.html -->
<form action="https://bank.example/transfer" method="POST">
  <input type="hidden" name="to" value="mallory">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>`,
  },
  img: {
    label: { en: 'Hidden <img> GET', zh: '隐藏 <img> GET' },
    request: 'GET /transfer?to=mallory&amount=1000',
    topLevel: false,
    safe: true,
    html: `<!-- evil.example/cute-cats.html -->
<img src="https://bank.example/transfer?to=mallory&amount=1000"
     width="0" height="0">`,
  },
  link: {
    label: { en: 'Link the victim clicks (GET)', zh: '诱导点击链接（GET）' },
    request: 'GET /transfer?to=mallory&amount=1000',
    topLevel: true,
    safe: true,
    html: `<!-- evil.example/cute-cats.html -->
<a href="https://bank.example/transfer?to=mallory&amount=1000">
  Claim your free textbook 📚
</a>`,
  },
};

function evaluate({ samesite, token, method }) {
  const m = METHODS[method];
  const cookieSent = samesite === 'None' || (samesite === 'Lax' && m.topLevel && m.safe);
  if (!cookieSent) return { cookieSent, status: 401, success: false, stoppedBy: 'samesite' };
  if (token) return { cookieSent, status: 403, success: false, stoppedBy: 'token' };
  return { cookieSent, status: 200, success: true, stoppedBy: null };
}

const ACTORS = [
  { id: 'evil', label: 'evil.example', sub: { en: 'attacker site', zh: '攻击者网站' }, tone: 'red' },
  { id: 'br', label: { en: "Alice's browser", zh: 'Alice 的浏览器' }, sub: { en: 'logged in to bank', zh: '已登录银行' }, tone: 'green' },
  { id: 'bank', label: 'bank.example', sub: { en: 'target', zh: '目标' }, tone: 'neutral' },
];

export default function Csrf() {
  const { tr } = useLang();
  const [samesite, setSamesite] = useState('None');
  const [token, setToken] = useState(false);
  const [method, setMethod] = useState('form');
  const outcome = useMemo(() => evaluate({ samesite, token, method }), [samesite, token, method]);
  const m = METHODS[method];

  const messages = useMemo(() => {
    const cookie = `Set-Cookie: session=…; SameSite=${samesite}`;
    const reqKind = outcome.cookieSent ? 'attack' : 'blocked';
    const final =
      outcome.status === 200
        ? { kind: 'attack', label: { en: '200 OK: $1000 sent to mallory', zh: '200 OK：$1000 转给了 mallory' }, note: { en: 'The bank saw a valid session cookie and a well-formed request. From its point of view, Alice asked for this transfer. The attack succeeded without the attacker ever seeing the cookie.', zh: '银行看到了有效的会话 Cookie 和格式正确的请求，在它看来就是 Alice 自己要转账。攻击者全程没有看到 Cookie，攻击却成功了。' } }
        : outcome.status === 401
          ? { kind: 'secure', label: { en: '401 Not logged in', zh: '401 未登录' }, note: { en: `SameSite=${samesite} kept the cookie out of this cross-site request, so the bank treats it as anonymous and refuses.`, zh: `SameSite=${samesite} 让这个跨站请求没有带上 Cookie，银行把它当作匿名请求并拒绝。` } }
          : { kind: 'secure', label: { en: '403 Invalid CSRF token', zh: '403 CSRF Token 无效' }, note: { en: 'The cookie arrived, but the request lacks the secret token that the real bank form embeds. evil.example cannot read that token (same-origin policy), so it cannot forge it.', zh: 'Cookie 到了，但请求里没有真实银行表单里嵌入的秘密 Token。由于同源策略，evil.example 读不到这个 Token，也就伪造不出来。' } };
    return [
      {
        from: 'br', to: 'bank',
        label: 'POST /login  alice / ••••••',
        note: { en: 'Earlier, Alice logs in to her bank normally.', zh: '早些时候，Alice 正常登录了网银。' },
      },
      {
        from: 'bank', to: 'br',
        label: cookie,
        note: token
          ? { en: `The bank sets a session cookie with SameSite=${samesite}, and also embeds a random CSRF token in every form it renders.`, zh: `银行设置了 SameSite=${samesite} 的会话 Cookie，并且在它渲染的每个表单里都嵌入了一个随机 CSRF Token。` }
          : { en: `The bank sets a session cookie with SameSite=${samesite}. From now on the browser attaches it to requests to bank.example according to that rule.`, zh: `银行设置了 SameSite=${samesite} 的会话 Cookie。此后浏览器会按这个规则，在发往 bank.example 的请求里带上它。` },
      },
      {
        from: 'br', to: 'evil',
        label: 'GET /cute-cats.html',
        note: { en: 'Still logged in, Alice opens a link from a chat message. It is Mallory’s site.', zh: '仍处于登录状态的 Alice 点开了聊天里的一个链接，那是 Mallory 的网站。' },
      },
      {
        from: 'evil', to: 'br', kind: 'attack',
        label: tr(m.label),
        note: { en: 'The page contains markup that makes the browser send a request to bank.example. Mallory cannot read the response, but she does not need to.', zh: '页面里的代码会让浏览器向 bank.example 发一个请求。Mallory 读不到响应，但她也不需要。' },
        code: m.html,
      },
      {
        from: 'br', to: 'bank', kind: reqKind,
        label: `${m.request}  ${outcome.cookieSent ? '🍪' : '(no cookie)'}`,
        note: outcome.cookieSent
          ? { en: `The browser attaches Alice’s session cookie automatically${samesite === 'Lax' ? ': Lax still allows cookies on top-level GET navigations' : ''}. This automatic attachment is the whole vulnerability.`, zh: `浏览器自动带上了 Alice 的会话 Cookie${samesite === 'Lax' ? '：Lax 仍然允许顶层 GET 导航携带 Cookie' : ''}。这种“自动携带”就是整个漏洞的根源。` }
          : { en: samesite === 'Strict' ? 'SameSite=Strict: the request comes from another site, so the browser sends it without the cookie.' : 'SameSite=Lax only sends cookies on top-level navigations with safe methods (GET). This request is not one, so no cookie.', zh: samesite === 'Strict' ? 'SameSite=Strict：请求来自其他站点，浏览器不带 Cookie 发送。' : 'SameSite=Lax 只在使用安全方法（GET）的顶层导航中携带 Cookie。这个请求不符合，所以不带 Cookie。' },
      },
      { from: 'bank', to: 'br', ...final },
    ];
  }, [samesite, token, outcome, m, tr]);

  const stepper = useStepper(messages.length, 2000);
  const { restart } = stepper;
  useEffect(() => {
    restart();
  }, [samesite, token, method, restart]);

  const done = stepper.step === messages.length - 1;
  const balance = done && outcome.success ? 4000 : 5000;

  return (
    <TopicShell
      id="csrf"
      tldr={{
        en: 'CSRF tricks a logged-in victim’s browser into sending a request the victim never meant to send. It works because browsers attach cookies automatically, even when another site triggered the request.',
        zh: 'CSRF 诱骗已登录受害者的浏览器发出一个他本人并不想发的请求。它之所以成立，是因为浏览器会自动带上 Cookie，哪怕请求是别的网站触发的。',
      }}
    >
      <Section kicker={{ en: 'Lab', zh: '实验' }} title={{ en: 'Make Alice send Mallory $1000', zh: '让 Alice 给 Mallory 转 $1000' }}>
        <div className="lab">
          <div className="panel">
            <Seg
              label={{ en: 'Session cookie SameSite', zh: '会话 Cookie 的 SameSite' }}
              value={samesite}
              onChange={setSamesite}
              options={[
                { value: 'None', label: 'None' },
                { value: 'Lax', label: 'Lax' },
                { value: 'Strict', label: 'Strict' },
              ]}
            />
            <Seg
              label={{ en: 'Anti-CSRF token', zh: '反 CSRF Token' }}
              value={token ? 'on' : 'off'}
              onChange={(v) => setToken(v === 'on')}
              options={[
                { value: 'off', label: { en: 'Off', zh: '关闭' } },
                { value: 'on', label: { en: 'On', zh: '开启' } },
              ]}
            />
            <Seg
              label={{ en: 'Attack technique', zh: '攻击方式' }}
              value={method}
              onChange={setMethod}
              options={Object.entries(METHODS).map(([value, x]) => ({ value, label: x.label }))}
            />
            <div className="field-label">{tr({ en: "Mallory's page", zh: 'Mallory 的页面' })}</div>
            <pre className="code small">{m.html}</pre>
            <p className="tiny muted">
              {tr({
                en: 'GET variants assume the bank (wrongly) lets GET change state. Modern Chrome treats cookies without a SameSite attribute as Lax.',
                zh: 'GET 方式的前提是银行（错误地）允许 GET 修改状态。现代 Chrome 会把没有 SameSite 属性的 Cookie 当作 Lax 处理。',
              })}
            </p>
          </div>

          <div className="panel">
            <div className={`outcome ${done ? (outcome.success ? 'bad' : 'good') : 'pending'}`}>
              <div className="outcome-head">
                <span>{tr({ en: "Alice's balance", zh: 'Alice 的余额' })}</span>
                <b className="mono">${balance.toLocaleString()}</b>
              </div>
              <p>
                {!done
                  ? tr({ en: 'Attack in progress…', zh: '攻击进行中…' })
                  : outcome.success
                    ? tr({ en: '💸 Attack succeeded. Nothing in the request looked forged to the bank.', zh: '💸 攻击成功。在银行看来，请求里没有任何伪造痕迹。' })
                    : outcome.stoppedBy === 'samesite'
                      ? tr({ en: `🛡️ Stopped by SameSite=${samesite}: the cookie was never sent.`, zh: `🛡️ 被 SameSite=${samesite} 拦下：Cookie 根本没有发送。` })
                      : tr({ en: '🛡️ Stopped by the CSRF token: cookie arrived, token missing.', zh: '🛡️ 被 CSRF Token 拦下：Cookie 到了，但 Token 缺失。' })}
              </p>
            </div>
            <div className="checks">
              <Check ok={!outcome.cookieSent} label={{ en: 'Cookie withheld on cross-site request', zh: '跨站请求不携带 Cookie' }} />
              <Check ok={token} label={{ en: 'Server verifies a secret per-session token', zh: '服务器校验每个会话的秘密 Token' }} />
              <Check ok={!m.safe} neutral label={{ en: 'Uses POST (GET should never change state)', zh: '使用 POST（GET 不应修改状态）' }} />
            </div>
            <div className="matrix">
              <div className="field-label">{tr({ en: 'Does the cookie get sent?', zh: 'Cookie 会被发送吗？' })}</div>
              <table>
                <thead>
                  <tr>
                    <th />
                    {Object.values(METHODS).map((x, i) => (
                      <th key={i}>{tr(x.label)}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {['None', 'Lax', 'Strict'].map((ss) => (
                    <tr key={ss} className={ss === samesite ? 'hl' : ''}>
                      <th>{ss}</th>
                      {Object.keys(METHODS).map((k) => {
                        const sent = evaluate({ samesite: ss, token: false, method: k }).cookieSent;
                        return (
                          <td key={k} className={`${sent ? 'bad-text' : 'good-text'} ${ss === samesite && k === method ? 'cur' : ''}`}>
                            {sent ? '🍪 ' + tr({ en: 'sent', zh: '发送' }) : '✕ ' + tr({ en: 'withheld', zh: '不发送' })}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </Section>

      <Section kicker={{ en: 'Trace', zh: '追踪' }} title={{ en: 'The request, step by step', zh: '逐步看这个请求' }}>
        <p className="muted">{tr({ en: 'Changing any setting above replays the attack.', zh: '修改上面任意设置都会重放攻击。' })}</p>
        <SequenceDiagram actors={ACTORS} messages={messages} step={stepper.step} onSelect={stepper.go} title={{ en: 'CSRF sequence', zh: 'CSRF 时序图' }} />
        <StepControls stepper={stepper} messages={messages} />
      </Section>

      <DeepDive id="csrf" />

      <Section kicker={{ en: 'Defend', zh: '防御' }} title={{ en: 'Defences that actually work', zh: '真正有效的防御' }}>
        <Defenses
          items={[
            { title: { en: 'Synchronizer or double-submit tokens', zh: '同步令牌或双重提交 Token' }, body: { en: 'Put an unpredictable token in each form or header and verify it server-side. Most frameworks (Django, Rails, Spring, ASP.NET) do this out of the box.', zh: '在每个表单或请求头里放一个不可预测的 Token，并在服务器端校验。多数框架（Django、Rails、Spring、ASP.NET）默认就支持。' } },
            { title: { en: 'SameSite cookies', zh: 'SameSite Cookie' }, body: { en: 'Lax blocks most CSRF; Strict blocks all cross-site cookie sending but logs users out when they arrive from links. A strong layer, but not a replacement for tokens.', zh: 'Lax 能挡住大多数 CSRF；Strict 完全不在跨站请求里带 Cookie，但用户从外部链接进来时会显示未登录。是一道很强的防线，但不能代替 Token。' } },
            { title: { en: 'Check Origin / Sec-Fetch-Site', zh: '检查 Origin / Sec-Fetch-Site' }, body: { en: 'Reject state-changing requests whose Origin is not yours, or whose Sec-Fetch-Site is cross-site.', zh: '拒绝 Origin 不是自己、或 Sec-Fetch-Site 为 cross-site 的状态修改请求。' } },
            { title: { en: 'Never change state with GET', zh: '永远不要用 GET 修改状态' }, body: { en: 'GET requests are triggered by images, links and prefetchers. Keep them side-effect free.', zh: 'GET 请求会被图片、链接、预加载随意触发，应保持无副作用。' } },
          ]}
        />
      </Section>

      <Section kicker={{ en: 'Interview prep', zh: '面试准备' }} title={{ en: 'Questions you might get', zh: '可能被问到的问题' }}>
        <InterviewQs
          items={[
            { q: { en: 'What is the difference between XSS and CSRF?', zh: 'XSS 和 CSRF 有什么区别？' }, a: { en: 'XSS runs the attacker’s code on the target origin, so it can read responses and do anything the user can. CSRF only makes the browser send a request; the attacker cannot read the result. XSS defeats CSRF tokens because it can read them from the page.', zh: 'XSS 让攻击者的代码在目标源上运行，能读取响应、做用户能做的一切。CSRF 只是让浏览器发出请求，攻击者看不到结果。XSS 能从页面里读出 CSRF Token，所以 XSS 可以绕过 CSRF 防护。' } },
            { q: { en: 'Does CORS protect against CSRF?', zh: 'CORS 能防 CSRF 吗？' }, a: { en: 'No. CORS controls whether a page may read a cross-origin response. Simple requests such as form POSTs are still sent; CSRF does not need to read the response.', zh: '不能。CORS 控制的是页面能否读取跨源响应。表单 POST 这样的简单请求照样会被发送，而 CSRF 根本不需要读响应。' } },
            { q: { en: 'Do APIs using Authorization: Bearer headers need CSRF protection?', zh: '用 Authorization: Bearer 头的 API 需要防 CSRF 吗？' }, a: { en: 'Generally not, because the browser does not attach that header automatically. CSRF is specific to ambient credentials: cookies, HTTP auth, client certificates.', zh: '一般不需要，因为浏览器不会自动附加这个头。CSRF 只针对“环境凭据”：Cookie、HTTP 认证、客户端证书。' } },
          ]}
        />
      </Section>
    </TopicShell>
  );
}

function Check({ ok, label, neutral }) {
  const { tr } = useLang();
  return (
    <div className={`check ${ok ? 'ok' : neutral ? 'meh' : 'no'}`}>
      <span>{ok ? '✓' : '✕'}</span> {tr(label)}
    </div>
  );
}
