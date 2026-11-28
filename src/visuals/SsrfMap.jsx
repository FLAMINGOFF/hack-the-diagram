import { useEffect, useMemo, useRef, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { APP_HOST, DEFENCES, NODES, PRESETS, simulate } from './ssrf.js';

const L = (en, zh) => ({ en, zh });

// Positions on the 760 × 360 map.
const POS = {
  attacker: [90, 180],
  app: [330, 180],
  stock: [640, 60],
  admin: [640, 180],
  meta: [640, 300],
  local: [330, 312],
};
const TONE = { attacker: 'var(--red)', app: 'var(--blue)', stock: 'var(--green)', admin: 'var(--amber)', meta: 'var(--amber)', local: 'var(--amber)' };

function Node({ id, label, sub, active, hit }) {
  const [x, y] = POS[id];
  return (
    <g className={`ssrf-node ${active ? 'active' : ''} ${hit ? 'hit' : ''}`} transform={`translate(${x - 78} ${y - 26})`}>
      <rect width="156" height="52" rx="10" style={{ stroke: TONE[id] }} />
      <text x="78" y="22" textAnchor="middle" className="n-label">
        {label}
      </text>
      <text x="78" y="40" textAnchor="middle" className="n-sub">
        {sub}
      </text>
    </g>
  );
}

/** Animated network map: watch the stock checker carry your URL past the firewall. */
export default function SsrfMap() {
  const { tr } = useLang();
  const [url, setUrl] = useState(PRESETS[0].url);
  const [defence, setDefence] = useState('none');
  const [run, setRun] = useState(null);
  const [phase, setPhase] = useState(0);
  const timer = useRef(null);

  // Route the packet takes for the last run: a list of map positions.
  const route = useMemo(() => {
    if (!run) return [];
    if (run.outcome === 'blocked' || run.outcome === 'error') {
      const r = ['attacker', 'app'];
      if (run.target === 'stock' && run.steps.some((s) => s.at === 'stock')) r.push('stock', 'app');
      return [...r, 'attacker'];
    }
    const out = ['attacker', 'app', ...(run.via ? [run.via, 'app'] : []), run.target, 'app', 'attacker'];
    return out;
  }, [run]);

  useEffect(() => {
    clearInterval(timer.current);
    if (!route.length) return undefined;
    timer.current = setInterval(() => setPhase((p) => (p >= route.length - 1 ? (clearInterval(timer.current), p) : p + 1)), 750);
    return () => clearInterval(timer.current);
  }, [route]);

  const send = (e) => {
    e?.preventDefault();
    setPhase(0);
    setRun(simulate(url.trim(), defence));
  };

  const at = route[phase] ?? 'attacker';
  const [px, py] = POS[at];
  const finished = run && phase >= route.length - 1;
  const shownSteps = run ? run.steps.slice(0, Math.max(1, Math.ceil(((phase + 1) / route.length) * run.steps.length))) : [];
  const bad = run?.outcome === 'pwned';

  return (
    <div className="ssrf-viz">
      <form className="ssrf-controls" onSubmit={send}>
        <Seg label={L('Server-side check', '服务端检查')} value={defence} onChange={(v) => { setDefence(v); setRun(null); }} options={Object.entries(DEFENCES).map(([value, label]) => ({ value, label }))} />
        <div className="chips">
          {PRESETS.map((p) => (
            <button type="button" key={p.url} className={`chip ${url === p.url ? 'on' : ''}`} onClick={() => setUrl(p.url)}>
              {tr(p.label)}
            </button>
          ))}
        </div>
        <label className="field-label" htmlFor="ssrf-url">
          stockApi =
        </label>
        <div className="row ssrf-input">
          <input id="ssrf-url" className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} autoComplete="off" />
          <button className="btn danger" type="submit">
            {tr(L('Send', '发送'))}
          </button>
        </div>
      </form>

      <p className="muted tiny scroll-hint">{tr(L('Swipe the map sideways to see the whole network.', '左右滑动地图可以看到整个网络。'))}</p>
      <div className="ssrf-stage">
        <svg viewBox="0 0 760 360" role="img" aria-label={tr(L('Network map: attacker, firewall, web app and internal services', '网络拓扑：攻击者、防火墙、Web 应用和内部服务'))}>
          <rect x="190" y="10" width="560" height="340" rx="16" className="ssrf-lan" />
          <text x="738" y="340" textAnchor="end" className="n-sub">
            {tr(L('internal network', '内网'))}
          </text>
          <line x1="190" y1="10" x2="190" y2="350" className="ssrf-fw" />
          <text x="196" y="30" className="n-sub fw-label">
            🧱 {tr(L('firewall', '防火墙'))}
          </text>

          {/* the direct route the firewall stops */}
          <path d="M150 196 L 190 212" className="ssrf-direct" />
          <text x="190" y="230" textAnchor="middle" className="fw-x">
            ✕
          </text>
          <text x="90" y="236" textAnchor="middle" className="n-sub">
            {tr(L('direct access: dropped', '直接访问：被丢弃'))}
          </text>

          {['stock', 'admin', 'meta'].map((id) => (
            <line key={id} x1={POS.app[0] + 78} y1={POS.app[1]} x2={POS[id][0] - 78} y2={POS[id][1]} className="ssrf-link" />
          ))}
          <line x1={POS.app[0]} y1={POS.app[1] + 26} x2={POS.local[0]} y2={POS.local[1] - 26} className="ssrf-link" />
          <line x1={POS.attacker[0] + 78} y1={POS.attacker[1]} x2={POS.app[0] - 78} y2={POS.app[1]} className="ssrf-link public" />
          <text x="211" y="170" textAnchor="middle" className="n-sub">
            :443
          </text>

          <Node id="attacker" label={tr(L('Attacker', '攻击者'))} sub="evil.example" active={at === 'attacker'} />
          <Node id="app" label={tr(L('Shop web app', '商城 Web 应用'))} sub={tr(L('stock checker', '库存查询'))} active={at === 'app'} />
          {Object.entries(NODES).map(([id, n]) => (
            <Node key={id} id={id} label={tr(n.label)} sub={n.sub} active={at === id} hit={finished && run?.target === id && run.outcome !== 'blocked'} />
          ))}

          {run && (
            <g className={`ssrf-packet ${bad && phase > route.indexOf(run.target) ? 'loot' : ''} ${run.outcome === 'blocked' && phase >= 2 ? 'stopped' : ''}`} style={{ transform: `translate(${px}px, ${py - 34}px)` }}>
              <circle r="9" />
            </g>
          )}
        </svg>
      </div>

      <div className="console ssrf-log" aria-live="polite">
        <div className="console-head">
          <span>{tr(L('Server log', '服务器日志'))}</span>
          <span className="muted">{APP_HOST}</span>
        </div>
        {!run && <div className="console-empty">{tr(L('Pick a URL and press Send.', '选一个 URL，然后点发送。'))}</div>}
        {shownSteps.map((s, i) => (
          <div key={i} className={`console-line ${s.kind === 'bad' || s.kind === 'blocked' ? 'bad' : s.kind === 'good' ? 'good' : ''}`}>
            {s.kind === 'blocked' ? '⛔ ' : s.kind === 'bad' ? '💥 ' : '› '}
            {tr(s.text)}
          </div>
        ))}
        {finished && run.body && <pre className="ssrf-body">{run.body}</pre>}
      </div>
      {finished && (
        <div className={`verdict ${bad ? 'bad' : 'good'}`}>
          {bad
            ? tr(L('The server reached a machine the attacker cannot, and handed back the answer. That is SSRF.', '服务器访问了攻击者自己够不着的机器，并把结果交了回来。这就是 SSRF。'))
            : run.outcome === 'blocked'
              ? tr(L('Stopped before anything internal was reached.', '在访问任何内部资源之前就被拦下了。'))
              : tr(L('A normal request: the server only talked to the stock API.', '正常请求：服务器只访问了库存 API。'))}
        </div>
      )}
    </div>
  );
}
