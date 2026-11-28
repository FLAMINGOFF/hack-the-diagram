import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { Chips, L, useBeats } from './kit.jsx';
import { DOM_PAYLOADS, DOM_SINKS, DOM_SOURCES, domRun, serverSees } from './batch3.js';

/** DOM XSS: follow a value from the URL to a sink, entirely inside the browser. */
export default function DomFlow() {
  const { tr } = useLang();
  const [source, setSource] = useState('hash');
  const [sink, setSink] = useState('innerHTML');
  const [value, setValue] = useState(DOM_PAYLOADS[1].value);
  const beats = useBeats(650);
  const r = domRun(value, sink);
  const url = `https://shop.example/${source === 'search' ? '?q=' : '#'}${value}`;
  const reset = (fn) => (v) => {
    fn(v);
    beats.reset();
  };
  const stages = [
    { k: 'url', title: L('Victim opens', '受害者打开'), body: url },
    { k: 'server', title: L('Server receives', '服务器收到'), body: serverSees(value, source), note: source === 'hash' ? L('The fragment never leaves the browser, so server-side filters and logs never see it.', '片段（# 后面的部分）不会离开浏览器，服务器端的过滤和日志都看不到它。') : null },
    { k: 'source', title: L('Source', '源'), body: `const q = decodeURIComponent(${source === 'search' ? "new URLSearchParams(location.search).get('q')" : 'location.hash.slice(1)'})` },
    { k: 'sink', title: L('Sink', '汇点'), body: DOM_SINKS[sink] },
    { k: 'dom', title: L('Result', '结果'), body: r.rendered },
  ];

  return (
    <div className="lab dom-viz">
      <div className="panel">
        <Seg label={L('Where the script reads from', '脚本从哪里读取')} value={source} onChange={reset(setSource)} options={Object.entries(DOM_SOURCES).map(([v, label]) => ({ value: v, label }))} />
        <Seg label={L('Where it writes to', '写到哪里')} value={sink} onChange={reset(setSink)} options={Object.entries(DOM_SINKS).map(([v, label]) => ({ value: v, label }))} />
        <Chips label={L('Payload', '载荷')} items={DOM_PAYLOADS} value={DOM_PAYLOADS.find((p) => p.value === value)?.id} onPick={(p) => reset(setValue)(p.value)} />
        <button type="button" className="btn danger dom-go" onClick={() => beats.start(stages.length)}>
          {tr(L('Open the link', '打开链接'))}
        </button>
      </div>
      <div className="panel">
        <ol className="dom-stages">
          {stages.map((s, i) => (
            <li key={s.k} className={`dom-stage ${i < beats.beat ? 'on' : ''} ${s.k === 'dom' && i < beats.beat && r.executes ? 'bad' : ''}`}>
              <span className="dom-title">{tr(s.title)}</span>
              <code>{s.body}</code>
              {s.note && i < beats.beat && <span className="dom-note">{tr(s.note)}</span>}
            </li>
          ))}
        </ol>
        {beats.done && r.executes && (
          <div className="dom-alert" role="img" aria-label="alert">
            <b>shop.example {tr(L('says', '显示'))}</b>
            <span>shop.example</span>
            {r.onClick && <em>{tr(L('(after the victim clicks the link)', '（在受害者点击链接之后）'))}</em>}
          </div>
        )}
        <div className={`verdict ${beats.done ? (r.executes ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {beats.done ? tr(r.why) : tr(L('Pick a source, a sink and a payload, then open the link.', '选一个源、一个汇点和一个载荷，然后打开链接。'))}
        </div>
      </div>
    </div>
  );
}
