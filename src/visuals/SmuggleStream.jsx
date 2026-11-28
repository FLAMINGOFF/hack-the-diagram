import { useMemo, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { StepControls, useStepper } from '../components/Stepper.jsx';
import { FRONT_BACK, SMUGGLED, VICTIM, build, run, visible } from './smuggling.js';

const L = (en, zh) => ({ en, zh });
const NAMES = { CL: 'Content-Length', TE: 'Transfer-Encoding: chunked' };
const PRESETS = [
  { id: 'normal', label: L('Normal request', '正常请求') },
  { id: 'clte', label: 'CL.TE' },
  { id: 'tecl', label: 'TE.CL' },
];

/** Render bytes as spans, each range with its own class. ranges: [[from, to, className]] */
function Bytes({ text, ranges }) {
  const parts = [];
  let at = 0;
  for (const [from, to, cls] of ranges) {
    if (from > at) parts.push([at, from, '']);
    if (to > from) parts.push([from, to, cls]);
    at = Math.max(at, to);
  }
  if (at < text.length) parts.push([at, text.length, '']);
  return (
    <pre className="smug-bytes">
      {parts.map(([a, b, cls], i) => (
        <span key={i} className={cls}>
          {visible(text.slice(a, b))}
        </span>
      ))}
    </pre>
  );
}

/** Step through one smuggling attack and see where each server thinks the request ends. */
export default function SmuggleStream() {
  const { tr } = useLang();
  const [preset, setPreset] = useState('clte');
  const [text, setText] = useState(() => build('clte', SMUGGLED.clte));
  const [front, setFront] = useState('CL');
  const [back, setBack] = useState('TE');
  const [defended, setDefended] = useState(false);

  const r = useMemo(() => run(text, front, back, defended), [text, front, back, defended]);

  const steps = useMemo(() => {
    const s = [{ kind: 'normal', label: L('The attacker sends one request', '攻击者发出一个请求'), note: L(`${r.wire.length} bytes go to the front end. Line breaks are CR LF (␍␊), 2 bytes each.`, `${r.wire.length} 字节发往前端。换行是 CR LF（␍␊），每个 2 字节。`) }];
    if (r.rejected) {
      s.push({ kind: defended ? 'secure' : 'blocked', label: L('Front end rejects it', '前端拒绝了它'), note: r.note });
      return s;
    }
    s.push({ kind: 'normal', label: L(`Front end trusts ${NAMES[front]}`, `前端按 ${NAMES[front]} 解析`), note: L(`${tr(r.f.note)}. It forwards bytes 0–${r.f.end} as one request, on a connection it reuses for other users.`, `${tr(r.f.note)}。它把第 0–${r.f.end} 字节作为一个请求转发，而这条连接还会被其他用户复用。`) });
    if (r.timeout) {
      s.push({ kind: 'blocked', label: L(`Back end trusts ${NAMES[back]}`, `后端按 ${NAMES[back]} 解析`), note: r.note });
      return s;
    }
    s.push({
      kind: r.poisoned ? 'attack' : 'secure',
      label: L(`Back end trusts ${NAMES[back]}`, `后端按 ${NAMES[back]} 解析`),
      note: r.poisoned
        ? L(`${tr(r.b.note)}, so its request ends at byte ${r.b.end}. The last ${r.leftover.length} bytes (red) stay in the connection, waiting.`, `${tr(r.b.note)}，所以它认为请求在第 ${r.b.end} 字节结束。最后 ${r.leftover.length} 字节（红色）留在连接里等待。`)
        : L(`${tr(r.b.note)}. Both servers agree where the request ends. Nothing is left over.`, `${tr(r.b.note)}。两台服务器对请求在哪里结束看法一致，没有剩余字节。`),
    });
    s.push({ kind: r.poisoned ? 'attack' : 'normal', label: L('A victim’s request arrives', '受害者的请求到达'), note: r.poisoned ? L('The front end sends the victim’s request down the same connection. The back end glues it onto the leftover bytes.', '前端把受害者的请求沿同一条连接发给后端，后端把它接在剩余字节后面。') : L('The victim’s request is processed on its own, as normal.', '受害者的请求被单独正常处理。') });
    const outcome = !r.poisoned
      ? L(`Back end sees ${r.method} ${r.path}: exactly what the victim sent.`, `后端看到的是 ${r.method} ${r.path}：正是受害者发的。`)
      : r.cookie
        ? L(`Back end sees ${r.method} ${r.path} carrying the victim’s cookie (${r.cookie}). The victim’s own request line became a junk header.`, `后端看到的是带着受害者 Cookie（${r.cookie}）的 ${r.method} ${r.path}。受害者自己的请求行变成了一个无用的请求头。`)
        : L(`Back end sees ${r.method} ${r.path}. The victim’s request is swallowed into its body, and the victim gets the response meant for the smuggled request.`, `后端看到的是 ${r.method} ${r.path}。受害者的请求被吞进了它的请求体，受害者收到的是走私请求的响应。`);
    s.push({ kind: r.poisoned ? 'attack' : 'secure', label: L('What the back end processes next', '后端接下来处理的内容'), note: outcome });
    return s;
  }, [r, front, back, defended, tr]);

  const stepper = useStepper(steps.length, 2600);
  const { step } = stepper;

  const ranges = [];
  let shown = r.wire;
  if (step === 1 && r.f) ranges.push([0, r.f.end, 'by-front']);
  if (step >= 2 && r.b) ranges.push([0, r.b.end, 'by-back'], [r.b.end, r.f.end, 'by-left']);
  if (step >= 3 && r.next !== undefined) {
    shown = r.next;
    ranges.length = 0;
    ranges.push([0, r.leftover.length, 'by-left'], [r.leftover.length, r.next.length, 'by-victim']);
  }
  if (r.rejected && step >= 1) ranges.push([0, r.wire.length, 'by-rejected']);

  const choose = (id) => {
    setPreset(id);
    setText(build(id, SMUGGLED[id] ?? ''));
    setFront(FRONT_BACK[id][0]);
    setBack(FRONT_BACK[id][1]);
    stepper.go(0);
  };
  const change = (fn) => (v) => {
    fn(v);
    setPreset(null);
    stepper.go(0);
  };

  return (
    <div className="smug-viz">
      <div className="lab">
        <div className="panel">
          <div className="field-label">{tr(L('Attack', '攻击'))}</div>
          <div className="chips">
            {PRESETS.map((p) => (
              <button type="button" key={p.id} className={`chip ${preset === p.id ? 'on' : ''}`} onClick={() => choose(p.id)}>
                {tr(p.label)}
              </button>
            ))}
          </div>
          <Seg label={L('Front end uses', '前端使用')} value={front} onChange={change(setFront)} options={[{ value: 'CL', label: 'Content-Length' }, { value: 'TE', label: 'chunked' }]} />
          <Seg label={L('Back end uses', '后端使用')} value={back} onChange={change(setBack)} options={[{ value: 'CL', label: 'Content-Length' }, { value: 'TE', label: 'chunked' }]} />
          <label className="check smug-check">
            <input type="checkbox" checked={defended} onChange={(e) => change(setDefended)(e.target.checked)} /> {tr(L('Defence: front end rejects requests with both headers', '防御：前端拒绝同时带两种头的请求'))}
          </label>
          <label className="field-label" htmlFor="smug-raw">
            {tr(L('Raw request (editable)', '原始请求（可编辑）'))}
          </label>
          <textarea id="smug-raw" className="input mono" rows={11} value={text} spellCheck={false} onChange={(e) => change(setText)(e.target.value)} />
        </div>
        <div className="panel">
          <div className="smug-actors" aria-hidden="true">
            <span className={step === 0 ? 'on atk' : 'atk'}>{tr(L('Attacker', '攻击者'))}</span>
            <span className="arrow">→</span>
            <span className={step === 1 ? 'on' : ''}>{tr(L('Front end', '前端'))} · {front}</span>
            <span className="arrow">→</span>
            <span className={step >= 2 ? 'on' : ''}>{tr(L('Back end', '后端'))} · {back}</span>
            <span className="arrow">←</span>
            <span className={step === 3 ? 'on vic' : 'vic'}>{tr(L('Victim', '受害者'))}</span>
          </div>
          <div className="field-label">{step >= 3 && r.next !== undefined ? tr(L('Bytes the back end reads next', '后端接下来读到的字节')) : tr(L('Bytes on the wire', '线路上的字节'))}</div>
          <Bytes text={shown} ranges={ranges} />
          <div className="smug-legend">
            {step === 1 && <span className="by-front">{tr(L('front end: request 1', '前端：请求 1'))}</span>}
            {step >= 2 && step < 3 && <span className="by-back">{tr(L('back end: request 1', '后端：请求 1'))}</span>}
            {step >= 2 && r.poisoned && <span className="by-left">{tr(L('left in the connection', '留在连接里'))}</span>}
            {step >= 3 && r.next !== undefined && <span className="by-victim">{tr(L('victim’s request', '受害者的请求'))}</span>}
          </div>
        </div>
      </div>
      <StepControls stepper={stepper} messages={steps} />
      <p className="muted tiny">
        {tr(L('Victim’s request used in step 4:', '第 4 步使用的受害者请求：'))} <code className="mono">{VICTIM.split('\r\n').slice(0, 3).join(' ⏎ ')}</code>
      </p>
    </div>
  );
}
