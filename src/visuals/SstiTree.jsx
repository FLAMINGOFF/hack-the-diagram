import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { Chips, L, useBeats } from './kit.jsx';
import { ENGINES, fingerprint, TREE } from './batch3.js';

const POS = {
  root: [340, 34],
  dollar: [150, 120],
  curly: [500, 120],
  mako: [70, 210],
  freemarker: [230, 210],
  mul: [400, 210],
  erbq: [590, 210],
  jinja2: [335, 300],
  twig: [432, 300],
  erb: [530, 300],
  none: [630, 300],
};
const LEAF = { mako: 'Mako', freemarker: 'FreeMarker', jinja2: 'Jinja2', twig: 'Twig', erb: 'ERB', none: '?' };
const EDGES = Object.entries(TREE).flatMap(([from, n]) => n.branches.map((b) => ({ from, to: b.to, when: b.when })));
const ITEMS = Object.entries(ENGINES).map(([id, e]) => ({ id, label: e.label }));

/** SSTI: fingerprint the template engine with a decision tree, then use its own syntax. */
export default function SstiTree() {
  const { tr } = useLang();
  const [engine, setEngine] = useState('jinja2');
  const [mode, setMode] = useState('concat');
  const beats = useBeats(800);
  const fp = fingerprint(engine, mode);
  const shown = fp.path.slice(0, beats.beat);
  const visited = new Set(['root', ...shown.map((p) => p.next)]);
  const taken = new Set(shown.map((p) => `${p.node}>${p.next}`));
  const found = beats.done && fp.verdict !== 'none';
  const reset = (fn) => (v) => {
    fn(v);
    beats.reset();
  };

  return (
    <div className="ssti-viz">
      <div className="race-controls">
        <div>
          <Chips label={L('The server’s engine (the attacker cannot see this)', '服务器用的模板引擎（攻击者看不到）')} items={ITEMS} value={engine} onPick={(p) => reset(setEngine)(p.id)} />
        </div>
        <Seg
          label={L('How the greeting is built', '问候语怎么生成')}
          value={mode}
          onChange={reset(setMode)}
          options={[
            { value: 'concat', label: L('render("Hi " + name)', 'render("Hi " + name)') },
            { value: 'data', label: L('render("Hi {{name}}", name)', 'render("Hi {{name}}", name)') },
          ]}
        />
        <button type="button" className="btn danger" onClick={() => beats.start(fp.path.length)}>
          {tr(L('Fingerprint', '识别引擎'))}
        </button>
      </div>
      <div className="panel">
        {/* A scrollable region must be focusable so keyboard users can scroll it. */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
        <div className="ssti-scroll" tabIndex={0} role="region" aria-label={tr(L('Decision tree', '决策树'))}>
          <svg viewBox="0 0 680 330" className="ssti-svg">
            {EDGES.map((e) => {
              const [x1, y1] = POS[e.from];
              const [x2, y2] = POS[e.to];
              const on = taken.has(`${e.from}>${e.to}`);
              return (
                <g key={`${e.from}>${e.to}`} className={`ssti-edge ${on ? 'on' : ''}`}>
                  <line x1={x1} y1={y1 + 16} x2={x2} y2={y2 - 16} />
                  <text x={(x1 + x2) / 2 + (x2 > x1 ? 6 : -6)} y={(y1 + y2) / 2 + 4} textAnchor={x2 > x1 ? 'start' : 'end'}>
                    {e.when === 'other' ? tr(L('else', '否则')) : e.when}
                  </text>
                </g>
              );
            })}
            {Object.entries(POS).map(([id, [x, y]]) => {
              const leaf = !TREE[id];
              const w = leaf ? 92 : 150;
              return (
                <g key={id} className={`ssti-node ${leaf ? 'leaf' : ''} ${visited.has(id) && beats.beat ? 'on' : ''} ${beats.done && id === fp.verdict ? 'final' : ''}`} transform={`translate(${x - w / 2} ${y - 16})`}>
                  <rect width={w} height="32" rx="8" />
                  <text x={w / 2} y="21" textAnchor="middle">
                    {leaf ? LEAF[id] : TREE[id].probe}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <ol className="ssti-log">
          {shown.map((p) => (
            <li key={p.node}>
              <code>Hi {p.probe}</code> → <code className={p.out === p.probe ? '' : 'bad-text'}>Hi {p.out}</code>
            </li>
          ))}
        </ol>
        {found && (
          <pre className="code small">
            {`${tr(L('Now in its own syntax:', '现在用它自己的语法：'))}\n${ENGINES[fp.verdict].rce}\n→ uid=1001(app) gid=1001(app)`}
          </pre>
        )}
        <div className={`verdict ${beats.done ? (found ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('Each probe is maths in a different syntax. Only the engine that understands it turns it into a number.', '每个探测都是用不同语法写的算式，只有能看懂它的引擎才会把它算成数字。'))
            : found
              ? tr(L(`Identified ${ENGINES[fp.verdict].label}. Template syntax is code, so the next step is running commands.`, `识别出 ${ENGINES[fp.verdict].label}。模板语法就是代码，所以下一步就是执行命令。`))
              : tr(L('Every probe came back as plain text. The name is data passed to the template, not part of it.', '每个探测都原样返回。名字是传给模板的数据，而不是模板的一部分。'))}
        </div>
      </div>
    </div>
  );
}
