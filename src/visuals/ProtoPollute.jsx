import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Log, useBeats } from './kit.jsx';
import { PP_ATTACKS, PP_DEFENCES, ppMerge } from './batch4.js';

const MERGE = `function merge(target, src) {
  for (const key in src) {
    if (isObject(src[key]))
      merge(target[key] ??= {}, src[key]);
    else target[key] = src[key];
  }
}
merge(settings, JSON.parse(body));`;

/** Prototype pollution, simulated: the merge walks a key path into the prototype every object shares. */
export default function ProtoPollute() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('proto');
  const [defence, setDefence] = useState('none');
  const beats = useBeats(750);
  const r = ppMerge(attack, defence);
  const done = beats.done;
  const polluted = done && r.polluted;
  const reset = (fn) => (v) => {
    fn(v);
    beats.reset();
  };

  return (
    <div className="lab pp-viz">
      <div className="panel">
        <Seg label={L('JSON body', 'JSON 请求体')} value={attack} onChange={reset(setAttack)} options={Object.entries(PP_ATTACKS).map(([value, a]) => ({ value, label: a.label }))} />
        <pre className="code small">{PP_ATTACKS[attack].body}</pre>
        <Seg label={L('Merge function', '合并函数')} value={defence} onChange={reset(setDefence)} options={Object.entries(PP_DEFENCES).map(([value, label]) => ({ value, label }))} />
        <pre className="code small">{MERGE}</pre>
        <button type="button" className="btn danger" onClick={() => beats.start(r.trace.length)}>
          {tr(L('Merge', '合并'))}
        </button>
      </div>
      <div className="panel">
        <Log title={L('merge() walks the keys', 'merge() 逐个处理键')} lines={r.trace} beat={beats.beat} empty={L('Press “Merge”.', '点击“合并”。')} />
        <div className="pp-objs">
          <div className="pp-obj">
            <b>settings</b>
            <code>theme: "dark"</code>
            {polluted && <code className="pp-inh">isAdmin: true ({tr(L('inherited', '继承来的'))})</code>}
          </div>
          <div className="pp-obj">
            <b>{'const opts = {}'}</b>
            <code>{tr(L('(no own properties)', '（没有自有属性）'))}</code>
            {polluted && <code className="pp-inh">isAdmin: true ({tr(L('inherited', '继承来的'))})</code>}
          </div>
          <div className={`pp-obj proto ${polluted ? 'bad' : ''}`}>
            <b>Object.prototype</b>
            <code>toString, hasOwnProperty, …</code>
            {polluted && <code className="bad-text">isAdmin: true</code>}
          </div>
        </div>
        <div className={`verdict ${done ? (r.polluted ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!done
            ? tr(L('Every plain object inherits from Object.prototype. Watch where the merge ends up writing.', '每个普通对象都继承自 Object.prototype。看合并最后写到了哪里。'))
            : r.polluted
              ? tr(L('Every object in the process now has isAdmin. A later check like if (opts.isAdmin) passes for everyone.', '进程里的每个对象现在都有 isAdmin 了。之后像 if (opts.isAdmin) 这样的检查对所有人都成立。'))
              : tr(L('Object.prototype is untouched.', 'Object.prototype 没有被改动。'))}
        </div>
      </div>
    </div>
  );
}
