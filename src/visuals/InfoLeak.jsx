import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, useBeats } from './kit.jsx';
import { INFO_MODES, recon } from './batch2.js';

/** Information disclosure: six cheap probes, and what each one hands the attacker. */
export default function InfoLeak() {
  const { tr } = useLang();
  const [mode, setMode] = useState('dev');
  const beats = useBeats(650);
  const probes = recon(mode);
  const shown = probes.slice(0, beats.beat);
  const loot = shown.filter((p) => p.loot);

  return (
    <div className="lab info-viz">
      <div className="panel">
        <Seg
          label={L('Site configuration', '站点配置')}
          value={mode}
          onChange={(v) => {
            setMode(v);
            beats.reset();
          }}
          options={Object.entries(INFO_MODES).map(([value, label]) => ({ value, label }))}
        />
        <button type="button" className="btn danger" onClick={() => beats.start(probes.length)}>
          {tr(L('Run recon', '开始侦察'))}
        </button>
        <div className="field-label">{tr(L('What the attacker learned', '攻击者拿到的信息'))}</div>
        <ol className="info-loot">
          {loot.map((p) => (
            <li key={p.id}>{tr(p.loot)}</li>
          ))}
        </ol>
        {beats.done && !loot.length && <p className="hint">{tr(L('Nothing useful.', '没有任何有用的信息。'))}</p>}
        <div className={`verdict ${beats.done ? (loot.length ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('None of these probes is an attack. They are requests anyone can make.', '这些探测都不是攻击，只是任何人都能发的请求。'))
            : loot.length
              ? tr(L(`${loot.length} findings, each one a lead for the next attack.`, `${loot.length} 条发现，每一条都是下一次攻击的线索。`))
              : tr(L('Generic errors, no debug pages, no stray files, TRACE disabled.', '通用错误信息，没有调试页面，没有遗留文件，TRACE 已禁用。'))}
        </div>
      </div>
      <div className="panel">
        <div className="info-probes">
          {probes.map((p, i) => (
            <div key={p.id} className={`info-probe ${i < beats.beat ? (p.loot ? 'leak' : 'clean') : 'wait'}`}>
              <div className="info-req">{p.req}</div>
              {i < beats.beat && <pre className="code small">{p.res}</pre>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
