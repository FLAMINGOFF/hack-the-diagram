import { useMemo, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from './TopicShell.jsx';

/**
 * A data-driven lab: some inputs, presets, a defence toggle, and a pure
 * run() that simulates what the server would do. Nothing touches the network.
 *
 * lab = {
 *   fields:   [{ id, label, default, rows? }],
 *   presets:  [{ label, values }],
 *   defense:  { label, off, on },
 *   run({ values, defended }) => { request, log: [string|{en,zh}], response, verdict: 'bad'|'good'|'neutral', message }
 * }
 */
export default function MiniLab({ lab }) {
  const { tr } = useLang();
  const initial = Object.fromEntries(lab.fields.map((f) => [f.id, f.default ?? '']));
  const [values, setValues] = useState(initial);
  const [defended, setDefended] = useState(false);
  const out = useMemo(() => lab.run({ values, defended }), [lab, values, defended]);
  const isPreset = (p) => Object.entries(p.values).every(([k, v]) => values[k] === v);

  return (
    <div className="lab">
      <div className="panel">
        {lab.defense && (
          <Seg
            label={lab.defense.label}
            value={defended ? 'on' : 'off'}
            onChange={(v) => setDefended(v === 'on')}
            options={[
              { value: 'off', label: lab.defense.off },
              { value: 'on', label: lab.defense.on },
            ]}
          />
        )}
        {lab.presets?.length > 0 && (
          <>
            <div className="field-label">{tr({ en: 'Payloads', zh: 'Payload 预设' })}</div>
            <div className="chips">
              {lab.presets.map((p, i) => (
                <button key={i} className={`chip ${isPreset(p) ? 'on' : ''}`} onClick={() => setValues({ ...values, ...p.values })}>
                  {tr(p.label)}
                </button>
              ))}
            </div>
          </>
        )}
        {lab.fields.map((f) => (
          <div key={f.id}>
            <label className="field-label" htmlFor={`ml-${f.id}`}>
              {tr(f.label)}
            </label>
            {f.rows ? (
              <textarea id={`ml-${f.id}`} className="input mono" rows={f.rows} value={values[f.id]} spellCheck={false} onChange={(e) => setValues({ ...values, [f.id]: e.target.value })} />
            ) : (
              <input id={`ml-${f.id}`} className="input mono" value={values[f.id]} spellCheck={false} autoComplete="off" onChange={(e) => setValues({ ...values, [f.id]: e.target.value })} />
            )}
          </div>
        ))}
        {lab.note && <p className="tiny muted">{tr(lab.note)}</p>}
      </div>
      <div className="panel">
        <div className="field-label">{tr({ en: 'Request', zh: '请求' })}</div>
        <pre className="code small">{out.request}</pre>
        {out.log?.length > 0 && (
          <>
            <div className="field-label">{tr({ en: 'What the server does', zh: '服务器做了什么' })}</div>
            <div className="console">
              {out.log.map((l, i) => {
                const text = tr(l);
                const cls = /^(✕|⚠|💥|📤)/.test(text) ? 'bad' : /^(✓|🛡)/.test(text) ? 'good' : '';
                return (
                  <div key={i} className={`console-line ${cls}`}>
                    {text}
                  </div>
                );
              })}
            </div>
          </>
        )}
        {out.response != null && (
          <>
            <div className="field-label">{tr({ en: 'Response', zh: '响应' })}</div>
            <pre className="code small">{tr(out.response)}</pre>
          </>
        )}
        <div className={`verdict ${out.verdict === 'bad' ? 'bad' : out.verdict === 'good' ? 'good' : 'neutral-v'}`}>{tr(out.message)}</div>
      </div>
    </div>
  );
}
