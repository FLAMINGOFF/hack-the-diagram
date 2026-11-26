import { useEffect, useState } from 'react';
import { useLang } from '../i18n.jsx';
import MiniLab from './MiniLab.jsx';
import { Section } from './TopicShell.jsx';
import { getSolved, markSolved } from '../progress.js';

// The deep-dive data is large, so it is loaded on demand in its own chunk.
let cache = null;
export const loadDeep = () => (cache ??= import('../topics/deep/index.js').then((m) => m.DEEP));

/** Variants, challenges and real-world cases for a topic (see src/topics/deep). */
export default function DeepDive({ id }) {
  const [all, setAll] = useState(null);
  useEffect(() => {
    let live = true;
    loadDeep().then((d) => live && setAll(d));
    return () => {
      live = false;
    };
  }, []);
  const deep = all?.[id];
  if (!deep) return null;
  return (
    <>
      {deep.variants?.length > 0 && <Variants id={id} variants={deep.variants} />}
      {deep.challenges?.length > 0 && <Challenges id={id} challenges={deep.challenges} />}
      {deep.cases?.length > 0 && <Cases cases={deep.cases} />}
    </>
  );
}

function Variants({ id, variants }) {
  const { tr } = useLang();
  const [cur, setCur] = useState(0);
  const v = variants[cur];
  return (
    <Section kicker={{ en: 'Variants', zh: '变体' }} title={{ en: `${variants.length} ways this shows up`, zh: `${variants.length} 种常见形态` }}>
      <div className="vtabs" role="tablist">
        {variants.map((x, i) => (
          <button key={x.id} role="tab" aria-selected={i === cur} className={i === cur ? 'on' : ''} onClick={() => setCur(i)}>
            {tr(x.title)}
          </button>
        ))}
      </div>
      <div className="variant-body">
        <p className="variant-summary">{tr(v.summary)}</p>
        {v.lab && <MiniLab key={`${id}-${v.id}`} lab={v.lab} />}
        {v.takeaway && (
          <p className="takeaway">
            <b>{tr({ en: 'Takeaway', zh: '要点' })}:</b> {tr(v.takeaway)}
          </p>
        )}
      </div>
    </Section>
  );
}

function Challenges({ id, challenges }) {
  const { tr } = useLang();
  const [solved, setSolved] = useState(getSolved);
  const n = challenges.filter((c, i) => solved.has(`${id}:${i + 1}`)).length;
  return (
    <Section kicker={{ en: 'Challenges', zh: '挑战关卡' }} title={{ en: `Your turn: ${n} / ${challenges.length} solved`, zh: `轮到你了：已通过 ${n} / ${challenges.length}` }}>
      <p className="muted">
        {tr({
          en: 'No presets here. Build the payload yourself; the explanation unlocks when you pass. Hints are there if you get stuck.',
          zh: '这里没有预设，需要你自己构造 payload，过关后才会解锁讲解。卡住了可以看提示。',
        })}
      </p>
      <div className="challenges">
        {challenges.map((c, i) => {
          const key = `${id}:${i + 1}`;
          return (
            <ChallengeCard
              key={key}
              n={i + 1}
              ch={c}
              solved={solved.has(key)}
              onSolve={() => {
                markSolved(key);
                setSolved(getSolved());
              }}
            />
          );
        })}
      </div>
    </Section>
  );
}

function ChallengeCard({ n, ch, solved, onSolve }) {
  const { tr } = useLang();
  const init = Object.fromEntries(ch.fields.map((f) => [f.id, f.default ?? '']));
  const [values, setValues] = useState(init);
  const [out, setOut] = useState(null);
  const [passed, setPassed] = useState(false);
  const [hint, setHint] = useState(false);
  const [sol, setSol] = useState(false);
  const submit = (e) => {
    e.preventDefault();
    const o = ch.run(values);
    setOut(o);
    const ok = ch.check(values, o);
    setPassed(ok);
    if (ok && !solved) onSolve();
  };
  const unlocked = passed || solved;
  return (
    <form className={`challenge ${unlocked ? 'done' : ''}`} onSubmit={submit}>
      <div className="challenge-head">
        <span className="level mono">
          {tr({ en: 'Level', zh: '关卡' })} {n}
        </span>
        <b>{tr(ch.title)}</b>
        {solved && <span className="solved-badge">✓ {tr({ en: 'solved', zh: '已通过' })}</span>}
      </div>
      <p className="goal">🎯 {tr(ch.goal)}</p>
      {ch.context && <pre className="code small">{tr(ch.context)}</pre>}
      {ch.fields.map((f) => (
        <div key={f.id}>
          <label className="field-label" htmlFor={`ch-${n}-${f.id}`}>
            {tr(f.label)}
          </label>
          {f.rows ? (
            <textarea id={`ch-${n}-${f.id}`} className="input mono" rows={f.rows} value={values[f.id]} spellCheck={false} onChange={(e) => setValues({ ...values, [f.id]: e.target.value })} />
          ) : (
            <input id={`ch-${n}-${f.id}`} className="input mono" value={values[f.id]} spellCheck={false} autoComplete="off" onChange={(e) => setValues({ ...values, [f.id]: e.target.value })} />
          )}
        </div>
      ))}
      <div className="row">
        <button className="btn danger" type="submit">
          {tr({ en: 'Send', zh: '发送' })}
        </button>
        {!unlocked && (
          <button className="btn ghost" type="button" onClick={() => (hint ? setSol(true) : setHint(true))}>
            {hint ? tr({ en: 'Show solution', zh: '查看答案' }) : tr({ en: 'Hint', zh: '提示' })}
          </button>
        )}
      </div>
      {hint && !unlocked && <p className="hint">💡 {tr(ch.hint)}</p>}
      {sol && !unlocked && (
        <p className="hint">
          🔑 <code className="mono">{ch.solution}</code>
        </p>
      )}
      {out && (
        <div className="challenge-out">
          {out.log?.length > 0 && (
            <div className="console">
              {out.log.map((l, i) => (
                <div className="console-line" key={i}>
                  {tr(l)}
                </div>
              ))}
            </div>
          )}
          {out.response != null && <pre className="code small">{tr(out.response)}</pre>}
          {!passed && <div className="verdict neutral-v">{tr({ en: 'Not yet. Look at the response and adjust.', zh: '还没过关。看看响应，再调整一下。' })}</div>}
        </div>
      )}
      {unlocked && (
        <div className="unlock">
          <div className="unlock-title">🔓 {passed ? tr({ en: 'Passed! Here is why it works', zh: '过关！原理如下' }) : tr({ en: 'Solved earlier. Explanation', zh: '之前已通过，讲解如下' })}</div>
          <p>{tr(ch.explain)}</p>
          <p className="mono tiny">{tr({ en: 'One solution:', zh: '参考答案：' })} {ch.solution}</p>
        </div>
      )}
    </form>
  );
}

function Cases({ cases }) {
  const { tr } = useLang();
  return (
    <Section kicker={{ en: 'In the wild', zh: '真实案例' }} title={{ en: 'When this happened for real', zh: '现实中真的发生过' }}>
      <div className="cases">
        {cases.map((c, i) => (
          <article className="case" key={i}>
            <div className="case-top">
              <span className="mono case-year">{c.year}</span>
              {c.ref && (typeof c.ref === 'string' && c.ref.startsWith('CVE-') ? (
                <a className="mono case-ref" href={`https://nvd.nist.gov/vuln/detail/${c.ref}`} target="_blank" rel="noreferrer">
                  {c.ref} ↗
                </a>
              ) : (
                <span className="mono case-ref">{typeof c.ref === 'string' ? c.ref : tr(c.ref)}</span>
              ))}
            </div>
            <h3>{tr(c.title)}</h3>
            <p>{tr(c.what)}</p>
            <p className="lesson">
              <b>{tr({ en: 'Lesson', zh: '教训' })}:</b> {tr(c.lesson)}
            </p>
          </article>
        ))}
      </div>
    </Section>
  );
}
