import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Toggle, useBeats } from './kit.jsx';
import { LLM_ATTACKS, LLM_DEFENCES, llmTurn, REVIEWS } from './batch4.js';

const WHO = { user: 'Carlos', tool: 'tool', model: 'model', bot: 'assistant', note: '', confirm: 'app', leak: 'browser' };

/** Indirect prompt injection: the attacker never talks to the model, only to the data it reads. */
export default function LlmChat() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('delete');
  const [d, setD] = useState({ delimit: false, confirm: false, least: false, noimg: false });
  const beats = useBeats(800);
  const r = llmTurn(attack, d);

  return (
    <div className="lab llm-viz">
      <div className="panel">
        <Seg
          label={L('Attack', '攻击')}
          value={attack}
          onChange={(v) => {
            setAttack(v);
            beats.reset();
          }}
          options={Object.entries(LLM_ATTACKS).map(([value, label]) => ({ value, label }))}
        />
        <div className="field-label">{tr(L('Review posted by the attacker', '攻击者发布的评论'))}</div>
        <pre className="code small llm-review">{REVIEWS[attack]}</pre>
        <div className="field-label">{tr(L('Defences', '防御'))}</div>
        <div className="up-gates">
          {Object.entries(LLM_DEFENCES).map(([k, label]) => (
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
        <button type="button" className="btn danger" onClick={() => beats.start(r.turns.length)}>
          {tr(L('Carlos asks the assistant', 'Carlos 向助手提问'))}
        </button>
      </div>
      <div className="panel">
        <div className="llm-chat">
          {r.turns.slice(0, beats.beat).map((t, i) => (
            <div key={i} className={`llm-msg ${t.who} ${t.bad ? 'bad' : ''}`}>
              {WHO[t.who] && <span className="llm-who">{WHO[t.who]}</span>}
              <span>{tr(t.text)}</span>
            </div>
          ))}
        </div>
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('Carlos asks an ordinary question. The attacker only wrote a product review.', 'Carlos 问了一个普通的问题。攻击者只是写了一条商品评论。'))
            : r.outcome === 'pwned'
              ? tr(L('The model did what the review said, with Carlos’s permissions.', '模型照着评论说的做了，用的是 Carlos 的权限。'))
              : tr(L('Stopped by code around the model, not by asking the model to behave.', '挡住它的是模型外面的代码，而不是让模型“乖一点”。'))}
        </div>
      </div>
    </div>
  );
}
