import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Toggle, useBeats } from './kit.jsx';
import { CP_ATTACKS, CP_DEFENCES, poison } from './batch4.js';

/** Web cache poisoning: one request with an unkeyed input, served to everyone afterwards. */
export default function CachePoison() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('header');
  const [d, setD] = useState({ key: false, ignore: false });
  const beats = useBeats(600);
  const r = poison(attack, d);
  const served = r.victims.slice(0, Math.max(0, beats.beat - 2));

  return (
    <div className="lab cp-viz">
      <div className="panel">
        <Seg
          label={L('Unkeyed input', '非键输入')}
          value={attack}
          onChange={(v) => {
            setAttack(v);
            beats.reset();
          }}
          options={Object.entries(CP_ATTACKS).map(([value, label]) => ({ value, label }))}
        />
        <div className="field-label">{tr(L('Attacker’s request', '攻击者的请求'))}</div>
        <div className="cp-req">
          {r.req.map((p) => (
            <div key={p.part} className={`cp-part ${p.evil ? 'evil' : ''}`}>
              <code>{p.part}</code>
              <span className={`cp-badge ${p.keyed ? 'keyed' : ''}`}>{p.keyed ? tr(L('in cache key', '属于缓存键')) : tr(L('not in key', '不属于缓存键'))}</span>
              {p.note && <small>{tr(p.note)}</small>}
            </div>
          ))}
        </div>
        <div className="up-gates cp-defs">
          {Object.entries(CP_DEFENCES).map(([k, label]) => (
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
        <button type="button" className="btn danger" onClick={() => beats.start(2 + r.victims.length)}>
          {tr(L('Poison the cache', '投毒缓存'))}
        </button>
      </div>
      <div className="panel">
        <div className={`cp-entry ${beats.beat >= 1 ? 'on' : ''}`}>
          <div className="field-label">{tr(L('Cache entry', '缓存条目'))}</div>
          <div className="cp-key">
            key = <code>{beats.beat >= 1 ? r.key : '…'}</code>
          </div>
          {beats.beat >= 2 && <pre className={`code small cp-body ${r.reflected ? 'bad-border' : ''}`}>{r.body}</pre>}
        </div>
        <div className="field-label">{tr(L('Next visitors to shop.example/', '之后访问 shop.example/ 的用户'))}</div>
        <div className="cp-victims">
          {r.victims.map((v, i) => {
            const shown = i < served.length;
            return (
              <div key={v.i} className={`cp-victim ${shown ? (v.poisoned ? 'bad' : 'ok') : ''}`}>
                <span aria-hidden="true">👤</span>
                <span>{shown ? (v.poisoned ? tr(L('poisoned', '被投毒')) : tr(L('clean page', '正常页面'))) : '…'}</span>
              </div>
            );
          })}
        </div>
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('The cache decides whether two requests are “the same” using only the keyed parts.', '缓存只用属于键的那几部分来判断两个请求是否“相同”。'))
            : r.outcome === 'pwned'
              ? tr(L('Every visitor gets the attacker’s response from the cache, until it expires. Their requests never contained anything malicious.', '在缓存过期之前，每个访问者都会从缓存拿到攻击者的响应，而他们自己的请求里没有任何恶意内容。'))
              : d.key
                ? tr(L('The poisoned response is stored under its own key, which only the attacker ever requests.', '被投毒的响应存在它自己的键下，只有攻击者自己会请求它。'))
                : tr(L('Nothing from the input reached the response, so there is nothing to poison.', '输入没有进入响应，所以没有东西可以投毒。'))}
        </div>
      </div>
    </div>
  );
}
