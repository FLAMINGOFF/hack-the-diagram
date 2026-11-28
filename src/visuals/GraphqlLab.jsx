import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Toggle, useBeats } from './kit.jsx';
import { GQL_ATTACKS, GQL_DEFENCES, GQL_PASSWORDS, GQL_SCHEMA, graphql } from './batch3.js';

/** GraphQL: mapping a hidden schema, and brute force hidden inside one request. */
export default function GraphqlLab() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('introspect');
  const [d, setD] = useState({ introspection: false, suggestions: false, cost: false });
  const slow = useBeats(900);
  const fast = useBeats(30);
  const r = graphql(attack, d);
  const beats = attack === 'aliases' ? fast : slow;
  const stepsShown = attack === 'aliases' ? (beats.beat > 0 ? r.steps : []) : r.steps.slice(0, beats.beat);
  const reset = () => {
    slow.reset();
    fast.reset();
  };
  const go = () => {
    reset();
    if (attack === 'aliases') fast.start(d.cost ? 1 : GQL_PASSWORDS.length);
    else slow.start(r.steps.length);
  };
  const relevant = attack === 'introspect' ? ['introspection', 'suggestions'] : ['cost'];

  return (
    <div className="lab gql-viz">
      <div className="panel">
        <Seg
          label={L('Attack', '攻击')}
          value={attack}
          onChange={(v) => {
            setAttack(v);
            reset();
          }}
          options={Object.entries(GQL_ATTACKS).map(([value, label]) => ({ value, label }))}
        />
        <div className="field-label">{tr(L('Server settings', '服务器设置'))}</div>
        <div className="up-gates">
          {relevant.map((k) => (
            <Toggle
              key={k}
              checked={d[k]}
              onChange={(v) => {
                setD((x) => ({ ...x, [k]: v }));
                reset();
              }}
            >
              {tr(GQL_DEFENCES[k])}
            </Toggle>
          ))}
        </div>
        <button type="button" className="btn danger" onClick={go}>
          {tr(L('Send query', '发送查询'))}
        </button>
        {attack === 'introspect' && (
          <div className="gql-schema">
            <div className="field-label">{tr(L('Schema as the attacker sees it', '攻击者眼中的 schema'))}</div>
            {GQL_SCHEMA.map((t) => (
              <div key={t.type} className="gql-type">
                <b>type {t.type}</b>
                {t.fields.map((f) => {
                  const known = beats.done && (r.schemaVisible || (!f.hidden && t.type !== 'Mutation') || (f.name === 'password' && r.outcome === 'pwned'));
                  return (
                    <div key={f.name} className={`gql-field ${known ? (f.hidden ? 'leak' : 'known') : ''}`}>
                      {known ? `${f.name}: ${f.type}` : '???'}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="panel">
        {stepsShown.map((s, i) => (
          <div key={i} className="gql-step">
            <pre className="code small">{s.q}</pre>
            <div className={`gql-res ${s.leak ? 'bad-text' : 'good-text'}`}>{tr(s.res)}</div>
          </div>
        ))}
        {attack === 'aliases' && r.results?.length > 0 && (
          <div className="gql-grid" aria-hidden="true">
            {r.results.map((ok, i) => (
              <span key={i} className={i < beats.beat ? (ok ? 'hit' : 'miss') : ''} />
            ))}
          </div>
        )}
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('One endpoint, one schema. See how much of it the attacker can learn or abuse.', '一个端点，一个 schema。看攻击者能从中了解或滥用多少。'))
            : r.outcome === 'pwned'
              ? attack === 'aliases'
                ? tr(L('Alias a63 returned success: true. carlos’s password is montana, found in a single HTTP request.', '别名 a63 返回 success: true。carlos 的密码是 montana，只用了一个 HTTP 请求就找到了。'))
                : tr(L('The private field was found and read. Hiding a field is not access control; the resolver must check who is asking.', '私有字段被找到并读取了。隐藏字段不是访问控制，resolver 必须检查是谁在请求。'))
              : tr(L('Blocked at this layer. Authorization in each resolver is still the real fix.', '在这一层被挡住了。真正的修复依然是在每个 resolver 里做授权检查。'))}
        </div>
      </div>
    </div>
  );
}
