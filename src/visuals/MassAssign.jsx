import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { Chips, L, useBeats } from './kit.jsx';
import { MA_MODES, MA_PRESETS, MA_PRIVILEGED, MA_USER, massAssign } from './batch2.js';

/** Mass assignment: every key in the JSON body is copied onto the user record. */
export default function MassAssign() {
  const { tr } = useLang();
  const [mode, setMode] = useState('spread');
  const [body, setBody] = useState(MA_PRESETS[1].body);
  const beats = useBeats(500);
  const r = massAssign(body, mode);
  const fields = r.fields ?? [];
  const seen = new Map(fields.slice(0, beats.beat).map((f) => [f.key, f]));
  const keys = [...new Set([...Object.keys(MA_USER), ...fields.map((f) => f.key)])];

  return (
    <div className="lab ma-viz">
      <div className="panel">
        <Seg
          label={L('PATCH /api/users/me handler', 'PATCH /api/users/me 处理逻辑')}
          value={mode}
          onChange={(v) => {
            setMode(v);
            beats.reset();
          }}
          options={Object.entries(MA_MODES).map(([value, label]) => ({ value, label }))}
        />
        <p className="hint">{tr(L('GET /api/users/me showed you every field the record has, including isAdmin. The settings form only sends email.', 'GET /api/users/me 已经把记录的所有字段都给你看了，包括 isAdmin。而设置表单只发送 email。'))}</p>
        <Chips
          label={L('Body', '请求体')}
          items={MA_PRESETS}
          value={MA_PRESETS.find((p) => p.body === body)?.id}
          onPick={(p) => {
            setBody(p.body);
            beats.reset();
          }}
        />
        <label className="field-label" htmlFor="ma-body">
          JSON
        </label>
        <textarea
          id="ma-body"
          className="input mono nosql-input"
          rows={2}
          spellCheck={false}
          value={body}
          onChange={(e) => {
            setBody(e.target.value);
            beats.reset();
          }}
        />
        <button type="button" className="btn danger ma-go" onClick={() => beats.start(Math.max(1, fields.length))}>
          {tr(L('Send PATCH', '发送 PATCH'))}
        </button>
      </div>
      <div className="panel">
        <div className="field-label">{tr(L('users row for wiener', 'wiener 的数据库记录'))}</div>
        {r.error ? (
          <div className="console-line bad nosql-err">{tr(r.error)}</div>
        ) : (
          <div className="ma-record">
            {keys.map((k) => {
              const f = seen.get(k);
              const changed = f?.applied;
              const value = changed ? f.value : k in MA_USER ? MA_USER[k] : undefined;
              if (value === undefined && !f) return null;
              return (
                <div key={k} className={`ma-field ${changed ? (MA_PRIVILEGED.includes(k) ? 'priv' : 'changed') : ''} ${f && !f.applied ? 'dropped' : ''}`}>
                  <span className="ma-key">{k}</span>
                  <span className="ma-val">{f && !f.applied ? `${JSON.stringify(MA_USER[k] ?? null)}  ← ${tr(L('ignored', '已忽略'))} ${JSON.stringify(f.value)}` : JSON.stringify(value)}</span>
                </div>
              );
            })}
          </div>
        )}
        <div className={`verdict ${beats.done && !r.error ? (r.escalated ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done || r.error
            ? tr(L('Watch which keys land on the record.', '看看哪些键落到了记录上。'))
            : r.escalated
              ? tr(L('A field the form never shows was written anyway. The server copied whatever keys the client sent.', '表单里根本没有的字段也被写进去了。服务器把客户端发来的所有键都复制了过去。'))
              : tr(L('Only the fields the user may change were updated.', '只更新了用户有权修改的字段。'))}
        </div>
      </div>
    </div>
  );
}
