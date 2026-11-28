import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { Chips, L, useBeats } from './kit.jsx';
import { NOSQL_DEFENCES, NOSQL_PRESETS, nosqlLogin } from './batch2.js';

/** NoSQL injection: an operator in the JSON body turns "equals" into "anything but". */
export default function NosqlMatch() {
  const { tr } = useLang();
  const [defence, setDefence] = useState('none');
  const [body, setBody] = useState(NOSQL_PRESETS[2].body);
  const beats = useBeats(500);
  const r = nosqlLogin(body, defence);
  const firstHit = r.rows.findIndex((x) => x.ok);
  const done = beats.done || (beats.total > 0 && r.error);

  return (
    <div className="lab nosql-viz">
      <div className="panel">
        <Seg
          label={L('Server', '服务器')}
          value={defence}
          onChange={(v) => {
            setDefence(v);
            beats.reset();
          }}
          options={Object.entries(NOSQL_DEFENCES).map(([value, label]) => ({ value, label }))}
        />
        <Chips
          label={L('Body', '请求体')}
          items={NOSQL_PRESETS}
          value={NOSQL_PRESETS.find((p) => p.body === body)?.id}
          onPick={(p) => {
            setBody(p.body);
            beats.reset();
          }}
        />
        <label className="field-label" htmlFor="nosql-body">
          POST /login (JSON)
        </label>
        <textarea
          id="nosql-body"
          className="input mono nosql-input"
          rows={3}
          spellCheck={false}
          value={body}
          onChange={(e) => {
            setBody(e.target.value);
            beats.reset();
          }}
        />
        <pre className="code small">{`db.users.findOne(${body.length > 80 ? body.slice(0, 80) + '…' : body})`}</pre>
        <button type="button" className="btn danger" onClick={() => beats.start(Math.max(1, r.rows.length))}>
          {tr(L('Log in', '登录'))}
        </button>
      </div>
      <div className="panel">
        <div className="field-label">{tr(L('users collection, checked in order', 'users 集合，按顺序检查'))}</div>
        {r.error ? (
          done && <div className="console-line bad nosql-err">{tr(r.error)}</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>username</th>
                  <th>password</th>
                  <th>{tr(L('match', '匹配'))}</th>
                </tr>
              </thead>
              <tbody>
                {r.rows.map((row, i) => {
                  const shown = i < beats.beat && (firstHit < 0 || i <= firstHit);
                  return (
                    <tr key={row.username} className={shown ? (row.ok ? 'nosql-hit' : 'nosql-miss') : ''}>
                      <td>
                        {row.username}
                        {shown && <small className={row.user.ok ? 'good-text' : 'bad-text'}> {row.user.why}</small>}
                      </td>
                      <td>
                        ••••••
                        {shown && <small className={row.pass.ok ? 'good-text' : 'bad-text'}> {row.pass.why.replace(/^"[^"]*"/, '"••••••"')}</small>}
                      </td>
                      <td>{shown ? (row.ok ? '✓' : '✗') : ''}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <div className={`verdict ${done ? (r.error || !r.login ? 'good' : r.injected ? 'bad' : 'neutral-v') : 'neutral-v'}`} aria-live="polite">
          {!done
            ? tr(L('findOne returns the first document where every field matches.', 'findOne 返回第一个所有字段都匹配的文档。'))
            : r.error
              ? tr(L('Rejected before it reached the database: an object is not a string.', '在到达数据库之前就被拒绝了：对象不是字符串。'))
              : !r.login
                ? tr(L('No document matched. Login failed.', '没有匹配的文档，登录失败。'))
                : r.injected
                  ? tr(L(`Logged in as ${r.login} without knowing the password. The operator replaced an equality check.`, `在不知道密码的情况下以 ${r.login} 身份登录。操作符替换掉了相等判断。`))
                  : tr(L(`Logged in as ${r.login} with the right password.`, `用正确的密码以 ${r.login} 身份登录。`))}
        </div>
      </div>
    </div>
  );
}
