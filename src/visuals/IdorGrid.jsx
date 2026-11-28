import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, useBeats } from './kit.jsx';
import { fetchInvoice, FIRST_ID, invoiceRows } from './batch1.js';

const ROWS = invoiceRows();
const LAST_ID = FIRST_ID + ROWS.length - 1;
const MINE = ROWS.find((r) => r.owner === 'alice').id;

/** IDOR: Alice changes the id in the URL and walks through everyone's invoices. */
export default function IdorGrid() {
  const { tr } = useLang();
  const [mode, setMode] = useState('none');
  const [pick, setPick] = useState(MINE);
  const beats = useBeats(260);

  const results = ROWS.map((r) => fetchInvoice(r.id, mode));
  const leaked = results.slice(0, beats.beat).filter((r) => r.leak).length;
  const one = fetchInvoice(pick, mode);

  return (
    <div className="lab idor-viz">
      <div className="panel">
        <Seg
          label={L('GET /api/invoices/:id', 'GET /api/invoices/:id')}
          value={mode}
          onChange={(v) => {
            setMode(v);
            beats.reset();
          }}
          options={[
            { value: 'none', label: L('Logged in is enough', '登录了就行') },
            { value: 'owner', label: L('Checks invoice.owner', '检查 invoice.owner') },
          ]}
        />
        <p className="hint">
          {tr(
            L(
              `Alice is logged in and her invoice is #${MINE}. The id is right there in the URL. Click any invoice to request it, or scan them all.`,
              `Alice 已登录，她的发票是 #${MINE}。id 就明晃晃地写在 URL 里。点任意一张发票去请求它，或者全部扫一遍。`,
            ),
          )}
        </p>
        <pre className="code small">
          {`GET /api/invoices/${pick}\nCookie: session=alice…\n\n`}
          {one.status === 200 ? `200 OK\n{"id":${pick},"owner":"${one.row.owner}","amount":${one.row.amount}}` : `${one.status} Forbidden`}
        </pre>
        <button type="button" className="btn danger" onClick={() => beats.start(ROWS.length)}>
          {tr(L(`Scan ${FIRST_ID}–${LAST_ID}`, `扫描 ${FIRST_ID}–${LAST_ID}`))}
        </button>
      </div>

      <div className="panel">
        <div className="idor-grid">
          {ROWS.map((r, i) => {
            const res = results[i];
            const scanned = i < beats.beat;
            const state = !scanned ? '' : res.leak ? 'leak' : res.status === 403 ? 'denied' : 'own';
            return (
              <button
                type="button"
                key={r.id}
                className={`idor-cell ${state} ${pick === r.id ? 'sel' : ''}`}
                aria-pressed={pick === r.id}
                onClick={() => setPick(r.id)}
              >
                <span className="idor-id">#{r.id}</span>
                <span className="idor-who">{scanned ? (res.status === 403 ? '403' : r.owner) : r.id === MINE ? 'alice' : '?'}</span>
                {scanned && res.status === 200 && <span className="idor-amt">${r.amount}</span>}
              </button>
            );
          })}
        </div>
        <div className={`verdict ${beats.done ? (leaked ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('Press scan to try every id in order.', '点击扫描，依次尝试每个 id。'))
            : leaked
              ? tr(L(`${leaked} other customers' invoices came back. The server checked that Alice was logged in, never that the invoice was hers.`, `返回了 ${leaked} 位其他客户的发票。服务器只检查了 Alice 是否登录，从没检查发票是不是她的。`))
              : tr(L('Every other id returns 403. The query is scoped to the logged-in user, so guessing ids gets nothing.', '其他 id 全部返回 403。查询限定在当前登录用户名下，猜 id 一无所获。'))}
        </div>
      </div>
    </div>
  );
}
