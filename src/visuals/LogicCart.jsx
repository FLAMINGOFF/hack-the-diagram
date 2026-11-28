import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Log, Toggle, useBeats } from './kit.jsx';
import { checkout, CREDIT, LOGIC_ATTACKS, LOGIC_CHECKS } from './batch2.js';

const $ = (c) => `${c < 0 ? '−' : ''}$${(Math.abs(c) / 100).toFixed(2)}`;

/** Business logic: the checkout trusts assumptions the attacker does not share. */
export default function LogicCart() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('negative');
  const [checks, setChecks] = useState({ qty: false, price: false, coupon: false });
  const beats = useBeats(450);
  const r = checkout(attack, checks);
  const rows = [...r.lines.map((l) => ({ text: `${tr(l.name)} × ${l.qty}`, cents: l.cents })), ...r.discounts.map((d) => ({ text: `${tr(L('Coupon', '优惠券'))} ${d.code}`, cents: d.cents }))];
  const shownRows = rows.slice(0, beats.beat);
  const running = shownRows.reduce((a, x) => a + x.cents, 0);
  const pct = Math.max(0, Math.min(100, (running / (CREDIT * 2)) * 100));

  return (
    <div className="lab logic-viz">
      <div className="panel">
        <Seg
          label={L('What the attacker tries', '攻击者的尝试')}
          value={attack}
          onChange={(v) => {
            setAttack(v);
            beats.reset();
          }}
          options={Object.entries(LOGIC_ATTACKS).map(([value, label]) => ({ value, label }))}
        />
        <div className="field-label">{tr(L('Server checks', '服务器检查'))}</div>
        <div className="up-gates">
          {Object.entries(LOGIC_CHECKS).map(([k, label]) => (
            <Toggle
              key={k}
              checked={checks[k]}
              onChange={(v) => {
                setChecks((c) => ({ ...c, [k]: v }));
                beats.reset();
              }}
            >
              {tr(label)}
            </Toggle>
          ))}
        </div>
        <button type="button" className="btn danger" onClick={() => beats.start(rows.length + 1)}>
          {tr(L('Check out', '结账'))}
        </button>
        <p className="hint">{tr(L(`Store credit: ${$(CREDIT)}. The headphones cost $1,299.00.`, `账户余额：${$(CREDIT)}。耳机售价 $1,299.00。`))}</p>
      </div>
      <div className="panel">
        <div className="logic-receipt">
          {shownRows.map((x, i) => (
            <div key={i} className={`logic-row ${x.cents < 0 ? 'neg' : ''}`}>
              <span>{x.text}</span>
              <span>{$(x.cents)}</span>
            </div>
          ))}
          <div className="logic-row total">
            <span>{tr(L('Total', '合计'))}</span>
            <span>{beats.total ? $(running) : '—'}</span>
          </div>
          <div className="logic-meter" aria-hidden="true">
            <span style={{ width: `${pct}%` }} className={running <= CREDIT && running >= 0 ? 'fits' : ''} />
            <i style={{ left: '50%' }} />
          </div>
          <div className="logic-credit">{tr(L(`credit line ${$(CREDIT)}`, `余额线 ${$(CREDIT)}`))}</div>
        </div>
        {beats.done && <Log lines={r.notes} empty={L('No checks fired.', '没有触发任何检查。')} />}
        <div className={`verdict ${beats.done ? (r.cheated ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('Each check below closes one assumption. Switch them on one at a time.', '下面每项检查都堵住一个假设。一次打开一项试试。'))
            : r.cheated
              ? tr(L(`Order placed for ${$(r.total)}. $1,299 headphones, paid with ${$(r.total)} of credit.`, `下单成功，只付了 ${$(r.total)}。价值 $1,299 的耳机，只用了 ${$(r.total)} 余额。`))
              : r.ok
                ? tr(L('Order placed at the right price.', '按正确价格下单。'))
                : tr(L(`Declined: ${$(r.total)} is not covered by ${$(CREDIT)} of credit.`, `被拒绝：${$(CREDIT)} 的余额付不起 ${$(r.total)}。`))}
        </div>
      </div>
    </div>
  );
}
