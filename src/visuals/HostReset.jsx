import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Toggle, useBeats } from './kit.jsx';
import { HH_ATTACKS, HH_DEFENCES, resetPoison } from './batch4.js';

/** Password reset poisoning: the reset link is built from a header the attacker sent. */
export default function HostReset() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('host');
  const [d, setD] = useState({ allow: false, config: false });
  const beats = useBeats(800);
  const r = resetPoison(attack, d);
  const total = r.rejected ? 1 : 3;

  return (
    <div className="lab hh-viz">
      <div className="panel">
        <Seg
          label={L('Header the attacker changes', '攻击者修改的请求头')}
          value={attack}
          onChange={(v) => {
            setAttack(v);
            beats.reset();
          }}
          options={Object.entries(HH_ATTACKS).map(([value, label]) => ({ value, label }))}
        />
        <pre className="code small">{r.request}</pre>
        <div className="up-gates">
          {Object.entries(HH_DEFENCES).map(([k, label]) => (
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
        <button type="button" className="btn danger" onClick={() => beats.start(total)}>
          {tr(L('Request a reset for carlos', '为 carlos 申请重置密码'))}
        </button>
      </div>
      <div className="panel">
        {r.rejected && beats.beat >= 1 && <div className="console-line good hh-rej">{tr(r.rejected)}</div>}
        {!r.rejected && beats.beat >= 1 && (
          <div className="hh-mail">
            <div className="hh-mail-head">
              <b>{tr(L('To: carlos', '收件人：carlos'))}</b>
              <span>{tr(L('Subject: Reset your password', '主题：重置你的密码'))}</span>
            </div>
            <p>{tr(L('Click the link below to choose a new password:', '点击下面的链接设置新密码：'))}</p>
            <span className={`hh-link ${r.leaked ? 'bad-text' : ''}`}>{r.link}</span>
            <small>{tr(r.why)}</small>
          </div>
        )}
        {!r.rejected && beats.beat >= 2 && (
          <div className="dom-stage on">
            <span className="dom-title">{tr(L('Carlos clicks it', 'Carlos 点击了链接'))}</span>
            <code>GET {r.link.replace('https://', '')}</code>
          </div>
        )}
        {!r.rejected && beats.beat >= 3 && (
          <div className={`dom-stage on ${r.leaked ? 'bad' : ''}`}>
            <span className="dom-title">{r.leaked ? tr(L('evil.example access log', 'evil.example 访问日志')) : tr(L('shop.example', 'shop.example'))}</span>
            <code>{r.leaked ? 'GET /reset?token=7f3a9c2e1b  ← carlos' : tr(L('The real reset page. The token stays with the shop.', '真正的重置页面，令牌留在商城这边。'))}</code>
          </div>
        )}
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('The email really comes from the shop. Only the link inside it is wrong.', '这封邮件确实是商城发的，只是里面的链接不对。'))
            : r.outcome === 'pwned'
              ? tr(L('The attacker now has carlos’s reset token and can set a new password on the real site.', '攻击者拿到了 carlos 的重置令牌，可以在真正的网站上设置新密码。'))
              : tr(L('The token never left shop.example.', '令牌从未离开 shop.example。'))}
        </div>
      </div>
    </div>
  );
}
