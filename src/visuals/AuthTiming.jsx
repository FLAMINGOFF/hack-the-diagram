import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Log, Toggle, useBeats } from './kit.jsx';
import { AUTH_MODES, bruteForce, CANDIDATES, tryUser } from './batch1.js';

const MAX_MS = 170;

/** Username enumeration from error messages and response times, then a password guess with or without lockout. */
export default function AuthTiming() {
  const { tr, lang } = useLang();
  const [mode, setMode] = useState('verbose');
  const [lockout, setLockout] = useState(false);
  const scan = useBeats(220);
  const brute = useBeats(380);

  const rows = CANDIDATES.map((name, i) => ({ name, ...tryUser(name, mode, i) }));
  const msgs = rows.map((r) => r.msg[lang] ?? r.msg.en);
  const common = msgs.filter((m) => m === msgs[0]).length >= msgs.length / 2 ? msgs[0] : msgs[1];
  const slow = (r) => r.ms > 100 && rows.filter((x) => x.ms > 100).length < rows.length / 2;
  const odd = rows.map((r, i) => msgs[i] !== common || slow(r));
  const found = scan.done ? rows.filter((_, i) => odd[i]).map((r) => r.name) : [];

  const tries = bruteForce('carlos', lockout);
  const lines = tries.map((t) =>
    t.result === 'ok'
      ? { kind: 'bad', text: L(`carlos : ${t.pw} → 302 /my-account`, `carlos : ${t.pw} → 302 /my-account`) }
      : t.result === 'locked'
        ? { kind: 'good', text: L(`carlos : ${t.pw} → account locked, try again in 30 min`, `carlos : ${t.pw} → 账号已锁定，30 分钟后再试`) }
        : { kind: 'info', text: `carlos : ${t.pw} → 200 ${tr(L('wrong password', '密码错误'))}` },
  );
  const cracked = tries.some((t) => t.result === 'ok');

  return (
    <div className="lab auth-viz">
      <div className="panel">
        <Seg
          label={L('Login form, wrong password', '登录表单，密码错误时')}
          value={mode}
          onChange={(v) => {
            setMode(v);
            scan.reset();
          }}
          options={Object.entries(AUTH_MODES).map(([v, label]) => ({ value: v, label }))}
        />
        <button type="button" className="btn danger" onClick={() => scan.start(rows.length)}>
          {tr(L('Try 8 usernames', '试 8 个用户名'))}
        </button>
        <div className="auth-bars" role="list">
          {rows.slice(0, scan.beat).map((r, i) => (
            <div key={r.name} role="listitem" className={`auth-row ${scan.done && odd[i] ? 'odd' : ''}`}>
              <span className="auth-name">{r.name}</span>
              <span className="auth-bar">
                <span style={{ width: `${(r.ms / MAX_MS) * 100}%` }} />
              </span>
              <span className="auth-ms">{r.ms} ms</span>
              <span className="auth-msg">{msgs[i]}</span>
            </div>
          ))}
        </div>
        <div className={`verdict ${scan.done ? (found.length ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!scan.done
            ? tr(L('Each attempt uses a wrong password. Watch what differs.', '每次都用错误的密码，看看哪里不一样。'))
            : found.length
              ? tr(L(`"${found.join(', ')}" stands out: ${mode === 'verbose' ? 'a different message' : 'it takes longer, because only real users get their password hash checked'}. Now you know which account to attack.`, `"${found.join(', ')}" 与众不同：${mode === 'verbose' ? '提示信息不一样' : '耗时更长，因为只有真实用户才会去校验密码哈希'}。现在你知道该攻击哪个账号了。`))
              : tr(L('Every attempt looks the same: same message, about the same time. The server hashes a dummy password for unknown users too.', '每次尝试看起来都一样：同样的提示，差不多的耗时。服务器对不存在的用户也会去计算一个假密码的哈希。'))}
        </div>
      </div>

      <div className="panel">
        <div className="field-label">{tr(L('Then: guess carlos’s password', '接着：猜 carlos 的密码'))}</div>
        <Toggle
          checked={lockout}
          onChange={(v) => {
            setLockout(v);
            brute.reset();
          }}
        >
          {tr(L('Lock the account after 5 failures', '失败 5 次后锁定账号'))}
        </Toggle>
        <div>
          <button type="button" className="btn danger auth-go" onClick={() => brute.start(lines.length)}>
            {tr(L('Guess passwords', '开始猜密码'))}
          </button>
        </div>
        <Log title={L('POST /login', 'POST /login')} lines={lines} beat={brute.beat} empty={L('A list of the most common passwords, one per request.', '一份最常见密码列表，每次请求试一个。')} />
        <div className={`verdict ${brute.done ? (cracked ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!brute.done
            ? tr(L('“montana” is seventh on the list.', '“montana” 在列表里排第七。'))
            : cracked
              ? tr(L('Logged in as carlos. Nothing limited how many guesses one client could make.', '以 carlos 身份登录了。没有任何机制限制一个客户端能猜多少次。'))
              : tr(L('Locked out before reaching the right password. Real sites pair this with rate limits per IP, so an attacker cannot just lock out everyone.', '还没猜到正确密码就被锁定了。真实网站还会配合按 IP 限速，避免攻击者把所有人都锁住。'))}
        </div>
      </div>
    </div>
  );
}
