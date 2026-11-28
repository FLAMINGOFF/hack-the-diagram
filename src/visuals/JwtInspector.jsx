import { useEffect, useRef, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { ISSUED_HEADER, ISSUED_PAYLOAD, SERVERS, WORDLIST, crack, issuedToken, makeToken, pretty, verify } from './jwt.js';

const L = (en, zh) => ({ en, zh });
const ADMIN = pretty({ ...ISSUED_PAYLOAD, role: 'admin' });

const PRESETS = [
  { id: 'legit', label: L('Your real token', '你的真实令牌'), header: pretty(ISSUED_HEADER), payload: pretty(ISSUED_PAYLOAD), sig: 'keep' },
  { id: 'tamper', label: L('Change role only', '只改角色'), header: pretty(ISSUED_HEADER), payload: ADMIN, sig: 'keep' },
  { id: 'none', label: 'alg: none', header: pretty({ ...ISSUED_HEADER, alg: 'none' }), payload: ADMIN, sig: 'none' },
  { id: 'weak', label: L('Weak secret', '弱密钥'), header: pretty(ISSUED_HEADER), payload: ADMIN, sig: 'sign', key: 'secret1' },
  { id: 'kid', label: 'kid → /dev/null', header: pretty({ ...ISSUED_HEADER, kid: '../../../../dev/null' }), payload: ADMIN, sig: 'sign', key: '' },
];

const ICON = { ok: '✓', fail: '✕', warn: '!' };

/** Edit a real JWT, sign it in your browser, and watch two servers verify it step by step. */
export default function JwtInspector() {
  const { tr } = useLang();
  const [server, setServer] = useState('naive');
  const [header, setHeader] = useState(PRESETS[0].header);
  const [payload, setPayload] = useState(PRESETS[0].payload);
  const [sig, setSig] = useState('keep');
  const [key, setKey] = useState('');
  const [preset, setPreset] = useState('legit');
  const [issued, setIssued] = useState('');
  const [token, setToken] = useState('');
  const [result, setResult] = useState(null);
  const [shown, setShown] = useState(0);
  const [cracked, setCracked] = useState(null);
  const timer = useRef(null);

  useEffect(() => {
    let live = true;
    issuedToken(server).then((t) => live && setIssued(t));
    return () => {
      live = false;
    };
  }, [server]);

  // Rebuild the token whenever an input changes.
  useEffect(() => {
    let live = true;
    const signature = issued.split('.')[2] ?? '';
    const compact = (s) => {
      try {
        return JSON.stringify(JSON.parse(s));
      } catch {
        return s;
      }
    };
    makeToken(compact(header), compact(payload), sig === 'sign' ? { mode: 'sign', key } : sig === 'keep' ? { mode: 'keep', signature } : { mode: 'none' }).then((t) => live && setToken(t));
    return () => {
      live = false;
    };
  }, [header, payload, sig, key, issued]);

  useEffect(() => () => clearInterval(timer.current), []);

  const apply = (p) => {
    setPreset(p.id);
    setHeader(p.header);
    setPayload(p.payload);
    setSig(p.sig);
    if (p.key !== undefined) setKey(p.key);
    setResult(null);
  };

  const send = async () => {
    clearInterval(timer.current);
    const r = await verify(token, server);
    setResult(r);
    setShown(0);
    timer.current = setInterval(() => setShown((n) => (n >= r.steps.length ? (clearInterval(timer.current), n) : n + 1)), 420);
  };

  const runCrack = async () => {
    setCracked({ busy: true });
    const r = await crack(issued);
    setCracked(r);
    if (r.found) {
      setSig('sign');
      setKey(r.found);
    }
  };

  const [h, p, s] = token.split('.');
  const finished = result && shown >= result.steps.length;

  return (
    <div className="lab jwt-viz">
      <div className="panel">
        <Seg label={L('Target', '目标')} value={server} onChange={(v) => { setServer(v); setResult(null); setCracked(null); }} options={Object.entries(SERVERS).map(([value, x]) => ({ value, label: x.label }))} />
        <div className="field-label">{tr(L('Attacks', '攻击方式'))}</div>
        <div className="chips">
          {PRESETS.map((x) => (
            <button type="button" key={x.id} className={`chip ${preset === x.id ? 'on' : ''}`} onClick={() => apply(x)}>
              {tr(x.label)}
            </button>
          ))}
        </div>
        <div className="jwt-edit">
          <div>
            <label className="field-label jwt-h" htmlFor="jwt-header">
              {tr(L('Header', '头部'))}
            </label>
            <textarea id="jwt-header" className="input mono" rows={7} value={header} spellCheck={false} onChange={(e) => { setHeader(e.target.value); setPreset(null); }} />
          </div>
          <div>
            <label className="field-label jwt-p" htmlFor="jwt-payload">
              {tr(L('Payload', '载荷'))}
            </label>
            <textarea id="jwt-payload" className="input mono" rows={7} value={payload} spellCheck={false} onChange={(e) => { setPayload(e.target.value); setPreset(null); }} />
          </div>
        </div>
        <Seg
          label={L('Signature', '签名')}
          value={sig}
          onChange={(v) => { setSig(v); setPreset(null); }}
          options={[
            { value: 'keep', label: L('Keep original', '保留原签名') },
            { value: 'sign', label: L('Sign with a key', '用密钥签名') },
            { value: 'none', label: L('No signature', '不签名') },
          ]}
        />
        {sig === 'sign' && (
          <input className="input mono" aria-label={tr(L('Signing key', '签名密钥'))} placeholder={tr(L('(empty key)', '（空密钥）'))} value={key} spellCheck={false} onChange={(e) => { setKey(e.target.value); setPreset(null); }} />
        )}
        <div className="row">
          <button type="button" className="btn ghost" onClick={runCrack} disabled={!issued || cracked?.busy}>
            🔨 {tr(L(`Crack your real token (${WORDLIST.length}-word list)`, `破解你的真实令牌（${WORDLIST.length} 个词的字典）`))}
          </button>
        </div>
        {cracked && !cracked.busy && (
          <p className={`hint ${cracked.found ? 'bad-text' : ''}`}>
            {cracked.found
              ? tr(L(`Found after ${cracked.tried} guesses: the key is "${cracked.found}". It is now in the signing key box.`, `试了 ${cracked.tried} 次就找到了：密钥是 "${cracked.found}"，已填进签名密钥框。`))
              : tr(L(`No match in ${cracked.tried} words. A long random key cannot be guessed.`, `${cracked.tried} 个词都不对。又长又随机的密钥猜不出来。`))}
          </p>
        )}
      </div>

      <div className="panel">
        <div className="field-label">{tr(L('Token you send', '你发送的令牌'))}</div>
        <div className="jwt-token mono" aria-label="JWT">
          <span className="jwt-h">{h}</span>.<span className="jwt-p">{p}</span>.<span className="jwt-s">{s || tr(L('(empty)', '（空）'))}</span>
        </div>
        <div className="row">
          <button type="button" className="btn danger" onClick={send} disabled={!token}>
            {tr(L('Send token', '发送令牌'))}
          </button>
          <span className="muted tiny">GET /my-account · Authorization: Bearer …</span>
        </div>
        <div className="field-label">{tr(L('What the server checks', '服务器检查了什么'))}</div>
        <ol className="jwt-steps" aria-live="polite">
          {(result?.steps ?? []).slice(0, shown).map((st, i) => (
            <li key={i} className={`st-${st.status}`}>
              <span className="st-icon" aria-hidden="true">
                {ICON[st.status]}
              </span>
              <b>{tr(st.label)}</b>
              <span>{tr(st.detail)}</span>
            </li>
          ))}
          {!result && <li className="st-idle">{tr(L('Send a token to see each check.', '发送令牌后，这里会逐项显示检查过程。'))}</li>}
        </ol>
        {finished && (
          <div className={`verdict ${result.admin ? 'bad' : result.ok ? 'neutral-v' : 'good'}`}>
            {result.admin
              ? tr(L('Forged token accepted: you are admin.', '伪造的令牌被接受了：你现在是管理员。'))
              : result.ok
                ? tr(L('A valid token for your own account. Nothing gained.', '这是你自己账号的合法令牌，没有得到额外权限。'))
                : tr(L('401 Unauthorized: the forgery was caught.', '401 未授权：伪造被识破了。'))}
          </div>
        )}
      </div>
    </div>
  );
}
