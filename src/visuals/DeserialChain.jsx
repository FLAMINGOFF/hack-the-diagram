import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Log, useBeats } from './kit.jsx';
import { DS_ATTACKS, DS_COOKIE, DS_DEFENCES, deserialize } from './batch3.js';

/** Insecure deserialization: the cookie decides which objects the server builds. */
export default function DeserialChain() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('gadget');
  const [defence, setDefence] = useState('none');
  const beats = useBeats(750);
  const r = deserialize(attack, defence);
  const reset = (fn) => (v) => {
    fn(v);
    beats.reset();
  };
  const sent = defence === 'json' ? (attack === 'tamper' ? '{"username":"wiener","isAdmin":true}' : '{"class":"TempFile","path":"/home/carlos/morale.txt"}') : DS_COOKIE[attack];

  return (
    <div className="lab ds-viz">
      <div className="panel">
        <Seg label={L('Attacker', '攻击者')} value={attack} onChange={reset(setAttack)} options={Object.entries(DS_ATTACKS).map(([value, label]) => ({ value, label }))} />
        <Seg label={L('Server', '服务器')} value={defence} onChange={reset(setDefence)} options={Object.entries(DS_DEFENCES).map(([value, label]) => ({ value, label }))} />
        <div className="field-label">{tr(L('Original cookie (base64-decoded)', '原始 Cookie（base64 解码后）'))}</div>
        <pre className="code small ds-cookie">{defence === 'json' ? '{"username":"wiener","isAdmin":false}' : DS_COOKIE.original}</pre>
        <div className="field-label">{tr(L('What the attacker sends', '攻击者发送的内容'))}</div>
        <pre className="code small ds-cookie bad-border">
          {sent}
          {defence === 'sign' ? '\n.sig=3f1a…(old signature)' : ''}
        </pre>
        {attack === 'gadget' && <pre className="code small ds-cookie">{'class TempFile {\n  public $path;\n  function __destruct() {\n    unlink($this->path);\n  }\n}'}</pre>}
        <button type="button" className="btn danger" onClick={() => beats.start(r.steps.length)}>
          {tr(L('Send cookie', '发送 Cookie'))}
        </button>
      </div>
      <div className="panel">
        <Log title={L('Server', '服务器')} lines={r.steps} beat={beats.beat} empty={L('Press “Send cookie”.', '点击“发送 Cookie”。')} />
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('The cookie is a serialized object. The client can change every byte of it.', 'Cookie 是一个序列化对象，客户端可以改动它的每一个字节。'))
            : r.outcome === 'pwned'
              ? attack === 'gadget'
                ? tr(L('The attacker picked which class to build and what its properties are. Real exploits chain many such methods into code execution.', '攻击者决定了要创建哪个类、属性取什么值。真实的漏洞利用会把许多这样的方法串成代码执行。'))
                : tr(L('The server trusted a field it should have looked up itself.', '服务器相信了一个本该自己去查的字段。'))
              : tr(L('Stopped before any attacker-chosen object existed.', '在任何攻击者指定的对象被创建之前就被挡住了。'))}
        </div>
      </div>
    </div>
  );
}
