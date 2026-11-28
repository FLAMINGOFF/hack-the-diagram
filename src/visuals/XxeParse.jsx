import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { Chips, L, Log, useBeats } from './kit.jsx';
import { parseXxe, XXE_DEFENCES, XXE_PRESETS } from './batch2.js';

/** XXE: what the XML parser does with a DOCTYPE, one step at a time. */
export default function XxeParse() {
  const { tr } = useLang();
  const [defence, setDefence] = useState('none');
  const [id, setId] = useState('file');
  const beats = useBeats(700);
  const preset = XXE_PRESETS.find((p) => p.id === id);
  const r = parseXxe(id, defence);

  return (
    <div className="lab xxe-viz">
      <div className="panel">
        <Seg
          label={L('XML parser', 'XML 解析器')}
          value={defence}
          onChange={(v) => {
            setDefence(v);
            beats.reset();
          }}
          options={Object.entries(XXE_DEFENCES).map(([value, label]) => ({ value, label }))}
        />
        <Chips
          label={L('Request', '请求')}
          items={XXE_PRESETS}
          value={id}
          onPick={(p) => {
            setId(p.id);
            beats.reset();
          }}
        />
        <pre className="code small xxe-body">{`POST /product/stock\nContent-Type: ${id === 'xinclude' ? 'application/x-www-form-urlencoded' : 'application/xml'}\n\n${preset.body}`}</pre>
        <button type="button" className="btn danger" onClick={() => beats.start(r.steps.length + 1)}>
          {tr(L('Send', '发送'))}
        </button>
      </div>
      <div className="panel">
        <Log title={L('Parser', '解析器')} lines={r.steps} beat={beats.beat} empty={L('Press “Send” to watch the parser.', '点击“发送”，看解析器怎么处理。')} />
        {beats.done && (
          <>
            <div className="field-label">{tr(L('Response', '响应'))}</div>
            <pre className="code small xxe-body">{r.response}</pre>
            {r.oob.length > 0 && <Log title={L('evil.example access log', 'evil.example 访问日志')} lines={r.oob.map((t) => ({ kind: 'bad', text: t }))} />}
          </>
        )}
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : r.outcome === 'blocked' ? 'good' : 'neutral-v') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('The stock checker parses XML you send it.', '库存查询功能会解析你发送的 XML。'))
            : r.outcome === 'pwned'
              ? id === 'blind'
                ? tr(L('Nothing in the response, but the data reached the attacker’s server anyway.', '响应里什么都没有，但数据照样送到了攻击者的服务器。'))
                : tr(L('The parser fetched a resource the attacker chose and the app echoed it back.', '解析器获取了攻击者指定的资源，应用又把它原样回显出来。'))
              : r.outcome === 'blocked'
                ? tr(L('Stopped by the parser configuration, not by filtering input.', '是解析器配置挡住了它，而不是靠过滤输入。'))
                : tr(L('A normal stock check. Now try an entity.', '正常的库存查询。现在试试实体。'))}
        </div>
      </div>
    </div>
  );
}
