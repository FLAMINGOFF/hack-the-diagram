import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Log, Toggle, useBeats } from './kit.jsx';
import { MCP_ATTACKS, MCP_DEFENCES, MCP_DESC, mcpRun } from './batch4.js';

/** MCP tool poisoning: the description is instructions the model reads and the user may never see. */
export default function McpTrace() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('poison');
  const [d, setD] = useState({ review: false, pin: false, scope: false });
  const beats = useBeats(800);
  const r = mcpRun(attack, d);

  return (
    <div className="lab mcp-viz">
      <div className="panel">
        <Seg
          label={L('Attack', '攻击')}
          value={attack}
          onChange={(v) => {
            setAttack(v);
            beats.reset();
          }}
          options={Object.entries(MCP_ATTACKS).map(([value, label]) => ({ value, label }))}
        />
        <div className="mcp-cards">
          <div className="mcp-card">
            <div className="field-label">{tr(L('What the user sees', '用户看到的'))}</div>
            <code>{MCP_DESC.clean}</code>
          </div>
          <div className="mcp-card model">
            <div className="field-label">{tr(attack === 'rugpull' ? L('What the model sees (version 2)', '模型看到的（第 2 版）') : L('What the model sees', '模型看到的'))}</div>
            <code>
              {MCP_DESC.clean} <mark>{MCP_DESC.hidden}</mark>
            </code>
          </div>
        </div>
        <div className="field-label">{tr(L('Client defences', '客户端防御'))}</div>
        <div className="up-gates">
          {Object.entries(MCP_DEFENCES).map(([k, label]) => (
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
        <button type="button" className="btn danger" onClick={() => beats.start(r.steps.length)}>
          {tr(L('Install and use it', '安装并使用'))}
        </button>
      </div>
      <div className="panel">
        <Log title={L('Agent trace', '智能体执行记录')} lines={r.steps} beat={beats.beat} empty={L('Press “Install and use it”.', '点击“安装并使用”。')} />
        <div className={`verdict ${beats.done ? (r.outcome === 'pwned' ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('A calculator server. The user only wants to add numbers.', '一个计算器服务器，用户只想做加法。'))
            : r.outcome === 'pwned'
              ? tr(L('A tool the user approved, doing exactly what its description told the model to do.', '一个用户批准过的工具，完全按照它的描述指使模型去做事。'))
              : tr(L('Stopped. Each defence covers a different moment: install time, later changes, or what tools can reach.', '被挡住了。每项防御覆盖的时机不同：安装时、之后的变更、或工具能触及的范围。'))}
        </div>
      </div>
    </div>
  );
}
