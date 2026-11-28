import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { Chips, L, useBeats } from './kit.jsx';
import { runShell, SH_DEFENCES, SH_PRESETS } from './batch1.js';

const OP_NOTE = {
  ';': L('then run the next command', '然后执行下一条命令'),
  '&&': L('run next only if this one succeeded', '前一条成功才执行下一条'),
  '||': L('run next only if this one failed', '前一条失败才执行下一条'),
  '|': L('pipe output into the next command', '把输出交给下一条命令'),
  '&': L('run in background, then the next', '放到后台，然后执行下一条'),
  '\n': L('newline: a new command', '换行：一条新命令'),
};

/** OS command injection: how the shell splits one string into several commands. */
export default function ShellParse() {
  const { tr } = useLang();
  const [defence, setDefence] = useState('shell');
  const [host, setHost] = useState(SH_PRESETS[1].value);
  const [run, setRun] = useState(null);
  const beats = useBeats(650);

  const reset = () => {
    setRun(null);
    beats.reset();
  };
  const go = () => {
    const r = runShell(host, defence);
    setRun(r);
    beats.start(r.parts.length);
  };

  const injected = run?.parts.some((p) => p.injected && p.ran);
  const oneArg = run?.parts[0]?.oneArg;

  return (
    <div className="lab sh-viz">
      <div className="panel">
        <Seg
          label={L('How the server runs ping', '服务器如何执行 ping')}
          value={defence}
          onChange={(v) => {
            setDefence(v);
            reset();
          }}
          options={Object.entries(SH_DEFENCES).map(([v, label]) => ({ value: v, label }))}
        />
        <Chips
          label={L('Payloads', '载荷')}
          items={SH_PRESETS}
          value={SH_PRESETS.find((p) => p.value === host)?.id}
          onPick={(p) => {
            setHost(p.value);
            reset();
          }}
        />
        <label className="field-label" htmlFor="sh-input">
          host =
        </label>
        <input
          id="sh-input"
          className="input mono"
          value={host}
          spellCheck={false}
          onChange={(e) => {
            setHost(e.target.value);
            reset();
          }}
        />
        <button type="button" className="btn danger" onClick={go}>
          {tr(L('Run it', '执行'))}
        </button>
        <p className="hint">
          {tr(
            L(
              'The shell reads the whole string, not just the part you meant as a hostname. Every ; && || | & or newline starts another command, and $(…) runs before anything else.',
              'shell 读取的是整个字符串，而不只是你以为的主机名部分。每个 ; && || | & 或换行都会开始另一条命令，而 $(…) 会最先执行。',
            ),
          )}
        </p>
      </div>

      <div className="panel">
        <div className="field-label">{tr(L('What the shell sees', 'shell 看到的内容'))}</div>
        <pre className="code small sh-line">{run ? run.line : '…'}</pre>
        <div className="sh-parts">
          {(run?.parts ?? []).slice(0, beats.beat).map((p, i) => (
            <div key={i} className="sh-part-wrap">
              {p.op && (
                <div className="sh-op">
                  <code>{p.op === '\n' ? '⏎' : p.op}</code> {tr(OP_NOTE[p.op])}
                </div>
              )}
              <div className={`sh-part ${p.injected ? 'injected' : ''} ${p.ran ? '' : 'skipped'}`}>
                <div className="sh-cmd">
                  <span className="sh-badge">{p.oneArg ? tr(L('one process', '一个进程')) : p.injected ? tr(L('injected', '被注入')) : tr(L('intended', '预期命令'))}</span>
                  <code>{p.text}</code>
                </div>
                {p.subs?.map((s, j) => (
                  <div key={j} className="sh-sub">
                    $({s.cmd}) → <b>{s.out}</b>
                  </div>
                ))}
                <div className="sh-out">{p.ran ? p.out : tr(L('(skipped)', '（跳过）'))}</div>
              </div>
            </div>
          ))}
        </div>
        <div className={`verdict ${beats.done ? (injected ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('Pick a payload and press “Run it”.', '选一个载荷，然后点击“执行”。'))
            : injected
              ? tr(L('Your input ran as a command on the server, as www-data.', '你的输入在服务器上以 www-data 身份作为命令执行了。'))
              : oneArg
                ? tr(L('No shell is involved: the whole string is a single argument to ping, so the operators mean nothing.', '这里没有 shell：整个字符串只是 ping 的一个参数，那些操作符毫无意义。'))
                : tr(L('Only ping ran. Note that double quotes still allow $(…) and backticks.', '只执行了 ping。注意：双引号里依然可以用 $(…) 和反引号。'))}
        </div>
      </div>
    </div>
  );
}
