import { useMemo, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import SequenceDiagram from '../components/SequenceDiagram.jsx';
import { StepControls, useStepper } from '../components/Stepper.jsx';
import { ACTORS, ATTACKS, DEFENCES, flow } from './oauth.js';

const L = (en, zh) => ({ en, zh });

/** The authorization code flow, rebuilt live as you switch attacks and defences. */
export default function OAuthFlow() {
  const { tr } = useLang();
  const [attack, setAttack] = useState('redirect');
  const [def, setDef] = useState({ exact: false, state: false, pkce: false });
  const { messages, outcome } = useMemo(() => flow(attack, def), [attack, def]);
  const stepper = useStepper(messages.length, 2400);
  const last = stepper.step >= messages.length - 1;

  const pick = (v) => {
    setAttack(v);
    stepper.go(0);
  };
  const toggle = (k) => {
    setDef((d) => ({ ...d, [k]: !d[k] }));
    stepper.go(0);
  };

  return (
    <div className="oauth-viz">
      <div className="oauth-controls">
        <Seg label={L('Scenario', '场景')} value={attack} onChange={pick} options={Object.entries(ATTACKS).map(([value, label]) => ({ value, label }))} />
        <div className="seg-group">
          <div className="seg-label">{tr(L('Defences', '防御'))}</div>
          <div className="oauth-defs">
            {Object.entries(DEFENCES).map(([k, label]) => (
              <label key={k} className={`oauth-def ${def[k] ? 'on' : ''}`}>
                <input type="checkbox" checked={def[k]} onChange={() => toggle(k)} /> {tr(label)}
              </label>
            ))}
          </div>
        </div>
      </div>
      <SequenceDiagram actors={ACTORS} messages={messages} step={stepper.step} onSelect={stepper.go} title={L('OAuth authorization code flow', 'OAuth 授权码流程')} />
      <StepControls stepper={stepper} messages={messages} />
      {last && (
        <div className={`verdict ${outcome === 'pwned' ? 'bad' : 'good'}`}>
          {outcome === 'pwned'
            ? tr(L('The attack worked. Turn on a defence and replay it.', '攻击成功了。打开一项防御再重放一遍。'))
            : outcome === 'blocked'
              ? tr(L('Stopped. Try turning this defence off and another on: each one blocks a different step.', '被挡住了。试试关掉这项、打开另一项：每项防御挡在不同的步骤。'))
              : tr(L('Normal login. Now pick an attack.', '正常登录。现在选一种攻击试试。'))}
        </div>
      )}
    </div>
  );
}
