import { Suspense } from 'react';
import { useLang } from '../i18n.jsx';
import DeepDive from './DeepDive.jsx';
import MiniLab from './MiniLab.jsx';
import SequenceDiagram from './SequenceDiagram.jsx';
import { StepControls, useStepper } from './Stepper.jsx';
import { Defenses, InterviewQs, Section, TopicShell } from './TopicShell.jsx';

/** Renders any topic described as data (see src/topics/content/*.js). */
export default function GenericTopic({ def, Visual }) {
  const { tr } = useLang();
  const stepper = useStepper(def.flow.length);
  const Custom = def.CustomLab;
  return (
    <TopicShell id={def.id} tldr={def.tldr}>
      {Visual && (
        <Section kicker={{ en: 'See it', zh: '看懂它' }} title={Visual.title}>
          {Visual.intro && <p className="muted viz-intro">{tr(Visual.intro)}</p>}
          <Suspense fallback={<div className="viz-loading" />}>
            <Visual.Component />
          </Suspense>
        </Section>
      )}
      {(def.lab || Custom) && (
        <Section kicker={{ en: 'Lab', zh: '实验' }} title={def.labTitle || { en: 'Try it', zh: '动手试试' }}>
          {def.labIntro && <p className="muted">{tr(def.labIntro)}</p>}
          {Custom ? <Custom /> : <MiniLab lab={def.lab} />}
        </Section>
      )}

      <Section kicker={{ en: 'Trace', zh: '追踪' }} title={def.flowTitle || { en: 'How the attack unfolds', zh: '攻击是如何展开的' }}>
        <SequenceDiagram actors={def.actors} messages={def.flow} step={stepper.step} onSelect={stepper.go} title={def.flowTitle} />
        <StepControls stepper={stepper} messages={def.flow} />
      </Section>

      <DeepDive id={def.id} />

      {def.concepts && (
        <Section kicker={{ en: 'Variants', zh: '变体' }} title={def.conceptsTitle || { en: 'What to look for', zh: '需要关注的点' }}>
          <div className="grid3">
            {def.concepts.map((c, i) => (
              <div className="mini" key={i}>
                <h3>{tr(c.t)}</h3>
                <p>{tr(c.b)}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {def.code && (
        <Section kicker={{ en: 'Code', zh: '代码' }} title={{ en: 'Vulnerable vs fixed', zh: '有漏洞 vs 已修复' }}>
          <div className="code-compare">
            <div>
              <div className="field-label bad-text">✕ {tr({ en: 'Vulnerable', zh: '有漏洞' })}</div>
              <pre className="code small">{def.code.vuln}</pre>
            </div>
            <div>
              <div className="field-label good-text">✓ {tr({ en: 'Fixed', zh: '已修复' })}</div>
              <pre className="code small">{def.code.fixed}</pre>
            </div>
          </div>
        </Section>
      )}

      <Section kicker={{ en: 'Defend', zh: '防御' }} title={{ en: 'Defences that actually work', zh: '真正有效的防御' }}>
        <Defenses items={def.defenses} />
      </Section>

      <Section kicker={{ en: 'Interview prep', zh: '面试准备' }} title={{ en: 'Questions you might get', zh: '可能被问到的问题' }}>
        <InterviewQs items={def.qa} />
      </Section>
    </TopicShell>
  );
}
