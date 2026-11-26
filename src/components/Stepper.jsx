import { useCallback, useEffect, useRef, useState } from 'react';
import { useLang } from '../i18n.jsx';

export function useStepper(total, interval = 2200) {
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const timer = useRef(null);

  useEffect(() => {
    if (!playing) return undefined;
    timer.current = setInterval(() => {
      setStep((s) => {
        if (s >= total - 1) {
          setPlaying(false);
          return s;
        }
        return s + 1;
      });
    }, interval);
    return () => clearInterval(timer.current);
  }, [playing, total, interval]);

  useEffect(() => {
    setStep((s) => Math.min(s, total - 1));
  }, [total]);

  const go = useCallback((i) => setStep(Math.max(0, Math.min(total - 1, i))), [total]);
  const play = useCallback(() => {
    setStep((s) => (s >= total - 1 ? 0 : s));
    setPlaying(true);
  }, [total]);
  const restart = useCallback(() => {
    setStep(0);
    setPlaying(true);
  }, []);

  return { step, go, playing, play, pause: () => setPlaying(false), restart, setPlaying };
}

export function StepControls({ stepper, messages }) {
  const { tr } = useLang();
  const { step, go, playing, play, pause } = stepper;
  const m = messages[step];
  const kind = m?.kind || 'normal';
  return (
    <div className="stepper">
      <div className="stepper-bar">
        <button className="btn ghost" onClick={() => go(0)} aria-label={tr({ en: 'First step', zh: '第一步' })}>
          ⏮
        </button>
        <button className="btn ghost" onClick={() => go(step - 1)} disabled={step === 0}>
          ◀ {tr({ en: 'Back', zh: '上一步' })}
        </button>
        {playing ? (
          <button className="btn" onClick={pause}>
            ⏸ {tr({ en: 'Pause', zh: '暂停' })}
          </button>
        ) : (
          <button className="btn primary" onClick={play}>
            ▶ {tr({ en: 'Play', zh: '播放' })}
          </button>
        )}
        <button className="btn ghost" onClick={() => go(step + 1)} disabled={step >= messages.length - 1}>
          {tr({ en: 'Next', zh: '下一步' })} ▶
        </button>
        <span className="step-count">
          {tr({ en: 'Step', zh: '第' })} {step + 1} / {messages.length}
          {tr({ en: '', zh: ' 步' })}
        </span>
      </div>
      {m && (
        <div className={`narration kind-${kind}`} aria-live="polite">
          <div className="narration-title">
            <span className="pill">{step + 1}</span> {m.lock ? '🔒 ' : ''}
            {tr(m.title || m.label)}
          </div>
          <p>{tr(m.note)}</p>
          {m.code && <pre className="code small">{tr(m.code)}</pre>}
        </div>
      )}
    </div>
  );
}
