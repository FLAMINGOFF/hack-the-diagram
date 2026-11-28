// Small shared pieces for the hand-built visuals.
import { useCallback, useEffect, useRef, useState } from 'react';
import { useLang } from '../i18n.jsx';

export const L = (en, zh) => ({ en, zh });

/**
 * Reveal a run one beat at a time. start(n) plays beats 0..n-1 every `ms`; `beat` is how many
 * have been shown. Respects reduced motion by showing everything at once.
 */
export function useBeats(ms = 600) {
  const [beat, setBeat] = useState(0);
  const [total, setTotal] = useState(0);
  const timer = useRef(null);
  const stop = () => clearInterval(timer.current);
  useEffect(() => stop, []);
  const start = useCallback(
    (n) => {
      stop();
      setTotal(n);
      const reduce = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      if (reduce) return setBeat(n);
      setBeat(1);
      timer.current = setInterval(() => setBeat((b) => (b >= n ? (stop(), b) : b + 1)), ms);
    },
    [ms],
  );
  const reset = useCallback(() => {
    stop();
    setBeat(0);
    setTotal(0);
  }, []);
  return { beat, total, done: total > 0 && beat >= total, start, reset };
}

export function Chips({ items, value, onPick, label }) {
  const { tr } = useLang();
  return (
    <>
      {label && <div className="field-label">{tr(label)}</div>}
      <div className="chips">
        {items.map((p) => (
          <button type="button" key={p.id} className={`chip ${value === p.id ? 'on' : ''}`} onClick={() => onPick(p)}>
            {tr(p.label)}
          </button>
        ))}
      </div>
    </>
  );
}

export function Toggle({ checked, onChange, children }) {
  return (
    <label className={`oauth-def ${checked ? 'on' : ''}`}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} /> {children}
    </label>
  );
}

/** Lines shown one by one: [{ kind: 'bad' | 'good' | 'info', text }] */
export function Log({ title, lines, beat = Infinity, empty }) {
  const { tr } = useLang();
  return (
    <div className="console" aria-live="polite">
      {title && (
        <div className="console-head">
          <span>{tr(title)}</span>
        </div>
      )}
      {lines.length === 0 && <div className="console-empty">{tr(empty ?? L('Nothing yet.', '还没有内容。'))}</div>}
      {lines.slice(0, beat).map((l, i) => (
        <div key={i} className={`console-line ${l.kind === 'bad' ? 'bad' : l.kind === 'good' ? 'good' : ''}`}>
          {l.kind === 'bad' ? '💥 ' : l.kind === 'good' ? '🛡 ' : '› '}
          {tr(l.text)}
        </div>
      ))}
    </div>
  );
}

export function Verdict({ bad, children }) {
  return <div className={`verdict ${bad === null ? 'neutral-v' : bad ? 'bad' : 'good'}`}>{children}</div>;
}
