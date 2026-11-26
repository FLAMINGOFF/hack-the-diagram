import { useLang } from '../i18n.jsx';
import { TOPICS, categoryById, topicById } from '../topics/registry.js';

export function TopicShell({ id, tldr, children }) {
  const { tr } = useLang();
  const topic = topicById(id);
  const idx = TOPICS.findIndex((t) => t.id === id);
  const next = TOPICS[(idx + 1) % TOPICS.length];
  const cat = categoryById(topic.category);
  return (
    <main className={`topic tone-${cat.tone}`}>
      <section className="topic-hero">
        <div className="container">
          <a href="#/" className="back">
            ← {tr({ en: 'All topics', zh: '全部主题' })}
          </a>
          <div className="eyebrow">
            <span className={`badge tone-${cat.tone}`}>{topic.short}</span>
            <span className="muted">{tr(cat.title)}</span>
            <span className="muted mono">{topic.tag}</span>
          </div>
          <h1>{tr(topic.title)}</h1>
          <p className="lede">{tr(tldr)}</p>
        </div>
      </section>
      <div className="container topic-body">{children}</div>
      <div className="container">
        <a className="next-topic" href={`#/${next.id}`}>
          <span className="muted">{tr({ en: 'Next topic', zh: '下一个主题' })}</span>
          <b>
            {tr(next.title)} →
          </b>
        </a>
      </div>
    </main>
  );
}

export function Section({ title, kicker, children, className = '' }) {
  const { tr } = useLang();
  return (
    <section className={`section ${className}`}>
      {kicker && <div className="kicker">{tr(kicker)}</div>}
      {title && <h2>{tr(title)}</h2>}
      {children}
    </section>
  );
}

export function Defenses({ items }) {
  const { tr } = useLang();
  return (
    <ul className="defenses">
      {items.map((d, i) => (
        <li key={i}>
          <b>{tr(d.title)}</b>
          <span>{tr(d.body)}</span>
        </li>
      ))}
    </ul>
  );
}

export function InterviewQs({ items }) {
  const { tr } = useLang();
  return (
    <div className="qa">
      {items.map((q, i) => (
        <details key={i}>
          <summary>{tr(q.q)}</summary>
          <p>{tr(q.a)}</p>
        </details>
      ))}
    </div>
  );
}

export function Seg({ value, onChange, options, label }) {
  const { tr } = useLang();
  return (
    <div className="seg-group">
      {label && <div className="seg-label">{tr(label)}</div>}
      <div className="seg" role="radiogroup" aria-label={tr(label)}>
        {options.map((o) => (
          <button key={o.value} role="radio" aria-checked={value === o.value} className={value === o.value ? 'on' : ''} onClick={() => onChange(o.value)}>
            {tr(o.label)}
          </button>
        ))}
      </div>
    </div>
  );
}
