import { useEffect, useState } from 'react';
import { useLang } from './i18n.jsx';
import { CATEGORIES, topicById } from './topics/registry.js';
import { CHEATSHEET } from './topics/cheatsheet.js';

const L = (en, zh) => ({ en, zh });
const setDocTitle = (t) => {
  document.title = t;
};

/** Every topic on one printable page: how to spot it, what to try, how to fix it. */
export default function Cheatsheet() {
  const { tr } = useLang();
  const [cat, setCat] = useState('all');
  useEffect(() => {
    setDocTitle(`${tr(L('Cheat sheet', '速查表'))} · Hack the Diagram`);
    return () => setDocTitle('Hack the Diagram');
  }, [tr]);
  const groups = CATEGORIES.filter((c) => cat === 'all' || c.id === cat)
    .map((c) => ({ c, items: CHEATSHEET.filter((e) => topicById(e.id).category === c.id) }))
    .filter((g) => g.items.length);

  return (
    <div className="topic tone-blue cheatsheet">
      <section className="topic-hero">
        <div className="container">
          <a href="#/" className="back no-print">
            ← {tr(L('Home', '首页'))}
          </a>
          <div className="eyebrow">
            <span className="badge tone-blue">{tr(L('Revision', '复习'))}</span>
            <span className="muted">{tr(L(`${CHEATSHEET.length} topics on one page`, `${CHEATSHEET.length} 个主题，一页看完`))}</span>
          </div>
          <h1>{tr(L('Cheat sheet', '速查表'))}</h1>
          <p className="lede">
            {tr(
              L(
                'For each topic: how to spot it, a few inputs to try in a lab, and the fix that actually works. Built for a last look before an interview, and it prints cleanly.',
                '每个主题三件事：怎么发现它，在实验里可以试哪些输入，以及真正有效的修复方式。适合面试前快速过一遍，也可以直接打印。',
              ),
            )}
          </p>
          <div className="row no-print">
            <button type="button" className="btn primary" onClick={() => window.print()}>
              🖨 {tr(L('Print or save as PDF', '打印或存为 PDF'))}
            </button>
          </div>
        </div>
      </section>
      <div className="container topic-body">
        <div className="chips no-print" role="group" aria-label={tr(L('Filter by category', '按分类筛选'))}>
          {[{ id: 'all', title: L('All', '全部'), tone: 'neutral' }, ...CATEGORIES].map((c) => (
            <button key={c.id} type="button" className={`chip tone-${c.tone} ${cat === c.id ? 'on' : ''}`} aria-pressed={cat === c.id} onClick={() => setCat(c.id)}>
              {tr(c.title)}
            </button>
          ))}
        </div>
        {groups.map(({ c, items }) => (
          <section key={c.id} className={`cs-group tone-${c.tone}`}>
            <h2>{tr(c.title)}</h2>
            <div className="cs-grid">
              {items.map((e) => {
                const t = topicById(e.id);
                return (
                  <article className="cs-card" key={e.id}>
                    <h3>
                      <a href={`#/${e.id}`}>{tr(t.title)}</a> <span className="muted mono">{t.tag}</span>
                    </h3>
                    <div className="cs-label">{tr(L('Spot it', '发现'))}</div>
                    <p>{tr(e.spot)}</p>
                    <div className="cs-label">{tr(L('Try', '尝试'))}</div>
                    <ul className="cs-payloads">
                      {e.payloads.map((p, i) => (
                        <li key={i}>
                          <code>{p}</code>
                        </li>
                      ))}
                    </ul>
                    <div className="cs-label good-text">{tr(L('Fix', '修复'))}</div>
                    <p>{tr(e.fix)}</p>
                  </article>
                );
              })}
            </div>
          </section>
        ))}
        <p className="muted tiny">{tr(L('For learning and authorised testing only.', '仅用于学习和获得授权的测试。'))}</p>
      </div>
    </div>
  );
}
