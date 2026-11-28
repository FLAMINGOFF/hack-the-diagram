import { useLang } from '../i18n.jsx';
import { CATEGORIES, TOPICS } from '../topics/registry.js';

export function Nav({ route }) {
  const { lang, setLang, tr } = useLang();
  return (
    <header className="nav">
      <div className="nav-inner">
        <a href="#/" className="logo" aria-label="Hack the Diagram home">
          <span className="logo-mark" aria-hidden="true">
            <i /> <i /> <i />
          </span>
          <span>
            hack<b>/</b>the<b>/</b>diagram
          </span>
        </a>
        <a href="#/start" className={`nav-start ${route === '/start' ? 'active' : ''}`} aria-current={route === '/start' ? 'page' : undefined}>
          {tr({ en: 'Start here', zh: '新手指引' })}
        </a>
        <a href="#/cheatsheet" className={`nav-start ${route === '/cheatsheet' ? 'active' : ''}`} aria-current={route === '/cheatsheet' ? 'page' : undefined}>
          {tr({ en: 'Cheat sheet', zh: '速查表' })}
        </a>
        <TopicMenu route={route} />
        <div className="nav-tools">
          <div className="lang-toggle" role="group" aria-label="Language">
            <button className={lang === 'en' ? 'on' : ''} aria-pressed={lang === 'en'} onClick={() => setLang('en')}>
              EN
            </button>
            <button className={lang === 'zh' ? 'on' : ''} aria-pressed={lang === 'zh'} onClick={() => setLang('zh')}>
              中文
            </button>
          </div>
          <a className="gh" href="https://github.com/FLAMINGOFF/hack-the-diagram" target="_blank" rel="noreferrer" aria-label="GitHub repository">
            <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true">
              <path
                fill="currentColor"
                d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"
              />
            </svg>
          </a>
        </div>
      </div>
    </header>
  );
}

export function Footer() {
  const { tr } = useLang();
  return (
    <footer className="footer">
      <div className="container footer-inner">
        <p>
          <b>Hack the Diagram</b> ·{' '}
          {tr({
            en: 'Every attack here runs against simulated targets inside your own browser. Nothing leaves the page.',
            zh: '这里的每一次攻击都只针对你浏览器里的模拟目标，不会有任何数据离开页面。',
          })}
        </p>
        <p className="muted">
          {tr({ en: 'Built by', zh: '作者' })}{' '}
          <a href="https://github.com/FLAMINGOFF" target="_blank" rel="noreferrer">
            @FLAMINGOFF
          </a>{' '}
          · {tr({ en: 'For learning only. Only test systems you own or are authorised to test.', zh: '仅供学习。只测试你拥有或获得授权的系统。' })}
        </p>
      </div>
    </footer>
  );
}

function TopicMenu({ route }) {
  const { tr } = useLang();
  return (
    <details className="topic-menu" key={route}>
      <summary>
        {tr({ en: 'Topics', zh: '主题' })} <span aria-hidden="true">▾</span>
      </summary>
      <div className="topic-menu-panel">
        {CATEGORIES.map((c) => (
          <div key={c.id} className={`tone-${c.tone}`}>
            <div className="topic-menu-cat">{tr(c.title)}</div>
            {TOPICS.filter((t) => t.category === c.id).map((t) => (
              <a key={t.id} href={`#/${t.id}`} className={route === `/${t.id}` ? 'active' : ''}>
                {tr(t.title)}
              </a>
            ))}
          </div>
        ))}
      </div>
    </details>
  );
}
