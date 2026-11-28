import { lazy, Suspense, useEffect, useState } from 'react';
import { Footer, Nav } from './components/Layout.jsx';
import Home from './Home.jsx';
import Guide from './Guide.jsx';
import { TOPICS } from './topics/registry.js';

// Topic pages are split into their own chunks so the home page loads fast.
const CUSTOM = {
  xss: lazy(() => import('./topics/Xss.jsx')),
  sqli: lazy(() => import('./topics/Sqli.jsx')),
  csrf: lazy(() => import('./topics/Csrf.jsx')),
  tls: lazy(() => import('./topics/Tls.jsx')),
};
const GenericPage = lazy(() => import('./topics/GenericPage.jsx'));
const Cheatsheet = lazy(() => import('./Cheatsheet.jsx'));
const TOPIC_IDS = new Set(TOPICS.map((t) => t.id));

function useHashRoute() {
  const read = () => window.location.hash.replace(/^#/, '') || '/';
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const onChange = () => {
      setRoute(read());
      window.scrollTo(0, 0);
    };
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}

function Page({ route }) {
  const id = route.replace(/^\//, '');
  if (id === 'start') return <Guide />;
  if (id === 'cheatsheet') return <Cheatsheet />;
  const Custom = CUSTOM[id];
  if (Custom) return <Custom />;
  if (TOPIC_IDS.has(id)) return <GenericPage id={id} />;
  return <Home />;
}

export default function App() {
  const route = useHashRoute();
  return (
    <>
      {/* Hash routing owns the URL fragment, so the skip link moves focus instead of linking to #main. */}
      <button className="skip-link" onClick={() => document.getElementById('main')?.focus()}>
        Skip to content
      </button>
      <Nav route={route} />
      <main id="main" tabIndex={-1}>
        <Suspense fallback={<div className="page-loading" aria-busy="true" />}>
          <Page route={route} />
        </Suspense>
      </main>
      <Footer />
    </>
  );
}
