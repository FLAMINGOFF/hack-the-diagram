import { useEffect, useState } from 'react';
import { Footer, Nav } from './components/Layout.jsx';
import GenericTopic from './components/GenericTopic.jsx';
import Home from './Home.jsx';
import Xss from './topics/Xss.jsx';
import Sqli from './topics/Sqli.jsx';
import Csrf from './topics/Csrf.jsx';
import Tls from './topics/Tls.jsx';
import { SERVER } from './topics/content/server.js';
import { CLIENT } from './topics/content/client.jsx';
import { ADVANCED } from './topics/content/advanced.js';

const CUSTOM = { xss: Xss, sqli: Sqli, csrf: Csrf, tls: Tls };
const DEFS = { ...SERVER, ...CLIENT, ...ADVANCED };

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
  const Custom = CUSTOM[id];
  if (Custom) return <Custom />;
  if (DEFS[id]) return <GenericTopic key={id} def={{ id, ...DEFS[id] }} />;
  return <Home />;
}

export default function App() {
  const route = useHashRoute();
  return (
    <>
      <Nav route={route} />
      <Page route={route} />
      <Footer />
    </>
  );
}
