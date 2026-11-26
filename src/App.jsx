import { useEffect, useState } from 'react';
import { Footer, Nav } from './components/Layout.jsx';
import Home from './Home.jsx';
import Xss from './topics/Xss.jsx';
import Sqli from './topics/Sqli.jsx';
import Csrf from './topics/Csrf.jsx';
import Tls from './topics/Tls.jsx';

const PAGES = { '/xss': Xss, '/sqli': Sqli, '/csrf': Csrf, '/tls': Tls };

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

export default function App() {
  const route = useHashRoute();
  const Page = PAGES[route] || Home;
  return (
    <>
      <Nav route={route} />
      <Page />
      <Footer />
    </>
  );
}
