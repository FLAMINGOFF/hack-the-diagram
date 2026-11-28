import { useMemo, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import SequenceDiagram from '../components/SequenceDiagram.jsx';
import { StepControls, useStepper } from '../components/Stepper.jsx';
import { Chips, L } from './kit.jsx';
import { CD_ACTORS, CD_CACHE, CD_ORIGIN, CD_PRESETS, deception } from './batch2.js';

/** Web cache deception: the cache and the origin read the same URL differently. */
export default function CacheDeceive() {
  const { tr } = useLang();
  const [path, setPath] = useState('mapping');
  const [origin, setOrigin] = useState('loose');
  const [cache, setCache] = useState('ext');
  const { messages, outcome } = useMemo(() => deception(path, origin, cache), [path, origin, cache]);
  const stepper = useStepper(messages.length, 2200);
  const last = stepper.step >= messages.length - 1;
  const set = (fn) => (v) => {
    fn(v);
    stepper.go(0);
  };

  return (
    <div className="cd-viz">
      <div className="oauth-controls">
        <Seg label={L('Origin', '源站')} value={origin} onChange={set(setOrigin)} options={Object.entries(CD_ORIGIN).map(([value, label]) => ({ value, label }))} />
        <Seg label={L('Cache', '缓存')} value={cache} onChange={set(setCache)} options={Object.entries(CD_CACHE).map(([value, label]) => ({ value, label }))} />
      </div>
      <Chips label={L('Link the attacker sends', '攻击者发送的链接')} items={CD_PRESETS} value={path} onPick={(p) => set(setPath)(p.id)} />
      <SequenceDiagram actors={CD_ACTORS} messages={messages} step={stepper.step} onSelect={stepper.go} title={L('Web cache deception', 'Web 缓存欺骗')} />
      <StepControls stepper={stepper} messages={messages} />
      {last && (
        <div className={`verdict ${outcome === 'pwned' ? 'bad' : outcome === 'blocked' ? 'good' : 'neutral-v'}`}>
          {outcome === 'pwned'
            ? tr(L('The cache saw a stylesheet, the origin saw /my-account. Anyone can now fetch the victim’s page from the cache.', '缓存以为这是样式表，源站以为这是 /my-account。现在任何人都能从缓存里取到受害者的页面。'))
            : outcome === 'blocked'
              ? tr(L('Nothing private was cached. Either the origin refused the odd path, or the cache obeyed no-store.', '没有缓存任何私有内容。要么源站拒绝了这个奇怪的路径，要么缓存遵守了 no-store。'))
              : tr(L('A normal visit. Now pick one of the tricked URLs.', '一次正常访问。现在选一个带陷阱的 URL。'))}
        </div>
      )}
    </div>
  );
}
