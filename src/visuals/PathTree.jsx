import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { Chips, L, useBeats } from './kit.jsx';
import { BASE, PT_DEFENCES, PT_PRESETS, TREE, walkPath } from './batch1.js';

const BASE_KEY = BASE.split('/').filter(Boolean).join('/');

function Tree({ node, path, hot }) {
  return (
    <ul className="pt-tree">
      {Object.entries(node).map(([k, v]) => {
        const p = path ? `${path}/${k}` : k;
        const cls = [p === hot ? 'hot' : hot.startsWith(p + '/') ? 'trail' : '', p === BASE_KEY ? 'base' : ''].join(' ');
        return (
          <li key={p}>
            <span className={`pt-node ${cls}`}>
              {typeof v === 'object' ? '📁' : '📄'} {k}
              {p === BASE_KEY && <em> ← {BASE}</em>}
            </span>
            {typeof v === 'object' && <Tree node={v} path={p} hot={hot} />}
          </li>
        );
      })}
    </ul>
  );
}

/** Path traversal: the server's folder tree, with the requested path walked one segment at a time. */
export default function PathTree() {
  const { tr } = useLang();
  const [defence, setDefence] = useState('none');
  const [value, setValue] = useState(PT_PRESETS[1].value);
  const [run, setRun] = useState(null);
  const beats = useBeats(550);

  const reset = () => {
    setRun(null);
    beats.reset();
  };
  const go = () => {
    const r = walkPath(value, defence);
    setRun(r);
    beats.start(Math.max(1, r.steps.length));
  };

  const shown = run ? run.steps.slice(0, beats.beat) : [];
  const hot = shown.length ? shown[shown.length - 1].at.join('/') : BASE_KEY;
  const done = run && (run.blocked && !run.steps.length ? true : beats.done);

  let verdict = null;
  if (done) {
    if (run.blocked) verdict = { bad: false, text: tr(run.notes[run.notes.length - 1]) };
    else if (run.content && run.escaped) verdict = { bad: true, text: tr(L(`The server read ${run.full}, outside the images folder.`, `服务器读取了 ${run.full}，它在图片文件夹之外。`)) };
    else if (run.content) verdict = { bad: null, text: tr(L('A normal image, inside the folder.', '一张正常的图片，在文件夹之内。')) };
    else verdict = { bad: null, text: tr(L(`${run.full} does not exist, so the server returns 404.`, `${run.full} 不存在，服务器返回 404。`)) };
  }

  return (
    <div className="lab pt-viz">
      <div className="panel">
        <Seg
          label={L('Server-side check', '服务器端检查')}
          value={defence}
          onChange={(v) => {
            setDefence(v);
            reset();
          }}
          options={Object.entries(PT_DEFENCES).map(([v, label]) => ({ value: v, label }))}
        />
        <Chips
          label={L('filename =', 'filename =')}
          items={PT_PRESETS}
          value={PT_PRESETS.find((p) => p.value === value)?.id}
          onPick={(p) => {
            setValue(p.value);
            reset();
          }}
        />
        <label className="field-label" htmlFor="pt-input">
          GET /image?filename=
        </label>
        <input
          id="pt-input"
          className="input mono"
          value={value}
          spellCheck={false}
          onChange={(e) => {
            setValue(e.target.value);
            reset();
          }}
        />
        <div className="code small pt-code">{`open("${BASE}" + filename)`}</div>
        <button type="button" className="btn danger" onClick={go}>
          {tr(L('Read file', '读取文件'))}
        </button>
        {run?.notes.length > 0 && (
          <ul className="pt-notes">
            {run.notes.map((n, i) => (
              <li key={i}>{tr(n)}</li>
            ))}
          </ul>
        )}
      </div>

      <div className="panel">
        <div className="pt-trail">
          {(run?.steps ?? []).map((s, i) => (
            <span key={i} className={`pt-seg ${i < beats.beat ? 'on' : ''} ${s.seg === '..' ? 'up' : ''}`}>
              {s.seg}
            </span>
          ))}
        </div>
        <div className="pt-root">
          <span className={`pt-node ${hot === '' ? 'hot' : 'trail'}`}>📁 /</span>
          <Tree node={TREE} path="" hot={hot} />
        </div>
        {done && run.content && (
          <pre className="code small">
            {run.full}
            {'\n'}
            {run.content}
          </pre>
        )}
        <div className={`verdict ${verdict ? (verdict.bad === null ? 'neutral-v' : verdict.bad ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {verdict ? verdict.text : tr(L('Pick a filename and press “Read file”.', '选一个文件名，然后点击“读取文件”。'))}
        </div>
      </div>
    </div>
  );
}
