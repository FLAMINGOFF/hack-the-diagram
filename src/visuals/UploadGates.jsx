import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Chips, L, Toggle, useBeats } from './kit.jsx';
import { FILES, GATES, upload } from './batch1.js';

const show = (s) => s.replace(/\x89/g, '\\x89');

/** File upload: push a file through the server's checks and see whether it ends up running as code. */
export default function UploadGates() {
  const { tr } = useLang();
  const [fileId, setFileId] = useState('ctype');
  const [gates, setGates] = useState({ block: false, ctype: true, magic: false, allow: false, store: false });
  const beats = useBeats(600);
  const file = FILES.find((f) => f.id === fileId);
  const res = upload(file, gates);
  const steps = res.checks.length + 1;
  const shown = res.checks.slice(0, beats.beat);
  const end = beats.done;
  const rejected = !res.stored;

  return (
    <div className="lab up-viz">
      <div className="panel">
        <Chips
          label={L('File to upload as your avatar', '作为头像上传的文件')}
          items={FILES}
          value={fileId}
          onPick={(f) => {
            setFileId(f.id);
            beats.reset();
          }}
        />
        <div className="field-label">{tr(L('Server checks', '服务器检查'))}</div>
        <div className="oauth-defs up-gates">
          {Object.entries(GATES).map(([k, label]) => (
            <Toggle
              key={k}
              checked={gates[k]}
              onChange={(v) => {
                setGates((g) => ({ ...g, [k]: v }));
                beats.reset();
              }}
            >
              {tr(label)}
            </Toggle>
          ))}
        </div>
        <button type="button" className="btn danger" onClick={() => beats.start(steps)}>
          {tr(L('Upload', '上传'))}
        </button>
      </div>

      <div className="panel">
        <pre className="code small">{`POST /my-account/avatar\nContent-Disposition: form-data; filename="${file.name}"\nContent-Type: ${file.type}\n\n${show(file.body)}`}</pre>
        <ol className="up-steps">
          {shown.map((c) => (
            <li key={c.k} className={c.pass ? 'pass' : 'fail'}>
              <b>{c.pass ? '✓' : '✗'} {tr(GATES[c.k])}</b>
              <span>{tr(c.why)}</span>
            </li>
          ))}
          {end && res.stored && (
            <li className={res.runs ? 'fail' : 'pass'}>
              <b>GET {res.stored}{res.runs ? '?cmd=id' : ''}</b>
              <span>{res.runs ? 'uid=33(www-data) gid=33(www-data)' : tr(L('Served as a file. Nothing runs.', '作为文件返回，什么都不会执行。'))}</span>
            </li>
          )}
        </ol>
        <div className={`verdict ${end ? (res.runs ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!end
            ? tr(L('Choose a file and the checks, then upload.', '选一个文件和要开启的检查，然后上传。'))
            : res.runs
              ? tr(L(`The server saved ${res.stored} and runs it as PHP. That is a web shell.`, `服务器保存了 ${res.stored}，并把它当作 PHP 执行。这就是一个 Web Shell。`))
              : rejected
                ? tr(L('Rejected. Try a file that slips past this check, then add the check that stops it.', '被拒绝了。试试能绕过这项检查的文件，再加上能挡住它的检查。'))
                : tr(L('Stored, but it cannot run.', '已保存，但无法执行。'))}
        </div>
      </div>
    </div>
  );
}
