import { useLang } from '../i18n.jsx';

const KIND_COLOR = {
  normal: 'var(--c-normal)',
  attack: 'var(--c-attack)',
  blocked: 'var(--c-blocked)',
  secure: 'var(--c-secure)',
};

/**
 * A small sequence diagram renderer.
 * actors:   [{ id, label, sub, tone }]
 * messages: [{ from, to, label, kind, lock }]  — from === to is a local action,
 *           from === '*' spans every actor (something both sides do).
 * step:     index of the message currently being explained.
 */
export default function SequenceDiagram({ actors, messages, step, onSelect, title }) {
  const { tr } = useLang();
  const W = 760;
  const top = 70;
  const rowH = 46;
  const H = top + messages.length * rowH + 14;
  const col = W / actors.length;
  const ax = (id) => col * actors.findIndex((a) => a.id === id) + col / 2;
  const boxW = Math.min(170, col - 16);

  return (
    <div className="seq-wrap">
      <svg className="seq" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={tr(title) || 'Sequence diagram'}>
        <defs>
          {Object.entries(KIND_COLOR).map(([k, c]) => (
            <marker key={k} id={`arr-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill={c} />
            </marker>
          ))}
        </defs>

        {actors.map((a) => {
          const x = ax(a.id);
          return (
            <g key={a.id}>
              <line x1={x} y1={52} x2={x} y2={H - 6} className="lifeline" />
              <rect x={x - boxW / 2} y={8} width={boxW} height={44} rx={9} className={`actor tone-${a.tone || 'neutral'}`} />
              <text x={x} y={27} className="actor-label">
                {tr(a.label)}
              </text>
              <text x={x} y={43} className="actor-sub">
                {tr(a.sub)}
              </text>
            </g>
          );
        })}

        {messages.map((m, i) => {
          const y = top + i * rowH + 22;
          const state = i < step ? 'past' : i === step ? 'current' : 'future';
          const kind = m.kind || 'normal';
          const color = KIND_COLOR[kind];
          const select = onSelect ? () => onSelect(i) : undefined;
          const label = `${m.lock ? '🔒 ' : ''}${tr(m.label)}`;

          if (m.from === m.to || m.from === '*') {
            const x1 = m.from === '*' ? ax(actors[0].id) : ax(m.from);
            const x2 = m.from === '*' ? ax(actors[actors.length - 1].id) : ax(m.from);
            const textW = [...label].reduce((w, ch) => w + (ch.charCodeAt(0) > 0x2e80 ? 12.5 : 6.9), 0) + 28;
            const width = Math.min(W - 40, Math.max(Math.abs(x2 - x1) + boxW - 12, textW));
            const left = Math.max(28, Math.min(W - 6 - width, (x1 + x2) / 2 - width / 2));
            return (
              <g key={i} className={`msg ${state}`} onClick={select}>
                <text x={10} y={y + 4} className="step-no">
                  {i + 1}
                </text>
                <rect x={left} y={y - 15} width={width} height={28} rx={7} className="self" style={{ stroke: color }} />
                <text x={left + width / 2} y={y + 4} className="msg-label self-label">
                  {label}
                </text>
              </g>
            );
          }

          const x1 = ax(m.from);
          const x2 = ax(m.to);
          const dir = x2 > x1 ? 1 : -1;
          return (
            <g key={i} className={`msg ${state}`} onClick={select}>
              <text x={10} y={y + 4} className="step-no">
                {i + 1}
              </text>
              <rect x={Math.min(x1, x2)} y={y - 22} width={Math.abs(x2 - x1)} height={30} fill="transparent" />
              <line
                x1={x1 + dir * 3}
                y1={y}
                x2={x2 - dir * 4}
                y2={y}
                stroke={color}
                strokeWidth={state === 'current' ? 2.6 : 1.8}
                strokeDasharray={kind === 'blocked' ? '6 5' : undefined}
                markerEnd={`url(#arr-${kind})`}
              />
              <text x={(x1 + x2) / 2} y={y - 8} className="msg-label">
                {label}
              </text>
              {state === 'current' && (
                <circle key={`p-${step}`} r="6" cx={x1} cy={y} fill={color} className="packet">
                  <animate attributeName="cx" from={x1} to={x2 - dir * 8} dur="0.75s" fill="freeze" />
                </circle>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
