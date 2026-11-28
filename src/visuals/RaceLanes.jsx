import { useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';
import { L, Toggle, useBeats } from './kit.jsx';
import { CHECK_TO_WRITE, RACE_MODES, raceRun } from './batch1.js';

const N = 10;
const W = 420;
const LEFT = 40;
const LANE = 22;
const TOP = 26;

/** Race condition: N requests redeem the same one-time coupon. Lanes show each request's check and write. */
export default function RaceLanes() {
  const { tr } = useLang();
  const [mode, setMode] = useState('parallel');
  const [atomic, setAtomic] = useState(false);
  const beats = useBeats(140);
  const run = raceRun(N, mode, atomic);
  const order = [...run.reqs].sort((a, b) => a.arrive - b.arrive || a.i - b.i);
  const x = (ms) => LEFT + (ms / run.end) * (W - LEFT - 10);
  const firstWrite = Math.min(...run.reqs.map((r) => r.write));
  const firstCheck = Math.min(...run.reqs.map((r) => r.check));
  const H = TOP + N * LANE + 24;
  const shown = new Set(order.slice(0, beats.beat).map((r) => r.i));
  const applied = run.reqs.filter((r) => shown.has(r.i) && r.ok).length;

  const change = (fn) => (v) => {
    fn(v);
    beats.reset();
  };

  return (
    <div className="race-viz">
      <div className="race-controls">
        <Seg label={L('How the requests are sent', '请求怎么发出')} value={mode} onChange={change(setMode)} options={Object.entries(RACE_MODES).map(([v, label]) => ({ value: v, label }))} />
        <Toggle checked={atomic} onChange={change(setAtomic)}>
          {tr(L('Check and use the coupon in one atomic UPDATE', '用一条原子 UPDATE 同时检查并使用优惠券'))}
        </Toggle>
        <button type="button" className="btn danger" onClick={() => beats.start(N)}>
          {tr(L(`Send ${N} requests`, `发送 ${N} 个请求`))}
        </button>
      </div>
      <div className="panel race-panel">
        <svg viewBox={`0 0 ${W} ${H}`} className="race-svg" role="img" aria-label={tr(L('Request timeline', '请求时间线'))}>
          {!atomic && (
            <rect className="race-window" x={x(firstCheck)} y={TOP - 8} width={Math.max(2, x(firstWrite) - x(firstCheck))} height={N * LANE + 4} rx="4" />
          )}
          {!atomic && (
            <text x={x(firstCheck) + 4} y={TOP - 12} className="race-wtext">
              {tr(L(`race window ≈ ${CHECK_TO_WRITE} ms`, `竞态窗口 ≈ ${CHECK_TO_WRITE} 毫秒`))}
            </text>
          )}
          {order.map((r, k) => {
            const y = TOP + k * LANE + LANE / 2;
            const on = shown.has(r.i);
            return (
              <g key={r.i} className={`race-lane ${on ? 'on' : ''} ${r.ok ? 'ok' : 'no'}`}>
                <text x="6" y={y + 4} className="race-label">
                  #{r.i + 1}
                </text>
                <line x1={x(r.arrive)} x2={x(r.write)} y1={y} y2={y} />
                <circle cx={x(r.check)} cy={y} r="5" />
                <rect x={x(r.write) - 5} y={y - 5} width="10" height="10" rx="2" />
              </g>
            );
          })}
          <text x={LEFT} y={H - 6} className="race-axis">
            0 ms
          </text>
          <text x={W - 10} y={H - 6} textAnchor="end" className="race-axis">
            {Math.round(run.end)} ms
          </text>
        </svg>
        <div className="race-key">
          <span>● {tr(L('reads “coupon unused”', '读到“优惠券未使用”'))}</span>
          <span>■ {tr(L('writes “used”', '写入“已使用”'))}</span>
          <span className="race-ok">{tr(L('red: discount applied', '红色：折扣生效'))}</span>
        </div>
        <div className={`verdict ${beats.done ? (run.applied > 1 ? 'bad' : 'good') : 'neutral-v'}`} aria-live="polite">
          {!beats.done
            ? tr(L('One coupon, “single use”. Send the requests and count how many times it is applied.', '一张“只能用一次”的优惠券。把请求发出去，数数它被用了几次。'))
            : run.applied > 1
              ? tr(L(`Applied ${applied} times. Every request that read the coupon before the first write saw it as unused.`, `生效了 ${applied} 次。凡是在第一次写入之前读取优惠券的请求，看到的都是“未使用”。`))
              : atomic
                ? tr(L('Applied once. The database checks and updates in one step, so only one UPDATE can change the row.', '只生效了一次。数据库在一步之内完成检查和更新，所以只有一条 UPDATE 能改到这一行。'))
                : tr(L('Applied once, because each request arrived after the previous one had finished. That is luck, not safety.', '只生效了一次，因为每个请求都在上一个完成之后才到。这是运气，不是安全。'))}
        </div>
      </div>
    </div>
  );
}
