import { useEffect, useRef, useState } from 'react';
import { useLang } from '../i18n.jsx';
import { Seg } from '../components/TopicShell.jsx';

const L = (en, zh) => ({ en, zh });

/**
 * Clickjacking in 3D: the decoy page and the invisible framed page are pulled apart so you can
 * see which layer the browser's hit test picks. Opacity changes what you see, not what you click.
 */
export default function ClickLayers() {
  const { tr } = useLang();
  const [apart, setApart] = useState(0);
  const [defence, setDefence] = useState('none');
  const [phase, setPhase] = useState(0); // 0 idle, 1 separating, 2 cursor falling, 3 hit
  const timers = useRef([]);
  const blocked = defence !== 'none';

  const clear = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };
  useEffect(() => clear, []);

  const play = () => {
    clear();
    setPhase(0);
    setApart(0);
    const at = (ms, fn) => timers.current.push(setTimeout(fn, ms));
    at(300, () => {
      setPhase(1);
      setApart(1);
    });
    at(1500, () => setPhase(2));
    at(2500, () => setPhase(3));
  };

  const t = apart;
  const stage = { transform: `rotateX(${t * 52}deg) rotateZ(${-t * 24}deg) scale(${1 - t * 0.12})` };
  const top = { transform: `translateZ(${t * 110}px)`, opacity: blocked ? 0.35 + t * 0.6 : 0.02 + t * 0.9 };

  return (
    <div className="lab cj3-viz">
      <div className="panel">
        <Seg
          label={L('bank.example sends', 'bank.example 发送的响应头')}
          value={defence}
          onChange={(v) => {
            clear();
            setDefence(v);
            setPhase(0);
          }}
          options={[
            { value: 'none', label: L('No framing header', '没有防嵌入头') },
            { value: 'xfo', label: 'X-Frame-Options: DENY' },
            { value: 'csp', label: "frame-ancestors 'none'" },
          ]}
        />
        <label className="field-label" htmlFor="cj3-apart">
          {tr(L('Pull the layers apart', '把图层拉开'))}
        </label>
        <input
          id="cj3-apart"
          type="range"
          min="0"
          max="1"
          step="0.01"
          value={apart}
          className="range"
          onChange={(e) => {
            clear();
            setApart(Number(e.target.value));
            setPhase(0);
          }}
        />
        <p className="hint">
          {tr(
            L(
              'Flat, this is what the victim sees: a prize page. Pulled apart, you can see the bank page the attacker framed on top, almost fully transparent, with its "Delete account" button placed exactly over "Claim prize".',
              '叠在一起时，这就是受害者看到的：一个领奖页面。拉开之后，就能看到攻击者嵌在上面的银行页面：几乎完全透明，“删除账号”按钮正好盖在“领取奖品”上。',
            ),
          )}
        </p>
        <button type="button" className="btn danger" onClick={play}>
          {tr(L('Play the click', '播放这次点击'))}
        </button>
        <ol className="cj3-legend">
          <li>{tr(L('The browser finds the topmost element under the pointer (hit testing).', '浏览器找到指针下方最上层的元素（命中测试）。'))}</li>
          <li>{tr(L('opacity: 0.0001 does not take an element out of hit testing. Only pointer-events or not rendering it would.', 'opacity: 0.0001 并不会让元素退出命中测试，只有 pointer-events 或者不渲染它才会。'))}</li>
          <li>{tr(L('So the click goes to bank.example, with Alice’s cookies.', '所以这次点击落在了 bank.example 上，带着 Alice 的 Cookie。'))}</li>
        </ol>
      </div>

      <div className="panel">
        <div className="cj3-scene" aria-hidden="true">
          <div className="cj3-stage" style={stage}>
            <div className="cj3-layer cj3-decoy">
              <div className="cj3-tag">win-a-prize.example</div>
              <h4>🎉 {tr(L('You won!', '你中奖了！'))}</h4>
              <p>{tr(L('Visitor #1,000,000', '第 1,000,000 位访客'))}</p>
              <span className="cj3-btn decoy">{tr(L('Claim prize', '领取奖品'))}</span>
            </div>
            <div className={`cj3-layer cj3-frame ${blocked ? 'refused' : ''} ${phase === 3 ? 'hit' : ''}`} style={top}>
              <div className="cj3-tag">&lt;iframe src="bank.example/account"&gt;</div>
              {blocked ? (
                <p className="cj3-refused">⛔ {tr(L('bank.example refused to be framed', 'bank.example 拒绝被嵌入'))}</p>
              ) : (
                <>
                  <h4>bank.example</h4>
                  <p>alice@uni.example · $5,000</p>
                  <span className="cj3-btn danger">{tr(L('Delete account', '删除账号'))}</span>
                </>
              )}
            </div>
            <div className={`cj3-cursor ${phase >= 2 ? 'fall' : ''}`}>👆</div>
          </div>
        </div>
        <div className={`verdict ${phase === 3 ? (blocked ? 'good' : 'bad') : 'neutral-v'}`} aria-live="polite">
          {phase < 3
            ? tr(L('Press “Play the click”, or drag the slider.', '点击“播放这次点击”，或者拖动滑块。'))
            : blocked
              ? tr(L('The frame is there but empty: the browser would not render bank.example inside another site. The click lands on nothing.', '框架还在，但里面是空的：浏览器拒绝在其他网站里渲染 bank.example，这次点击什么也没点到。'))
              : tr(L('The click hit the top layer: “Delete account” on bank.example. Alice only ever saw the prize button.', '点击落在了最上层：bank.example 的“删除账号”。Alice 自始至终只看到了领奖按钮。'))}
        </div>
      </div>
    </div>
  );
}
