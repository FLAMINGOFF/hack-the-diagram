export const L = (en, zh) => ({ en, zh });

export const actor = (id, label, sub, tone = 'neutral') => ({ id, label, sub, tone });

/** msg(from, to, label, note, kind?, extra?) */
export const msg = (from, to, label, note, kind = 'normal', extra = {}) => ({ from, to, label, note, kind, ...extra });

export const ATTACKER = actor('atk', L('Attacker', '攻击者'), 'mallory', 'red');
export const VICTIM = actor('vic', L("Victim's browser", '受害者浏览器'), L('logged in', '已登录'), 'green');

export const verdict = (bad, en, zh) => ({ verdict: bad ? 'bad' : 'good', message: L(en, zh) });
