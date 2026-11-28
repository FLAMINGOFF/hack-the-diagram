// Real JWT mechanics for the token inspector: base64url and HMAC-SHA256 via Web Crypto.
// Two simulated servers verify tokens: a naive one that trusts the header, and a hardened one.
const L = (en, zh) => ({ en, zh });
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const b64urlText = (s) => b64url(enc.encode(s));
export function unb64url(s) {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  return dec.decode(Uint8Array.from(atob(pad), (c) => c.charCodeAt(0)));
}

/** HMAC-SHA256. An empty key is the same as a single zero byte (HMAC pads keys with zeros). */
export async function hs256(key, data) {
  const raw = key.length ? enc.encode(key) : new Uint8Array([0]);
  const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(data))));
}

/** Build a token. sig: { mode: 'sign', key } | { mode: 'keep', signature } | { mode: 'none' } */
export async function makeToken(headerJson, payloadJson, sig) {
  const input = `${b64urlText(headerJson)}.${b64urlText(payloadJson)}`;
  if (sig.mode === 'none') return `${input}.`;
  if (sig.mode === 'keep') return `${input}.${sig.signature}`;
  return `${input}.${await hs256(sig.key, input)}`;
}

export const SERVERS = {
  naive: { label: L('Naive server', '有漏洞的服务器'), key: 'secret1' },
  hardened: { label: L('Hardened server', '加固后的服务器'), key: 'q7$Vm2!pZ9w#Lx4@Rt8&Nf1^Hk6*Jd3%' },
};

export const WORDLIST = ['123456', 'password', 'admin', 'changeme', 'jwt', 'secret', 'letmein', 'qwerty', 'welcome', 'secret123', 'supersecret', 'secret1', 'monkey', 'dragon'];

const NOW = 1_800_000_000; // a fixed "now" so the demo never expires
export const ISSUED_HEADER = { alg: 'HS256', typ: 'JWT', kid: 'key-1' };
export const ISSUED_PAYLOAD = { sub: 'wiener', role: 'user', iat: NOW - 600, exp: NOW + 3000 };
export const pretty = (o) => JSON.stringify(o, null, 2);

/** The token the server handed to the attacker when they logged in as wiener. */
export const issuedToken = (server) => makeToken(JSON.stringify(ISSUED_HEADER), JSON.stringify(ISSUED_PAYLOAD), { mode: 'sign', key: SERVERS[server].key });

/** Where a naive server's kid lookup ends up: keys/<kid>, normalised. */
function readKeyFile(kid) {
  const parts = [];
  for (const seg of `/app/keys/${kid}`.split('/')) {
    if (seg === '..') parts.pop();
    else if (seg && seg !== '.') parts.push(seg);
  }
  const path = '/' + parts.join('/');
  if (path === '/app/keys/key-1') return { path, key: SERVERS.naive.key };
  if (path === '/dev/null') return { path, key: '' };
  return { path, key: null };
}

/** Verify a token step by step. Each step: { label, status: 'ok' | 'fail' | 'warn', detail }. */
export async function verify(token, server) {
  const steps = [];
  const done = (ok, extra = {}) => ({ steps, ok, ...extra });
  const parts = token.trim().split('.');
  let header, payload;
  try {
    if (parts.length !== 3) throw new Error();
    header = JSON.parse(unb64url(parts[0]));
    payload = JSON.parse(unb64url(parts[1]));
    steps.push({ label: L('Decode', '解码'), status: 'ok', detail: L(`alg=${header.alg} kid=${header.kid ?? '—'} sub=${payload.sub}`, `alg=${header.alg} kid=${header.kid ?? '—'} sub=${payload.sub}`) });
  } catch {
    steps.push({ label: L('Decode', '解码'), status: 'fail', detail: L('Not three base64url JSON parts', '不是三段 base64url 编码的 JSON') });
    return done(false);
  }
  const input = `${parts[0]}.${parts[1]}`;

  // 2. algorithm
  if (server === 'hardened') {
    if (header.alg !== 'HS256') {
      steps.push({ label: L('Algorithm', '算法'), status: 'fail', detail: L(`Server only accepts HS256, got "${header.alg}"`, `服务器只接受 HS256，收到的是 "${header.alg}"`) });
      return done(false);
    }
    steps.push({ label: L('Algorithm', '算法'), status: 'ok', detail: L('Fixed by the server: HS256 (header ignored)', '由服务器固定：HS256（忽略头部）') });
  } else if (String(header.alg).toLowerCase() === 'none') {
    steps.push({ label: L('Algorithm', '算法'), status: 'warn', detail: L('Header says "none", and the server believes it', '头部写着 "none"，服务器就信了') });
    steps.push({ label: L('Signature', '签名'), status: 'warn', detail: L('Skipped: "none" means nothing to check', '跳过："none" 表示不需要验证') });
    return authorise(steps, payload);
  } else {
    steps.push({ label: L('Algorithm', '算法'), status: 'ok', detail: L(`Taken from the header: ${header.alg}`, `取自头部：${header.alg}`) });
  }

  // 3. key
  let key;
  if (server === 'hardened') {
    key = SERVERS.hardened.key;
    steps.push({ label: L('Key', '密钥'), status: 'ok', detail: L('Fixed 256-bit server key (kid not used for file lookup)', '固定的 256 位服务器密钥（kid 不用于查找文件）') });
  } else {
    const f = readKeyFile(header.kid ?? 'key-1');
    if (f.key === null) {
      steps.push({ label: L('Key', '密钥'), status: 'fail', detail: L(`kid → ${f.path}: no such file`, `kid → ${f.path}：文件不存在`) });
      return done(false);
    }
    key = f.key;
    steps.push({ label: L('Key', '密钥'), status: f.path === '/dev/null' ? 'warn' : 'ok', detail: f.path === '/dev/null' ? L(`kid → ${f.path}: an empty key`, `kid → ${f.path}：空密钥`) : L(`kid → ${f.path}`, `kid → ${f.path}`) });
  }

  // 4. signature
  const expected = await hs256(key, input);
  if (expected !== parts[2]) {
    steps.push({ label: L('Signature', '签名'), status: 'fail', detail: L('HMAC does not match: the token was changed or signed with another key', 'HMAC 不匹配：令牌被改过，或用了别的密钥签名') });
    return done(false);
  }
  steps.push({ label: L('Signature', '签名'), status: key === '' ? 'warn' : 'ok', detail: L('HMAC-SHA256 matches', 'HMAC-SHA256 匹配') });
  return authorise(steps, payload);
}

function authorise(steps, payload) {
  if (!(payload.exp > NOW)) {
    steps.push({ label: L('Expiry', '过期'), status: 'fail', detail: L('exp is in the past', 'exp 已经过去') });
    return { steps, ok: false };
  }
  steps.push({ label: L('Expiry', '过期'), status: 'ok', detail: L('exp is in the future', 'exp 还没到') });
  const admin = payload.role === 'admin' || payload.sub === 'administrator';
  steps.push({ label: L('Access', '授权'), status: admin ? 'warn' : 'ok', detail: admin ? L(`Admin panel opened for ${payload.sub}`, `为 ${payload.sub} 打开了管理后台`) : L(`Logged in as ${payload.sub} (${payload.role ?? 'user'})`, `以 ${payload.sub}（${payload.role ?? 'user'}）身份登录`) });
  return { steps, ok: true, admin, user: payload.sub };
}

/** Try every word in the list as the HMAC key of a token. */
export async function crack(token) {
  const [h, p, s] = token.split('.');
  for (let i = 0; i < WORDLIST.length; i++) if ((await hs256(WORDLIST[i], `${h}.${p}`)) === s) return { found: WORDLIST[i], tried: i + 1 };
  return { found: null, tried: WORDLIST.length };
}
