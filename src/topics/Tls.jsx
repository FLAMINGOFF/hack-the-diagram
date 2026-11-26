import { useEffect, useMemo, useState } from 'react';
import { useLang } from '../i18n.jsx';
import DeepDive from '../components/DeepDive.jsx';
import SequenceDiagram from '../components/SequenceDiagram.jsx';
import { StepControls, useStepper } from '../components/Stepper.jsx';
import { Defenses, InterviewQs, Section, Seg, TopicShell } from '../components/TopicShell.jsx';

// Deterministic "ciphertext" so the eavesdropper view is stable between renders.
function noise(seed, len = 28) {
  let x = 0;
  for (const ch of seed) x = (x * 31 + ch.charCodeAt(0)) >>> 0;
  let out = '';
  for (let i = 0; i < len; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    out += (x >>> 16).toString(16).padStart(4, '0').slice(-2);
  }
  return out;
}

const NORMAL = [
  {
    from: 'c', to: 's',
    label: 'ClientHello',
    note: { en: 'The client proposes TLS 1.3, lists cipher suites, and, unlike TLS 1.2, already sends an ephemeral X25519 public key (key_share). It guesses the key exchange so the handshake can finish in one round trip.', zh: '客户端提出使用 TLS 1.3，列出支持的加密套件，并且（与 TLS 1.2 不同）直接发送一个临时 X25519 公钥（key_share）。它提前“猜”好密钥交换方式，握手只需一个往返。' },
    wire: [
      ['supported_versions', 'TLS 1.3'],
      ['cipher_suites', 'TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256'],
      ['key_share', 'X25519 pub = 9f3c…a1'],
      ['server_name (SNI)', 'example.com'],
    ],
  },
  {
    from: 's', to: 'c',
    label: 'ServerHello',
    note: { en: 'The server picks a cipher suite and replies with its own ephemeral public key. Neither private key ever crosses the wire.', zh: '服务器选定加密套件，并回复它自己的临时公钥。双方的私钥都从未在网络上出现。' },
    wire: [
      ['cipher_suite', 'TLS_AES_128_GCM_SHA256'],
      ['key_share', 'X25519 pub = 4be0…7d'],
    ],
  },
  {
    from: '*', to: '*', kind: 'secure',
    label: { en: 'Both sides: ECDHE → handshake keys', zh: '双方：ECDHE → 握手密钥' },
    note: { en: 'Each side combines its own private key with the other side’s public key and arrives at the same shared secret. HKDF stretches it into handshake keys. An eavesdropper who saw both public keys still cannot compute it. Everything from here on is encrypted.', zh: '双方各自用自己的私钥和对方的公钥计算，得到相同的共享秘密，再通过 HKDF 派生出握手密钥。窃听者即使看到了两个公钥也算不出它。从这里开始的所有内容都是加密的。' },
  },
  {
    from: 's', to: 'c', lock: true,
    label: 'EncryptedExtensions',
    note: { en: 'Extra parameters such as ALPN (h2 or http/1.1). In TLS 1.2 these were sent in the clear.', zh: '额外参数，比如 ALPN（h2 或 http/1.1）。在 TLS 1.2 中这些是明文发送的。' },
    wire: [['ALPN', 'h2']],
  },
  {
    from: 's', to: 'c', lock: true,
    label: 'Certificate',
    note: { en: 'The server’s X.509 certificate chain: “this public key belongs to example.com”, signed by a CA. In TLS 1.3 it is encrypted, so observers can’t see which certificate was used.', zh: '服务器的 X.509 证书链：“这个公钥属于 example.com”，由 CA 签名。在 TLS 1.3 中它是加密的，旁观者看不到用的是哪张证书。' },
    wire: [['certificate', 'CN=example.com, issuer=Let’s Encrypt R11']],
  },
  {
    from: 's', to: 'c', lock: true,
    label: 'CertificateVerify',
    note: { en: 'The server signs a hash of the whole handshake so far with the certificate’s private key. This proves it owns the certificate and that nobody tampered with the earlier messages.', zh: '服务器用证书私钥对目前为止整个握手记录的哈希签名。这证明它确实拥有该证书，并且前面的消息没有被篡改。' },
    wire: [['signature', 'ECDSA-P256(transcript hash)']],
  },
  {
    from: 's', to: 'c', lock: true,
    label: 'Finished',
    note: { en: 'A MAC over the transcript using a key derived from the handshake secret. Confirms both sides saw the same handshake.', zh: '用握手秘密派生出的密钥对握手记录计算 MAC，确认双方看到的是同一份握手。' },
    wire: [['verify_data', 'HMAC(transcript)']],
  },
  {
    from: 'c', to: 'c', kind: 'secure',
    label: { en: 'Verify chain, hostname, signature', zh: '校验证书链、域名、签名' },
    note: { en: 'The client checks: the chain leads to a trusted root CA, the certificate is valid for example.com and not expired, and CertificateVerify is a valid signature. Any failure aborts the connection.', zh: '客户端检查：证书链能追溯到受信任的根 CA；证书对 example.com 有效且未过期；CertificateVerify 签名正确。任何一项失败都会中断连接。' },
  },
  {
    from: 'c', to: 's', lock: true,
    label: 'Finished',
    note: { en: 'The client sends its own Finished. The handshake took one round trip; the client could already send application data alongside this message.', zh: '客户端发送自己的 Finished。整个握手只用了一个往返，客户端甚至可以和这条消息一起发送应用数据。' },
    wire: [['verify_data', 'HMAC(transcript)']],
  },
  {
    from: 'c', to: 's', lock: true, kind: 'secure',
    label: 'HTTP GET /account',
    note: { en: 'Application data, encrypted with traffic keys derived from the same secret. Because the key exchange was ephemeral, recording this today and stealing the server’s certificate key tomorrow still won’t decrypt it (forward secrecy).', zh: '应用数据，使用从同一秘密派生出的流量密钥加密。由于密钥交换是临时的，即使今天录下流量、明天偷到服务器证书私钥，也解不开它（前向保密）。' },
    wire: [['http', 'GET /account  Cookie: session=7f3a…']],
  },
];

const MITM = [
  { ...NORMAL[0], to: 'm', note: { en: 'Mallory controls the café Wi-Fi and intercepts the ClientHello. She will try to pose as example.com.', zh: 'Mallory 控制了咖啡馆的 Wi-Fi，截获了 ClientHello。她打算冒充 example.com。' } },
  { ...NORMAL[1], from: 'm', kind: 'attack', label: { en: 'ServerHello (Mallory’s key)', zh: 'ServerHello（Mallory 的密钥）' }, note: { en: 'Mallory answers with her own key share. Key exchange alone proves nothing about who is on the other end.', zh: 'Mallory 用她自己的 key_share 回复。光靠密钥交换，无法证明对面到底是谁。' } },
  { from: 'c', to: 'c', kind: 'attack', label: { en: 'ECDHE → keys shared with Mallory', zh: 'ECDHE → 与 Mallory 共享密钥' }, note: { en: 'The client now shares a secret with Mallory, not with example.com. Encryption is working perfectly, just with the wrong party. Only authentication can catch this.', zh: '客户端现在和 Mallory 共享了一个秘密，而不是 example.com。加密完全正常，只是对象错了。只有身份认证能发现这一点。' } },
  { ...NORMAL[3], from: 'm' },
  { ...NORMAL[4], from: 'm', kind: 'attack', label: { en: 'Certificate (forged)', zh: 'Certificate（伪造）' }, note: { en: 'Mallory sends a certificate for example.com that she generated herself. She does not have a CA’s signature, and she does not have the real server’s private key.', zh: 'Mallory 发送了一张她自己生成的 example.com 证书。她没有 CA 的签名，也没有真正服务器的私钥。' }, wire: [['certificate', 'CN=example.com, issuer=Mallory Self-Signed']] },
  { ...NORMAL[5], from: 'm', kind: 'attack', note: { en: 'She can sign the transcript, but only with her own key, which matches her own fake certificate.', zh: '她可以对握手记录签名，但只能用她自己的私钥，对应的也只是她那张假证书。' } },
  { ...NORMAL[6], from: 'm' },
  { from: 'c', to: 'c', kind: 'blocked', label: { en: '✕ Untrusted issuer → abort', zh: '✕ 签发者不受信任 → 中止' }, note: { en: 'The chain does not lead to any trusted root CA. The browser stops and shows a full-page certificate warning. The cookie is never sent. This is why clicking through certificate warnings is dangerous.', zh: '证书链无法追溯到任何受信任的根 CA。浏览器中止连接，并显示整页证书警告，Cookie 根本不会被发送。这就是为什么点“继续访问”很危险。' } },
  { from: 'c', to: 'm', kind: 'blocked', label: 'Alert: bad_certificate', note: { en: 'The client sends a fatal alert and closes the connection. Mallory learned nothing beyond the SNI.', zh: '客户端发送致命警报并关闭连接。除了 SNI，Mallory 什么也没得到。' } },
];

export default function Tls() {
  const { tr } = useLang();
  const [mode, setMode] = useState('normal');
  const messages = mode === 'normal' ? NORMAL : MITM;
  const stepper = useStepper(messages.length, 2400);
  const { restart } = stepper;
  const [booted, setBooted] = useState(false);
  useEffect(() => {
    if (booted) restart();
    else setBooted(true);
  }, [mode]); // eslint-disable-line react-hooks/exhaustive-deps

  const actors = useMemo(
    () => [
      { id: 'c', label: { en: 'Client', zh: '客户端' }, sub: { en: 'browser', zh: '浏览器' }, tone: 'green' },
      mode === 'normal'
        ? { id: 'm', label: { en: 'Eavesdropper', zh: '窃听者' }, sub: { en: 'café Wi-Fi', zh: '咖啡馆 Wi-Fi' }, tone: 'neutral' }
        : { id: 'm', label: 'Mallory', sub: { en: 'active MITM', zh: '主动中间人' }, tone: 'red' },
      { id: 's', label: { en: 'Server', zh: '服务器' }, sub: 'example.com', tone: 'blue' },
    ],
    [mode],
  );

  const step = stepper.step;
  const encryptedFrom = 3; // index of first encrypted message in both flows
  const wireLog = messages
    .slice(0, step + 1)
    .map((m, i) => ({ m, i }))
    .filter(({ m }) => m.wire);
  const sharedKnown = step >= 2;
  const verified = mode === 'normal' ? step >= 7 : false;
  const failed = mode === 'mitm' && step >= 7;

  return (
    <TopicShell
      id="tls"
      tldr={{
        en: 'TLS lets two parties who have never met agree on secret keys over a network an attacker can watch, and proves the server is who it claims to be. TLS 1.3 does it in a single round trip.',
        zh: 'TLS 让素未谋面的双方在一个可能被监听的网络上协商出秘密密钥，并证明服务器就是它声称的那个身份。TLS 1.3 只需一个往返就能完成。',
      }}
    >
      <Section kicker={{ en: 'Lab', zh: '实验' }} title={{ en: 'Walk the handshake', zh: '逐步走完握手' }}>
        <Seg
          label={{ en: 'Network', zh: '网络环境' }}
          value={mode}
          onChange={setMode}
          options={[
            { value: 'normal', label: { en: 'Passive eavesdropper', zh: '被动窃听' } },
            { value: 'mitm', label: { en: 'Active man-in-the-middle', zh: '主动中间人攻击' } },
          ]}
        />
        <SequenceDiagram actors={actors} messages={messages} step={step} onSelect={stepper.go} title={{ en: 'TLS 1.3 handshake', zh: 'TLS 1.3 握手' }} />
        <StepControls stepper={stepper} messages={messages} />

        <div className="lab tls-panels">
          <div className="panel">
            <div className="field-label">{tr({ en: 'Key material', zh: '密钥材料' })}</div>
            <div className="keys">
              <KeyBox who={{ en: 'Client', zh: '客户端' }} rows={[
                [{ en: 'ephemeral private key', zh: '临时私钥' }, 'a = ••••••', 'secret'],
                [{ en: 'ephemeral public key', zh: '临时公钥' }, 'A = a·G = 9f3c…a1', step >= 0 ? 'public' : 'hidden'],
                [{ en: 'shared secret', zh: '共享秘密' }, mode === 'normal' ? 'a·B = 3e91…0c' : 'a·M = 77d2…e5', sharedKnown ? (mode === 'normal' ? 'derived' : 'bad') : 'hidden'],
                [{ en: 'server identity', zh: '服务器身份' }, failed ? tr({ en: 'REJECTED', zh: '已拒绝' }) : verified ? tr({ en: 'verified ✓', zh: '已验证 ✓' }) : tr({ en: 'unknown', zh: '未知' }), failed ? 'bad' : verified ? 'derived' : 'hidden'],
              ]} tr={tr} />
              <KeyBox who={mode === 'normal' ? { en: 'Server', zh: '服务器' } : 'Mallory'} rows={[
                [{ en: 'ephemeral private key', zh: '临时私钥' }, mode === 'normal' ? 'b = ••••••' : 'm = ••••••', 'secret'],
                [{ en: 'ephemeral public key', zh: '临时公钥' }, mode === 'normal' ? 'B = b·G = 4be0…7d' : 'M = m·G = c81a…02', step >= 1 ? 'public' : 'hidden'],
                [{ en: 'shared secret', zh: '共享秘密' }, mode === 'normal' ? 'b·A = 3e91…0c' : 'm·A = 77d2…e5', sharedKnown ? (mode === 'normal' ? 'derived' : 'bad') : 'hidden'],
                [{ en: 'certificate key', zh: '证书私钥' }, mode === 'normal' ? 'example.com (CA-signed)' : tr({ en: 'self-signed, not trusted', zh: '自签名，不受信任' }), mode === 'normal' ? 'secret' : 'bad'],
              ]} tr={tr} />
            </div>
            <p className="tiny muted">
              {tr({
                en: 'a·B = b·A: elliptic-curve Diffie–Hellman gives both sides the same value without ever sending it.',
                zh: 'a·B = b·A：椭圆曲线 Diffie–Hellman 让双方得到同一个值，而这个值从未被传输。',
              })}
            </p>
          </div>
          <div className="panel">
            <div className="field-label">
              {mode === 'normal' ? tr({ en: 'What the eavesdropper sees on the wire', zh: '窃听者在线路上看到的内容' }) : tr({ en: 'What Mallory sees', zh: 'Mallory 看到的内容' })}
            </div>
            <div className="wire">
              {wireLog.length === 0 && <div className="muted">…</div>}
              {wireLog.map(({ m, i }) => (
                <div key={i} className="wire-msg">
                  <div className="wire-title">
                    <span className="pill">{i + 1}</span> {tr(m.label)} {i >= encryptedFrom && mode === 'normal' ? '🔒' : ''}
                  </div>
                  {m.wire.map(([k, v]) => {
                    const hidden = i >= encryptedFrom && mode === 'normal';
                    return (
                      <div key={k} className="wire-row">
                        <span className="wire-k">{k}</span>
                        <span className={`wire-v ${hidden ? 'enc' : k.includes('SNI') ? 'leak' : ''}`}>{hidden ? noise(k + v) : v}</span>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
            <p className="tiny muted">
              {mode === 'normal'
                ? tr({ en: 'Highlighted: SNI is still visible in TLS 1.3. Encrypted Client Hello (ECH) is the fix being rolled out.', zh: '高亮部分：在 TLS 1.3 中 SNI 依然可见，正在推广的加密 ClientHello（ECH）用来解决这个问题。' })
                : tr({ en: 'Mallory terminates TLS herself, so she can read what she receives, but the client aborts before sending anything sensitive.', zh: 'Mallory 自己终结了 TLS，所以她能读到收到的内容，但客户端在发送任何敏感数据前就中止了。' })}
            </p>
          </div>
        </div>
      </Section>

      <Section kicker={{ en: 'Compare', zh: '对比' }} title={{ en: 'TLS 1.2 vs TLS 1.3', zh: 'TLS 1.2 与 TLS 1.3' }}>
        <div className="table-wrap">
          <table className="compare">
            <thead>
              <tr>
                <th />
                <th>TLS 1.2</th>
                <th>TLS 1.3</th>
              </tr>
            </thead>
            <tbody>
              {[
                [{ en: 'Round trips before data', zh: '发送数据前的往返次数' }, '2-RTT', { en: '1-RTT (0-RTT on resumption)', zh: '1-RTT（会话恢复可 0-RTT）' }],
                [{ en: 'Key exchange', zh: '密钥交换' }, { en: 'RSA or (EC)DHE', zh: 'RSA 或 (EC)DHE' }, { en: '(EC)DHE only', zh: '只允许 (EC)DHE' }],
                [{ en: 'Forward secrecy', zh: '前向保密' }, { en: 'Optional', zh: '可选' }, { en: 'Always', zh: '始终具备' }],
                [{ en: 'Certificate on the wire', zh: '证书是否加密' }, { en: 'Plaintext', zh: '明文' }, { en: 'Encrypted', zh: '加密' }],
                [{ en: 'Cipher suites', zh: '加密套件' }, { en: '300+ incl. CBC, RC4, export', zh: '300+，含 CBC、RC4、出口级' }, { en: '5, all AEAD', zh: '5 个，全部是 AEAD' }],
              ].map(([k, a, b], i) => (
                <tr key={i}>
                  <th>{tr(k)}</th>
                  <td>{tr(a)}</td>
                  <td className="good-text">{tr(b)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <DeepDive id="tls" />

      <Section kicker={{ en: 'Defend', zh: '防御' }} title={{ en: 'Getting TLS right', zh: '正确使用 TLS' }}>
        <Defenses
          items={[
            { title: { en: 'Validate certificates, always', zh: '永远校验证书' }, body: { en: 'verify=False, InsecureSkipVerify or a trust-all TrustManager silently turns TLS into an open door for exactly the attack above.', zh: 'verify=False、InsecureSkipVerify 或“信任所有”的 TrustManager，会悄悄让 TLS 对上面这种攻击完全敞开。' } },
            { title: { en: 'HSTS', zh: 'HSTS' }, body: { en: 'Strict-Transport-Security tells browsers to never use plain HTTP for your domain, which stops SSL-stripping downgrades.', zh: 'Strict-Transport-Security 告诉浏览器永远不要用明文 HTTP 访问你的域名，从而防止 SSL 剥离降级攻击。' } },
            { title: { en: 'Disable old versions', zh: '禁用旧版本' }, body: { en: 'Turn off SSLv3, TLS 1.0 and 1.1; prefer TLS 1.3 and AEAD suites in TLS 1.2.', zh: '关闭 SSLv3、TLS 1.0 和 1.1；优先 TLS 1.3，TLS 1.2 中优先 AEAD 套件。' } },
            { title: { en: 'Protect and rotate keys', zh: '保护并轮换私钥' }, body: { en: 'Short-lived certificates (e.g. ACME/Let’s Encrypt) limit the damage of a leaked key.', zh: '短期证书（比如 ACME/Let’s Encrypt）能减小私钥泄露造成的损失。' } },
          ]}
        />
      </Section>

      <Section kicker={{ en: 'Interview prep', zh: '面试准备' }} title={{ en: 'Questions you might get', zh: '可能被问到的问题' }}>
        <InterviewQs
          items={[
            { q: { en: 'What does “forward secrecy” mean?', zh: '什么是“前向保密”？' }, a: { en: 'Session keys come from ephemeral Diffie–Hellman keys that are thrown away. Stealing the server’s long-term certificate key later does not decrypt recorded traffic.', zh: '会话密钥来自用完即弃的临时 Diffie–Hellman 密钥。之后即使偷到服务器的长期证书私钥，也解不开之前录下的流量。' } },
            { q: { en: 'If the key exchange is secure, why do we need certificates?', zh: '既然密钥交换是安全的，为什么还需要证书？' }, a: { en: 'Diffie–Hellman only guarantees a shared secret with whoever answered. Without authentication, a MITM runs two separate handshakes. The certificate plus CertificateVerify proves the other end holds example.com’s key.', zh: 'Diffie–Hellman 只保证你和“回应你的那一方”共享了秘密。没有认证，中间人就能分别和两边各握手一次。证书加 CertificateVerify 证明对方持有 example.com 的私钥。' } },
            { q: { en: 'What is the risk of 0-RTT?', zh: '0-RTT 有什么风险？' }, a: { en: 'Early data can be replayed by an attacker, so servers should only accept idempotent requests in 0-RTT.', zh: '早期数据可能被攻击者重放，所以服务器在 0-RTT 中只应接受幂等请求。' } },
          ]}
        />
      </Section>
    </TopicShell>
  );
}

function KeyBox({ who, rows, tr }) {
  return (
    <div className="keybox">
      <div className="keybox-who">{tr(who)}</div>
      {rows.map(([k, v, state], i) => (
        <div key={i} className={`key-row ${state}`}>
          <span>{tr(k)}</span>
          <b className="mono">{state === 'hidden' ? '—' : v}</b>
        </div>
      ))}
    </div>
  );
}
