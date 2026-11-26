export const TOPICS = [
  {
    id: 'xss',
    short: 'XSS',
    title: { en: 'Cross-Site Scripting', zh: '跨站脚本攻击' },
    owasp: 'OWASP A03:2021 · Injection',
    tone: 'red',
    kind: { en: 'Live sandbox', zh: '实时沙箱' },
    blurb: {
      en: 'Post a comment to a vulnerable forum and watch your payload run inside a real (sandboxed) browser page. Then fix it with escaping and CSP.',
      zh: '在一个有漏洞的论坛里发评论，看你的 payload 在真实（沙箱隔离的）页面里执行，再用转义和 CSP 把它修好。',
    },
  },
  {
    id: 'sqli',
    short: 'SQLi',
    title: { en: 'SQL Injection', zh: 'SQL 注入' },
    owasp: 'OWASP A03:2021 · Injection',
    tone: 'amber',
    kind: { en: 'Real SQLite in your browser', zh: '浏览器内真实 SQLite' },
    blurb: {
      en: 'Attack a login form backed by a real SQLite database. Every character you type is coloured by whether the database reads it as data or as code.',
      zh: '攻击一个由真实 SQLite 数据库驱动的登录表单。你输入的每个字符都会按“被当成数据还是代码”着色。',
    },
  },
  {
    id: 'csrf',
    short: 'CSRF',
    title: { en: 'Cross-Site Request Forgery', zh: '跨站请求伪造' },
    owasp: 'OWASP A01:2021 · Broken Access Control',
    tone: 'violet',
    kind: { en: 'Configurable simulator', zh: '可配置模拟器' },
    blurb: {
      en: 'Flip SameSite, CSRF tokens and the attack technique, then replay the attack to see exactly which defence stops it, and where.',
      zh: '切换 SameSite、CSRF Token 和攻击方式，重放攻击，看清是哪一道防线、在哪一步拦住了它。',
    },
  },
  {
    id: 'tls',
    short: 'TLS',
    title: { en: 'TLS 1.3 Handshake', zh: 'TLS 1.3 握手' },
    owasp: 'OWASP A02:2021 · Cryptographic Failures',
    tone: 'blue',
    kind: { en: 'Step-through + MITM mode', zh: '逐步演示 + 中间人模式' },
    blurb: {
      en: 'Walk the handshake message by message while an eavesdropper watches the wire. Switch on a man-in-the-middle and see where the client catches it.',
      zh: '逐条消息走完握手，同时看窃听者在线路上能看到什么。打开中间人攻击，看客户端在哪一步识破它。',
    },
  },
];

export const topicById = (id) => TOPICS.find((t) => t.id === id);
