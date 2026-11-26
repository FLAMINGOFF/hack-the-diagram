// Topic catalogue. Categories follow the PortSwigger Web Security Academy topic map;
// all explanations and labs on this site are original.
const L = (en, zh) => ({ en, zh });

export const CATEGORIES = [
  { id: 'server', title: L('Server-side', '服务器端'), tone: 'amber', blurb: L('Bugs in how the back end handles input, files, identity and other systems.', '后端在处理输入、文件、身份以及与其他系统交互时出现的问题。') },
  { id: 'client', title: L('Client-side', '客户端'), tone: 'red', blurb: L('Attacks that run in, or abuse, the victim’s browser.', '在受害者浏览器中执行、或滥用浏览器行为的攻击。') },
  { id: 'advanced', title: L('Advanced', '进阶'), tone: 'violet', blurb: L('Protocol, framework and AI-era attack surfaces.', '协议、框架以及 AI 时代的新攻击面。') },
  { id: 'foundations', title: L('Foundations', '基础'), tone: 'blue', blurb: L('The protocols everything else stands on.', '其他一切所依赖的底层协议。') },
];

const T = (id, category, short, title, tag, blurb, kind = 'lab') => ({ id, category, short, title, tag, blurb, kind });

export const TOPICS = [
  // server-side
  T('sqli', 'server', 'SQLi', L('SQL Injection', 'SQL 注入'), 'CWE-89', L('Attack a login form backed by a real SQLite database and watch your input turn from data into code.', '攻击一个由真实 SQLite 驱动的登录表单，看你的输入如何从数据变成代码。'), L('Real SQLite in your browser', '浏览器内真实 SQLite')),
  T('auth', 'server', 'Auth', L('Authentication', '身份认证漏洞'), 'CWE-287', L('Enumerate usernames from error messages, then see how generic errors and rate limits shut it down.', '通过错误信息枚举用户名，再看通用错误提示和限速如何堵上它。')),
  T('path-traversal', 'server', 'Path', L('Path Traversal', '路径遍历'), 'CWE-22', L('Climb out of the images folder with ../ and read files the server never meant to share.', '用 ../ 爬出图片目录，读取服务器本不打算公开的文件。')),
  T('cmdi', 'server', 'CMDi', L('OS Command Injection', '操作系统命令注入'), 'CWE-78', L('A ping tool that builds a shell command from your input. See how ; and $() become new commands.', '一个用你的输入拼 shell 命令的 ping 工具，看 ; 和 $() 如何变成新的命令。')),
  T('logic', 'server', 'Logic', L('Business Logic Flaws', '业务逻辑漏洞'), 'CWE-840', L('Buy things for negative money. The code works exactly as written, just not as intended.', '用负数价格买东西。代码完全按写的那样运行，只是不是设计者想要的那样。')),
  T('info-disclosure', 'server', 'Info', L('Information Disclosure', '信息泄露'), 'CWE-200', L('Stack traces, .git folders and backup files: probe a server for the clues it leaks.', '堆栈跟踪、.git 目录、备份文件：探测服务器泄露的线索。')),
  T('access-control', 'server', 'IDOR', L('Access Control & IDOR', '访问控制与 IDOR'), 'CWE-639', L('Change one number in the URL and read someone else’s invoice. Then add the missing ownership check.', '改 URL 里的一个数字就能看别人的账单，然后补上缺失的归属校验。')),
  T('file-upload', 'server', 'Upload', L('File Upload Vulnerabilities', '文件上传漏洞'), 'CWE-434', L('Upload an “avatar” that is really a web shell, and learn which checks actually stop it.', '上传一个其实是 Web Shell 的“头像”，弄清哪些校验真正有效。')),
  T('race', 'server', 'Race', L('Race Conditions', '竞态条件'), 'CWE-362', L('Fire a single-use coupon many times in parallel and watch every request win the race.', '并发多次使用一张单次优惠券，看每个请求都赢得竞态。')),
  T('ssrf', 'server', 'SSRF', L('Server-Side Request Forgery', '服务器端请求伪造'), 'CWE-918', L('Make the server fetch its own cloud metadata endpoint. Try IP tricks against a naive blocklist.', '让服务器去请求它自己的云元数据接口，用各种 IP 写法绕过简陋的黑名单。')),
  T('xxe', 'server', 'XXE', L('XXE Injection', 'XXE 注入'), 'CWE-611', L('Define an external entity in XML and have the parser paste /etc/passwd into the response.', '在 XML 里定义外部实体，让解析器把 /etc/passwd 贴进响应。')),
  T('nosqli', 'server', 'NoSQLi', L('NoSQL Injection', 'NoSQL 注入'), 'CWE-943', L('Send {"$ne": null} as a password and log in as admin on a MongoDB-style login.', '把 {"$ne": null} 当密码发出去，在 MongoDB 风格的登录里以 admin 登录。')),
  T('api', 'server', 'API', L('API Testing & Mass Assignment', 'API 测试与批量赋值'), 'CWE-915', L('Add "isAdmin": true to a profile update and see whether the API blindly binds it.', '在资料更新请求里加上 "isAdmin": true，看 API 会不会照单全收。')),
  T('cache-deception', 'server', 'WCD', L('Web Cache Deception', 'Web 缓存欺骗'), 'CWE-524', L('Trick a CDN into caching a victim’s private account page by making it look like a .css file.', '让私人账户页看起来像 .css 文件，骗 CDN 把它缓存起来。')),
  // client-side
  T('xss', 'client', 'XSS', L('Cross-Site Scripting', '跨站脚本攻击'), 'CWE-79', L('Post a payload to a vulnerable forum and watch it run in a sandboxed page. Fix it with encoding and CSP.', '向有漏洞的论坛发 payload，看它在沙箱页面里运行，再用编码和 CSP 修好。'), L('Live sandbox', '实时沙箱')),
  T('csrf', 'client', 'CSRF', L('Cross-Site Request Forgery', '跨站请求伪造'), 'CWE-352', L('Flip SameSite and CSRF tokens, replay the attack, and see which defence stops it and where.', '切换 SameSite 和 CSRF Token，重放攻击，看哪道防线在哪一步拦住它。'), L('Configurable simulator', '可配置模拟器')),
  T('cors', 'client', 'CORS', L('CORS Misconfiguration', 'CORS 配置错误'), 'CWE-942', L('An API that reflects any Origin with credentials. Test which origins can read a user’s data.', '一个带凭据、反射任意 Origin 的 API，测试哪些源能读到用户数据。')),
  T('clickjacking', 'client', 'Click', L('Clickjacking', '点击劫持'), 'CWE-1021', L('Drag the opacity slider to reveal the invisible bank page hiding under a “Claim prize” button.', '拖动透明度滑块，揭开藏在“领取奖品”按钮下的隐形银行页面。'), L('Visual overlay lab', '可视化叠层实验')),
  T('dom', 'client', 'DOM', L('DOM-based Vulnerabilities', '基于 DOM 的漏洞'), 'CWE-79', L('Follow a value from location.hash (source) to innerHTML (sink) without it ever touching the server.', '追踪一个值从 location.hash（源）流到 innerHTML（汇），全程不经过服务器。')),
  T('websockets', 'client', 'WS', L('WebSocket Hijacking', 'WebSocket 劫持'), 'CWE-1385', L('A WebSocket handshake that trusts cookies but not Origin lets any site read your chat history.', '只认 Cookie 不查 Origin 的 WebSocket 握手，任何网站都能读你的聊天记录。')),
  // advanced
  T('deserialization', 'advanced', 'Deser', L('Insecure Deserialization', '不安全的反序列化'), 'CWE-502', L('Edit a serialized PHP object in a cookie, flip admin from false to true, and become admin.', '修改 Cookie 里的 PHP 序列化对象，把 admin 从 false 改成 true。')),
  T('mcp', 'advanced', 'MCP', L('MCP Server Vulnerabilities', 'MCP 服务器漏洞'), 'CWE-1427', L('Tool poisoning, over-privileged tools and confused deputies in Model Context Protocol setups.', 'Model Context Protocol 中的工具投毒、权限过大的工具和混淆代理问题。'), 'steps'),
  T('llm', 'advanced', 'LLM', L('Web LLM Attacks', 'Web LLM 攻击'), 'OWASP LLM01', L('Hide instructions in a product review and make a shopping assistant call a dangerous tool.', '在商品评论里藏指令，让购物助手调用危险工具。')),
  T('graphql', 'advanced', 'GraphQL', L('GraphQL API Vulnerabilities', 'GraphQL API 漏洞'), 'CWE-200', L('Use introspection to map a hidden schema, then brute-force with aliases in a single request.', '用内省查出隐藏的 schema，再用别名在一个请求里暴力破解。')),
  T('ssti', 'advanced', 'SSTI', L('Server-Side Template Injection', '服务器端模板注入'), 'CWE-1336', L('Type {{7*7}} into a greeting and fingerprint the template engine all the way to RCE.', '在问候语里输入 {{7*7}}，一路识别模板引擎直到 RCE。')),
  T('cache-poisoning', 'advanced', 'Poison', L('Web Cache Poisoning', 'Web 缓存投毒'), 'CWE-444', L('An unkeyed X-Forwarded-Host header ends up in a cached page served to every visitor.', '一个不计入缓存键的 X-Forwarded-Host 头，最终出现在发给所有访问者的缓存页面里。')),
  T('host-header', 'advanced', 'Host', L('HTTP Host Header Attacks', 'HTTP Host 头攻击'), 'CWE-640', L('Poison a password-reset email so the victim’s reset token is sent to your domain.', '投毒密码重置邮件，让受害者的重置令牌发到你的域名。')),
  T('smuggling', 'advanced', 'Smuggle', L('HTTP Request Smuggling', 'HTTP 请求走私'), 'CWE-444', L('Front end trusts Content-Length, back end trusts chunked. See exactly where the requests split.', '前端认 Content-Length，后端认 chunked，看请求究竟在哪里被切开。')),
  T('oauth', 'advanced', 'OAuth', L('OAuth 2.0 Authentication', 'OAuth 2.0 认证'), 'CWE-601', L('Steal an authorization code through a loosely validated redirect_uri.', '通过校验不严的 redirect_uri 偷走授权码。')),
  T('jwt', 'advanced', 'JWT', L('JWT Attacks', 'JWT 攻击'), 'CWE-347', L('Edit a token’s header and payload. Try alg: none against a server that trusts the header.', '编辑令牌的头部和载荷，对信任头部的服务器尝试 alg: none。')),
  T('prototype-pollution', 'advanced', 'Proto', L('Prototype Pollution', '原型污染'), 'CWE-1321', L('A recursive merge plus "__proto__" turns every object in the app into an admin.', '一次递归合并加上 "__proto__"，让应用里每个对象都变成管理员。')),
  // foundations
  T('tls', 'foundations', 'TLS', L('TLS 1.3 Handshake', 'TLS 1.3 握手'), 'RFC 8446', L('Walk the handshake while an eavesdropper watches the wire. Turn on a MITM and see where the client catches it.', '逐步走完握手并观察窃听者能看到什么，打开中间人看客户端在哪一步识破它。'), L('Step-through + MITM mode', '逐步演示 + 中间人模式')),
];

export const topicById = (id) => TOPICS.find((t) => t.id === id);
export const categoryById = (id) => CATEGORIES.find((c) => c.id === id);
