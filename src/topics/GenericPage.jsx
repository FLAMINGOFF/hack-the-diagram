import { lazy } from 'react';
import GenericTopic from '../components/GenericTopic.jsx';
import { SERVER } from './content/server.js';
import { CLIENT } from './content/client.jsx';
import { ADVANCED } from './content/advanced.js';

const DEFS = { ...SERVER, ...CLIENT, ...ADVANCED };
const L = (en, zh) => ({ en, zh });

// Hand-built interactive visuals for some topics, each in its own chunk.
const VISUALS = {
  xxe: {
    title: L('Watch the parser fetch it', '看解析器替你去取'),
    intro: L('An XML parser that honours DOCTYPEs will read files and make requests on your behalf. Step through what it does with each payload, then change how the parser is configured.', '支持 DOCTYPE 的 XML 解析器会替你读取文件、发出请求。逐步查看它如何处理每种载荷，再修改解析器的配置。'),
    Component: lazy(() => import('../visuals/XxeParse.jsx')),
  },
  nosqli: {
    title: L('Turn "equals" into "anything but"', '把“等于”变成“只要不等于”'),
    intro: L('The login sends your JSON straight into the query. Watch each stored user being compared, and see what one operator in place of a string does.', '登录功能把你的 JSON 直接放进查询。看每个已存储的用户如何被比较，以及把字符串换成一个操作符会发生什么。'),
    Component: lazy(() => import('../visuals/NosqlMatch.jsx')),
  },
  api: {
    title: L('Send one field too many', '多发一个字段'),
    intro: L('The settings form sends only your email, but the API accepts any JSON. See which keys end up on the database record.', '设置表单只会发送你的邮箱，但 API 接受任何 JSON。看看哪些键最终落到了数据库记录上。'),
    Component: lazy(() => import('../visuals/MassAssign.jsx')),
  },
  logic: {
    title: L('Check out for almost nothing', '几乎不花钱就结账'),
    intro: L('Every request below is well formed. The bugs are in what the checkout assumes: that quantities are positive, prices come from the server, and coupons are used once.', '下面每个请求格式都完全正确。漏洞出在结账流程的假设上：数量一定是正数，价格来自服务器，优惠券只能用一次。'),
    Component: lazy(() => import('../visuals/LogicCart.jsx')),
  },
  'info-disclosure': {
    title: L('Six requests anyone can make', '六个人人都能发的请求'),
    intro: L('Reconnaissance is mostly asking politely. Run the same six probes against a site with debug settings left on, then against a production setup.', '侦察大多只是礼貌地问一问。用同样六个探测分别去试调试配置没关的网站和生产环境配置的网站。'),
    Component: lazy(() => import('../visuals/InfoLeak.jsx')),
  },
  'cache-deception': {
    title: L('Two readers, one URL', '同一个 URL，两种读法'),
    intro: L('The cache decides by the end of the URL; the origin decides by its routes. Step through what happens when they disagree, then change either one.', '缓存看 URL 的结尾做决定，源站按自己的路由做决定。逐步查看两者意见不一时会发生什么，再修改其中任意一方。'),
    Component: lazy(() => import('../visuals/CacheDeceive.jsx')),
  },
  'path-traversal': {
    title: L('Walk the folder tree', '沿着目录树往上走'),
    intro: L('The server glues your filename onto its images folder. Watch each "../" climb one folder up, then switch on each check and see which bypass beats it.', '服务器把你给的文件名拼在图片文件夹后面。看每个 "../" 如何往上爬一层目录，再依次打开各种检查，看哪种绕过能打败它。'),
    Component: lazy(() => import('../visuals/PathTree.jsx')),
  },
  cmdi: {
    title: L('One string, several commands', '一个字符串，好几条命令'),
    intro: L('The server wants to ping a host you type. See how the shell splits your input into separate commands, and why passing arguments without a shell ends the problem.', '服务器想 ping 你输入的主机。看 shell 如何把你的输入拆成几条独立的命令，以及为什么不经过 shell 直接传参数就能根治这个问题。'),
    Component: lazy(() => import('../visuals/ShellParse.jsx')),
  },
  'access-control': {
    title: L('Change the number in the URL', '改一下 URL 里的数字'),
    intro: L('An insecure direct object reference in one picture: the server knows who Alice is but never asks whether the invoice belongs to her.', '一张图看懂不安全的直接对象引用：服务器知道 Alice 是谁，却从不问这张发票是不是她的。'),
    Component: lazy(() => import('../visuals/IdorGrid.jsx')),
  },
  auth: {
    title: L('Find the real username, then the password', '先找出真实用户名，再猜密码'),
    intro: L('Every attempt below uses a wrong password. Small differences in the reply, even a few milliseconds, tell the attacker which accounts exist. Then see what a lockout changes.', '下面每次尝试用的都是错误密码。响应里的细微差别，哪怕只差几毫秒，都会告诉攻击者哪些账号存在。然后看看账号锁定能改变什么。'),
    Component: lazy(() => import('../visuals/AuthTiming.jsx')),
  },
  race: {
    title: L('Squeeze requests into the gap', '把请求塞进那道缝隙'),
    intro: L('Redeeming a coupon is two steps: check that it is unused, then mark it used. Each lane is one request. Anything that checks inside the shaded window wins.', '兑换优惠券分两步：先检查它没被用过，再标记为已使用。每条轨道是一个请求，凡是在阴影窗口内完成检查的请求都能成功。'),
    Component: lazy(() => import('../visuals/RaceLanes.jsx')),
  },
  'file-upload': {
    title: L('Get a web shell past the checks', '让 Web Shell 混过检查'),
    intro: L('Pick a file and the checks the server makes. Each check looks at one thing the attacker controls; see which combination finally keeps PHP from running.', '选一个文件和服务器要做的检查。每项检查都只看攻击者能控制的某一个方面；看看哪种组合最终能让 PHP 跑不起来。'),
    Component: lazy(() => import('../visuals/UploadGates.jsx')),
  },
  clickjacking: {
    title: L('Pull the page apart', '把页面拆开看'),
    intro: L('A clickjacking page is two pages stacked on top of each other. Separate the layers to see which one actually receives the click.', '点击劫持页面其实是两个叠在一起的页面。把图层拆开，看看真正接收点击的是哪一层。'),
    Component: lazy(() => import('../visuals/ClickLayers.jsx')),
  },
  oauth: {
    title: L('Break the login flow, then fix it', '先攻破登录流程，再修好它'),
    intro: L('The diagram is rebuilt as you change it. Pick an attack, switch defences on and off, and step through to see exactly which message each defence stops.', '图会随着你的选择实时重建。选一种攻击，打开或关闭各项防御，然后逐步查看，看每项防御具体挡住了哪一条消息。'),
    Component: lazy(() => import('../visuals/OAuthFlow.jsx')),
  },
  cors: {
    title: L('Who is allowed to read the answer?', '谁能读到响应？'),
    intro: L('A script on another site asks the bank\'s API for Alice\'s data, with her cookie. The request always reaches the server; CORS only decides whether the browser hands the answer to the script. Pick a server policy and an origin.', '另一个网站上的脚本带着 Alice 的 Cookie，向银行 API 请求她的数据。请求一定会到达服务器；CORS 只决定浏览器是否把响应交给这个脚本。选一种服务器策略和一个来源试试。'),
    Component: lazy(() => import('../visuals/CorsGate.jsx')),
  },
  ssrf: {
    title: L('Follow the request past the firewall', '跟着请求穿过防火墙'),
    intro: L('You cannot reach the internal network, but the shop\'s stock checker can. Give it a URL and watch where the server goes for you. Then switch on each check and try the bypasses.', '你连不上内网，但商城的库存查询功能可以。给它一个 URL，看服务器替你去了哪里。然后依次打开每种检查，再试试各种绕过。'),
    Component: lazy(() => import('../visuals/SsrfMap.jsx')),
  },
  jwt: {
    title: L('Forge a token, watch the server check it', '伪造令牌，看服务器怎么验证'),
    intro: L('This is a real JWT, encoded and HMAC-signed in your browser. Edit it, choose how to sign it, and see every check the server makes. The naive server trusts the header; the hardened one does not.', '这是一个真实的 JWT，在你的浏览器里编码并用 HMAC 签名。修改它，选择签名方式，看服务器做的每一项检查。有漏洞的服务器相信头部的内容，加固后的服务器不信。'),
    Component: lazy(() => import('../visuals/JwtInspector.jsx')),
  },
  smuggling: {
    title: L('Where does the request end?', '请求到底在哪里结束？'),
    intro: L('Step through the bytes. The front end and back end each pick a rule for where a request ends; when they pick different rules, the leftover bytes become the start of the next user\'s request.', '逐步查看每个字节。前端和后端各自用一种规则判断请求在哪里结束；两边规则不同时，剩下的字节就会变成下一个用户请求的开头。'),
    Component: lazy(() => import('../visuals/SmuggleStream.jsx')),
  },
};

/** All data-driven topic pages, in one chunk that loads only when a topic is opened. */
export default function GenericPage({ id }) {
  if (!DEFS[id]) return null;
  return <GenericTopic key={id} def={{ id, ...DEFS[id] }} Visual={VISUALS[id]} />;
}
