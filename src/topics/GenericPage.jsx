import { lazy } from 'react';
import GenericTopic from '../components/GenericTopic.jsx';
import { SERVER } from './content/server.js';
import { CLIENT } from './content/client.jsx';
import { ADVANCED } from './content/advanced.js';

const DEFS = { ...SERVER, ...CLIENT, ...ADVANCED };
const L = (en, zh) => ({ en, zh });

// Hand-built interactive visuals for some topics, each in its own chunk.
const VISUALS = {
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
