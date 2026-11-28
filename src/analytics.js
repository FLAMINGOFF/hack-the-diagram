// Privacy-friendly page counts with GoatCounter: no cookies, no personal data, no fingerprinting.
// Off until a site code is set. To turn it on, create a free site at https://www.goatcounter.com
// and put its code here (the part before .goatcounter.com).
export const GOATCOUNTER_CODE = '';

let ready = false;
const queue = [];

function send(path) {
  if (window.goatcounter?.count) window.goatcounter.count({ path, title: document.title });
  else queue.push(path);
}

/** Load the counter once. It never runs on localhost or in previews. */
export function initAnalytics() {
  if (!GOATCOUNTER_CODE || ready || typeof document === 'undefined') return;
  if (/^(localhost|127\.|\[::1\])/.test(window.location.hostname)) return;
  ready = true;
  window.goatcounter = { no_onload: true };
  const s = document.createElement('script');
  s.async = true;
  s.src = 'https://gc.zgo.at/count.js';
  s.dataset.goatcounter = `https://${GOATCOUNTER_CODE}.goatcounter.com/count`;
  s.onload = () => queue.splice(0).forEach(send);
  document.head.appendChild(s);
}

/** Count a page view. Hash routes (#/xss) are counted as /xss. */
export function trackPage(route) {
  if (!ready) return;
  send(route === '/' ? '/' : route);
}
