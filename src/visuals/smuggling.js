// HTTP/1.1 request smuggling, byte by byte. Requests are typed with \n and sent as \r\n.
// Each server decides where a request ends using either Content-Length or chunked encoding.
const L = (en, zh) => ({ en, zh });
const CRLF = '\r\n';

export const toWire = (text) => text.replace(/\r?\n/g, CRLF);

export const VICTIM = `GET /my-account HTTP/1.1${CRLF}Host: shop.example${CRLF}Cookie: session=victim-8f3a${CRLF}${CRLF}`;

/** Find where the header block ends. Returns the index of the first body byte, or -1. */
function headerEnd(wire) {
  const i = wire.indexOf(CRLF + CRLF);
  return i < 0 ? -1 : i + 4;
}

export function headers(wire) {
  const end = headerEnd(wire);
  const lines = wire.slice(0, end < 0 ? wire.length : end - 4).split(CRLF);
  const out = [];
  for (const line of lines.slice(1)) {
    const m = /^([^:]+):\s*(.*)$/.exec(line);
    if (m) out.push([m[1], m[2]]);
  }
  return { start: lines[0] ?? '', list: out, bodyAt: end };
}

const get = (h, name) => h.list.find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

/**
 * How many bytes this server treats as the first request.
 * mode: 'CL' (Content-Length) or 'TE' (chunked). Returns { end, note, error }.
 */
export function boundary(wire, mode) {
  const h = headers(wire);
  if (h.bodyAt < 0) return { end: wire.length, error: L('Headers never end (missing blank line)', '请求头没有结束（缺少空行）') };
  const te = get(h, 'Transfer-Encoding');
  const cl = get(h, 'Content-Length');
  if (mode === 'TE' && te && te.trim().toLowerCase() === 'chunked') {
    let i = h.bodyAt;
    for (let guard = 0; guard < 100; guard++) {
      const nl = wire.indexOf(CRLF, i);
      if (nl < 0) return { end: wire.length, error: L('Chunk size line not terminated', '分块大小行没有结束') };
      const size = parseInt(wire.slice(i, nl).trim(), 16);
      if (Number.isNaN(size)) return { end: wire.length, error: L(`Bad chunk size "${wire.slice(i, nl)}"`, `分块大小 "${wire.slice(i, nl)}" 不合法`) };
      i = nl + 2;
      if (size === 0) {
        const end = wire.indexOf(CRLF, i) === i ? i + 2 : i;
        return { end, note: L('chunked: stops at the 0-size chunk', 'chunked：读到大小为 0 的分块就停') };
      }
      i += size + 2;
      if (i > wire.length) return { end: wire.length, error: L('Chunk is longer than the data sent: the server waits for more', '分块比发送的数据长：服务器会一直等'), wait: true };
    }
  }
  const n = cl === undefined ? 0 : Number(cl);
  if (!Number.isInteger(n) || n < 0) return { end: wire.length, error: L('Invalid Content-Length', 'Content-Length 不合法') };
  const end = h.bodyAt + n;
  if (end > wire.length) return { end: wire.length, error: L('Content-Length is longer than the body: the server waits for more', 'Content-Length 比请求体长：服务器会一直等'), wait: true };
  return { end, note: L(`Content-Length: reads ${n} body bytes`, `Content-Length：读取 ${n} 字节请求体`) };
}

/** Build a CL.TE or TE.CL attack with correct lengths for the given smuggled prefix. */
export function build(kind, smuggled) {
  const host = 'Host: shop.example';
  if (kind === 'normal') {
    const body = 'q=shoes';
    return `POST /search HTTP/1.1\n${host}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: ${body.length}\n\n${body}`;
  }
  if (kind === 'clte') {
    const body = `0${CRLF}${CRLF}${toWire(smuggled)}`;
    return `POST / HTTP/1.1\n${host}\nContent-Length: ${body.length}\nTransfer-Encoding: chunked\n\n0\n\n${smuggled}`;
  }
  // TE.CL: the smuggled request goes inside one chunk; the back end reads only the size line.
  const chunk = toWire(smuggled);
  const size = chunk.length.toString(16);
  return `POST / HTTP/1.1\n${host}\nContent-Length: ${size.length + 2}\nTransfer-Encoding: chunked\n\n${size}\n${smuggled}\n0\n\n`;
}

export const SMUGGLED = {
  clte: 'GET /admin HTTP/1.1\nX-Ignore: ',
  tecl: 'GET /admin HTTP/1.1\nHost: shop.example\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 60\n\nx=',
};

export const FRONT_BACK = { normal: ['CL', 'CL'], clte: ['CL', 'TE'], tecl: ['TE', 'CL'] };

/**
 * Run the whole scenario. Returns the byte ranges for drawing and what the back end does next.
 * defended: the front end rejects any request carrying both Content-Length and Transfer-Encoding.
 */
export function run(text, front, back, defended) {
  const wire = toWire(text);
  const h = headers(wire);
  if (defended && get(h, 'Content-Length') !== undefined && get(h, 'Transfer-Encoding') !== undefined)
    return { wire, rejected: true, note: L('Front end: both Content-Length and Transfer-Encoding → 400 Bad Request. Nothing reaches the back end.', '前端：同时带 Content-Length 和 Transfer-Encoding → 400 Bad Request，什么都不会转发给后端。') };
  const f = boundary(wire, front);
  if (f.error) return { wire, f, rejected: true, note: f.error };
  const forwarded = wire.slice(0, f.end);
  const b = boundary(forwarded, back);
  if (b.wait) return { wire, f, b, timeout: true, note: L('The back end waits for bytes that never come → timeout. A timeout like this is how testers detect smuggling safely.', '后端在等永远不会来的字节 → 超时。测试人员正是靠这种超时来安全地发现走私漏洞。') };
  const leftover = forwarded.slice(b.end);
  const next = leftover + VICTIM;
  const nh = headers(next);
  const [method, path] = nh.start.split(' ');
  const cookie = get(nh, 'Cookie');
  return { wire, f, b, leftover, next, method, path, cookie, poisoned: leftover.length > 0 };
}

/** Show CR and LF so byte counts make sense. */
export const visible = (s) => s.replace(/\r\n/g, '␍␊\n');
