import { mkdirSync, writeFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { TOPICS } from './src/topics/registry.js';

const SITE = 'https://flamingoff.github.io/hack-the-diagram/';
const esc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

/**
 * Link-preview pages. The app uses hash routes (#/xss), which crawlers ignore, so each topic
 * also gets a tiny static page at /t/<id>/ carrying its own title and description. People who
 * open it are sent straight on to the real page.
 */
function sharePages() {
  let outDir = 'dist';
  return {
    name: 'share-pages',
    apply: 'build',
    configResolved(c) {
      outDir = c.build.outDir;
    },
    closeBundle() {
      for (const t of TOPICS) {
        const title = `${t.title.en} · Hack the Diagram`;
        const target = `${SITE}#/${t.id}`;
        const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>${esc(title)}</title>
<meta name="description" content="${esc(t.blurb.en)}">
<link rel="canonical" href="${target}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Hack the Diagram">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(t.blurb.en)} ${esc(t.blurb.zh)}">
<meta property="og:url" content="${SITE}t/${t.id}/">
<meta property="og:image" content="${SITE}og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta http-equiv="refresh" content="0; url=../../#/${t.id}">
<script>location.replace('../../#/${t.id}')</script>
</head><body><p><a href="../../#/${t.id}">${esc(t.title.en)}</a></p></body></html>
`;
        mkdirSync(`${outDir}/t/${t.id}`, { recursive: true });
        writeFileSync(`${outDir}/t/${t.id}/index.html`, html);
      }
    },
  };
}

// GitHub Pages serves the site from /<repo-name>/
export default defineConfig({
  base: '/hack-the-diagram/',
  plugins: [react(), sharePages()],
});
