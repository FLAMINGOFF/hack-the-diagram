# Hack the Diagram

**Understand web attacks by breaking things.** Interactive diagrams and live, sandboxed labs that explain classic web vulnerabilities, in English and 中文.

🔗 **Live site:** https://flamingoff.github.io/hack-the-diagram/

![Landing page](docs/home.png)

## Topics

32 topics, organised like the [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-topics) topic map (used only as a checklist; all explanations, diagrams and labs here are original).

| Category | Topics |
| --- | --- |
| **Server-side** | SQL injection · Authentication · Path traversal · OS command injection · Business logic · Information disclosure · Access control / IDOR · File upload · Race conditions · SSRF · XXE · NoSQL injection · API testing / mass assignment · Web cache deception |
| **Client-side** | XSS · CSRF · CORS · Clickjacking · DOM-based · WebSocket hijacking |
| **Advanced** | Insecure deserialization · MCP server vulnerabilities · Web LLM attacks · GraphQL · SSTI · Web cache poisoning · Host header attacks · HTTP request smuggling · OAuth 2.0 · JWT · Prototype pollution |
| **Foundations** | TLS 1.3 handshake |

New visitors can start with the in-site **beginner’s guide** (`#/start`): how the labs work, six prerequisite ideas, a 5-stage learning path with progress ticks, and a glossary.

Every topic has the same shape: **TL;DR → interactive lab → step-by-step sequence diagram → vulnerable vs fixed code → defences → interview questions**, in English and 中文.

Highlights:

- **XSS**: payloads run in a real sandboxed iframe; an attacker console shows cookie reads and exfiltration.
- **SQL injection**: a real SQLite engine (sql.js); every input character is coloured as data or code.
- **CSRF / TLS**: configurable simulators (SameSite, tokens; passive eavesdropper vs active MITM).
- **Clickjacking**: an opacity slider reveals the invisible frame under the decoy button.
- **Request smuggling**: paste a raw request and see exactly where front end and back end disagree.
- **SSRF, JWT, SSTI, NoSQLi, prototype pollution, …**: each lab simulates the vulnerable server and the fixed one with a single toggle.

| XSS | SQL injection |
| --- | --- |
| ![XSS lab](docs/xss.png) | ![SQL injection lab](docs/sqli.png) |

## Safety

Everything runs client-side against simulated targets. The XSS forum lives in a `sandbox="allow-scripts"` iframe with an opaque origin; `alert`, `document.cookie` and outgoing requests are stubbed, and its own Content-Security-Policy blocks all real network access. Nothing leaves the page.

For learning only. Only test systems you own or are authorised to test.

## Tech

- [Vite](https://vite.dev/) + React 19, no UI framework, hand-written SVG sequence diagrams
- [sql.js](https://github.com/sql-js/sql.js) (SQLite compiled to WebAssembly) for the SQL injection lab
- Bilingual UI (EN / 中文) with a tiny context-based i18n helper
- Hash routing, so it works on GitHub Pages without server config
- Deployed by GitHub Actions on every push to `main`

## Run locally

```bash
npm install
npm run dev      # http://localhost:5173/hack-the-diagram/
npm run build    # production build in dist/
```

## Project structure

```
src/
  App.jsx                  hash router
  Home.jsx                 landing page
  i18n.jsx                 EN / 中文 context
  components/
    SequenceDiagram.jsx    reusable animated SVG sequence diagram
    Stepper.jsx            play / step controls + narration
    TopicShell.jsx         shared topic layout, defences, interview Q&A
    GenericTopic.jsx       page template for data-driven topics
    MiniLab.jsx            input → simulated server → verdict lab
  topics/
    registry.js            topic catalogue and categories
    Xss.jsx  Sqli.jsx  Csrf.jsx  Tls.jsx      hand-built labs
    content/
      server.js  client.jsx  advanced.js     data-driven topics
```

## Adding a topic

1. Add an entry to `TOPICS` in `src/topics/registry.js`.
2. Add a definition object to one of the files in `src/topics/content/` (`tldr`, `lab`, `actors`, `flow`, `code`, `defenses`, `qa`). A lab is just `fields`, `presets`, a `defense` toggle and a pure `run({ values, defended })` function.
3. For a fully custom page, add a component and register it in `CUSTOM` in `src/App.jsx`.

## License

MIT
