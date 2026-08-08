'use strict';

const express = require('express');
const { checkPassword } = require('./ntlm');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function runCheck(hash, password) {
  try {
    return checkPassword(hash, password);
  } catch (e) {
    return { error: e.message };
  }
}

const ICON_CHECK = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4 10.5l4 4 8-9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const ICON_CROSS = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const ICON_WARN = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 6v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="10" cy="14" r="1.1" fill="currentColor"/></svg>';

function renderResult(result) {
  if (!result) return '';
  if (result.error) {
    return `<div class="result show warn">
      <span class="result-icon">${ICON_WARN}</span>
      <span class="result-text">
        <span class="headline">Не удалось разобрать хеш</span>
        <span class="detail">${escapeHtml(result.error)}</span>
      </span>
    </div>`;
  }
  const cls = result.match ? 'ok' : 'bad';
  const icon = result.match ? ICON_CHECK : ICON_CROSS;
  const headline = result.match ? 'Пароль подходит' : 'Пароль не подходит';
  return `<div class="result show ${cls}">
    <span class="result-icon">${icon}</span>
    <span class="result-text">
      <span class="headline">${headline}</span>
      <span class="detail result-meta">${escapeHtml(result.variant)} &middot; ${escapeHtml(result.username)}\\${escapeHtml(result.domain)}</span>
    </span>
  </div>`;
}

const PAGE = (result, hashValue, passwordValue) => `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetNTLM Checker</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0a0a;
    --surface: #161616;
    --field: #101010;
    --border: rgba(255, 255, 255, 0.1);
    --border-soft: rgba(255, 255, 255, 0.07);
    --text: #f5f5f5;
    --text-muted: #a1a1aa;
    --text-faint: #71717a;
    --accent: #22c55e;
    --accent-soft: rgba(34, 197, 94, 0.14);
    --bad: #ef4444;
    --bad-soft: rgba(239, 68, 68, 0.14);
    --warn: #f59e0b;
    --warn-soft: rgba(245, 158, 11, 0.14);
    --radius: 12px;
  }
  * { box-sizing: border-box; }
  html { color-scheme: dark; }
  body {
    margin: 0; min-height: 100vh; background: var(--bg); color: var(--text);
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
    font-size: 16px; line-height: 1.5;
    display: flex; justify-content: center;
    padding: 64px 20px;
  }
  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }
  main { width: 100%; max-width: 560px; }

  .eyebrow {
    font-size: 12px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;
    color: var(--text-faint); margin-bottom: 12px;
  }
  h1 { font-size: 27px; font-weight: 700; letter-spacing: -0.02em; margin: 0 0 8px; }
  .lede { color: var(--text-muted); font-size: 15.5px; line-height: 1.6; margin: 0 0 32px; max-width: 46ch; }

  .panel {
    background: var(--surface); border: 1px solid var(--border-soft); border-radius: var(--radius);
    padding: 28px;
  }

  form { display: flex; flex-direction: column; gap: 20px; }
  .field label {
    display: block; font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 8px;
  }
  .field .hint {
    display: block; font-size: 12px; color: var(--text-faint); margin-top: 8px;
    font-family: ui-monospace, SFMono-Regular, "Roboto Mono", Menlo, Consolas, monospace;
  }
  textarea, input[type="text"] {
    width: 100%; background: var(--field); color: var(--text);
    border: 1px solid var(--border); border-radius: 8px;
    padding: 11px 13px; font-size: 14px;
    font-family: ui-monospace, SFMono-Regular, "Roboto Mono", Menlo, Consolas, monospace;
    transition: border-color 150ms, box-shadow 150ms;
  }
  input[type="text"] { font-family: inherit; font-size: 15px; }
  textarea { height: 108px; resize: vertical; line-height: 1.5; }
  textarea::placeholder, input::placeholder { color: var(--text-faint); }
  textarea:focus, input:focus {
    outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  textarea::-webkit-scrollbar { width: 10px; }
  textarea::-webkit-scrollbar-track { background: transparent; }
  textarea::-webkit-scrollbar-thumb { background: var(--border); border-radius: 6px; }

  .actions { display: flex; align-items: center; justify-content: space-between; margin-top: 4px; }
  .btn {
    appearance: none; cursor: pointer; font-family: inherit; font-size: 14px; font-weight: 600;
    border-radius: 8px; padding: 10px 18px;
    background: transparent; color: var(--text); border: 1px solid var(--border);
    transition: border-color 150ms, background-color 150ms, color 150ms;
  }
  .btn:hover { border-color: var(--accent); color: var(--accent); }
  .btn:focus-visible { outline: none; box-shadow: 0 0 0 3px var(--accent-soft); }
  .btn-text {
    appearance: none; cursor: pointer; background: none; border: none; padding: 4px 0;
    color: var(--text-faint); font-family: inherit; font-size: 13px; font-weight: 500;
    transition: color 150ms;
  }
  .btn-text:hover { color: var(--text-muted); }
  .btn-text:focus-visible { outline: none; text-decoration: underline; }

  #resultWrap { transition: opacity 150ms; }
  #resultWrap.pending { opacity: 0.5; }
  .result {
    display: none; align-items: flex-start; gap: 12px;
    margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-soft);
  }
  .result.show { display: flex; }
  .result-icon {
    flex-shrink: 0; width: 22px; height: 22px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
  }
  .result-icon svg { width: 13px; height: 13px; }
  .result.ok .result-icon { background: var(--accent-soft); color: var(--accent); }
  .result.bad .result-icon { background: var(--bad-soft); color: var(--bad); }
  .result.warn .result-icon { background: var(--warn-soft); color: var(--warn); }
  .result-text { flex: 1; min-width: 0; }
  .result-text .headline { display: block; font-size: 15px; font-weight: 600; margin-bottom: 4px; }
  .result.ok .headline { color: var(--accent); }
  .result.bad .headline { color: var(--bad); }
  .result.warn .headline { color: var(--warn); }
  .detail {
    display: block; font-size: 13px; color: var(--text-muted); word-break: break-word;
  }
  .result-meta { font-family: ui-monospace, SFMono-Regular, "Roboto Mono", Menlo, Consolas, monospace; }

  footer { margin-top: 24px; text-align: center; font-size: 12px; color: var(--text-faint); }
</style>
</head>
<body>
  <main>
    <div class="eyebrow">NetNTLM Checker</div>
    <h1>Проверка пароля по хешу</h1>
    <p class="lede">Вставьте перехваченный NetNTLMv1 или NetNTLMv2 хеш и предполагаемый пароль — проверка идёт локально, по мере ввода.</p>

    <div class="panel">
      <form id="checkForm">
        <div class="field">
          <label for="hash">Хеш</label>
          <textarea id="hash" name="hash" placeholder="user::domain:challenge:proof:blob" spellcheck="false" required>${escapeHtml(hashValue ?? '')}</textarea>
          <span class="hint">v1: user::domain:LMresp:NTresp:challenge &middot; v2: user::domain:challenge:proof:blob</span>
        </div>

        <div class="field">
          <label for="password">Предполагаемый пароль</label>
          <input id="password" name="password" type="text" autocomplete="off" placeholder="Введите вариант" required value="${escapeHtml(passwordValue ?? '')}">
        </div>

        <div class="actions">
          <button type="button" class="btn-text" id="clearBtn">Очистить</button>
          <button type="submit" class="btn">Проверить</button>
        </div>
      </form>

      <div id="resultWrap">${renderResult(result)}</div>
    </div>

    <footer>Вычисления выполняются на этом сервере, ничего не отправляется наружу.</footer>
  </main>

  <script>
    const hashEl = document.getElementById('hash');
    const passwordEl = document.getElementById('password');
    const resultWrap = document.getElementById('resultWrap');
    let liveTimer = null;
    let liveSeq = 0;

    function runLiveCheck() {
      const hash = hashEl.value;
      const password = passwordEl.value;
      if (!hash.trim() || !password) {
        resultWrap.classList.remove('pending');
        resultWrap.innerHTML = '';
        return;
      }
      const seq = ++liveSeq;
      resultWrap.classList.add('pending');
      fetch('/check/live', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'hash=' + encodeURIComponent(hash) + '&password=' + encodeURIComponent(password),
      })
        .then((r) => r.text())
        .then((html) => {
          if (seq !== liveSeq) return;
          resultWrap.classList.remove('pending');
          resultWrap.innerHTML = html;
        })
        .catch(() => resultWrap.classList.remove('pending'));
    }

    function scheduleLiveCheck() {
      clearTimeout(liveTimer);
      liveTimer = setTimeout(runLiveCheck, 250);
    }

    hashEl.addEventListener('input', scheduleLiveCheck);
    passwordEl.addEventListener('input', scheduleLiveCheck);

    document.getElementById('checkForm').addEventListener('submit', (e) => {
      e.preventDefault();
      clearTimeout(liveTimer);
      runLiveCheck();
    });

    document.getElementById('clearBtn').addEventListener('click', () => {
      clearTimeout(liveTimer);
      hashEl.value = '';
      passwordEl.value = '';
      resultWrap.classList.remove('pending');
      resultWrap.innerHTML = '';
      hashEl.focus();
    });
  </script>
</body>
</html>`;

app.get('/', (req, res) => {
  res.send(PAGE(null, '', ''));
});

app.post('/check', (req, res) => {
  const hash = typeof req.body.hash === 'string' ? req.body.hash : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  res.send(PAGE(runCheck(hash, password), hash, password));
});

// Used by the page's own JS for live, as-you-type checking — returns just
// the result fragment instead of the whole page.
app.post('/check/live', (req, res) => {
  const hash = typeof req.body.hash === 'string' ? req.body.hash : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  res.type('html').send(renderResult(runCheck(hash, password)));
});

app.use((req, res) => {
  res.status(404).type('text').send('Not found');
});

app.listen(PORT, HOST, () => {
  console.log(`NTLM checker listening on http://${HOST}:${PORT}`);
});
