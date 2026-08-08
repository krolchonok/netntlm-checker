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

function renderResult(result) {
  if (!result) return '';
  if (result.error) {
    return `<div class="result sunken show warn">
      <span class="result-icon">!</span>
      <span class="result-text">
        <span class="headline">Ошибка разбора хеша.</span>
        <span>${escapeHtml(result.error)}</span>
      </span>
    </div>`;
  }
  const cls = result.match ? 'ok' : 'bad';
  const icon = result.match ? '&#10003;' : '&#10007;';
  const headline = result.match ? 'Пароль подходит.' : 'Пароль не подходит.';
  return `<div class="result sunken show ${cls}">
    <span class="result-icon">${icon}</span>
    <span class="result-text">
      <span class="headline">${headline}</span>
      <span class="result-meta">${escapeHtml(result.variant)} &middot; ${escapeHtml(result.username)} \\ ${escapeHtml(result.domain)}</span>
    </span>
  </div>`;
}

const PAGE = (result, hashValue, passwordValue) => `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetNTLMv2 Checker</title>
<style>
  :root {
    --face: #c0c0c0;
    --face-soft: #d4d4d4;
    --hi: #ffffff;
    --hi-soft: #dfdfdf;
    --sh: #808080;
    --sh-dark: #000000;
    --desktop: #008080;
    --text: #000000;
    --text-disabled: #808080;
    --field-bg: #ffffff;
    --titlebar-l: #000080;
    --titlebar-r: #1084d0;
    --titlebar-text: #ffffff;
    --selection: #000080;
    --selection-text: #ffffff;
    --ok: #008000;
    --bad: #c00000;
    --warn-bg: #ffff00;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; background: var(--desktop);
    font-family: Tahoma, "MS Sans Serif", Geneva, sans-serif;
    font-size: 15px; color: var(--text);
    -webkit-font-smoothing: none; font-smooth: never;
    display: flex; flex-direction: column; justify-content: center; align-items: center;
    padding: 24px 12px 76px; gap: 14px; overflow-x: hidden;
  }
  ::selection { background: var(--selection); color: var(--selection-text); }
  .window {
    width: min(100%, 680px); background: var(--face);
    border: 2px solid; border-color: var(--hi) var(--sh-dark) var(--sh-dark) var(--hi);
    box-shadow: inset 2px 2px 0 var(--hi-soft), inset -2px -2px 0 var(--sh), 4px 4px 12px rgba(0,0,0,.4);
  }
  .titlebar {
    background: linear-gradient(90deg, var(--titlebar-l), var(--titlebar-r));
    color: var(--titlebar-text); display: flex; align-items: center; gap: 8px;
    padding: 6px 6px 6px 8px; font-weight: bold; font-size: 16px;
  }
  .titlebar .title { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .titlebar-btns { display: flex; gap: 3px; }
  .titlebar-btns button {
    width: 24px; height: 21px; background: var(--face);
    border: 1px solid; border-color: var(--hi) var(--sh-dark) var(--sh-dark) var(--hi);
    font-family: monospace; font-size: 13px; line-height: 1; padding: 0; cursor: pointer;
  }
  .titlebar-btns button:active { border-color: var(--sh-dark) var(--hi) var(--hi) var(--sh-dark); }
  .icon-lock { position: relative; width: 16px; height: 16px; flex-shrink: 0; }
  .icon-lock::before {
    content: ""; position: absolute; top: 0; left: 3px; width: 10px; height: 8px;
    border: 2px solid #ffd400; border-bottom: none; border-radius: 6px 6px 0 0;
  }
  .icon-lock::after {
    content: ""; position: absolute; top: 7px; left: 1px; width: 13px; height: 9px;
    background: #ffd400; border: 1px solid #7a5c00;
  }
  .menubar { display: flex; gap: 18px; padding: 5px 10px; border-bottom: 1px solid var(--sh); font-size: 14px; }
  .menubar span { cursor: default; }
  .menubar span u { text-decoration: underline; }
  .menubar span:hover { background: var(--selection); color: var(--selection-text); padding: 0 2px; margin: 0 -2px; }
  .content { padding: 16px; display: flex; flex-direction: column; gap: 16px; }
  fieldset {
    border: 1px solid; border-color: var(--sh-dark) var(--hi) var(--hi) var(--sh-dark);
    box-shadow: inset 0 0 0 1px var(--hi-soft); padding: 14px 12px 12px; margin: 0;
  }
  legend { padding: 0 5px; font-size: 14px; }
  textarea, input[type="text"] {
    width: 100%; background: var(--field-bg);
    border: 1px solid; border-color: var(--sh-dark) var(--hi) var(--hi) var(--sh-dark);
    box-shadow: inset 1px 1px 0 var(--sh);
    font-family: "Courier New", Courier, monospace; font-size: 14px; padding: 8px 9px; color: var(--text);
  }
  textarea { height: 110px; resize: vertical; line-height: 1.5; scrollbar-color: var(--face) var(--sh-dark); scrollbar-width: auto; }
  textarea:focus, input:focus { outline: 1px dotted #000; outline-offset: -3px; }
  textarea::-webkit-scrollbar { width: 16px; }
  textarea::-webkit-scrollbar-track {
    background: var(--face);
    box-shadow: inset 1px 1px 0 var(--sh), inset -1px -1px 0 var(--hi-soft);
  }
  textarea::-webkit-scrollbar-thumb {
    background: var(--face);
    border: 1px solid; border-color: var(--hi) var(--sh-dark) var(--sh-dark) var(--hi);
    box-shadow: inset 1px 1px 0 var(--hi-soft), inset -1px -1px 0 var(--sh);
  }
  textarea::-webkit-scrollbar-button {
    display: block; height: 16px; background: var(--face);
    border: 1px solid; border-color: var(--hi) var(--sh-dark) var(--sh-dark) var(--hi);
    box-shadow: inset 1px 1px 0 var(--hi-soft), inset -1px -1px 0 var(--sh);
  }
  .field-label { display: block; margin-bottom: 5px; font-size: 13px; }
  .hint { color: var(--text-disabled); font-size: 12px; margin-top: 6px; display: block; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; padding: 0 16px 16px; }
  .btn95 {
    min-width: 108px; padding: 9px 16px; background: var(--face); color: var(--text);
    border: 1px solid; border-color: var(--hi) var(--sh-dark) var(--sh-dark) var(--hi);
    box-shadow: inset 1px 1px 0 var(--hi-soft), inset -1px -1px 0 var(--sh);
    font-family: inherit; font-size: 14px; cursor: pointer;
  }
  .btn95:active { border-color: var(--sh-dark) var(--hi) var(--hi) var(--sh-dark); box-shadow: inset 1px 1px 0 var(--sh); }
  .btn95:focus-visible { outline: 1px dotted #000; outline-offset: 2px; }
  .btn95-default-wrap { border: 1px solid var(--text); padding: 1px; display: inline-flex; }
  .result { margin: 0 16px 18px; display: none; gap: 12px; align-items: flex-start; padding: 14px; background: var(--face-soft); transition: opacity .1s; }
  .result.show { display: flex; }
  #resultWrap.pending .result { opacity: .55; }
  .result-icon {
    flex-shrink: 0; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center;
    justify-content: center; color: #fff; font-weight: bold; font-size: 18px; border: 1px solid rgba(0,0,0,.4);
  }
  .result.ok .result-icon { background: var(--ok); }
  .result.bad .result-icon { background: var(--bad); }
  .result.warn .result-icon { background: var(--warn-bg); color: #000; }
  .result-text { flex: 1; }
  .result-text .headline { font-weight: bold; font-size: 15px; display: block; margin-bottom: 5px; }
  .result-meta { color: var(--text-disabled); font-family: "Courier New", monospace; font-size: 13px; }
  dialog { padding: 0; border: none; background: transparent; width: min(90vw, 360px); }
  dialog::backdrop { background: rgba(0,0,0,.3); }
  .about-body { padding: 18px; display: flex; gap: 14px; align-items: flex-start; }
  .about-body .icon-lock { width: 28px; height: 28px; transform: scale(2); transform-origin: top left; }
  .about-text { font-size: 14px; line-height: 1.6; }
  .about-actions { display: flex; justify-content: center; padding: 0 18px 16px; }
  .taskbar {
    position: fixed; left: 0; right: 0; bottom: 0; height: 38px; background: var(--face);
    border-top: 1px solid var(--hi); display: flex; align-items: center; gap: 8px; padding: 4px 6px; z-index: 10;
  }
  .start-btn { flex-shrink: 0; display: flex; align-items: center; gap: 5px; padding: 5px 12px 5px 6px; font-weight: bold; font-size: 14px;
    border: 1px solid; border-color: var(--hi) var(--sh-dark) var(--sh-dark) var(--hi);
    box-shadow: inset 1px 1px 0 var(--hi-soft), inset -1px -1px 0 var(--sh); background: var(--face); cursor: pointer; }
  .flag { flex-shrink: 0; width: 16px; height: 16px; display: grid; grid-template-columns: 1fr 1fr; grid-template-rows: 1fr 1fr; gap: 1px; transform: skewX(-6deg); }
  .flag span:nth-child(1) { background: #ff3b30; }
  .flag span:nth-child(2) { background: #34c759; }
  .flag span:nth-child(3) { background: #0a84ff; }
  .flag span:nth-child(4) { background: #ffcc00; }
  .task-item {
    display: flex; align-items: center; gap: 6px; padding: 5px 14px; font-size: 14px;
    flex: 1 1 170px; min-width: 0; max-width: 260px; overflow: hidden; white-space: nowrap; text-overflow: ellipsis;
    border: 1px solid; border-color: var(--sh-dark) var(--hi) var(--hi) var(--sh-dark); box-shadow: inset 1px 1px 0 var(--sh);
  }
  .task-item .icon-lock { flex-shrink: 0; }
  .clock { flex-shrink: 0; margin-left: auto; padding: 6px 14px; font-variant-numeric: tabular-nums; font-size: 14px;
    border: 1px solid; border-color: var(--sh-dark) var(--hi) var(--hi) var(--sh-dark); box-shadow: inset 1px 1px 0 var(--sh); }
  @media (max-width: 420px) { .task-item { flex-basis: 90px; padding: 5px 8px; } .clock { padding: 6px 8px; } }
</style>
</head>
<body>
  <div class="window" role="group" aria-label="NetNTLMv2 Checker">
    <div class="titlebar">
      <span class="icon-lock" aria-hidden="true"></span>
      <span class="title">NetNTLMv2 Checker</span>
      <div class="titlebar-btns">
        <button type="button" aria-label="Свернуть" title="Свернуть">_</button>
        <button type="button" aria-label="Развернуть" title="Развернуть">&#9633;</button>
        <button type="button" id="closeBtn" aria-label="Закрыть" title="Закрыть">&#10005;</button>
      </div>
    </div>

    <div class="menubar">
      <span><u>F</u>ile</span>
      <span><u>E</u>dit</span>
      <span id="helpMenu"><u>H</u>elp</span>
    </div>

    <form class="content" method="POST" action="/check">
      <fieldset>
        <legend>Захваченный хеш</legend>
        <label class="field-label" for="hash">NetNTLMv1 или NetNTLMv2 (hashcat -m 5500 / -m 5600)</label>
        <textarea id="hash" name="hash" spellcheck="false" required>${escapeHtml(hashValue ?? '')}</textarea>
        <span class="hint">v1: user::domain:LMresp:NTresp:challenge &middot; v2: user::domain:challenge:proof:blob</span>
      </fieldset>

      <fieldset>
        <legend>Предполагаемый пароль</legend>
        <label class="field-label" for="password">Введите вариант для проверки</label>
        <input id="password" name="password" type="text" autocomplete="off" required value="${escapeHtml(passwordValue ?? '')}">
      </fieldset>

      <div class="actions">
        <div class="btn95-default-wrap"><button class="btn95" type="submit">Проверить</button></div>
        <button class="btn95" type="button" id="clearBtn">Очистить</button>
      </div>
    </form>

    <div id="resultWrap">${renderResult(result)}</div>
  </div>

  <dialog id="aboutDialog">
    <div class="window">
      <div class="titlebar">
        <span class="icon-lock" aria-hidden="true"></span>
        <span class="title">О программе</span>
        <div class="titlebar-btns"><button type="button" id="aboutCloseX" aria-label="Закрыть">&#10005;</button></div>
      </div>
      <div class="about-body">
        <span class="icon-lock" aria-hidden="true"></span>
        <span class="about-text">
          <b>NetNTLMv2 Checker</b> 1.0<br>
          Локальная проверка пароля по перехваченному хешу (NetNTLMv1/ESS/NetNTLMv2).<br>
          Все вычисления выполняются на этом сервере, ничего не отправляется наружу.
        </span>
      </div>
      <div class="about-actions">
        <div class="btn95-default-wrap"><button class="btn95" id="aboutOk" type="button">OK</button></div>
      </div>
    </div>
  </dialog>

  <div class="taskbar">
    <button class="start-btn" type="button">
      <span class="flag" aria-hidden="true"><span></span><span></span><span></span><span></span></span>
      Start
    </button>
    <span class="task-item"><span class="icon-lock" aria-hidden="true"></span>NetNTLMv2 Checker</span>
    <span class="clock" id="clock">00:00</span>
  </div>

  <script>
    function pad(n) { return String(n).padStart(2, "0"); }
    function tick() {
      var d = new Date();
      document.getElementById("clock").textContent = pad(d.getHours()) + ":" + pad(d.getMinutes());
    }
    tick();
    setInterval(tick, 15000);
    var aboutDialog = document.getElementById("aboutDialog");
    document.getElementById("helpMenu").addEventListener("click", function () { aboutDialog.showModal(); });
    document.getElementById("aboutOk").addEventListener("click", function () { aboutDialog.close(); });
    document.getElementById("aboutCloseX").addEventListener("click", function () { aboutDialog.close(); });

    // Live, as-you-type checking: debounce keystrokes, POST to /check/live,
    // swap in the returned result fragment. Falls back to a normal full-page
    // POST /check submit if JS is unavailable.
    var hashEl = document.getElementById("hash");
    var passwordEl = document.getElementById("password");
    var resultWrap = document.getElementById("resultWrap");
    var liveTimer = null;
    var liveSeq = 0;

    function runLiveCheck() {
      var hash = hashEl.value;
      var password = passwordEl.value;
      if (!hash.trim() || !password) {
        resultWrap.classList.remove("pending");
        resultWrap.innerHTML = "";
        return;
      }
      var seq = ++liveSeq;
      resultWrap.classList.add("pending");
      fetch("/check/live", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "hash=" + encodeURIComponent(hash) + "&password=" + encodeURIComponent(password),
      })
        .then(function (r) { return r.text(); })
        .then(function (html) {
          if (seq !== liveSeq) return; // a newer keystroke already superseded this request
          resultWrap.classList.remove("pending");
          resultWrap.innerHTML = html;
        })
        .catch(function () { resultWrap.classList.remove("pending"); });
    }

    function scheduleLiveCheck() {
      clearTimeout(liveTimer);
      liveTimer = setTimeout(runLiveCheck, 250);
    }

    hashEl.addEventListener("input", scheduleLiveCheck);
    passwordEl.addEventListener("input", scheduleLiveCheck);

    document.querySelector(".content").addEventListener("submit", function (e) {
      e.preventDefault();
      clearTimeout(liveTimer);
      runLiveCheck();
    });

    document.getElementById("clearBtn").addEventListener("click", function () {
      clearTimeout(liveTimer);
      hashEl.value = "";
      passwordEl.value = "";
      resultWrap.classList.remove("pending");
      resultWrap.innerHTML = "";
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
