"use strict";
// Minimal ttyd client. Protocol (ttyd 1.7): client -> server '0'+input, '1'+JSON resize;
// server -> client '0'+output ('1' title / '2' preferences are ignored: agent-controlled).
// The control plane adds the ttyd credential to the handshake; the browser never sees it.
(() => {
  const name = location.pathname.split("/")[2];
  const statusEl = document.getElementById("status");
  const setStatus = (text, bad = false) => {
    statusEl.textContent = text; statusEl.className = "status" + (bad ? " bad" : "") + (text ? "" : " hidden");
  };
  const term = new Terminal({
    fontSize: 14, cursorBlink: true, scrollback: 5000, allowProposedApi: false,
    // Agent output is untrusted: OSC 8 hyperlinks are not activated.
    linkHandler: { activate: () => {}, allowNonHttpProtocols: false },
    theme: { background: "#0b1020" },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById("term"));
  fit.fit();
  document.title = `tallygate · ${name}`;

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let ws, retry = 0;
  const send = (s) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(enc.encode(s)); };
  const resize = () => send("1" + JSON.stringify({ columns: term.cols, rows: term.rows }));

  function connect() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/term/${encodeURIComponent(name)}/ws`, ["tty"]);
    ws.binaryType = "arraybuffer";
    ws.onopen = () => {
      retry = 0; setStatus("");
      ws.send(JSON.stringify({ columns: term.cols, rows: term.rows }));
      term.focus();
    };
    ws.onmessage = (ev) => {
      const data = typeof ev.data === "string" ? ev.data : dec.decode(new Uint8Array(ev.data));
      if (data[0] === "0") term.write(data.slice(1));
    };
    ws.onclose = (ev) => {
      if (ev.code === 4401 || ev.code === 1008) { setStatus("session expired – reload the page", true); return; }
      retry = Math.min(retry + 1, 6); setStatus(`disconnected – reconnecting in ${retry * 2}s`, true);
      setTimeout(connect, retry * 2000);
    };
  }
  term.onData((d) => send("0" + d));
  term.onBinary((d) => {  // raw bytes (e.g. mouse reports): must not be UTF-8 encoded
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const buf = new Uint8Array(d.length + 1); buf[0] = 0x30;
    for (let i = 0; i < d.length; i++) buf[i + 1] = d.charCodeAt(i) & 0xff;
    ws.send(buf);
  });
  term.onResize(resize);
  window.addEventListener("resize", () => fit.fit());
  connect();
})();
