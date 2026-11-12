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
  const CHUNK = 32 * 1024;  // the control plane accepts frames up to 64 KiB: split large pastes
  let ws, retry = 0;
  // Sends one message type ('0' input, '1' resize) with the payload bytes, in frames of at most CHUNK bytes.
  const sendBytes = (type, bytes) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    for (let i = 0; i < bytes.length || i === 0; i += CHUNK) {
      const part = bytes.subarray(i, i + CHUNK), frame = new Uint8Array(part.length + 1);
      frame[0] = type.charCodeAt(0); frame.set(part, 1); ws.send(frame);
    }
  };
  const resize = () => sendBytes("1", enc.encode(JSON.stringify({ columns: term.cols, rows: term.rows })));

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
      if (typeof ev.data === "string") { if (ev.data[0] === "0") term.write(ev.data.slice(1)); return; }
      // Bytes go to xterm as they are: its decoder keeps state, so a UTF-8 character split across two
      // frames is not garbled.
      const bytes = new Uint8Array(ev.data);
      if (bytes[0] === 0x30) term.write(bytes.subarray(1));
    };
    ws.onclose = (ev) => {
      if (ev.code === 4401 || ev.code === 1008) return expired();
      // A refused handshake (e.g. 401 after the session ended) looks like any other drop: ask the server.
      fetch("/api/meta", { credentials: "same-origin" }).then((r) => {
        if (r.status === 401) return expired();
        reconnect();
      }, reconnect);
    };
  }
  const expired = () => setStatus("session expired – log in again and reload the page", true);
  const reconnect = () => {
    retry = Math.min(retry + 1, 6); setStatus(`disconnected – reconnecting in ${retry * 2}s`, true);
    setTimeout(connect, retry * 2000);
  };
  term.onData((d) => sendBytes("0", enc.encode(d)));
  term.onBinary((d) => {  // raw bytes (e.g. mouse reports): must not be UTF-8 encoded
    sendBytes("0", Uint8Array.from(d, (c) => c.charCodeAt(0) & 0xff));
  });
  term.onResize(resize);
  window.addEventListener("resize", () => fit.fit());
  connect();
})();
