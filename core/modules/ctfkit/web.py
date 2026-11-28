"""A tiny local web UI for ctfkit, built on the standard library only.

`ctfkit web` starts an HTTP server bound to 127.0.0.1, opens a browser, and
lets you drive triage / rop / offset / pwn / heap / libcid / onegadget from a
page -- reusing the exact same command functions as the CLI (their stdout is
captured and its ANSI colors converted to HTML).

Safety:
  * binds to 127.0.0.1 only (never exposed on the network);
  * the JSON API requires a per-session token in a custom header, so another
    web page open in the same browser cannot drive it (CSRF protection);
  * it runs the user's own tool on their own machine -- `offset` still executes
    the target binary locally, exactly as the CLI does.
"""
import contextlib
import html
import io
import json
import re
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from . import heap as heapmod
from . import libc as libcmod
from . import libcid as libcidmod
from . import offset as offsetmod
from . import onegadget as onegadgetmod
from . import pwngen, rop, triage
from .ui import C, force_color, good, hdr, info

_SGR_COLORS = {
    "31": "#e06c75", "32": "#98c379", "33": "#d19a66", "34": "#61afef",
    "35": "#c678dd", "36": "#56b6c2", "37": "#abb2bf", "90": "#7f848e",
}
_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")


def ansi_to_html(text):
    """Convert the subset of ANSI SGR codes ctfkit uses into styled <span>s."""
    color = None
    bold = dim = False
    out = []
    for part in re.split(r"(\x1b\[[0-9;]*m)", text):
        m = _ANSI_RE.fullmatch(part)
        if m:
            codes = m.group(1).split(";") if m.group(1) else ["0"]
            for c in codes:
                if c in ("", "0"):
                    color, bold, dim = None, False, False
                elif c == "1":
                    bold = True
                elif c == "2":
                    dim = True
                elif c in _SGR_COLORS:
                    color = _SGR_COLORS[c]
            continue
        if not part:
            continue
        esc = html.escape(part)
        style = []
        if color:
            style.append(f"color:{color}")
        if bold:
            style.append("font-weight:600")
        if dim:
            style.append("opacity:.65")
        out.append(f'<span style="{";".join(style)}">{esc}</span>' if style else esc)
    return "".join(out)


def _need(path, what="binary"):
    import os
    if not path:
        raise ValueError(f"no {what} given")
    if not os.path.exists(path):
        raise ValueError(f"{what} not found: {path}")


def _leaks(p):
    raw = (p.get("leaks") or "").replace(",", " ")
    return [t for t in raw.split() if "=" in t]


def _read_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {"name": path, "content": f.read()}
    except OSError:
        return None


def run_action(p):
    """Execute one action, capturing printed output. Returns {output, file?}."""
    action = p.get("action")
    binary = (p.get("binary") or "").strip()
    libc = (p.get("libc") or "").strip() or None
    buf = io.StringIO()
    extra = {}
    try:
        with contextlib.redirect_stdout(buf):
            if action == "triage":
                _need(binary)
                triage.cmd_triage(binary)
            elif action == "rop":
                _need(binary)
                rop.cmd_rop(binary)
            elif action == "offset":
                _need(binary)
                offsetmod.cmd_offset(binary, length=int(p.get("length") or 200),
                                     arg=bool(p.get("arg")))
            elif action == "pwn":
                _need(binary)
                out = (p.get("out") or "exploit.py").strip()
                pwngen.cmd_pwn(binary, out, p.get("host") or "CHANGE_ME",
                               int(p.get("port") or 0),
                               auto_offset=bool(p.get("auto_offset")),
                               libc=libc, libc_leak=_leaks(p) or None)
                extra["file"] = _read_file(out)
            elif action == "heap":
                _need(binary)
                out = (p.get("out") or "heap.py").strip()
                heapmod.cmd_heap(binary, out, p.get("host") or "CHANGE_ME",
                                 int(p.get("port") or 0), libc=libc)
                extra["file"] = _read_file(out)
            elif action == "libc":
                _need(binary)
                libcmod.cmd_libc(binary, libc)
            elif action == "onegadget":
                _need(libc, "libc")
                onegadgetmod.cmd_onegadget(libc, level=int(p.get("level") or 0))
            elif action == "libcid":
                libs = (p.get("libs") or "").strip() or None
                libcidmod.cmd_libcid(_leaks(p), libs=libs, online=libs is None,
                                     download="." if p.get("download") else None)
            else:
                raise ValueError(f"unknown action: {action}")
    except Exception as e:  # surface any failure as output, don't crash the server
        buf.write(f"\n\033[31m[-] {e}\033[0m")
    res = {"output": ansi_to_html(buf.getvalue())}
    res.update(extra)
    return res


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ctfkit</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.5 system-ui,sans-serif; background:#1a1d23; color:#c8ccd4; }
  header { padding:14px 20px; background:#15171c; border-bottom:1px solid #2a2e37;
           display:flex; align-items:center; gap:12px; }
  header b { color:#56b6c2; font-size:16px; letter-spacing:.5px; }
  header span { color:#636973; font-size:12px; }
  main { display:grid; grid-template-columns:320px 1fr; gap:0; min-height:calc(100vh - 51px); }
  .panel { padding:18px; background:#1e2127; border-right:1px solid #2a2e37; }
  label { display:block; font-size:11px; text-transform:uppercase; letter-spacing:.6px;
          color:#7f848e; margin:12px 0 4px; }
  input[type=text], input[type=number] { width:100%; padding:7px 9px; background:#15171c;
          border:1px solid #2a2e37; border-radius:6px; color:#c8ccd4; font-family:ui-monospace,monospace; }
  input:focus { outline:none; border-color:#56b6c2; }
  .row { display:flex; gap:8px; }
  .row > * { flex:1; }
  .check { display:flex; align-items:center; gap:7px; margin-top:10px; font-size:13px; color:#abb2bf; }
  .check input { width:auto; }
  .btns { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
  button { padding:8px 13px; background:#2a2e37; border:1px solid #363b45; border-radius:6px;
           color:#d7dae1; cursor:pointer; font-size:13px; font-weight:500; }
  button:hover { background:#333842; border-color:#56b6c2; }
  button.go { background:#2d5a63; border-color:#56b6c2; color:#cdeef2; }
  .out { padding:18px 20px; overflow:auto; }
  pre { margin:0; font-family:ui-monospace,"Cascadia Code",monospace; font-size:13px;
        white-space:pre-wrap; word-break:break-word; }
  .file { margin-top:18px; border:1px solid #2a2e37; border-radius:8px; overflow:hidden; }
  .file h4 { margin:0; padding:8px 12px; background:#15171c; font-size:12px; color:#98c379;
             display:flex; justify-content:space-between; }
  .file pre { padding:12px; background:#15171c; color:#9aa0ab; max-height:340px; overflow:auto; }
  .hint { color:#636973; font-size:12px; margin-top:4px; }
  a.copy { color:#56b6c2; cursor:pointer; text-decoration:none; font-size:11px; }
</style></head><body>
<header><b>ctfkit</b><span>v__VERSION__ &middot; local UI &middot; 127.0.0.1</span></header>
<main>
  <div class="panel">
    <label>Binary path</label>
    <input id="binary" type="text" placeholder="./chall" spellcheck="false">
    <label>libc path (for libc / onegadget / pwn)</label>
    <input id="libc" type="text" placeholder="./libc.so.6" spellcheck="false">
    <label>Leaks (for libcid / pwn --libc-leak)</label>
    <input id="leaks" type="text" placeholder="puts=0x7f..340 printf=0x..f90" spellcheck="false">
    <div class="row">
      <div><label>Output file</label><input id="out" type="text" placeholder="exploit.py" spellcheck="false"></div>
      <div><label>Host</label><input id="host" type="text" placeholder="ctf.io" spellcheck="false"></div>
      <div><label>Port</label><input id="port" type="number" placeholder="1337"></div>
    </div>
    <label class="check"><input id="auto_offset" type="checkbox"> auto-offset (runs the binary)</label>
    <label class="check"><input id="download" type="checkbox"> libcid: download matched libc</label>
    <div class="btns">
      <button class="go" onclick="run('triage')">Triage</button>
      <button onclick="run('rop')">ROP</button>
      <button onclick="run('offset')">Offset</button>
      <button onclick="run('pwn')">Pwn</button>
      <button onclick="run('heap')">Heap</button>
      <button onclick="run('libc')">libc</button>
      <button onclick="run('onegadget')">onegadget</button>
      <button onclick="run('libcid')">libcid</button>
    </div>
    <p class="hint">Server runs locally. <b>offset</b> and <b>auto-offset</b> execute the target binary.</p>
  </div>
  <div class="out">
    <pre id="output">pick a binary and an action &rarr;</pre>
    <div id="filebox"></div>
  </div>
</main>
<script>
const TOKEN = "__TOKEN__";
const $ = id => document.getElementById(id);
async function run(action){
  const payload = {action,
    binary:$('binary').value, libc:$('libc').value, leaks:$('leaks').value,
    out:$('out').value, host:$('host').value, port:$('port').value,
    length:200, level:0, auto_offset:$('auto_offset').checked,
    download:$('download').checked};
  $('output').textContent = 'running ' + action + ' ...';
  $('filebox').innerHTML = '';
  try {
    const r = await fetch('/api/run', {method:'POST',
      headers:{'Content-Type':'application/json','X-CTFKit-Token':TOKEN},
      body:JSON.stringify(payload)});
    const j = await r.json();
    $('output').innerHTML = j.output || '(no output)';
    if (j.file){
      const box = $('filebox');
      const esc = s => s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
      box.innerHTML = '<div class="file"><h4><span>'+esc(j.file.name)+
        '</span><a class="copy" onclick="navigator.clipboard.writeText(this.closest(\'.file\').dataset.c)">copy</a></h4><pre>'+
        esc(j.file.content)+'</pre></div>';
      box.querySelector('.file').dataset.c = j.file.content;
    }
  } catch(e){ $('output').textContent = 'request failed: ' + e; }
}
</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    token = ""

    def log_message(self, *a):
        pass  # keep the console quiet

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?")[0] in ("/", "/index.html"):
            page = PAGE.replace("__TOKEN__", self.token).replace("__VERSION__", __version__)
            self._send(200, page)
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        # always drain the request body first -- not reading it before replying
        # with an error makes some clients see a connection reset, not the status
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        if self.path.split("?")[0] != "/api/run":
            self._send(404, "not found", "text/plain")
            return
        if self.headers.get("X-CTFKit-Token", "") != self.token:
            self._send(403, '{"error":"bad token"}', "application/json")
            return
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            self._send(400, '{"error":"bad json"}', "application/json")
            return
        result = run_action(payload)
        self._send(200, json.dumps(result), "application/json")


def make_server(host="127.0.0.1", port=8777):
    """Create the server. Returns (httpd, token). Port 0 picks a free port."""
    token = secrets.token_urlsafe(16)
    handler = type("_BoundHandler", (_Handler,), {"token": token})
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd, token


def serve(host="127.0.0.1", port=8777, open_browser=True):
    httpd, token = make_server(host, port)
    url = f"http://{host}:{httpd.server_address[1]}/"
    hdr("ctfkit web UI")
    good(f"serving at {C.CY}{url}{C.RST}")
    info("bound to localhost only; press Ctrl-C to stop")
    if open_browser:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        httpd.shutdown()


def cmd_web(port=8777, no_browser=False, host="127.0.0.1"):
    force_color()  # web output is always colorized, then converted to HTML
    serve(host=host, port=port, open_browser=not no_browser)
