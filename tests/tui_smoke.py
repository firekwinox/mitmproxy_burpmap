#!/usr/bin/env python
"""End-to-end smoke test: drive the real mitmproxy console through a pty.

Not part of `unittest discover` - it starts a fixture web server and a real
mitmproxy, so it is slow and needs free ports. Run it by hand:

    ~/.local/share/pipx/venvs/mitmproxy/bin/python tests/tui_smoke.py

It exits non-zero if any check fails.
"""

import fcntl
import os
import pty
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ansiscreen import Screen  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MITM = os.path.expanduser("~/.local/share/pipx/venvs/mitmproxy/bin/mitmproxy")

FIXTURE = {
    "index.html": """<html><head><script src="/static/app.js"></script></head><body>
<a href="page2.html">page two</a>
<a href="/secret/never-clicked.html">never clicked</a>
<form action="/login" method="post"><input name=u></form>
<a href="/items/1">1</a><a href="/items/2">2</a>
<a href="/items/3">3</a><a href="/items/4">4</a>
</body></html>""",
    "page2.html": '<html><body><a href="/deeper/leaf.html">leaf</a></body></html>',
    "static/app.js": (
        'const API = "/api/v1/hidden-endpoint";\n'
        'fetch("/api/v1/users", {headers: {"accept": "application/json"}});\n'
        "const tpl = `/api/${id}/x`;\n"
    ),
    "secret/never-clicked.html": "<html>secret</html>",
    "deeper/leaf.html": "<html>leaf</html>",
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Term:
    def __init__(self, argv, cwd, rows=45, cols=150):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        env = dict(os.environ, TERM="xterm-256color", LANG="en_US.UTF-8")
        self.proc = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave, cwd=cwd, env=env,
            preexec_fn=os.setsid,
        )
        os.close(slave)
        self.screen_model = Screen(rows, cols)

    def drain(self, seconds=1.0):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.15)
            if not r:
                continue
            try:
                chunk = os.read(self.master, 1 << 20)
            except OSError:
                break
            if not chunk:
                break
            self.screen_model.feed(chunk.decode("utf8", "replace"))

    def send(self, keys="", wait=1.0) -> str:
        if keys:
            os.write(self.master, keys.encode())
        self.drain(wait)
        return self.screen_model.flat()

    def highlighted(self):
        return self.screen_model.highlighted()

    def close(self):
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception:
            pass


RESULTS = []


def check(name, screen, *needles, absent=()):
    missing = [n for n in needles if n not in screen]
    present = [n for n in absent if n in screen]
    ok = not missing and not present
    detail = f" missing={missing}" if missing else ""
    detail += f" unexpected={present}" if present else ""
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{detail}")
    RESULTS.append(ok)
    return screen


def main():
    root = tempfile.mkdtemp(prefix="burpmap-fixture-")
    for name, body in FIXTURE.items():
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(body)

    site_port, proxy_port = free_port(), free_port()
    site = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(site_port)],
        cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{site_port}"
    term = Term([MITM, "--listen-port", str(proxy_port), "-s", "burpmap.py"], cwd=HERE)
    try:
        term.drain(4)
        for path in ("/index.html", "/page2.html", "/static/app.js"):
            subprocess.run(
                ["curl", "-s", "-x", f"http://127.0.0.1:{proxy_port}",
                 "-o", os.devnull, base + path], timeout=20)
        term.drain(2)

        s = check("T opens the site map", term.send("T"),
                  "Site map", f"127.0.0.1:{site_port}",
                  "never-clicked.html", "hidden-endpoint")
        check("our quick-help row is shown", s, "Visit", "Send", "Scope", "{id}")

        check("c folds id siblings", term.send("c"), "{id}", absent=("/1 GET link",))
        term.send("c")
        check("u shows unvisited only", term.send("u"), "unvisited only",
              absent=("/index.html",))
        term.send("u")
        check("? documents the sitemap keys", term.send("?"),
              "Request the focused URI", "Toggle {id} collapsing")
        term.send("q")

        # G lands on the last row (/static/app.js); two k's reach the grey
        # /secret/never-clicked.html above it.
        term.send("G")
        check("the cursor row is highlighted", " ".join(term.highlighted()), "app.js")
        term.send("k")
        check("the highlight follows the cursor", " ".join(term.highlighted()),
              "/static", absent=("app.js",))
        term.send("k")
        check("the highlight reaches the grey row",
              " ".join(term.highlighted()), "never-clicked.html")
        check("enter on a grey row does not request it", term.send("\r", 2.0),
              "never been requested", absent=("Requesting",))
        check("the grey row is still grey after enter", term.send(""),
              "never-clicked.html GET link")
        check("v requests the focused grey URI", term.send("v", 3.0), "Requesting")
        check("the grey row turned black", term.send("", 1.0),
              "never-clicked.html GET 200")

        term.send("\x12")  # ctrl-r
        check("R opens the repeater with the new slot", term.send("R"),
              "Repeater", "never-clicked", "not sent yet")
        check("r sends the slot and records history", term.send("r", 3.5),
              "sends:", "Response")
        open("/tmp/burpmap-repeater.txt", "w").write(term.screen_model.text())

        # --- the raw-text editor -------------------------------------------
        term.send("t")  # back to the editable template
        check("e opens the raw text editor", term.send("e"),
              "EDITING", "GET /secret/never-clicked.html HTTP/1.1")
        # cursor starts at the top; drop to line 2 and insert a header
        term.send("\x1b[B")      # down
        term.send("\x1b[H")      # home
        term.send("X-Burpmap: smoke\r")
        check("typed text lands in the editor", term.send(""), "X-Burpmap: smoke")
        check("esc applies the edit", term.send("\x1b", 1.5), "applied",
              absent=("EDITING",))
        check("the applied header is in the request", term.send(""),
              "X-Burpmap: smoke")
        check("the send carries the edit", term.send("r", 3.5), "sends:")
        check("two sends are recorded", term.send(""), "X-Burpmap: smoke")

        term.send("t")
        term.send("e")
        term.send("ZZZZ")
        check("ctrl-x discards the edit", term.send("\x18"),
              "discarded", absent=("ZZZZ", "EDITING"))

        term.send("e")
        check("ctrl-r applies and sends from inside the editor",
              term.send("\x12", 3.5), "sends:", absent=("EDITING",))

        check("tab moves between the panes", term.send("\t"), "Response")

        check("q leaves the repeater", term.send("q"), "Site map")
        check("q leaves the site map", term.send("q"), "Flow:")
        check("E still opens the event log", term.send("E"), "Events")
        term.send("q")

        # Both pages have to work in a split layout: two stacks, two widgets.
        term.send("-")
        check("split layout is up", term.send(""), "Events")
        term.send("T")
        check("site map renders in a split pane", term.send(""),
              "Site map", "never-clicked.html")
        term.send("\x1b[Z")  # shift-tab: focus the other pane
        term.send("R")
        check("both pages render side by side", term.send(""),
              "Repeater", "Site map")
        term.send("q")
        term.send("-")
        term.send("-")
        term.send("q")

        # A reload must not strand a dead widget, double-bind keys, or lose data.
        os.utime(os.path.join(HERE, "burpmap.py"), None)
        term.drain(4)
        check("site map survives a script reload", term.send("T", 2.0),
              "Site map", "never-clicked.html")
        check("no duplicate keybindings after reload", term.send("?", 2.0),
              "Request the focused URI")
        term.send("q")
        check("repeater survives a script reload", term.send("R", 2.0),
              "Repeater", "sends:")
    finally:
        term.close()
        site.terminate()
        shutil.rmtree(root, ignore_errors=True)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} TUI checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
