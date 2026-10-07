# burpmap

A Burp-style site map and repeater addon for mitmproxy.

Two extra pages in mitmproxy's console UI:

* **`T` - Site map.** A tree of every host, directory and request seen, plus the
  URIs that were only ever *referenced* by a page and never requested. Those
  render grey, and `v` requests one.
* **`R` - Repeater.** Split panes, request left and response right, with the
  request editable as raw text and every send kept in a per-slot history.

Written against **mitmproxy 12.2.1**.

```
mitmproxy -s burpmap.py
```

It also loads under `mitmdump` and `mitmweb`, where the pages are skipped but the
site map is still built (see `sitemap.dump`).

## Site map

```
Site map  1 hosts  4 visited  8 unvisited   |   scope[on]: ^https://app\.example\.com/

▾ https://app.example.com
  ▾ /api
    ▾ /v1
      ○ /hidden-endpoint          GET  link
      ● /users                    GET  200   json     1.2k
  ● /index.html                   GET  200   html     325b
  ▾ /items
    ▸ {id}  (847)
  ▾ /login
      GET                         GET  200   html
      POST                        POST 302
  ○ /secret/never-clicked.html    GET  link
```

`●` requested · `○` seen as a link only · `▸`/`▾` collapsed/expanded ·

`{id} (847)` folded id-like parts of the URI.

| key | |
|---|---|
| `→` `l` / `←` `h` | expand / collapse (`←` on a leaf jumps to the parent) |
| `⏎` | expand a node, or open an already-requested row in the flow view. Never sends anything — that is `v` |
| `v` | **request** the focused URI (a directory node is requested as a plain GET) |
| `V` | request every unvisited URI below the cursor, after a confirmation |
| `ctrl-r` | send the focused request to the repeater |
| `S` / `X` | set the scope regex / the scope exclusion regex |
| `H` | scope to the host under the cursor |
| `s` | show everything vs. in-scope only |
| `c` | fold id-like parts of the URI into `{id}` for more concise output |
| `u` | show only URIs never requested |
| `A` / `Z` | expand / collapse the whole tree |
| `d` | drop the focused node or request from the map |
| `z` | clear the map |
| `w` / `L` | save / load the map as JSON |
| `b` | rebuild the map from the flows mitmproxy already holds |

`g` `G` `j` `k` and the rest of mitmproxy's global keys work as usual.

### Nothing is requested unless you ask

`v` and `V` are the only keys that put traffic on the wire. `⏎` on a grey row
says so and does nothing else: a discovered URI can be a logout link or a delete
endpoint, and firing one by reflex while exploring a target is not recoverable.

### Scope

Scope is a regex matched against the whole URL, plus an optional exclusion regex:

```
:set sitemap_scope ^https://app\.example\.com/
:set sitemap_scope_exclude /logout|\.(png|css|woff2)$
```

Scope only affects **what is displayed**. Capture is always complete, the same way
Burp keeps out-of-scope traffic behind the "show only in-scope items" checkbox, so
widening the scope later shows traffic recorded while it was narrow.

### Requesting a discovered URI

`v` synthesizes the request and puts it through mitmproxy's client replay, so the
response comes back through the normal pipeline and the grey row turns black by
itself. By default the request inherits `cookie`, `authorization`, `user-agent`,
`accept` and `accept-language` from the page the link was found on, and gets a
`Referer` pointing at it. Turn it off with `sitemap_visit_inherit_headers=false`.

## Repeater

Request on the left, response on the right, and the request is a raw text box.

```
 #1 POST /api/login    #2 GET /admin
 sends:  200  [401]  200      -- EDITING --  esc apply  ctrl-r apply+send  ctrl-x discard
──────────────────────────────────────────┬──────────────────────────────────────────
 Request (editing)                        │  Response  401  1.1k  83ms
POST /api/login HTTP/1.1                  │ HTTP/1.1 401 Unauthorized
Host: app.example.com                     │ content-type: application/json
Content-Type: application/json            │ www-authenticate: Bearer
Content-Length: 29                        │
                                          │ {"error":"bad credentials"}
{"user":"admin","pass":"x"}               │
```

| key | |
|---|---|
| `e` or `i` | edit the request as raw text |
| `esc` | apply the edit (stays in the editor if it does not parse) |
| `ctrl-r` | apply and send, without leaving the editor |
| `ctrl-x` | discard the edit |
| `tab` | move between the request and response panes |
| `r` | send |
| `[` `]` | previous / next slot |
| `<` `>` | previous / next send in the history |
| `c` | copy the selected send back over the template |
| `t` | back to the editable template |
| `⏎` | open the selected exchange in mitmproxy's flow view |
| `D` / `N` | delete / rename the slot |

`ctrl-r` in the flow list, flow view and site map creates a slot.

### Content-Length and Transfer-Encoding

`Content-Length` is recomputed on apply, as Burp does by default. Set
`repeater_update_content_length=false` to send exactly what you typed — a length
that disagrees with the body, duplicate `Content-Length` headers, or one sitting
next to `Transfer-Encoding`. A request carrying `Transfer-Encoding` is never
touched even with the option on, and a bodyless `GET` does not grow a
`Content-Length: 0` it never had. (mitmproxy rewrites `Content-Length` whenever
message content is assigned, so this takes explicit work; without it the option
would quietly do nothing.)

A body that is not valid UTF-8 is decoded as latin-1 for editing, which maps every
byte to one character and round-trips binary losslessly. The pane title says so
when that happens.

Each send is a snapshot, so the history is a real record and the template keeps
your edits. Sends are added to the flow list; the template is not, unless you open
it with `⏎`.

### Hackvertor tags

Hackvertor tags in the template are expanded when it is sent, so the request
keeps the payload in clear and can be edited and resent. They work in the
request line, header values and body, and nest innermost first:

```
<@urlencode>hello world<@/urlencode>                          -> hello%20world
<@base64encode>test<@/base64encode>                           -> dGVzdA==
<@base64decode>/w==<@/base64decode>                           -> the byte 0xff
<@urlencode><@base64encode>test<@/base64encode><@/urlencode>  -> dGVzdA%3D%3D
```

The tags are `urlencode`, `urldecode`, `base64encode` and `base64decode`; they
work on bytes, so binary results go on the wire as is. The send history shows the
expanded request. A tag that is unclosed, closed by the wrong tag or does not
decode stops the send with an error rather than sending the literal tag.
Content-Length is recomputed for the expanded body if it matched the template's
body; a deliberately wrong one is kept.

## Options

| option | default | |
|---|---|---|
| `sitemap_scope` | `""` | display scope regex, empty means everything |
| `sitemap_scope_exclude` | `""` | exclusion regex |
| `sitemap_scope_only` | `true` | apply the scope to the display |
| `sitemap_discovery` | `html, js, json` | where to look for unvisited URIs; `headers` is also available |
| `sitemap_discovery_max_body` | `2097152` | skip extraction for bodies bigger than this |
| `sitemap_discovery_max_links` | `500` | cap per response |
| `sitemap_collapse` | `false` | fold id-like segments into `{id}` |
| `sitemap_collapse_threshold` | `3` | how many id-like siblings before folding |
| `sitemap_unvisited_only` | `false` | hide requested URIs |
| `sitemap_visit_inherit_headers` | `true` | reuse the discovering page's session headers |
| `sitemap_visit_max` | `50` | cap on a single subtree visit |
| `sitemap_max_entries` | `100000` | stop growing the map past this |
| `repeater_update_content_length` | `true` | recompute Content-Length when a request is edited |

### Discovery sources

* `html` — `href`, `src`, `srcset`, `action` (with the form's method), `data`,
  `data-url`/`data-href`/`data-src`, `<meta refresh>`, honouring `<base href>`.
* `js` — quoted URLs and rooted paths in script bodies and inline `<script>`,
  plus `url()` in stylesheets. This is the noisy one, and the one that makes an
  SPA legible.
* `json` — the same sweep over JSON responses.
* `headers` — `Location`, `Refresh`, `Link`, `Content-Location`. Off by default.

Template literals (`` `/users/${id}` ``), format strings, MIME types and anything
containing whitespace are rejected.

## Commands

Everything is reachable from `:` without the pages:

```
sitemap.view              sitemap.visit             sitemap.visit.url <url> [method]
sitemap.visit.subtree     sitemap.open              sitemap.goto
sitemap.scope.set <re>    sitemap.scope.here        sitemap.scope.only.toggle
sitemap.collapse.toggle   sitemap.unvisited.toggle  sitemap.expand.all
sitemap.collapse.all      sitemap.delete            sitemap.clear
sitemap.rebuild           sitemap.save <path>       sitemap.load <path>
sitemap.dump
repeater.view             repeater.add <flows>      repeater.send
repeater.edit             repeater.apply            repeater.cancel
repeater.open             repeater.template         repeater.history.restore
repeater.slot.next        repeater.slot.prev        repeater.slot.delete
repeater.slot.rename <s>  repeater.history.next     repeater.history.prev
```

`sitemap.dump` prints an ASCII tree and `sitemap.visit.url` needs no cursor, so
both work under `mitmdump`:

```
mitmdump -s burpmap.py --set sitemap_scope='^https://app\.example\.com/'
```

To get a saved capture into the tree, load the flows and then run
`sitemap.rebuild` — reading a `.flow` file fires no request/response hooks.

## Tests

```
~/.local/share/pipx/venvs/mitmproxy/bin/python -m unittest discover -s tests -t .
~/.local/share/pipx/venvs/mitmproxy/bin/python tests/tui_smoke.py
```

The first is 176 unit tests over the tree, the link extractor, the raw HTTP
round trip, the addon hooks and the console integration. The second runs 32
checks: it starts a fixture site
and a real mitmproxy on a pty, presses keys and reads the screen back — including
the background attributes, so "the cursor row is highlighted" is a real
assertion rather than a claim.

## Notes and limits

* The site map survives a script reload (mitmproxy re-executes `burpmap.py` when
  it changes); the collected tree and the repeater slots are stashed on the
  master. Editing a file under `burpmap/` needs a restart, though — mitmproxy's
  reloader only re-executes the entry script, and the package stays cached in
  `sys.modules`.
* Opening a flow from the site map needs that flow to be in the flow list. If a
  view filter is hiding it, you get a message saying so rather than a jump.
* Discovery runs inline on each response. The body-size and link-count caps keep
  it bounded, but a huge minified bundle costs a few milliseconds.
