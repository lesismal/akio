#!/usr/bin/env python3
"""Link checker for the documentation site built by book/site.sh (standard library only).

Serves the site over HTTP under its base path (like GitHub Pages: missing paths get 404.html
with status 404), then fetches every HTML page of both books and of the API docs and checks:

  * every internal link and resource (href / src, honouring <base>) answers 200;
  * every #fragment names an element id (or <a name>) on the target page;
  * links to the published site (https://lesismal.github.io/only/...) resolve the same way
    locally: these are the guide links in the crates' rustdoc;
  * both books have the same pages (the language switch maps a page to the same path in the
    other language), the language picker and the API index exist, and a missing page returns
    the 404 page.

External links are only counted (`--external` lists them).

Usage:
  python3 book/check-site.py target/site [--base /only/] [--external]
  python3 book/check-site.py target/site --serve 8000     # just serve it for a browser
Exit status 1 on any problem.
"""
import argparse
import concurrent.futures
import functools
import html.parser
import http.client
import http.server
import pathlib
import re
import sys
import threading
import urllib.parse

PUBLISHED = "https://lesismal.github.io/only/"
LANGS = ("en", "zh-CN")


class Handler(http.server.SimpleHTTPRequestHandler):
    """Serves `directory` at `base`; everything else, and missing files, get 404.html."""

    base = "/"
    protocol_version = "HTTP/1.1"  # keep-alive

    def log_message(self, *args):
        pass

    def translate_path(self, path):
        path = urllib.parse.urlsplit(path).path
        if not path.startswith(self.base):
            return str(pathlib.Path(self.directory) / "\0missing")
        return super().translate_path("/" + path[len(self.base):])

    def send_error(self, code, message=None, explain=None):
        page = pathlib.Path(self.directory) / "404.html"
        if code != 404 or not page.is_file():
            return super().send_error(code, message, explain)
        body = page.read_bytes()
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []  # (attribute, value)
        self.ids = set()
        self.base = None
        self.refresh = None  # rustdoc's redirect pages: <meta http-equiv="refresh">

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for key in ("id",):
            if a.get(key):
                self.ids.add(a[key])
        if tag == "a" and a.get("name"):
            self.ids.add(a["name"])
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
            m = re.search(r"url=(.*)", a.get("content") or "", re.I)
            if m:
                self.refresh = m.group(1).strip()
        if tag == "base" and a.get("href") and self.base is None:
            self.base = a["href"]
        for key in ("href", "src"):
            if a.get(key) and tag in ("a", "link", "script", "img", "iframe", "source"):
                if tag == "link" and a.get("rel") in ("canonical", "preconnect", "dns-prefetch"):
                    continue
                self.links.append(a[key])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("site")
    ap.add_argument("--base", default="/only/")
    ap.add_argument("--external", action="store_true", help="list external links")
    ap.add_argument("--serve", type=int, metavar="PORT", help="only serve the site")
    args = ap.parse_args()
    site = pathlib.Path(args.site).resolve()
    base = args.base
    if not (base.startswith("/") and base.endswith("/")):
        sys.exit("--base must start and end with /")

    Handler.base = base
    handler = functools.partial(Handler, directory=str(site))
    http.server.ThreadingHTTPServer.request_queue_size = 256
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.serve or 0), handler)
    origin = f"http://127.0.0.1:{srv.server_address[1]}"
    if args.serve:
        print(f"serving {site} at {origin}{base}")
        srv.serve_forever()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    root = origin + base

    problems = []
    cache = {}  # url without fragment -> (status, Page or None)
    lock = threading.Lock()

    local = threading.local()  # one keep-alive connection per thread: no port exhaustion
    port = srv.server_address[1]

    def get(url):
        path = urllib.parse.urlsplit(url)
        target = path.path + (f"?{path.query}" if path.query else "")
        for attempt in range(5):
            conn = getattr(local, "conn", None)
            if conn is None:
                conn = local.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            try:
                conn.request("GET", target)
                r = conn.getresponse()
                return r.status, r.getheader("Content-Type", ""), r.read()
            except (OSError, http.client.HTTPException):
                conn.close()
                local.conn = None
                if attempt == 4:
                    raise
        raise AssertionError

    def fetch(url):
        with lock:
            if url in cache:
                return cache[url]
        status, ctype, body = get(url)
        page = None
        if status in (200, 404) and "html" in ctype and body:
            page = Page()
            page.feed(body.decode("utf-8", "replace"))
        with lock:
            cache[url] = (status, page)
        return status, page

    def internal(url):
        if url.startswith(PUBLISHED):
            return root + url[len(PUBLISHED):]
        return url if url.startswith(origin + "/") else None

    # Every HTML file of the site is a starting page.
    pages = sorted(p for p in site.rglob("*.html"))
    starts = [root + str(p.relative_to(site)) for p in pages]
    external = set()
    checked = 0

    def check_page(url):
        out = []
        status, page = fetch(url)
        if status != 200 or page is None:
            return [f"{url}: status {status}"], []
        doc_base = urllib.parse.urljoin(url, page.base) if page.base else url
        links = []
        for raw in page.links:
            if raw.startswith(("mailto:", "javascript:", "data:", "tel:")):
                continue
            target = urllib.parse.urljoin(doc_base, raw)
            if not target.startswith(("http://", "https://")):
                continue
            local = internal(target)
            if local is None:
                links.append(("ext", target))
                continue
            links.append(("int", local, raw))
        for item in links:
            if item[0] == "ext":
                continue
            local, raw = item[1], item[2]
            path, _, frag = local.partition("#")
            if raw.startswith("#"):
                path = url  # same page (a <base> must not turn it into another page)
            st, tp = fetch(path)
            if st == 404 and re.search(r"/(trait|type)\.impl/.*\.js$", path):
                continue  # rustdoc loads implementor lists optionally; none exist for some traits
            for _ in range(3):  # follow redirect pages for the fragment
                if st != 200 or tp is None or tp.refresh is None:
                    break
                path = urllib.parse.urljoin(path, tp.refresh)
                st, tp = fetch(path)
            if st != 200:
                out.append(f"{url}: {raw} -> {st}")
                continue
            if not frag or tp is None:
                continue
            if "/src/" in path and re.fullmatch(r"\d+(-\d+)?", frag):
                continue  # rustdoc source line numbers are handled by JavaScript
            if frag not in tp.ids and urllib.parse.unquote(frag) not in tp.ids:
                out.append(f"{url}: {raw} -> no id '{frag}'")
        return out, [i[1] for i in links if i[0] == "ext"]

    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        for out, ext in pool.map(check_page, starts):
            problems.extend(out)
            external.update(ext)
            checked += 1

    # The language switch maps a page to the same path in the other book.
    trees = {lang: {p.relative_to(site / lang) for p in (site / lang).rglob("*.html")} for lang in LANGS}
    for a, b in ((LANGS[0], LANGS[1]), (LANGS[1], LANGS[0])):
        for rel in sorted(trees[a] - trees[b]):
            problems.append(f"{a}/{rel}: no {b} counterpart (language switch would 404)")
    for must in ("index.html", "404.html", "en/index.html", "zh-CN/index.html", "api/index.html",
                 "api/only/index.html", "en/lang-switch.js", "zh-CN/lang-switch.js"):
        if fetch(root + must)[0] != 200:
            problems.append(f"{must}: missing")
    st, pg = fetch(root + "no/such/page.html")
    if st != 404 or pg is None or pg.base != base + "en/":
        problems.append(f"missing page: status {st}, expected 404 with the 404 page")

    for p in problems:
        print(p, file=sys.stderr)
    if args.external:
        for e in sorted(external):
            print("external:", e)
    print(f"{checked} pages, {len(cache)} URLs checked, {len(external)} external links "
          f"not followed, {len(problems)} problem(s)")
    srv.shutdown()
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
