#!/usr/bin/env python3
"""
js_finder_spider.py

Features:
- Crawl starting URL; find .js links in HTML and inside .js files; follow recursively.
- Cleans malformed tokens (like '?|\\|' fragments).
- Validates reachable JS via HEAD (adds on GET if needed).
- Same-domain only by default (toggle with --no-same-domain).
- Importable function `js_finder_by_domain(url, ...)` returns a list (and optional provenance).
- CLI flags to print arrays, JSON, or also save a simple text list.

Usage examples:
  # print arrays (Python repr)
  python js_finder_spider.py https://example.com --workers 20 --max-depth 5 --same-domain

  # print arrays as JSON (great for piping to dashboards)
  python js_finder_spider.py https://example.com --json

  # also save only working JS URLs to a file
  python js_finder_spider.py https://example.com --output js_list.txt
"""

import argparse
import json
import re
import threading
from urllib.parse import urljoin, urlparse, urldefrag, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque, defaultdict
import requests
from bs4 import BeautifulSoup

# ---- Configurable defaults ----
DEFAULT_WORKERS = 16
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_DEPTH = 5
USER_AGENT = "Mozilla/5.0 (compatible; js-finder-spider/2.3; +https://example.com/bot)"
# -------------------------------

# Regex to find .js references inside code
_JS_URL_RE = re.compile(
    r"""(?:
        ["'](?P<rel>[^"']+?\.js(?:\?[^"']*)?)["']         # 'file.js' or "file.js?ver"
      | (?P<http>https?://[^\s"'()<>]+?\.js(?:\?[^"'()<>]*)?)  # absolute http(s)
      | import\(\s*["'](?P<imp>[^"']+?\.js(?:\?[^"']*)?)["']\s*\)
      | require\(\s*["'](?P<req>[^"']+?\.js(?:\?[^"']*)?)["']\s*\)
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# Clean weird regex fragments like ?|\|
_BAD_TRAIL = re.compile(r'[\?\|\\].*', re.IGNORECASE)
_HTML_JS_SRC_RE = re.compile(r'\.js(\?.*)?$', re.IGNORECASE)


def clean_js_url(raw_url: str):
    """Strip junk like ?|\\| or trailing wrappers/spaces; return only if contains .js."""
    if not raw_url:
        return None
    u = unquote(raw_url.strip())
    u = u.replace("\\/", "/")
    u = _BAD_TRAIL.sub("", u)              # remove weird trailing junk
    u = re.sub(r'[\"\'<>#{}\s]+$', '', u)  # trim bad trailing chars
    return u if ".js" in u.lower() else None


def normalize_url(base: str, link: str):
    if not link:
        return None
    link = urldefrag(link)[0]
    return urljoin(base, link)


def extract_js_urls_from_html(base_url: str, html_text: str):
    soup = BeautifulSoup(html_text, "html.parser")
    urls = set()

    # <script src="...">
    for s in soup.find_all("script", src=True):
        u = normalize_url(base_url, s["src"])
        if u and _HTML_JS_SRC_RE.search(u):
            urls.add(u)

    # <link rel="modulepreload|preload|module" href="...">
    for l in soup.find_all("link", href=True):
        rels = [r.lower() for r in (l.get("rel") or [])]
        href = l["href"]
        if any(r in ("preload", "modulepreload", "module") for r in rels):
            u = normalize_url(base_url, href)
            if u and _HTML_JS_SRC_RE.search(u):
                urls.add(u)

    # <a href="...js">
    for a in soup.find_all("a", href=True):
        u = normalize_url(base_url, a["href"])
        if u and _HTML_JS_SRC_RE.search(u):
            urls.add(u)

    # Inline script text for dynamic strings/imports
    for t in (tag.string or "" for tag in soup.find_all("script") if not tag.get("src")):
        for m in _JS_URL_RE.finditer(t or ""):
            candidate = (m.group("rel") or m.group("http") or m.group("imp") or m.group("req"))
            cleaned = clean_js_url(candidate)
            if cleaned:
                u = normalize_url(base_url, cleaned)
                if u:
                    urls.add(u)

    return urls


def extract_js_urls_from_js(base_url: str, js_text: str):
    urls = set()
    for m in _JS_URL_RE.finditer(js_text or ""):
        candidate = (m.group("rel") or m.group("http") or m.group("imp") or m.group("req"))
        cleaned = clean_js_url(candidate)
        if cleaned:
            u = normalize_url(base_url, cleaned)
            if u:
                urls.add(u)
    return urls


class JSFinder:
    def __init__(self, start_url: str, workers: int = DEFAULT_WORKERS, timeout: int = DEFAULT_TIMEOUT,
                 same_domain: bool = True, max_depth: int = DEFAULT_MAX_DEPTH, verbose: bool = True):
        self.start_url = start_url if start_url.endswith('/') else start_url
        self.parsed_start = urlparse(start_url)
        self.domain = self.parsed_start.netloc
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.workers = workers
        self.timeout = timeout
        self.same_domain = same_domain
        self.max_depth = max_depth
        self.verbose = verbose

        self.lock = threading.Lock()
        self.visited = set()
        self.working = set()                    # set of working JS URLs
        self.sources = defaultdict(set)         # js_url -> set of pages/js where found

    def log(self, *args):
        if self.verbose:
            print(*args)

    def in_domain(self, url):
        if not self.same_domain:
            return True
        return urlparse(url).netloc == self.domain

    def fetch(self, url):
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if r.status_code < 400:
                return r
        except Exception as e:
            self.log(f"[!] fetch error {url} -> {e}")
        return None

    def check_url_ok(self, url):
        """HEAD request to verify the file exists (status < 400)."""
        try:
            r = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            if r.status_code < 400:
                return True
            # Sometimes servers don't like HEAD; try GET quickly
            g = self.session.get(url, timeout=self.timeout, allow_redirects=True, stream=True)
            return g.status_code < 400
        except Exception:
            return False

    def _record_js(self, js_url, found_on_url):
        """Mark JS as working (if it is) and record provenance (where found)."""
        if not self.in_domain(js_url):
            return
        if self.check_url_ok(js_url):
            with self.lock:
                self.working.add(js_url)
                self.sources[js_url].add(found_on_url)

    def worker(self, url, depth):
        if depth > self.max_depth:
            return set()

        if not self.in_domain(url):
            return set()

        with self.lock:
            if url in self.visited:
                return set()
            self.visited.add(url)

        self.log(f"[depth={depth}] {url}")

        r = self.fetch(url)
        if not r:
            return set()

        ct = r.headers.get("Content-Type", "").lower()
        try:
            text = r.text
        except Exception:
            text = r.content.decode("utf-8", errors="ignore")

        discovered = set()

        # JS or HTML detection
        if url.lower().split("?")[0].endswith(".js") or "javascript" in ct:
            # This URL itself is JS
            self._record_js(url, found_on_url=url)
            discovered |= extract_js_urls_from_js(url, text)
            # Any discovered JS from this file was "found on" this JS file
            for u in list(discovered):
                if u.lower().split("?")[0].endswith(".js"):
                    self._record_js(u, found_on_url=url)
        else:
            discovered |= extract_js_urls_from_html(url, text)
            # Fallback: regex scan of body
            for m in _JS_URL_RE.finditer(text or ""):
                candidate = (m.group("rel") or m.group("http") or m.group("imp") or m.group("req"))
                cleaned = clean_js_url(candidate)
                if cleaned:
                    discovered.add(normalize_url(url, cleaned))
            # Record provenance for JS found on this HTML page
            for u in list(discovered):
                if u and u.lower().split("?")[0].endswith(".js"):
                    self._record_js(u, found_on_url=url)

        # Normalize + filter + enqueue for further crawling
        filtered = set()
        for u in discovered:
            if not u:
                continue
            u = urldefrag(u.strip())[0]
            if not u:
                continue
            if self.same_domain and urlparse(u).netloc != self.domain:
                continue
            filtered.add(u)

        return filtered

    def run(self):
        queue = deque([(self.start_url, 0)])
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {}
            while queue or futures:
                while queue and len(futures) < self.workers:
                    url, depth = queue.popleft()
                    fut = executor.submit(self.worker, url, depth)
                    futures[fut] = (url, depth)

                for fut in as_completed(list(futures.keys())):
                    url, depth = futures.pop(fut)
                    try:
                        new_urls = fut.result()
                    except Exception as e:
                        self.log(f"[error] {url}: {e}")
                        new_urls = set()
                    for u in new_urls:
                        with self.lock:
                            if u not in self.visited:
                                queue.append((u, depth + 1))
                    break  # allow fresh tasks to be queued
        return self.working, self.sources


# ---------- PUBLIC HELPER: call from anywhere ----------
def js_finder_by_domain(
    url: str,
    workers: int = DEFAULT_WORKERS,
    timeout: int = DEFAULT_TIMEOUT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    same_domain: bool = True,
    quiet: bool = True,
    with_sources: bool = False
):
    """
    Crawl `url` and return working .js URLs. Import and call this function from any script/API.

    Args:
        url (str): Target starting URL
        workers (int): Thread count
        timeout (int): Request timeout per URL
        max_depth (int): Crawl depth
        same_domain (bool): Restrict crawling to same domain
        quiet (bool): Disable verbose logging
        with_sources (bool): If True, also return where each JS was discovered

    Returns:
        list[str]  -> if with_sources=False
        tuple(list[str], list[dict]) -> if with_sources=True:
            (working_js_list, [{"js_url": ..., "found_on": [...]}, ...])
    """
    jf = JSFinder(
        start_url=url,
        workers=workers,
        timeout=timeout,
        same_domain=same_domain,
        max_depth=max_depth,
        verbose=not quiet,
    )
    working_js, sources = jf.run()
    working_js_list = sorted(list(working_js))

    if not with_sources:
        return working_js_list

    js_with_sources = [
        {"js_url": js_url, "found_on": sorted(list(sources[js_url]))}
        for js_url in working_js_list
    ]
    return working_js_list, js_with_sources
# -------------------------------------------------------


def parse_args():
    p = argparse.ArgumentParser(description="JS Finder Spider — arrays only (working URLs + where found)")
    p.add_argument("start_url", help="Start URL (e.g. https://example.com)")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Thread count")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    p.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Max recursion depth")
    p.add_argument("--no-same-domain", dest="same_domain", action="store_false", help="Allow external domains")
    p.add_argument("--same-domain", dest="same_domain", action="store_true", help="Restrict to same domain (default)")
    p.add_argument("--output", help="Also save working JS URLs (one per line)")
    p.add_argument("--json", action="store_true", help="Print arrays as JSON (otherwise Python repr)")
    p.add_argument("--quiet", action="store_true", help="Less verbose output")
    return p.parse_args()


def main():
    args = parse_args()

    # call the public helper so importers and CLI share identical behavior
    if args.json:
        urls, prov = js_finder_by_domain(
            args.start_url,
            workers=args.workers,
            timeout=args.timeout,
            max_depth=args.max_depth,
            same_domain=args.same_domain,
            quiet=args.quiet,
            with_sources=True
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                for u in urls:
                    f.write(u + "\n")
        print(json.dumps({"working_js_list": urls, "js_with_sources": prov}, indent=2))
    else:
        urls = js_finder_by_domain(
            args.start_url,
            workers=args.workers,
            timeout=args.timeout,
            max_depth=args.max_depth,
            same_domain=args.same_domain,
            quiet=args.quiet,
            with_sources=False
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                for u in urls:
                    f.write(u + "\n")
        print("\nworking_js_list =")
        print(urls)


if __name__ == "__main__":
    main()
