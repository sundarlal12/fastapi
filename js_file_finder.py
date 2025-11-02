# #!/usr/bin/env python3
# """
# js_finder_spider.py

# Usage:
#     python js_finder_spider.py https://example.com --workers 20 --max-depth 5 --same-domain --output js_list.txt

# Description:
#     Crawls starting URL, finds .js links in pages and inside .js files, follows them recursively.
# """
# import sys
# import argparse
# import re
# import threading
# from urllib.parse import urljoin, urlparse, urldefrag
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from collections import deque
# import requests
# from bs4 import BeautifulSoup

# # ---- Configurable defaults ----
# DEFAULT_WORKERS = 16
# DEFAULT_TIMEOUT = 12
# USER_AGENT = "Mozilla/5.0 (compatible; js-finder-spider/1.0; +https://example.com/bot)"
# # -------------------------------

# # Regex to find .js references inside JS/text
# _JS_URL_RE = re.compile(
#     r"""(?:
#         ["'](?P<rel>[^"']+?\.js(?:\?[^"']*)?)["']       # '...file.js' or "...file.js?qs"
#       | (?P<http>https?://[^\s"'()<>]+?\.js(?:\?[^"'()<>]*)?)  # http(s) absolute urls
#       | import\(\s*["'](?P<imp>[^"']+?\.js(?:\?[^"']*)?)["']\s*\)
#       | require\(\s*["'](?P<req>[^"']+?\.js(?:\?[^"']*)?)["']\s*\)
#     )""",
#     re.IGNORECASE | re.VERBOSE,
# )

# _HTML_JS_SRC_RE = re.compile(r'\.js(\?.*)?$', re.IGNORECASE)


# def normalize_url(base, link):
#     if not link:
#         return None
#     # Remove fragment
#     link = urldefrag(link)[0]
#     # Resolve relative to base
#     return urljoin(base, link)


# def extract_js_urls_from_html(base_url, html_text):
#     soup = BeautifulSoup(html_text, "html.parser")

#     urls = set()

#     # <script src="...">
#     for s in soup.find_all("script", src=True):
#         u = normalize_url(base_url, s["src"])
#         if u and _HTML_JS_SRC_RE.search(u):
#             urls.add(u)

#     # <link rel="modulepreload" href="..."> or rel=preload
#     for l in soup.find_all("link", href=True):
#         rel = (l.get("rel") or [])
#         href = l["href"]
#         if any("preload" in r or "modulepreload" in r or "module" in r for r in rel):
#             u = normalize_url(base_url, href)
#             if u and _HTML_JS_SRC_RE.search(u):
#                 urls.add(u)

#     # <a href="...js">
#     for a in soup.find_all("a", href=True):
#         u = normalize_url(base_url, a["href"])
#         if u and _HTML_JS_SRC_RE.search(u):
#             urls.add(u)

#     # Search in inline scripts for dynamically added scripts (very basic)
#     inline_texts = [tag.string or "" for tag in soup.find_all("script") if not tag.get("src")]
#     for t in inline_texts:
#         for m in _JS_URL_RE.finditer(t or ""):
#             candidate = (m.group("rel") or m.group("http") or m.group("imp") or m.group("req"))
#             if candidate:
#                 u = normalize_url(base_url, candidate)
#                 if u:
#                     urls.add(u)

#     return urls


# def extract_js_urls_from_js(base_url, js_text):
#     urls = set()
#     for m in _JS_URL_RE.finditer(js_text or ""):
#         candidate = (m.group("rel") or m.group("http") or m.group("imp") or m.group("req"))
#         if candidate:
#             u = normalize_url(base_url, candidate)
#             if u:
#                 urls.add(u)
#     return urls


# class JSFinder:
#     def __init__(self, start_url, workers=DEFAULT_WORKERS, timeout=DEFAULT_TIMEOUT,
#                  same_domain=True, max_depth=5, verbose=True):
#         self.start_url = start_url if start_url.endswith('/') else start_url
#         self.parsed_start = urlparse(start_url)
#         self.domain = self.parsed_start.netloc
#         self.scheme = self.parsed_start.scheme
#         self.session = requests.Session()
#         self.session.headers.update({"User-Agent": USER_AGENT})
#         self.workers = workers
#         self.timeout = timeout
#         self.same_domain = same_domain
#         self.max_depth = max_depth
#         self.verbose = verbose

#         self.lock = threading.Lock()
#         self.found = set()
#         self.visited = set()
#         self.results = set()

#     def in_domain(self, url):
#         if not self.same_domain:
#             return True
#         p = urlparse(url)
#         return p.netloc == self.domain

#     def log(self, *args, **kwargs):
#         if self.verbose:
#             print(*args, **kwargs)

#     def fetch(self, url):
#         try:
#             r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
#             r.raise_for_status()
#             return r
#         except Exception as e:
#             self.log(f"[! fetch error] {url} -> {e}")
#             return None

#     def worker(self, url, depth):
#         """Process a URL which may be HTML or JS. Return discovered js links."""
#         if depth > self.max_depth:
#             return set()

#         # Skip if not in domain (optionally)
#         if not self.in_domain(url):
#             self.log(f"[skip external] {url}")
#             return set()

#         # Avoid re-visits
#         with self.lock:
#             if url in self.visited:
#                 return set()
#             self.visited.add(url)

#         self.log(f"[visit d={depth}] {url}")

#         r = self.fetch(url)
#         if not r:
#             return set()

#         ct = r.headers.get("Content-Type", "").lower()
#         discovered = set()

#         try:
#             text = r.text
#         except Exception:
#             text = r.content.decode('utf-8', errors='ignore')

#         # Heuristic: if URL ends with .js or content-type includes javascript, parse as JS
#         if url.lower().split('?')[0].endswith(".js") or "javascript" in ct or "application/x-javascript" in ct:
#             # It's JS: extract more js links from text
#             discovered |= extract_js_urls_from_js(url, text)
#             # store result
#             with self.lock:
#                 self.results.add(url)
#         else:
#             # Assume HTML: extract script tags and JS links
#             discovered |= extract_js_urls_from_html(url, text)

#             # Also add any .js mentioned in page body via regex (fallback)
#             for m in _JS_URL_RE.finditer(text or ""):
#                 cand = (m.group("rel") or m.group("http") or m.group("imp") or m.group("req"))
#                 if cand:
#                     discovered.add(normalize_url(url, cand))

#         # Filter discovered URLs: normalize, same-domain constraint
#         filtered = set()
#         for u in discovered:
#             if not u:
#                 continue
#             # remove fragments and whitespace
#             u = urldefrag(u.strip())[0]
#             if not u:
#                 continue
#             if self.same_domain and urlparse(u).netloc != self.domain:
#                 # skip external if same_domain set
#                 continue
#             filtered.add(u)

#         # Add any .js discovered from HTML that are .js files to results immediately
#         with self.lock:
#             for u in filtered:
#                 if u.lower().split('?')[0].endswith(".js"):
#                     self.results.add(u)

#         return filtered

#     def run(self):
#         # BFS-style queue with depth tracking
#         queue = deque()
#         queue.append((self.start_url, 0))

#         # Use ThreadPoolExecutor to parallelize fetching discovered URLs
#         with ThreadPoolExecutor(max_workers=self.workers) as exc:
#             futures = {}
#             # Kick off initial batch
#             while queue or futures:
#                 # flood the pool up to workers
#                 while queue and len(futures) < self.workers:
#                     url, depth = queue.popleft()
#                     # schedule
#                     f = exc.submit(self.worker, url, depth)
#                     futures[f] = (url, depth)

#                 # wait for any to complete
#                 done, _ = as_completed(futures), None
#                 # iterate over completed futures (one-by-one)
#                 for fut in list(futures):
#                     if fut.done():
#                         url, depth = futures.pop(fut)
#                         try:
#                             discovered = fut.result()
#                         except Exception as e:
#                             self.log(f"[error result] {url} -> {e}")
#                             discovered = set()
#                         # enqueue newly discovered links (increase depth)
#                         for u in discovered:
#                             # Avoid already visited or queued
#                             with self.lock:
#                                 if u in self.visited:
#                                     continue
#                             if depth + 1 <= self.max_depth:
#                                 queue.append((u, depth + 1))
#                         # break to allow pool to accept new tasks
#                         break
#                 else:
#                     # no future done yet: wait briefly
#                     continue

#         return self.results


# def main():
#     parser = argparse.ArgumentParser(description="JS Finder Spider — find all .js files reachable from a start URL")
#     parser.add_argument("start_url", help="Start URL (e.g. https://example.com)")
#     parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of threads")
#     parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
#     parser.add_argument("--no-same-domain", dest="same_domain", action="store_false", help="Allow following external domains")
#     parser.add_argument("--same-domain", dest="same_domain", action="store_true", help="Restrict to same domain (default)")
#     parser.add_argument("--max-depth", type=int, default=5, help="Max recursive depth (pages -> js -> more js)")
#     parser.add_argument("--output", help="Write found .js URLs to file (one per line)")
#     parser.add_argument("--quiet", action="store_true", help="Less verbose output")
#     args = parser.parse_args()

#     jf = JSFinder(
#         start_url=args.start_url,
#         workers=args.workers,
#         timeout=args.timeout,
#         same_domain=args.same_domain,
#         max_depth=args.max_depth,
#         verbose=not args.quiet,
#     )

#     found = jf.run()
#     found_list = sorted(found)
#     print("\n=== Found .js files ===")
#     for u in found_list:
#         print(u)

#     if args.output:
#         with open(args.output, "w", encoding="utf-8") as f:
#             for u in found_list:
#                 f.write(u + "\n")
#         print(f"Saved {len(found_list)} entries to {args.output}")


# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
"""
js_finder_spider.py

Usage:
  python js_finder_spider.py https://example.com --workers 20 --max-depth 5 --same-domain --output js_list.txt
  python js_finder_spider.py https://example.com --workers 20 --max-depth 5 --csv js_list.csv

Description:
  Crawls starting URL, finds .js links in pages and inside .js files, follows them recursively.
  - Cleans malformed tokens (e.g., '?|\\| ...')
  - Same-domain only by default (toggle with --no-same-domain)
  - Verifies .js with HEAD (working-only results)
  - Can save plain list (--output) or CSV with discovery source (--csv)
"""
import sys
import argparse
import re
import csv
import threading
from urllib.parse import urljoin, urlparse, urldefrag, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque, defaultdict
import requests
from bs4 import BeautifulSoup

# ---- Configurable defaults ----
DEFAULT_WORKERS = 16
DEFAULT_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (compatible; js-finder-spider/2.1; +https://example.com/bot)"
# -------------------------------

# Regex to find .js references inside code
_JS_URL_RE = re.compile(
    r"""(?:
        ["'](?P<rel>[^"']+?\.js(?:\?[^"']*)?)["']       # 'file.js' or "file.js?ver"
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


def normalize_url(base, link):
    if not link:
        return None
    link = urldefrag(link)[0]
    return urljoin(base, link)


def extract_js_urls_from_html(base_url, html_text):
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


def extract_js_urls_from_js(base_url, js_text):
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
    def __init__(self, start_url, workers=DEFAULT_WORKERS, timeout=DEFAULT_TIMEOUT,
                 same_domain=True, max_depth=5, verbose=True):
        self.start_url = start_url if start_url.endswith('/') else start_url
        self.parsed_start = urlparse(start_url)
        self.domain = self.parsed_start.netloc
        self.scheme = self.parsed_start.scheme
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
            return r.status_code < 400
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
            # If this URL itself is a JS file, validate & record (found on itself or previous referrer)
            self._record_js(url, found_on_url=url)
            discovered |= extract_js_urls_from_js(url, text)
            # every discovered JS from this file was "found on" this JS file
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
            # record provenance for JS found on this HTML page
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


def main():
    parser = argparse.ArgumentParser(description="JS Finder Spider — find and validate .js files (with provenance)")
    parser.add_argument("start_url", help="Start URL (e.g. https://example.com)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Thread count")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    parser.add_argument("--max-depth", type=int, default=5, help="Max recursion depth")
    parser.add_argument("--no-same-domain", dest="same_domain", action="store_false", help="Allow external domains")
    parser.add_argument("--same-domain", dest="same_domain", action="store_true", help="Restrict to same domain (default)")
    parser.add_argument("--output", help="Save working JS URLs (one per line)")
    parser.add_argument("--csv", help="Save CSV with columns: js_url,found_on")
    parser.add_argument("--quiet", action="store_true", help="Less verbose output")
    args = parser.parse_args()

    jf = JSFinder(
        start_url=args.start_url,
        workers=args.workers,
        timeout=args.timeout,
        same_domain=args.same_domain,
        max_depth=args.max_depth,
        verbose=not args.quiet,
    )

    working_js, sources = jf.run()
    working_js = sorted(working_js)

    print("\n=== Working .js files ===")
    for u in working_js:
        print(u)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for u in working_js:
                f.write(u + "\n")
        print(f"\n✅ Saved {len(working_js)} working JS URLs to {args.output}")

    if args.csv:
        rows = 0
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["js_url", "found_on"])
            for js_url in working_js:
                srcs = sorted(sources.get(js_url, []) or [""])
                # one row per source (clear for analysis)
                for src in srcs:
                    writer.writerow([js_url, src])
                    rows += 1
        print(f"✅ Saved {rows} rows to {args.csv} (js_url, found_on)")


if __name__ == "__main__":
    main()
