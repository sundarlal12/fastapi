# #!/usr/bin/env python3
# import sys
# import subprocess
# import os
# import shutil   # ✅ for removing tmp folder after execution
# from js_finder_spider import js_finder_by_domain

# def main():
#     if len(sys.argv) < 3:
#         print("\nUsage: python3 js_code.py <url> <scan_id>\n")
#         print("Example:")
#         print("  python3 js_code.py https://vaptlabs.com SCAN123\n")
#         sys.exit(1)

#     url = sys.argv[1]
#     scan_id = sys.argv[2]

#     print(f"\n🔍 Crawling: {url}\n")
#     js_urls = js_finder_by_domain(url, workers=24, max_depth=5)
#     print(f"✅ Found {len(js_urls)} JS URLs")

#     if not js_urls:
#         print("\n❌ No JS URLs found. Exiting.\n")
#         sys.exit(1)

#     # --------------- Save URLs into a temporary file for jsDownloader.py ---------------
#     tmp_dir = "tmp"
#     os.makedirs(tmp_dir, exist_ok=True)
#     url_list_file = os.path.join(tmp_dir, f"{scan_id}_urls.txt")

#     with open(url_list_file, "w") as f:
#         f.write("\n".join(js_urls))

#     # --------------- Run JS Downloader ---------------
#     print("\n⬇️ Running jsDownloader.py ...\n")
#     dl_proc = subprocess.run(["python3", "jsDownloader.py", url_list_file, scan_id])

#     if dl_proc.returncode != 0:
#         print("\n❌ jsDownloader failed. Stopping.\n")
#         shutil.rmtree(tmp_dir, ignore_errors=True)
#         sys.exit(1)

#     # --------------- Run JS Beautifier ---------------
#     print("\n✨ Running jsBeautifier.py ...\n")
#     beaut_proc = subprocess.run(["python3", "jsBeautifier.py", scan_id])

#     # --------------- Cleanup tmp folder ---------------
#     print("\n🧹 Cleaning up temp files...\n")
#     shutil.rmtree(tmp_dir, ignore_errors=True)

#     if beaut_proc.returncode == 0:
#         print("\n✅ All steps completed successfully!\n")
#     else:
#         print("\n⚠️ Beautifier finished with errors.\n")

#     print(f"📂 Final results in: {scan_id}/")


# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
import sys
import subprocess
import os
import shutil   # ✅ for removing tmp folder after execution
import re
import requests
from pathlib import Path
from urllib.parse import urlparse
from js_finder_spider import js_finder_by_domain

REQUEST_TIMEOUT = 8



import random

def get_geonode_proxy():
    PORT = random.choice(range(10000, 11000))  # rotation
    username = "geonode_I3kPzwLXUc-country-gb"
    password = "f64059fc-d2c7-44a1-ac32-f505b81610ab"
    host = f"premium-residential.geonode.com:{PORT}"

    proxy_url = f"http://{username}:{password}@{host}"

    return {
        "http": proxy_url,
        "https": proxy_url
    }


import requests
SESSION = requests.Session()

def fetch_html(url: str) -> str:
    try:
        proxies = get_geonode_proxy()  # 👈 rotating residential IP

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/123.0.0 Safari/537.36"
            )
        }

        resp = SESSION.get(url, headers=headers, proxies=proxies, timeout=30)
        resp.raise_for_status()
        return resp.text

    except Exception as e:
        return f"[ERROR fetching HTML] {e}"




def _has_scheme(u: str) -> bool:
    return re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', u) is not None

# def _probe(url: str) -> bool:
#     """Return True if target is reachable (2xx/3xx considered OK)."""
#     try:
#         r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
#         return 200 <= r.status_code < 400
#     except requests.RequestException:
#         return False






import random

CHROME_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
]

HARDCODED_COOKIE = (
    "cf_clearance=xyz123; "
    "sessionid=abcd1234efgh5678; "
    "auth=TOKEN987654321; "
)


def get_browser_headers():
    return {
        "User-Agent": random.choice(CHROME_UAS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://google.com/",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "no-cache",
        "Cookie": HARDCODED_COOKIE,     # 🔥 Always apply hardcoded cookies
    }



def _probe(url: str) -> bool:
    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers=get_browser_headers()
        )
        return 200 <= r.status_code < 400
    except:
        return False





def normalize_url(user_input: str) -> str:
    """
    If no scheme is present, try https:// first, then http://.
    Choose the first that responds; otherwise return https://<host> by default.
    """
    raw = user_input.strip()

    # If scheme already present, just return it
    if _has_scheme(raw):
        return raw

    https = f"https://{raw}"
    http  = f"http://{raw}"

    print(f"ℹ️ No scheme provided. Probing {https} then {http} ...")
    if _probe(https):
        print("✅ Using HTTPS (reachable).")
        return https
    if _probe(http):
        print("⚠️ HTTPS failed, using HTTP (reachable).")
        return http

    # Neither responded — prefer HTTPS anyway
    print("⚠️ Neither HTTPS nor HTTP responded. Proceeding with HTTPS.")
    return https

def cleanup_originals(root_dir: str, aggressive: bool = False) -> None:
    """
    Delete original .js files after beautification.
    - Safe (default): delete an original foo.js only if foo_beautified.js exists.
    - Aggressive: delete every .js that does NOT end with _beautified.js.
    """
    root = Path(root_dir)
    deleted = 0
    kept = 0

    for p in root.rglob("*.js"):
        name = p.name

        # Always keep beautified outputs
        if name.endswith("_beautified.js"):
            kept += 1
            continue

        if aggressive:
            try:
                p.unlink()
                deleted += 1
                print(f"🗑️  deleted (aggressive) → {p.relative_to(root)}")
            except Exception as e:
                print(f"⚠️ could not delete {p}: {e}")
            continue

        # Safe mode: only delete if the corresponding beautified file exists
        beautified_candidate = p.with_name(p.stem + "_beautified.js")
        if beautified_candidate.exists():
            try:
                p.unlink()
                deleted += 1
                print(f"🗑️  deleted original → {p.relative_to(root)}")
            except Exception as e:
                print(f"⚠️ could not delete {p}: {e}")
        else:
            kept += 1

    mode = "aggressive" if aggressive else "safe"
    print(f"🧹 Cleanup done ({mode}): deleted={deleted}, kept={kept}")

def main():
    if len(sys.argv) < 3:
        print("\nUsage: python3 js_code.py <url-or-domain> <scan_id> [--aggressive-cleanup]\n")
        print("Example:")
        print("  python3 js_code.py vaptlabs.com SCAN123\n")
        print("  python3 js_code.py https://vaptlabs.com SCAN123 --aggressive-cleanup\n")
        sys.exit(1)

    # Parse args
    raw_input_url = sys.argv[1]
    scan_id = sys.argv[2]
    aggressive_cleanup = ("--aggressive-cleanup" in sys.argv[3:])

    url = normalize_url(raw_input_url)

    print(f"\n🔍 Crawling: {url}\n")


    html_content = fetch_html(url)
    print("\n📄 FULL HTML CONTENT BELOW:\n")
    print(html_content)
    print("\n---------- END OF HTML ----------\n")

    js_urls = js_finder_by_domain(url, workers=24, max_depth=5)
    print(f"✅ Found {len(js_urls)} JS URLs")

    if not js_urls:
        print("\n❌ No JS URLs found. Exiting.\n")
        sys.exit(1)

    # --------------- Save URLs into a temporary file for jsDownloader.py ---------------
    tmp_dir = "tmp"
    os.makedirs(tmp_dir, exist_ok=True)
    url_list_file = os.path.join(tmp_dir, f"{scan_id}_urls.txt")

    with open(url_list_file, "w") as f:
        f.write("\n".join(js_urls))

    # --------------- Run JS Downloader ---------------
    print("\n⬇️ Running jsDownloader.py ...\n")
    dl_proc = subprocess.run(["python3", "jsDownloader.py", url_list_file, scan_id])

    if dl_proc.returncode != 0:
        print("\n❌ jsDownloader failed. Stopping.\n")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        sys.exit(1)

    # --------------- Run JS Beautifier ---------------
    print("\n✨ Running jsBeautifier.py ...\n")
    beaut_proc = subprocess.run(["python3", "jsBeautifier.py", scan_id])

    # --------------- Cleanup originals (post-beautify) ---------------
    # your downloader/beautifier should output into a directory named exactly <scan_id> or scan_id_*
    # Resolve the actual output directory reliably:
    # Prefer exact match, else fallback to first scan_id_* dir containing files.
    scan_root = None
    exact = Path(scan_id)
    if exact.exists() and exact.is_dir():
        scan_root = exact
    else:
        # fallback: find a folder that starts with scan_id (common when prefixed scan_id_<uuid>)
        candidates = [p for p in Path(".").glob(f"{scan_id}*") if p.is_dir()]
        if candidates:
            # pick the one that actually contains JS content
            candidates.sort()
            for c in candidates:
                if any(c.rglob("*.js")):
                    scan_root = c
                    break

    if scan_root is not None:
        print(f"\n🧹 Post-beautify cleanup in: {scan_root}\n")
        cleanup_originals(str(scan_root), aggressive=aggressive_cleanup)
    else:
        print("\n⚠️ Could not locate scan output directory for cleanup.\n")

    # --------------- Cleanup tmp folder ---------------
    print("\n🧽 Cleaning up temp files...\n")
    shutil.rmtree(tmp_dir, ignore_errors=True)

    if beaut_proc.returncode == 0:
        print("\n✅ All steps completed successfully!\n")
    else:
        print("\n⚠️ Beautifier finished with errors.\n")

    print(f"📂 Final results in: {scan_root if scan_root else scan_id}/")

if __name__ == "__main__":
    main()
