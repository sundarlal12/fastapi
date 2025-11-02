# #!/usr/bin/env python3
# """
# jsDownloader.py

# Usage:
#   python jsDownloader.py <js_urls_file> <scan_id_folder> [--dl-workers 8] [--timeout 12] [--max-bytes 2000000]

# Description:
#   - Reads a file containing JS URLs (one per line).
#   - Downloads each JS (concurrent, size-capped) into the given folder.
#   - Does NOT beautify; that's step 2 (jsBeautifier.py).
#   - Writes a small manifest: <scan_id_folder>/download_manifest.json
# """

# import argparse
# import concurrent.futures
# import hashlib
# import json
# import os
# import sys
# import time
# from typing import List
# from urllib.parse import urlparse

# import requests

# USER_AGENT = "Mozilla/5.0 (compatible; vapt-jsdownloader/1.0)"
# DEFAULT_TIMEOUT = 12
# DEFAULT_DL_WORKERS = 8
# DEFAULT_MAX_BYTES = 2_000_000  # 2 MB

# def human_bytes(n: int) -> str:
#     if n is None:
#         return "?"
#     for unit in ["B", "KB", "MB", "GB"]:
#         if n < 1024.0:
#             return f"{n:.1f}{unit}"
#         n /= 1024.0
#     return f"{n:.1f}TB"

# def read_urls(path: str) -> List[str]:
#     urls = []
#     with open(path, "r", encoding="utf-8", errors="ignore") as f:
#         for line in f:
#             u = line.strip()
#             if not u or u.startswith("#"):
#                 continue
#             urls.append(u)
#     return urls

# def safe_output_name(url: str) -> str:
#     """
#     Build a safe filename from the URL path and append an 8-char SHA1 for uniqueness.
#     Keeps original extension if present, else ensure .js.
#     """
#     p = urlparse(url)
#     tail = (p.path or "/script.js").rsplit("/", 1)[-1] or "script.js"
#     if not tail.lower().endswith(".js"):
#         tail += ".js"
#     base, ext = os.path.splitext(tail)
#     h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]
#     return f"{base}_{h}{ext}"

# def download_js(url: str, timeout: int, max_bytes: int) -> dict:
#     headers = {"User-Agent": USER_AGENT}
#     try:
#         # HEAD (quick size/type check if provided)
#         hr = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
#         clen = hr.headers.get("Content-Length")
#         if clen:
#             try:
#                 if int(clen) > max_bytes:
#                     return {"ok": False, "url": url, "error": f"too_large({clen}>{max_bytes})"}
#             except ValueError:
#                 pass

#         # GET streaming with cap
#         r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)
#         r.raise_for_status()

#         buf = []
#         got = 0
#         for chunk in r.iter_content(65536):
#             if not chunk:
#                 continue
#             buf.append(chunk)
#             got += len(chunk)
#             if got > max_bytes:
#                 break

#         raw = b"".join(buf)
#         return {
#             "ok": True,
#             "url": url,
#             "status": r.status_code,
#             "size": len(raw),
#             "content_type": r.headers.get("Content-Type") or hr.headers.get("Content-Type"),
#             "raw": raw,
#         }
#     except Exception as e:
#         return {"ok": False, "url": url, "error": str(e)}

# def write_manifest(folder: str, data: dict):
#     path = os.path.join(folder, "download_manifest.json")
#     with open(path, "w", encoding="utf-8") as f:
#         json.dump(data, f, ensure_ascii=False, indent=2)

# def run(urls_file: str, scan_dir: str, dl_workers: int, timeout: int, max_bytes: int):
#     # prepare output dir
#     os.makedirs(scan_dir, exist_ok=True)

#     # read URL list
#     urls = read_urls(urls_file)
#     print(f"➡️  Will download {len(urls)} URLs into: {scan_dir} (<= {human_bytes(max_bytes)} each)")

#     saved, errors = [], []
#     t0 = time.time()
#     with concurrent.futures.ThreadPoolExecutor(max_workers=dl_workers) as pool:
#         futmap = {pool.submit(download_js, u, timeout, max_bytes): u for u in urls}
#         done = 0
#         for fut in concurrent.futures.as_completed(futmap):
#             url = futmap[fut]
#             done += 1
#             try:
#                 res = fut.result()
#             except Exception as e:
#                 errors.append({"url": url, "error": f"executor: {e}"})
#                 continue

#             if not res.get("ok"):
#                 errors.append({"url": url, "error": res.get("error")})
#                 continue

#             # choose filename & ensure uniqueness
#             name = safe_output_name(url)
#             outp = os.path.join(scan_dir, name)
#             base, ext = os.path.splitext(outp)
#             i = 2
#             while os.path.exists(outp):
#                 outp = f"{base}_{i}{ext}"
#                 i += 1

#             try:
#                 with open(outp, "wb") as f:
#                     f.write(res["raw"])
#                 saved.append({
#                     "url": url,
#                     "path": outp,
#                     "size": res.get("size"),
#                     "content_type": res.get("content_type"),
#                 })
#             except Exception as e:
#                 errors.append({"url": url, "error": f"write: {e}"})

#             # progress pulse
#             if done % max(1, len(urls)//10 or 1) == 0:
#                 elapsed = time.time() - t0
#                 pct = int(done / max(1, len(urls)) * 100)
#                 print(f"  ... {done}/{len(urls)} ({pct}%) in {elapsed:.1f}s")

#     manifest = {
#         "created_at": int(time.time()),
#         "total_urls": len(urls),
#         "total_saved": len(saved),
#         "total_errors": len(errors),
#         "files": saved,
#         "errors": errors,
#     }
#     write_manifest(scan_dir, manifest)

#     print(f"\n📦 Downloaded {len(saved)} files → {scan_dir}")
#     if errors:
#         print(f"⚠️  {len(errors)} errors (see download_manifest.json)")
#     else:
#         print("🎉 No errors")

# def parse_args():
#     ap = argparse.ArgumentParser(description="Download JS files into a scan folder")
#     ap.add_argument("js_urls_file", help="Path to a text file containing JS URLs (one per line)")
#     ap.add_argument("scan_id_folder", help="Folder where files will be saved")
#     ap.add_argument("--dl-workers", type=int, default=DEFAULT_DL_WORKERS, help="Downloader thread count")
#     ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout (s)")
#     ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Max bytes per file")
#     return ap.parse_args()

# def main():
#     args = parse_args()
#     run(args.js_urls_file, args.scan_id_folder, args.dl_workers, args.timeout, args.max_bytes)

# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
"""
jsDownloader.py

Usage (simple):
  python jsDownloader.py <js_urls_file> <scan_id_folder>

Usage (optional overrides):
  python jsDownloader.py <js_urls_file> <scan_id_folder> --dl-workers 16 --timeout 15 --max-bytes 3000000

Description:
  - Reads a text file of JS URLs (one per line).
  - Downloads each JS (concurrent, size-capped) into the given folder.
  - Does NOT beautify (use jsBeautifier.py in step 2).
  - Writes <scan_id_folder>/download_manifest.json with summary & errors.

Dependencies:
  pip install requests
"""

# import argparse
# import concurrent.futures
# import hashlib
# import json
# import os
# import sys
# import time
# from typing import List
# from urllib.parse import urlparse

# import requests

# # ---- Defaults (used automatically if flags are not provided) ----
# USER_AGENT = "Mozilla/5.0 (compatible; vapt-jsdownloader/1.1)"
# DEFAULT_TIMEOUT = 12           # seconds
# DEFAULT_DL_WORKERS = 8         # threads
# DEFAULT_MAX_BYTES = 2_000_000  # 2 MB per file

# def human_bytes(n: int) -> str:
#     if n is None:
#         return "?"
#     for unit in ["B", "KB", "MB", "GB"]:
#         if n < 1024.0:
#             return f"{n:.1f}{unit}"
#         n /= 1024.0
#     return f"{n:.1f}TB"

# def read_urls(path: str) -> List[str]:
#     urls = []
#     with open(path, "r", encoding="utf-8", errors="ignore") as f:
#         for line in f:
#             u = line.strip()
#             if not u or u.startswith("#"):
#                 continue
#             urls.append(u)
#     return urls

# def safe_output_name(url: str) -> str:
#     """
#     Build a safe filename from the URL path and append an 8-char SHA1 for uniqueness.
#     Keeps original extension if present, else forces .js.
#     """
#     p = urlparse(url)
#     tail = (p.path or "/script.js").rsplit("/", 1)[-1] or "script.js"
#     if not tail.lower().endswith(".js"):
#         tail += ".js"
#     base, ext = os.path.splitext(tail)
#     h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]
#     return f"{base}_{h}{ext}"

# def download_js(url: str, timeout: int, max_bytes: int) -> dict:
#     """
#     Stream-download up to max_bytes. Returns:
#       {'ok', 'url', 'status', 'size', 'content_type', 'raw'} or {'ok': False, 'error': '...'}
#     """
#     headers = {"User-Agent": USER_AGENT}
#     try:
#         # HEAD for quick size/type check (optional on some servers)
#         hr = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
#         clen = hr.headers.get("Content-Length")
#         if clen:
#             try:
#                 if int(clen) > max_bytes:
#                     return {"ok": False, "url": url, "error": f"too_large({clen}>{max_bytes})"}
#             except ValueError:
#                 pass

#         # GET streaming with cap
#         r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)
#         r.raise_for_status()

#         buf = []
#         got = 0
#         for chunk in r.iter_content(65536):
#             if not chunk:
#                 continue
#             buf.append(chunk)
#             got += len(chunk)
#             if got > max_bytes:
#                 break

#         raw = b"".join(buf)
#         return {
#             "ok": True,
#             "url": url,
#             "status": r.status_code,
#             "size": len(raw),
#             "content_type": r.headers.get("Content-Type") or hr.headers.get("Content-Type"),
#             "raw": raw,
#         }
#     except Exception as e:
#         return {"ok": False, "url": url, "error": str(e)}

# def write_manifest(folder: str, data: dict):
#     path = os.path.join(folder, "download_manifest.json")
#     with open(path, "w", encoding="utf-8") as f:
#         json.dump(data, f, ensure_ascii=False, indent=2)

# def run(urls_file: str, scan_dir: str, dl_workers: int, timeout: int, max_bytes: int):
#     os.makedirs(scan_dir, exist_ok=True)

#     urls = read_urls(urls_file)
#     print(f"➡️  Will download {len(urls)} URLs into: {scan_dir} (<= {human_bytes(max_bytes)} each)")

#     saved, errors = [], []
#     t0 = time.time()
#     with concurrent.futures.ThreadPoolExecutor(max_workers=dl_workers) as pool:
#         futmap = {pool.submit(download_js, u, timeout, max_bytes): u for u in urls}
#         done = 0
#         for fut in concurrent.futures.as_completed(futmap):
#             url = futmap[fut]
#             done += 1
#             try:
#                 res = fut.result()
#             except Exception as e:
#                 errors.append({"url": url, "error": f"executor: {e}"})
#                 continue

#             if not res.get("ok"):
#                 errors.append({"url": url, "error": res.get("error")})
#                 continue

#             # choose filename & ensure uniqueness
#             name = safe_output_name(url)
#             outp = os.path.join(scan_dir, name)
#             base, ext = os.path.splitext(outp)
#             i = 2
#             while os.path.exists(outp):
#                 outp = f"{base}_{i}{ext}"
#                 i += 1

#             try:
#                 with open(outp, "wb") as f:
#                     f.write(res["raw"])
#                 saved.append({
#                     "url": url,
#                     "path": outp,
#                     "size": res.get("size"),
#                     "content_type": res.get("content_type"),
#                 })
#             except Exception as e:
#                 errors.append({"url": url, "error": f"write: {e}"})

#             # progress pulse
#             if done % max(1, len(urls)//10 or 1) == 0:
#                 elapsed = time.time() - t0
#                 pct = int(done / max(1, len(urls)) * 100)
#                 print(f"  ... {done}/{len(urls)} ({pct}%) in {elapsed:.1f}s")

#     manifest = {
#         "created_at": int(time.time()),
#         "total_urls": len(urls),
#         "total_saved": len(saved),
#         "total_errors": len(errors),
#         "files": saved,
#         "errors": errors,
#     }
#     write_manifest(scan_dir, manifest)

#     print(f"\n📦 Downloaded {len(saved)} files → {scan_dir}")
#     if errors:
#         print(f"⚠️  {len(errors)} errors (see download_manifest.json)")
#     else:
#         print("🎉 No errors")

# def parse_args():
#     ap = argparse.ArgumentParser(
#         description="Download JS files into a scan folder (flags optional; sane defaults applied)."
#     )
#     ap.add_argument("js_urls_file", help="Path to a text file containing JS URLs (one per line)")
#     ap.add_argument("scan_id_folder", help="Folder where files will be saved")
#     # Optional overrides (not required)
#     ap.add_argument("--dl-workers", type=int, default=DEFAULT_DL_WORKERS, help="Downloader thread count (default: 8)")
#     ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout seconds (default: 12)")
#     ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Max bytes per file (default: 2,000,000)")
#     return ap.parse_args()

# def main():
#     args = parse_args()
#     run(args.js_urls_file, args.scan_id_folder, args.dl_workers, args.timeout, args.max_bytes)

# if __name__ == "__main__":
#     main()



# #!/usr/bin/env python3
# import argparse
# import concurrent.futures
# import hashlib
# import os
# import sys
# from urllib.parse import urlparse

# import requests

# USER_AGENT = "Mozilla/5.0 (compatible; vapt-jsdownloader/1.2)"
# DEFAULT_TIMEOUT = 12
# DEFAULT_DL_WORKERS = 8
# DEFAULT_MAX_BYTES = 2_000_000  # 2 MB

# def read_urls(path: str):
#     urls = []
#     with open(path, "r", encoding="utf-8", errors="ignore") as f:
#         for line in f:
#             u = line.strip()
#             if u and not u.startswith("#"):
#                 urls.append(u)
#     return urls

# def safe_output_name(url: str) -> str:
#     p = urlparse(url)
#     tail = (p.path or "/script.js").rsplit("/", 1)[-1] or "script.js"
#     if not tail.lower().endswith(".js"):
#         tail += ".js"
#     base, ext = os.path.splitext(tail)
#     h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]
#     return f"{base}_{h}{ext}"

# def download_js(url: str, timeout: int, max_bytes: int):
#     headers = {"User-Agent": USER_AGENT}
#     try:
#         r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)
#         r.raise_for_status()
#         data = r.content[:max_bytes]
#         return True, data
#     except Exception as e:
#         return False, str(e)

# def run(urls_file: str, scan_dir: str, workers: int, timeout: int, max_bytes: int) -> bool:
#     os.makedirs(scan_dir, exist_ok=True)
#     urls = read_urls(urls_file)

#     errors = 0
#     with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
#         futures = {pool.submit(download_js, url, timeout, max_bytes): url for url in urls}
#         for fut in concurrent.futures.as_completed(futures):
#             url = futures[fut]
#             ok, result = fut.result()
#             if not ok:
#                 print(f"✗ FAILED {url} ({result})")
#                 errors += 1
#                 continue
#             fname = safe_output_name(url)
#             try:
#                 with open(os.path.join(scan_dir, fname), "wb") as f:
#                     f.write(result)
#                 print(f"✓ Saved {fname}")
#             except Exception as e:
#                 print(f"✗ FAILED write {url} ({e})")
#                 errors += 1

#     return errors == 0  # ✅ return TRUE if no errors, FALSE otherwise

# def main():
#     ap = argparse.ArgumentParser()
#     ap.add_argument("js_urls_file")
#     ap.add_argument("scan_id_folder")
#     ap.add_argument("--dl-workers", type=int, default=DEFAULT_DL_WORKERS)
#     ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
#     ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
#     args = ap.parse_args()

#     success = run(args.js_urls_file, args.scan_id_folder, args.dl_workers, args.timeout, args.max_bytes)
#     sys.exit(0 if success else 1)

# if __name__ == "__main__":
#     main()


# jsDownloader.py (core pieces)
import os, sys, requests
from urllib.parse import urlparse, unquote, urljoin

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "VAPTlabs-JSFetcher/1.0"})

def derive_rel_path(js_url: str, base_domain: str) -> str | None:
    """
    Convert a JS URL to a repo-like relative path to store on disk.
    - strips query/fragment
    - normalizes & prevents '..' traversal
    - prefixes external hosts to avoid collisions (cdn.example.com/foo.js -> cdn.example.com/foo.js)
    """
    u = urlparse(js_url)

    # If scheme/host missing (very rare if your finder already absolutizes), treat as relative to root
    if not u.scheme and not u.netloc:
        path = js_url
        netloc = ""
    else:
        path = u.path or ""
        netloc = u.netloc

    if not path or path.endswith("/"):
        return None

    path = unquote(path.lstrip("/"))           # remove leading slash, decode %xx
    path = os.path.normpath(path)              # collapse //, /./, /../
    if path.startswith(".."):
        path = path.replace("..", "")          # hard stop any attempt to escape

    # If external host, prefix the host as a top-level folder
    if netloc and (base_domain not in (netloc, netloc.lstrip("www."))):
        path = f"{netloc}/{path}"

    return path

def download_one(js_url: str, out_root: str, base_domain: str):
    rel_path = derive_rel_path(js_url, base_domain)
    if not rel_path:
        print(f"⏭️  Skip (no file path): {js_url}")
        return

    dst_path = os.path.join(out_root, rel_path)
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    try:
        r = SESSION.get(js_url, timeout=20)
        r.raise_for_status()
        with open(dst_path, "wb") as f:
            f.write(r.content)
        print(f"✅ Saved: {dst_path}")
    except Exception as e:
        print(f"❌ Download failed: {js_url} -> {e}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python jsDownloader.py <url_list_file> <scan_id>")
        sys.exit(1)

    url_list_file, scan_id = sys.argv[1], sys.argv[2]
    with open(url_list_file, "r") as f:
        js_urls = [line.strip() for line in f if line.strip()]

    # Infer base domain (first URL) for host-prefix logic. Fallback empty.
    base_domain = ""
    if js_urls:
        try:
            base_domain = urlparse(js_urls[0]).netloc
        except Exception:
            pass

    for u in js_urls:
        download_one(u, scan_id, base_domain)

if __name__ == "__main__":
    main()
