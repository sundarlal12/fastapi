#!/usr/bin/env python3
import sys
import subprocess
import os
import shutil   # ✅ for removing tmp folder after execution
from js_finder_spider import js_finder_by_domain

def main():
    if len(sys.argv) < 3:
        print("\nUsage: python3 js_code.py <url> <scan_id>\n")
        print("Example:")
        print("  python3 js_code.py https://app.matterai.so SCAN123\n")
        sys.exit(1)

    url = sys.argv[1]
    scan_id = sys.argv[2]

    print(f"\n🔍 Crawling: {url}\n")
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

    # --------------- Cleanup tmp folder ---------------
    print("\n🧹 Cleaning up temp files...\n")
    shutil.rmtree(tmp_dir, ignore_errors=True)

    if beaut_proc.returncode == 0:
        print("\n✅ All steps completed successfully!\n")
    else:
        print("\n⚠️ Beautifier finished with errors.\n")

    print(f"📂 Final results in: {scan_id}/")


if __name__ == "__main__":
    main()
