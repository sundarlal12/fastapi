# #!/usr/bin/env python3
# """
# jsBeautifier.py

# Usage:
#   python jsBeautifier.py <scan_id_folder> [--indent 2]

# Description:
#   - Finds all *.js files in the folder that do NOT already end with "_beautified.js".
#   - Beautifies each file using jsbeautifier.
#   - Saves as "<original_base>_beautified.js" (UTF-8).
#   - If beautify succeeded, deletes the original .js file.
#   - Writes <scan_id_folder>/beautify_manifest.json with mapping & errors.
# """

# import argparse
# import json
# import os
# import sys
# import time

# try:
#     import jsbeautifier
# except Exception as e:
#     print("ERROR: jsbeautifier is not installed. Install with:", file=sys.stderr)
#     print("  pip install jsbeautifier", file=sys.stderr)
#     sys.exit(1)

# def find_target_js(folder: str):
#     for root, _, files in os.walk(folder):
#         for fn in files:
#             if not fn.lower().endswith(".js"):
#                 continue
#             if fn.lower().endswith("_beautified.js"):
#                 # already beautified file — skip
#                 continue
#             yield os.path.join(root, fn)

# def out_name_for(path: str) -> str:
#     base, ext = os.path.splitext(path)
#     return f"{base}_beautified.js"

# def beautify_text(code: str, indent: int = 2) -> str:
#     opts = jsbeautifier.default_options()
#     opts.indent_size = indent
#     opts.preserve_newlines = True
#     return jsbeautifier.beautify(code, opts)

# def run(folder: str, indent: int):
#     folder = os.path.abspath(folder)
#     if not os.path.isdir(folder):
#         print(f"ERROR: Folder not found: {folder}", file=sys.stderr)
#         sys.exit(1)

#     targets = list(find_target_js(folder))
#     print(f"➡️  Beautifying {len(targets)} JS files in: {folder}")

#     mapped, errors = [], []
#     done = 0
#     t0 = time.time()

#     for src in targets:
#         try:
#             with open(src, "r", encoding="utf-8", errors="ignore") as f:
#                 code = f.read()
#             pretty = beautify_text(code, indent=indent)
#             outp = out_name_for(src)

#             # write beautified
#             with open(outp, "w", encoding="utf-8") as f:
#                 f.write(pretty)

#             # delete original only after successful write
#             try:
#                 os.remove(src)
#             except Exception as e:
#                 # non-fatal; keep going
#                 errors.append({"file": src, "error": f"delete: {e}"})

#             mapped.append({"source": src, "beautified": outp})
#         except Exception as e:
#             errors.append({"file": src, "error": str(e)})

#         done += 1
#         if done % max(1, len(targets)//10 or 1) == 0:
#             elapsed = time.time() - t0
#             pct = int(done / max(1, len(targets)) * 100)
#             print(f"  ... {done}/{len(targets)} ({pct}%) in {elapsed:.1f}s")

#     manifest = {
#         "created_at": int(time.time()),
#         "folder": folder,
#         "total_processed": len(targets),
#         "total_beautified": len(mapped),
#         "total_errors": len(errors),
#         "mapping": mapped,
#         "errors": errors,
#     }
#     with open(os.path.join(folder, "beautify_manifest.json"), "w", encoding="utf-8") as f:
#         json.dump(manifest, f, ensure_ascii=False, indent=2)

#     print(f"\n✅ Beautified {len(mapped)} files.")
#     if errors:
#         print(f"⚠️  {len(errors)} issues (see beautify_manifest.json)")
#     else:
#         print("🎉 No errors.")

# def parse_args():
#     ap = argparse.ArgumentParser(description="Beautify all JS files in a folder and remove originals")
#     ap.add_argument("scan_id_folder", help="Folder containing downloaded JS files")
#     ap.add_argument("--indent", type=int, default=2, help="Indent size for jsbeautifier")
#     return ap.parse_args()

# def main():
#     args = parse_args()
#     run(args.scan_id_folder, args.indent)

# if __name__ == "__main__":
#     main()



# #!/usr/bin/env python3
# import argparse
# import json
# import os
# import sys
# import time

# # Ensure we're actually using the env that has jsbeautifier
# try:
#     import jsbeautifier
# except Exception:
#     print("ERROR: jsbeautifier not installed for this Python. Install with: pip install jsbeautifier", file=sys.stderr)
#     sys.exit(1)

# TARGET_EXTS = (".js", ".mjs", ".cjs")

# def is_target(fn: str) -> bool:
#     low = fn.lower()
#     if low.endswith("_beautified.js"):
#         return False
#     return any(low.endswith(ext) for ext in TARGET_EXTS)

# def find_targets(folder: str):
#     for root, _, files in os.walk(folder):
#         for fn in files:
#             if is_target(fn):
#                 yield os.path.join(root, fn)

# def out_name(src: str) -> str:
#     base, _ = os.path.splitext(src)
#     return f"{base}_beautified.js"

# def beautify_text(code: str) -> str:
#     opts = jsbeautifier.default_options()
#     opts.indent_size = 2
#     opts.preserve_newlines = True
#     return jsbeautifier.beautify(code, opts)

# def run(folder: str) -> int:
#     folder = os.path.abspath(folder)
#     print(f"✨ jsBeautifier working in: {folder}")
#     if not os.path.isdir(folder):
#         print(f"ERROR: Folder not found: {folder}", file=sys.stderr)
#         return 2

#     targets = list(find_targets(folder))
#     print(f"Found {len(targets)} file(s) to beautify (matching .js/.mjs/.cjs and not *_beautified.js).")
#     if not targets:
#         print("Nothing to beautify. If you expected files, run:\n  ls -la \"" + folder + "\"")
#         return 0

#     mapped, errors = [], []
#     start = time.time()

#     for i, src in enumerate(targets, 1):
#         rel = os.path.relpath(src, folder)
#         try:
#             with open(src, "r", encoding="utf-8", errors="ignore") as f:
#                 code = f.read()
#             pretty = beautify_text(code)
#             outp = out_name(src)
#             with open(outp, "w", encoding="utf-8") as f:
#                 f.write(pretty)
#             try:
#                 os.remove(src)  # delete original only after success
#             except Exception as e:
#                 errors.append({"file": src, "error": f"delete: {e}"})
#             mapped.append({"source": src, "beautified": outp})
#             print(f"[{i}/{len(targets)}] ✓ {rel}  →  {os.path.basename(outp)}")
#         except Exception as e:
#             print(f"[{i}/{len(targets)}] ✗ {rel}  ({e})", file=sys.stderr)
#             errors.append({"file": src, "error": str(e)})

#     manifest = {
#         "created_at": int(time.time()),
#         "folder": folder,
#         "total_processed": len(targets),
#         "total_beautified": len(mapped),
#         "total_errors": len(errors),
#         "mapping": mapped,
#         "errors": errors,
#     }
#     with open(os.path.join(folder, "beautify_manifest.json"), "w", encoding="utf-8") as f:
#         json.dump(manifest, f, ensure_ascii=False, indent=2)

#     took = time.time() - start
#     print(f"\n✅ Beautified {len(mapped)}/{len(targets)} in {took:.1f}s")
#     if errors:
#         print("⚠️  Some issues. See beautify_manifest.json")
#         return 3
#     return 0

# def main():
#     ap = argparse.ArgumentParser(description="Beautify JS files in a folder and remove originals")
#     ap.add_argument("scan_id_folder", help="Folder containing downloaded JS")
#     args = ap.parse_args()
#     sys.exit(run(args.scan_id_folder))

# if __name__ == "__main__":
#     main()



# #!/usr/bin/env python3
# import argparse
# import os
# import sys
# import time

# # Ensure jsbeautifier is installed in THIS Python interpreter
# try:
#     import jsbeautifier
# except Exception:
#     print("ERROR: jsbeautifier not installed. Install with: pip install jsbeautifier", file=sys.stderr)
#     sys.exit(1)

# TARGET_EXTS = (".js", ".mjs", ".cjs")

# def is_target(fn: str) -> bool:
#     low = fn.lower()
#     if low.endswith("_beautified.js"):
#         return False
#     return any(low.endswith(ext) for ext in TARGET_EXTS)

# def find_targets(folder: str):
#     for root, _, files in os.walk(folder):
#         for fn in files:
#             if is_target(fn):
#                 yield os.path.join(root, fn)

# def out_name(src: str) -> str:
#     base, _ = os.path.splitext(src)
#     return f"{base}_beautified.js"

# def beautify_text(code: str) -> str:
#     opts = jsbeautifier.default_options()
#     opts.indent_size = 2
#     opts.preserve_newlines = True
#     return jsbeautifier.beautify(code, opts)

# def run(folder: str) -> int:
#     folder = os.path.abspath(folder)
#     print(f"✨ Beautifying JS in: {folder}")

#     if not os.path.isdir(folder):
#         print(f"ERROR: Folder not found: {folder}", file=sys.stderr)
#         return 2

#     targets = list(find_targets(folder))
#     print(f"Found {len(targets)} file(s) to beautify.")

#     if not targets:
#         print("⚠️ Nothing to beautify.")
#         return 0

#     start = time.time()
#     ok = 0
#     errors = 0

#     for i, src in enumerate(targets, 1):
#         rel = os.path.relpath(src, folder)
#         try:
#             with open(src, "r", encoding="utf-8", errors="ignore") as f:
#                 code = f.read()

#             pretty = beautify_text(code)
#             outp = out_name(src)

#             with open(outp, "w", encoding="utf-8") as f:
#                 f.write(pretty)

#             # remove original only after success
#             os.remove(src)

#             print(f"[{i}/{len(targets)}] ✓ {rel}  →  {os.path.basename(outp)}")
#             ok += 1
#         except Exception as e:
#             print(f"[{i}/{len(targets)}] ✗ {rel} ({e})", file=sys.stderr)
#             errors += 1

#     took = time.time() - start
#     print(f"\n✅ Beautified {ok}/{len(targets)} files in {took:.1f}s")
#     if errors:
#         print(f"⚠️ {errors} file(s) failed to beautify.")

#     return 0 if errors == 0 else 3

# def main():
#     ap = argparse.ArgumentParser(description="Beautify JS files in a folder and delete originals")
#     ap.add_argument("scan_id_folder", help="Folder containing downloaded JS files")
#     args = ap.parse_args()
#     sys.exit(run(args.scan_id_folder))

# if __name__ == "__main__":
#     main()




# #!/usr/bin/env python3
# import argparse
# import os
# import sys
# import jsbeautifier

# TARGET_EXTS = (".js", ".mjs", ".cjs")

# def find_targets(folder: str):
#     for root, _, files in os.walk(folder):
#         for fn in files:
#             if fn.lower().endswith(TARGET_EXTS) and not fn.lower().endswith("_beautified.js"):
#                 yield os.path.join(root, fn)

# def run(folder: str) -> bool:
#     folder = os.path.abspath(folder)
#     targets = list(find_targets(folder))
#     if not targets:
#         print("⚠️ No JS files found to beautify.")
#         return False

#     errors = 0
#     for src in targets:
#         try:
#             with open(src, "r", encoding="utf-8", errors="ignore") as f:
#                 code = f.read()
#             pretty = jsbeautifier.beautify(code)
#             outp = src.replace(".js", "_beautified.js")
#             with open(outp, "w", encoding="utf-8") as f:
#                 f.write(pretty)
#             os.remove(src)
#             print(f"✓ Beautified {os.path.basename(src)}")
#         except Exception as e:
#             print(f"✗ FAILED beautify {src} ({e})")
#             errors += 1

#     return errors == 0  # ✅ True if all beautified OK, else False

# def main():
#     ap = argparse.ArgumentParser()
#     ap.add_argument("scan_id_folder")
#     args = ap.parse_args()

#     success = run(args.scan_id_folder)
#     sys.exit(0 if success else 1)

# if __name__ == "__main__":
#     main()



# jsBeautifier.py (sketch)
import os, sys
from jsbeautifier import beautify

def is_js(path: str) -> bool:
    lower = path.lower()
    return lower.endswith(".js") and not lower.endswith("_beautified.js")

def out_path_for(src: str) -> str:
    # insert _beautified before .js
    base, ext = os.path.splitext(src)
    return f"{base}_beautified{ext}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python jsBeautifier.py <scan_id>")
        sys.exit(1)

    root = sys.argv[1]
    for dirpath, _, files in os.walk(root):
        for fn in files:
            src = os.path.join(dirpath, fn)
            if not is_js(src):
                continue
            dst = out_path_for(src)
            try:
                with open(src, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                pretty = beautify(code)
                with open(dst, "w", encoding="utf-8") as f:
                    f.write(pretty)
                print(f"✨ Beautified: {dst}")
            except Exception as e:
                print(f"⚠️ Beautify failed: {src} -> {e}")

if __name__ == "__main__":
    main()
