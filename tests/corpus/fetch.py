#!/usr/bin/env python3
"""Fetch the real-APK test corpus described by manifest.yml.

Downloads are pinned by SHA-256 in corpus.lock.json: the first run records
hashes (``--update-lock``); later runs verify and hard-fail on any mismatch,
so a sample swapped upstream cannot silently change test results. Malware is
quarantined (chmod 600), never unzipped, never executed - the toolkit only
parses it statically.

Egress is restricted to f-droid.org and raw.githubusercontent.com.

Usage:
    python tests/corpus/fetch.py                 # download + verify against lock
    python tests/corpus/fetch.py --update-lock   # download + (re)record hashes
    python tests/corpus/fetch.py --only vlc_native newpipe
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import yaml

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.yml"
LOCK = HERE / "corpus.lock.json"
SAMPLES = HERE / "samples"

ALLOWED_HOSTS = {"f-droid.org", "raw.githubusercontent.com"}
_TIMEOUT = 120
_UA = "apktriage-corpus-fetcher/0.1 (static analysis test harness)"


def sample_url(sample: dict) -> str:
    if sample["source"] == "ashishb":
        return (
            "https://raw.githubusercontent.com/ashishb/android-malware/"
            f"{sample['commit']}/{sample['path']}"
        )
    return str(sample["url"])


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest() -> list[dict]:
    data = yaml.safe_load(MANIFEST.read_text())
    return list(data["samples"])


def load_lock() -> dict[str, dict]:
    if LOCK.exists():
        return dict(json.loads(LOCK.read_text()))
    return {}


def save_lock(lock: dict[str, dict]) -> None:
    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


def _download(url: str, dest_dir: Path) -> Path:
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to fetch from non-allowlisted host: {host!r}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    fd, tmp_name = tempfile.mkstemp(dir=dest_dir, suffix=".part")
    tmp = Path(tmp_name)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp, os.fdopen(fd, "wb") as out:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def fetch_one(sample: dict, lock: dict[str, dict], *, update_lock: bool) -> str:
    """Return a one-word status: ok | cached | recorded | mismatch | skipped."""
    name = sample["name"]
    url = sample_url(sample)
    dest = SAMPLES / f"{name}.apk"
    expected = lock.get(name, {}).get("sha256")

    # Idempotent: a present file that already matches the lock needs no network.
    if dest.exists() and expected and sha256_file(dest) == expected:
        return "cached"

    try:
        tmp = _download(url, SAMPLES)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"  ! {name}: download failed ({exc}); skipping", file=sys.stderr)
        return "skipped"

    digest = sha256_file(tmp)
    size = tmp.stat().st_size

    if expected and digest != expected and not update_lock:
        tmp.unlink(missing_ok=True)
        print(
            f"  ! {name}: SHA-256 MISMATCH\n      expected {expected}\n      got      {digest}",
            file=sys.stderr,
        )
        return "mismatch"

    os.replace(tmp, dest)
    dest.chmod(0o600)  # quarantine: not executable

    if not expected or update_lock:
        lock[name] = {"sha256": digest, "size": size}
        return "recorded"
    return "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-lock", action="store_true", help="record/refresh hashes")
    parser.add_argument("--only", nargs="*", help="fetch only these sample names")
    args = parser.parse_args(argv)

    samples = load_manifest()
    if args.only:
        wanted = set(args.only)
        samples = [s for s in samples if s["name"] in wanted]
    lock = load_lock()

    counts: dict[str, int] = {}
    for sample in samples:
        status = fetch_one(sample, lock, update_lock=args.update_lock)
        counts[status] = counts.get(status, 0) + 1
        mark = {"cached": "=", "ok": "+", "recorded": "*"}.get(status, "!")
        print(f"  {mark} {sample['name']:18} {status}")

    save_lock(lock)
    print(f"\nsummary: {counts}  (lock: {LOCK})")
    # A hash mismatch is the only hard failure; missing network is tolerated.
    return 1 if counts.get("mismatch") else 0


if __name__ == "__main__":
    raise SystemExit(main())
