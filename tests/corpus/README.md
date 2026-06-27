# Real-APK test corpus

Validates the toolkit against **real** apps pulled from the internet - benign
ones from F-Droid and **real malware** from the `ashishb/android-malware` repo.
This is opt-in and network-fetched; the default `make test` never touches it.

## Safety

- **Static only.** The pipeline parses/decompiles samples; it never installs or
  executes them. Downloading malware here is safe for that reason, but treat the
  files as live: do not run them on a device.
- **Quarantined.** Samples land in `samples/` (gitignored), `chmod 600`, and are
  **never committed**. Only `manifest.yml` and `corpus.lock.json` (hashes, no
  binaries) are tracked - so the GitHub repo never hosts malware.
- **Pinned.** Every sample is locked by SHA-256 in `corpus.lock.json`. A later
  fetch that gets a different hash hard-fails (supply-chain guard). Malware URLs
  are pinned to a fixed `ashishb/android-malware` commit for immutability.
- **Egress** is restricted to `f-droid.org` and `raw.githubusercontent.com`.

## Run

```bash
make corpus            # fetch (if needed) + run the corpus tests
# or step by step:
python tests/corpus/fetch.py          # download + verify against the lock
pytest -q -m corpus                   # run validation
```

If the global PreToolUse scope-guard blocks egress, allowlist those two domains
for the fetch command (or run the fetch outside the sandbox). A sample that
fails to download is skipped, not fatal.

## What gets checked

- **Invariants (every sample):** the pipeline never crashes, returns a coherent
  JSON-serializable `Report`, and emits a YARA rule that compiles. This is what
  caught the real `ResParserError` crash on a malformed manifest (now handled by
  the DEX-only fallback in `unpack.py`).
- **Ground truth (per `expect` in `manifest.yml`):** benign VLC exposes its
  native `.so` libraries; each malware sample trips behavioural/permission
  signals and maps to ≥1 MITRE ATT&CK Mobile technique.

## Refresh the lock

```bash
python tests/corpus/fetch.py --update-lock   # re-record hashes after a manifest edit
```
