# apktriage

[![ci](https://github.com/gpamarthy/apktriage/actions/workflows/ci.yml/badge.svg)](https://github.com/gpamarthy/apktriage/actions/workflows/ci.yml)

Static APK reverse-engineering and triage toolkit. Point it at an `.apk` and it
unpacks and decompiles the app, digs through the native ARM `.so` libraries,
flags packers/obfuscation, pulls hardcoded secrets and C2/crypto indicators out
of the DEX and native code, **auto-writes a YARA signature** for what it finds,
and tags everything against **MITRE ATT&CK Mobile**.

It is **static only**: the sample is parsed and decompiled, never installed or
executed, and the core pipeline makes no network calls.

## Why these tools

The toolkit orchestrates the proven, standard Android triage stack rather than
reinventing it:

| Stage | Tool | Role |
|---|---|---|
| Load + DEX | [androguard](https://github.com/androguard/androguard) | Pure-Python APK/DEX/manifest parser with cross-references |
| Smali / Java | [apktool](https://apktool.org/), [Jadx](https://github.com/skylot/jadx) | Optional source dumps (auto-detected) |
| Packers | [APKiD](https://github.com/rednaga/APKiD) | "PEiD for Android": packer/obfuscator/compiler ID |
| Native | [LIEF](https://lief.re/) | ELF parsing of `.so` libraries |
| Signatures | [yara-python](https://github.com/VirusTotal/yara-python) | Compile-validated rule generation |

This mirrors how [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
structures static analysis, but as a small, readable CLI instead of a server.

## Pipeline

`pipeline.run()` runs the documented Android static-analysis methodology in order:

1. **Load** the APK with androguard; optionally dump smali (apktool) and Java (Jadx).
2. **DEX analysis** - dangerous permissions and combos, exported components,
   suspicious APIs and dynamic code loading, all via androguard xrefs.
3. **Native** - parse each `lib/<abi>/*.so` with LIEF; flag `ptrace`/`system`/
   `dlopen` imports; sweep native strings.
4. **Packers** - APKiD verdicts (packer / obfuscator / anti-debug / compiler).
5. **Secrets** - curated credential regexes with an entropy gate.
6. **Indicators** - URLs, IPv4, base64 blobs, crypto tells (C2 candidates).
7. **YARA** - synthesize and compile a signature from the strongest evidence.
8. **ATT&CK** - map permissions/APIs/findings to ATT&CK Mobile technique IDs.

## Install

```bash
make install                 # uv venv (python 3.12) + pip install -e ".[all]"
# optional external decompilers (richer smali/Java dumps):
sudo apt-get install -y apktool jadx
```

The toolkit works with androguard alone; apktool/jadx/APKiD are auto-detected and
used when present, and skipped gracefully when not.

## Usage

```bash
apktriage scan app.apk                 # rich terminal report
apktriage scan app.apk -f json         # JSON to stdout
apktriage scan app.apk -o /tmp/out     # choose output dir
```

Every run writes `report.json`, `report.md` and a generated `<package>.yar` into
the output directory (default `<apk>.out`).

## Develop

```bash
make lint        # ruff check + format check
make typecheck   # mypy --strict
make test        # offline pytest (unit + e2e on the committed fixture)
make corpus      # opt-in: fetch real APKs and validate against them (network)
```

See `tests/fixtures/README.md` for how the deterministic benign fixture APK is
built (apktool from committed smali, with a planted fake secret and C2 URL).

### Real-APK validation

`make test` is fully offline and deterministic. `make corpus` additionally
downloads a pinned set of **real** apps - benign ones from F-Droid plus real
malware from `ashishb/android-malware` - and runs the toolkit against them to
prove detections fire on genuine threats and that the parsers survive messy,
hostile inputs. Each sample is scanned in its own subprocess (mirrors production,
isolates native-library crashes) and pinned by SHA-256. Samples are quarantined
and never committed. See `tests/corpus/README.md` for safety details.

## Out of scope

Dynamic analysis / Frida, VirusTotal or any network enrichment, and ML
classification are intentionally excluded to keep the tool small and offline.
They are natural extensions.
