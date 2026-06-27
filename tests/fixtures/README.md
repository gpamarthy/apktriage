# Test fixtures

`benign_sample.apk` is a tiny, **benign** APK built from the committed source in
`src/`. It exists so the end-to-end pipeline test is deterministic and offline.

It is not malware. It only carries *planted, fake* artifacts so each detector
has something concrete to find:

| Planted artifact | Where | Detector it exercises |
|---|---|---|
| `AIzaSy...` fake Google API key | `src/smali/.../MainActivity.smali` | secrets |
| `native_secret_AKIA...EXAMPLE` | `src/libdemo.c` (native string) | secrets (native) |
| `http://198.51.100.23/gate.php` | smali const-string | C2 indicators |
| `http://203.0.113.45/native_gate` | native string | C2 indicators (native) |
| `DexClassLoader`, `Runtime.exec`, `SmsManager` | smali xrefs | DEX behaviour, ATT&CK |
| `READ_SMS` / `ACCESS_FINE_LOCATION` / `INTERNET` | manifest | permission combos, ATT&CK |
| `system()` import | `libdemo.c` | native import flag |

The IPs are RFC 5737 documentation ranges; the keys are well-known example
values. Nothing here is live.

## Regenerate

```bash
./build_fixture.sh        # needs apktool + a C compiler on PATH
```

The native `.so` is built for the host arch when an `aarch64` cross-compiler is
absent; the toolkit reads the architecture from the ELF regardless, so the test
asserts on parsing and the `system` import, not on a specific machine type.
