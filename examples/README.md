# Examples

Drop an APK in this directory and triage it:

```bash
apktriage scan examples/yourapp.apk -o examples/yourapp.out
```

That writes three artifacts into the output directory:

- `report.json` - full structured result (pipe into other tooling)
- `report.md` - human-readable report (paste into a ticket / write-up)
- `<package>.yar` - a compiled-and-validated YARA signature for the sample

## Try it on the test fixture

No real APK handy? The committed benign fixture works out of the box:

```bash
apktriage scan tests/fixtures/benign_sample.apk -o /tmp/triage
cat /tmp/triage/report.md
```

Expected highlights: a planted Google API key and AWS key, two C2 URLs/IPs, a
`DexClassLoader` + `Runtime.exec` dynamic-code finding, a native `system` import,
and six MITRE ATT&CK Mobile techniques (T1407, T1437, T1426, T1430, T1636.004,
T1623).

## Safe sources of real (benign) APKs

[F-Droid](https://f-droid.org/) packages are open-source and safe to analyze.
Only analyze apps you are authorized to inspect.
