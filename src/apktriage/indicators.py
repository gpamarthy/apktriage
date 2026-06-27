"""Stage 6: C2 / crypto indicator extraction.

Pulls network IOCs (URLs, bare IPv4, suspicious base64 blobs) and crypto tells
out of the same text corpus the secret scanner uses. These feed both the report
and the generated YARA rule. Common-noise hosts (schema URLs, localhost) are
filtered so the C2 list stays signal-heavy.
"""

from __future__ import annotations

import re

from apktriage.models import Finding, Indicator, Severity

_URL_RE = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_CRYPTO_RE = re.compile(
    r"\b(AES/CBC|AES/ECB|AES/GCM|DES|RC4|Blowfish|SecretKeySpec|IvParameterSpec|MessageDigest|PBEWith\w+)\b"
)

# Hosts that are almost always framework/schema noise, not C2.
_HOST_DENYLIST = (
    "schemas.android.com",
    "www.w3.org",
    "schemas.xmlsoap.org",
    "java.sun.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "example.com",
    "play.google.com",
    "developer.android.com",
    "goo.gl/",
    "ns.adobe.com",
)
# Reserved / non-routable IPs that are not interesting as C2.
_IP_DENY_PREFIXES = ("0.", "127.", "10.", "192.168.", "255.", "224.")


def _is_noise_url(url: str) -> bool:
    return any(host in url for host in _HOST_DENYLIST)


def _is_noise_ip(ip: str) -> bool:
    return ip.startswith(_IP_DENY_PREFIXES) or ip.startswith(("172.16.", "172.17.", "172.18."))


def _url_host(url: str) -> str:
    host = url.split("://", 1)[-1]
    return host.split("/", 1)[0].split(":", 1)[0]


def scan(text: str, location: str) -> tuple[list[Indicator], list[Finding]]:
    indicators: list[Indicator] = []
    findings: list[Finding] = []
    seen: set[str] = set()

    # Embedded URLs are catalogued as indicators but NOT scored as findings on
    # their own: benign apps legitimately carry hundreds of URLs. Only a URL
    # whose host is a literal IP (a classic hardcoded-C2 tell) raises a finding.
    for url in _URL_RE.findall(text):
        if _is_noise_url(url) or url in seen:
            continue
        seen.add(url)
        indicators.append(Indicator(kind="url", value=url, location=location))
        host = _url_host(url)
        if _IPV4_RE.fullmatch(host) and not _is_noise_ip(host):
            findings.append(
                Finding(
                    category="c2_indicator",
                    title="Hardcoded IP-literal URL",
                    severity=Severity.MEDIUM,
                    detail="URL points at a raw IP rather than a domain",
                    location=location,
                    evidence=url,
                )
            )

    # A bare dotted-quad is catalogued but NOT scored: in real apps it is far
    # more often a version string or coincidental match than a C2 address. The
    # IP-literal *URL* above is the scored signal; a lone IP is just an indicator.
    for ip in _IPV4_RE.findall(text):
        if _is_noise_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        indicators.append(Indicator(kind="ipv4", value=ip, location=location))

    for algo in set(_CRYPTO_RE.findall(text)):
        indicators.append(Indicator(kind="crypto", value=algo, location=location))

    for blob in _B64_RE.findall(text)[:20]:
        if blob in seen:
            continue
        seen.add(blob)
        indicators.append(Indicator(kind="base64_blob", value=blob[:64], location=location))

    return indicators, findings


# Keep the indicator catalogue readable on large benign apps (which can carry
# hundreds of unique URLs) while never dropping the higher-signal kinds.
_MAX_PER_KIND = 100


def run(sources: dict[str, list[str]]) -> tuple[list[Indicator], list[Finding]]:
    indicators: list[Indicator] = []
    findings: list[Finding] = []
    seen_values: set[str] = set()
    seen_findings: set[tuple[str, str]] = set()
    kind_counts: dict[str, int] = {}
    for location, lines in sources.items():
        inds, finds = scan("\n".join(lines), location)
        for ind in inds:
            if ind.value in seen_values:
                continue
            if kind_counts.get(ind.kind, 0) >= _MAX_PER_KIND:
                continue
            seen_values.add(ind.value)
            kind_counts[ind.kind] = kind_counts.get(ind.kind, 0) + 1
            indicators.append(ind)
        for finding in finds:
            key = (finding.title, finding.evidence)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(finding)
    return indicators, findings
