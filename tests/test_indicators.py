from apktriage import indicators


def test_extracts_url_and_ip():
    inds, finds = indicators.scan("contact http://198.51.100.23/gate.php now", "x")
    kinds = {i.kind for i in inds}
    assert "url" in kinds
    assert "ipv4" in kinds
    assert any(f.category == "c2_indicator" for f in finds)


def test_filters_framework_url_noise():
    inds, _ = indicators.scan("xmlns=http://schemas.android.com/apk/res/android", "x")
    assert not any(i.kind == "url" for i in inds)


def test_filters_private_ip():
    inds, _ = indicators.scan("server 192.168.1.10 and 10.0.0.5", "x")
    assert not any(i.kind == "ipv4" for i in inds)


def test_detects_crypto_tell():
    inds, _ = indicators.scan('Cipher.getInstance("AES/CBC/PKCS5Padding")', "x")
    assert any(i.kind == "crypto" for i in inds)


def test_run_dedupes_indicators():
    src = {"a": ["http://203.0.113.45/x"], "b": ["http://203.0.113.45/x"]}
    inds, finds = indicators.run(src)
    urls = [i for i in inds if i.kind == "url"]
    assert len(urls) == 1
    # An IP-literal URL is the high-signal case that still raises one finding.
    assert len([f for f in finds if f.title == "Hardcoded IP-literal URL"]) == 1


def test_domain_url_is_indicator_only_not_finding():
    # Benign domain URLs are catalogued but must not inflate the finding count.
    inds, finds = indicators.scan("see https://api.example.org/v2/data for docs", "x")
    assert any(i.kind == "url" for i in inds)
    assert not any(f.category == "c2_indicator" for f in finds)
