from digiscope.detection import detect_selector, detect_type


def test_detector_covers_every_supported_selector():
    cases = {
        "analyst@example.org": "email",
        "example.org": "domain",
        "8.8.8.8": "ip",
        "octocat": "username",
        "+1 202 555 0123": "phone",
        "Ada Lovelace": "person",
        "Acme Corporation": "company",
        "https://example.org/path?q=1": "url",
        "d41d8cd98f00b204e9800998ecf8427e": "hash",
        "1BoatSLRHtKNngkdXxeobR76b53LETtpyT": "crypto",
        "0x0000000000000000000000000000000000000000": "crypto",
    }
    for value, expected in cases.items():
        detection = detect_selector(value)
        assert detection.type == expected, (value, detection.to_dict())
        assert 0 <= detection.confidence <= 1
        assert detection.normalized
        assert detection.candidates


def test_detector_explains_ambiguous_free_text():
    result = detect_selector("unusual free text selector")
    assert result.type == "person"
    assert result.reason
    assert result.candidates[0]["reason"]


def test_detect_type_helper():
    assert detect_type("deadbeef") == "username"
    assert detect_type("2001:db8::1") == "ip"
