from analyzer.jar import SafeJar
from analyzer.limits import Limits
from analyzer.manifest import parse_manifest, read_manifest


def test_parse_basic_manifest():
    m = parse_manifest(
        b"Manifest-Version: 1.0\r\n"
        b"Main-Class: com.example.Main\r\n"
        b"Implementation-Title: Example\r\n"
        b"Implementation-Version: 1.2.0\r\n"
        b"Implementation-Vendor: Someone\r\n\r\n"
        b"Name: com/example/Main.class\r\nSHA-256-Digest: abc\r\n"
    )
    assert m.present
    assert m.attributes["Main-Class"] == "com.example.Main"
    assert m.attributes["Implementation-Version"] == "1.2.0"
    # Per-entry sections after the blank line are ignored.
    assert "SHA-256-Digest" not in m.attributes


def test_continuation_lines():
    m = parse_manifest(b"Implementation-Title: Example Mod With A Long Na\n me\n")
    assert m.attributes["Implementation-Title"] == "Example Mod With A Long Name"


def test_invalid_utf8_and_garbage_do_not_crash():
    m = parse_manifest(b"\xff\xfe\x00garbage line without colon\nKey: \xc3\x28value\n")
    assert m.present
    assert "Key" in m.attributes


def test_control_chars_sanitized():
    m = parse_manifest(b"Implementation-Title: evil\x1b[2J\n")
    assert "\x1b" not in m.attributes["Implementation-Title"]


def test_read_manifest_missing(make_jar):
    with SafeJar.open(make_jar({"a.txt": "x"})) as jar:
        info, errors = read_manifest(jar)
    assert not info.present and errors == []


def test_read_manifest_case_insensitive(make_jar):
    with SafeJar.open(make_jar({"META-INF/manifest.mf": "Manifest-Version: 1.0\n"})) as jar:
        info, _ = read_manifest(jar)
    assert info.attributes["Manifest-Version"] == "1.0"


def test_oversized_manifest_reported(make_jar):
    path = make_jar({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n" + "X: y\n" * 1000})
    with SafeJar.open(path, Limits(max_metadata_size=100)) as jar:
        info, errors = read_manifest(jar)
    assert not info.present
    assert errors and "limit" in errors[0]
