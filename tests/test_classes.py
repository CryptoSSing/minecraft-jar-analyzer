import struct

import pytest

from analyzer.classes import (ClassParseError, java_version_label, parse_class,
                              scan_classes, top_package)
from analyzer.jar import SafeJar
from analyzer.limits import Limits
from tests.classbuilder import build_class


def test_parse_valid_class():
    data = build_class(
        "com/example/Evil",
        strings=["https://example.com/payload", "cmd.exe"],
        class_refs=["[Ljava/lang/String;"],
        method_refs=[("java/lang/Runtime", "exec"), ("java/lang/Runtime", "getRuntime")],
    )
    c = parse_class(data, "com/example/Evil.class")
    assert c.name == "com/example/Evil"
    assert c.super_name == "java/lang/Object"
    assert c.major_version == 61
    assert "https://example.com/payload" in c.strings
    assert ("java/lang/Runtime", "exec") in c.member_refs
    assert "java/lang/String" in c.class_refs  # array type unwrapped


def test_long_constants_take_two_slots():
    # Hand-build a pool: [1] Long (occupies 1 and 2), [3] utf8 "A", [4] class -> 3
    pool = struct.pack(">BQ", 5, 42) + struct.pack(">BH", 1, 1) + b"A" + struct.pack(">BH", 7, 3)
    data = (struct.pack(">IHHH", 0xCAFEBABE, 0, 52, 5) + pool
            + struct.pack(">HHHHHHH", 0x21, 4, 0, 0, 0, 0, 0))
    c = parse_class(data)
    assert c.name == "A" and c.super_name is None


@pytest.mark.parametrize("data", [
    b"",
    b"\x00\x01\x02\x03",
    b"\xca\xfe\xba\xbe\x00\x00",               # truncated header
    b"\xca\xfe\xba\xbe\x00\x00\x00\x3d\xff\xff\x01\xff\xff",  # utf8 length beyond end
    b"\xca\xfe\xba\xbe\x00\x00\x00\x3d\x00\x02\x63",          # unknown tag 99
    build_class("a/B")[:-10],                   # chopped off the end
])
def test_invalid_class_raises(data):
    with pytest.raises(ClassParseError):
        parse_class(data)


def test_invalid_this_class_index():
    data = bytearray(build_class("a/B"))
    # this_class is the 2 bytes after access flags; point it at index 999.
    idx = len(data) - 12
    data[idx:idx + 2] = struct.pack(">H", 999)
    with pytest.raises(ClassParseError, match="this_class"):
        parse_class(bytes(data))


def test_invalid_utf8_in_pool_is_replaced():
    data = build_class("a/B", strings=["ok"]).replace(b"ok", b"\xff\xfe")
    assert parse_class(data).strings == ["��"]


def test_scan_classes(make_jar):
    path = make_jar({
        "com/ex/A.class": build_class("com/ex/A"),
        "com/ex/B.class": build_class("com/ex/B", major=52),
        "com/ex/Broken.class": b"\xca\xfe\xba\xbe garbage",
        "readme.txt": "not a class",
    })
    seen = []
    with SafeJar.open(path) as jar:
        summary, errors = scan_classes(jar, seen.append)
    assert [c.name for c in seen] == ["com/ex/A", "com/ex/B"]
    assert (summary.total, summary.parsed, summary.failed) == (3, 2, 1)
    assert summary.packages == {"com/ex": 2}
    assert summary.java_versions == {"Java 17": 1, "Java 8": 1}
    assert "Broken" in summary.failed_entries[0]


def test_scan_respects_budget(make_jar):
    files = {f"p/C{i}.class": build_class(f"p/C{i}", strings=["x" * 4000]) for i in range(20)}
    path = make_jar(files)
    with SafeJar.open(path, Limits(max_total_decompressed=20_000)) as jar:
        summary, errors = scan_classes(jar, lambda c: None)
    assert summary.skipped > 0
    assert summary.parsed + summary.skipped == 20
    assert any("budget" in e for e in errors)


def test_scan_cancel(make_jar):
    path = make_jar({f"p/C{i}.class": build_class(f"p/C{i}") for i in range(5)})
    with SafeJar.open(path) as jar:
        summary, errors = scan_classes(jar, lambda c: None, should_cancel=lambda: True)
    assert summary.skipped == 5 and "cancelled" in errors[-1]


def test_helpers():
    assert java_version_label(52) == "Java 8"
    assert java_version_label(65) == "Java 21"
    assert top_package("com/example/mod/Main") == "com/example"
    assert top_package("a/B") == "a"
    assert top_package("Main") == "(default package)"
