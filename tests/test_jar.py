import os
import zipfile

import pytest

from analyzer.jar import (BudgetExceeded, EntryReadError, JarError, SafeJar,
                          detect_file_type)
from analyzer.limits import Limits
from tests.conftest import jar_bytes


def test_valid_jar_opens_and_reads(make_jar):
    path = make_jar({"a.txt": "hello", "com/x/Y.class": b"\xca\xfe\xba\xbe"})
    with SafeJar.open(path) as jar:
        assert jar.has("a.txt")
        assert jar.read("a.txt") == b"hello"
        assert len(jar.files()) == 2


def test_missing_entry(make_jar):
    with SafeJar.open(make_jar({"a.txt": "x"})) as jar:
        with pytest.raises(EntryReadError):
            jar.read("nope.txt")


def test_random_bytes_rejected(tmp_path):
    p = tmp_path / "garbage.jar"
    p.write_bytes(os.urandom(4096))
    with pytest.raises(JarError, match="Not a valid JAR"):
        SafeJar.open(p)


def test_renamed_exe_detected(tmp_path):
    p = tmp_path / "evil.jar"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    with pytest.raises(JarError, match="Windows executable"):
        SafeJar.open(p)


def test_truncated_zip_rejected(make_jar, tmp_path):
    good = make_jar({"a.txt": "hello" * 100})
    data = good.read_bytes()
    bad = tmp_path / "truncated.jar"
    bad.write_bytes(data[: len(data) // 2])  # chop off the central directory
    with pytest.raises(JarError):
        SafeJar.open(bad)


def test_empty_file_rejected(tmp_path):
    p = tmp_path / "empty.jar"
    p.write_bytes(b"")
    with pytest.raises(JarError):
        SafeJar.open(p)


def test_not_a_file(tmp_path):
    with pytest.raises(JarError, match="Not a regular file"):
        SafeJar.open(tmp_path)


def test_bad_crc_entry_fails_safely(make_jar, tmp_path):
    path = make_jar({"a.txt": "A" * 1000}, compression=zipfile.ZIP_STORED)
    data = bytearray(path.read_bytes())
    idx = data.find(b"AAAA")
    data[idx] = ord("B")  # corrupt the stored bytes -> CRC mismatch
    bad = tmp_path / "badcrc.jar"
    bad.write_bytes(bytes(data))
    with SafeJar.open(bad) as jar:
        with pytest.raises(EntryReadError, match="CRC"):
            jar.read("a.txt")


def test_oversized_file_refused(make_jar):
    path = make_jar({"a.txt": "x" * 5000}, compression=zipfile.ZIP_STORED)
    with pytest.raises(JarError, match="larger than"):
        SafeJar.open(path, Limits(max_jar_size=1000))


def test_too_many_entries_refused(make_jar):
    path = make_jar({f"f{i}.txt": "x" for i in range(20)})
    with pytest.raises(JarError, match="entries"):
        SafeJar.open(path, Limits(max_entries=10))


def test_zip_bomb_single_entry_stopped(make_jar):
    # 10 MB of zeros compresses to ~10 KB: a 1000:1 ratio, like a real bomb.
    path = make_jar({"bomb.bin": b"\x00" * (10 * 1024 * 1024)})
    assert path.stat().st_size < 50_000
    with SafeJar.open(path, Limits(max_entry_size=1024 * 1024)) as jar:
        with pytest.raises(EntryReadError, match="read limit"):
            jar.read("bomb.bin")
        # We stopped early: only ~1 MB was actually decompressed.
        assert jar.budget.used <= 1024 * 1024


def test_zip_bomb_total_budget_stopped(make_jar):
    # Many entries, each under the per-entry limit, together over budget.
    files = {f"part{i}.bin": b"\x00" * (512 * 1024) for i in range(10)}
    path = make_jar(files)
    limits = Limits(max_entry_size=1024 * 1024, max_total_decompressed=2 * 1024 * 1024)
    with SafeJar.open(path, limits) as jar:
        with pytest.raises(BudgetExceeded):
            for info in jar.files():
                jar.read(info)
        assert jar.budget.exhausted


def test_max_bytes_lowers_limit(make_jar):
    path = make_jar({"meta.json": "x" * 5000})
    with SafeJar.open(path) as jar:
        with pytest.raises(EntryReadError):
            jar.read("meta.json", max_bytes=100)


def test_duplicate_names_recorded(tmp_path):
    p = tmp_path / "dup.jar"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.txt", "first")
        with pytest.warns(UserWarning):  # zipfile warns about duplicates
            zf.writestr("a.txt", "second")
    with SafeJar.open(p) as jar:
        assert jar.duplicate_names == ["a.txt"]


def test_nested_jar_shares_budget(make_jar):
    inner = jar_bytes({"inner.bin": b"\x00" * (600 * 1024)})
    path = make_jar({"META-INF/jars/inner.jar": inner, "outer.bin": b"\x00" * (600 * 1024)})
    limits = Limits(max_total_decompressed=1024 * 1024)
    with SafeJar.open(path, limits) as outer:
        outer.read("outer.bin")
        nested = SafeJar.open_nested(outer.read("META-INF/jars/inner.jar"), "inner.jar", outer)
        with pytest.raises(BudgetExceeded):
            nested.read("inner.bin")


def test_nesting_depth_limit(make_jar):
    path = make_jar({"x.txt": "x"})
    with SafeJar.open(path, Limits(max_nesting_depth=0)) as outer:
        with pytest.raises(JarError, match="Nesting"):
            SafeJar.open_nested(jar_bytes({"a": "b"}), "n.jar", outer)


def test_detect_file_type():
    assert detect_file_type(b"PK\x03\x04") == "ZIP/JAR archive"
    assert "Windows" in detect_file_type(b"MZ\x90\x00")
    assert detect_file_type(b"") == "empty file"
