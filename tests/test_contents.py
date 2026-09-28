import zipfile

from analyzer.contents import extension_of, is_unsafe_path, summarize_contents
from analyzer.jar import SafeJar
from analyzer.limits import Limits


def test_inventory_counts(make_jar):
    path = make_jar({
        "com/ex/A.class": b"\xca\xfe\xba\xbe",
        "com/ex/B.class": b"\xca\xfe\xba\xbe",
        "fabric.mod.json": "{}",
        "assets/ex/icon.png": b"\x89PNG",
        "natives/lib.dll": b"MZ",
        "run.bat": "@echo off",
        "META-INF/jars/lib.jar": b"PK",
        "weird.xyz": b"?",
        "LICENSE": "MIT",
        "META-INF/CERT.RSA": b"sig",
    })
    with SafeJar.open(path) as jar:
        s = summarize_contents(jar)
    assert s.total_files == 10
    assert s.by_extension[".class"] == 2
    assert s.native_libraries == ["natives/lib.dll"]
    assert s.executables_and_scripts == ["run.bat"]
    assert s.nested_jars == ["META-INF/jars/lib.jar"]
    assert s.unusual_files == ["weird.xyz"]  # LICENSE is not unusual
    assert s.signature_files == ["META-INF/CERT.RSA"]


def test_large_and_high_ratio(make_jar):
    path = make_jar({"zeros.bin": b"\x00" * (2 * 1024 * 1024)})
    limits = Limits(large_file_threshold=1024 * 1024, suspicious_ratio_min_size=1024 * 1024)
    with SafeJar.open(path, limits) as jar:
        s = summarize_contents(jar)
    assert [e.path for e in s.large_files] == ["zeros.bin"]
    assert [e.path for e in s.high_ratio_entries] == ["zeros.bin"]


def test_unsafe_and_deceptive_names(tmp_path):
    p = tmp_path / "t.jar"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../../evil.txt", "x")
        zf.writestr("readme\u202etxt.exe", "x")
    with SafeJar.open(p) as jar:
        s = summarize_contents(jar)
    assert s.unsafe_names == ["../../evil.txt"]
    assert len(s.deceptive_names) == 1


def test_helpers():
    assert extension_of("a/b/C.CLASS") == ".class"
    assert extension_of("a/b/noext") == ""
    assert is_unsafe_path("C:/Windows/x.dll")
    assert is_unsafe_path("a\\b.txt")
    assert not is_unsafe_path("a/b..c/d.txt")


def test_disguised_files(make_jar):
    from analyzer.contents import find_disguised_files
    from tests.classbuilder import build_class
    path = make_jar({
        "assets/texture.png": b"MZ\x90\x00" + b"\x00" * 60,            # exe named .png
        "data/cfg.dat": build_class("hidden/Payload"),                  # class named .dat
        "assets/real.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 20,
        "lib/native.dll": b"MZ\x90\x00" + b"\x00" * 60,                 # expected
        "META-INF/jars/x.jar": b"PK\x03\x04" + b"\x00" * 30,            # expected
    })
    with SafeJar.open(path) as jar:
        disguised, errors = find_disguised_files(jar)
    assert len(disguised) == 2
    assert disguised[0].startswith("assets/texture.png (detected: Windows")
    assert disguised[1].startswith("data/cfg.dat (detected: Java class")
