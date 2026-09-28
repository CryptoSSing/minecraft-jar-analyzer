import json
import os

from analyzer.hash_database import HashDatabase
from analyzer.hashing import sha256_file
from analyzer.limits import Limits
from analyzer.models import HashClassification, Severity
from analyzer.pipeline import analyze_file, analyze_files, collect_jars, load_hash_database
from tests.classbuilder import build_class
from tests.conftest import jar_bytes

FABRIC = json.dumps({"schemaVersion": 1, "id": "coolmod", "name": "Cool Mod", "version": "1.0.0",
                     "entrypoints": {"main": ["com.cool.CoolMod"]}, "depends": {"minecraft": "1.20.1"}})


def rules(result):
    return {f.rule_id for f in result.findings}


def empty_db():
    return HashDatabase()


def test_clean_fabric_mod_end_to_end(make_jar):
    path = make_jar({
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Title: Cool Mod\n",
        "fabric.mod.json": FABRIC,
        "com/cool/CoolMod.class": build_class("com/cool/CoolMod", class_refs=["net/minecraft/class_310"]),
        "assets/coolmod/icon.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 20,
    }, name="cool.jar")
    r = analyze_file(path, empty_db())
    assert r.errors == []
    assert r.file.name == "cool.jar" and r.file.is_valid_jar
    assert r.file.sha256 == sha256_file(path)
    assert r.file.file_type == "ZIP/JAR archive"
    assert r.loader == "Fabric"
    assert r.primary_mod().name == "Cool Mod"
    assert r.manifest.attributes["Implementation-Title"] == "Cool Mod"
    assert r.contents.total_files == 4 and r.classes.parsed == 1
    assert r.hash_lookup.classification == HashClassification.UNKNOWN
    assert r.highest_severity() == Severity.INFO


def test_malicious_looking_mod_end_to_end(make_jar):
    evil = build_class("com/cool/Updater", strings=["https://discord.com/api/webhooks/1/abc",
                                                    "\\Local Storage\\leveldb"],
                       method_refs=[("java/net/URL", "openConnection"), ("java/lang/Runtime", "exec")])
    path = make_jar({"fabric.mod.json": FABRIC, "com/cool/CoolMod.class": build_class("com/cool/CoolMod"),
                     "com/cool/Updater.class": evil, "run.bat": "@echo off"})
    r = analyze_file(path, empty_db())
    assert r.highest_severity() == Severity.WARNING
    assert {"strings.url", "combo.data_theft", "combo.downloader", "contents.executables"} <= rules(r)
    assert r.findings[0].severity == Severity.WARNING  # sorted


def test_corrupt_jar_still_reports_hash(tmp_path):
    p = tmp_path / "broken.jar"
    p.write_bytes(b"PK\x03\x04" + os.urandom(2000))
    r = analyze_file(p, empty_db())
    assert not r.file.is_valid_jar
    assert r.file.sha256 == sha256_file(p)
    assert r.errors and "Corrupt" in r.errors[0]


def test_exe_renamed_to_jar(tmp_path):
    p = tmp_path / "mod.jar"
    p.write_bytes(b"MZ" + b"\x00" * 200)
    r = analyze_file(p, empty_db())
    assert r.file.file_type == "Windows executable (PE)"
    assert "Windows executable" in r.errors[0]


def test_oversized_file_refused_but_hashed(make_jar):
    path = make_jar({"a.bin": os.urandom(5000)})
    r = analyze_file(path, empty_db(), Limits(max_jar_size=1000))
    assert not r.file.is_valid_jar and "larger than" in r.errors[0]
    assert r.file.sha256 is not None


def test_suspicious_hash_reported_even_for_unopenable_file(tmp_path):
    p = tmp_path / "x.jar"
    p.write_bytes(b"not a zip at all")
    db = HashDatabase()
    db.set_entry(sha256_file(p), HashClassification.SUSPICIOUS, name="Known bad")
    r = analyze_file(p, db)
    assert r.hash_lookup.classification == HashClassification.SUSPICIOUS
    assert "hash.suspicious" in rules(r)


def test_missing_file(tmp_path):
    r = analyze_file(tmp_path / "gone.jar", empty_db())
    assert "Cannot access" in r.errors[0]


def test_zip_bomb_end_to_end(make_jar):
    path = make_jar({"com/a/A.class": build_class("com/a/A"),
                     "bomb.bin": b"\x00" * (4 * 1024 * 1024)})
    limits = Limits(suspicious_ratio_min_size=1024 * 1024)
    r = analyze_file(path, empty_db(), limits)
    assert "contents.compression_ratio" in rules(r)
    # Nothing read the bomb in full: only its 8-byte header was sniffed.
    assert r.classes.parsed == 1


def test_nested_jar_findings_merged(make_jar):
    inner = jar_bytes({
        "fabric.mod.json": json.dumps({"id": "innerlib", "version": "0.1"}),
        "lib/Stage2.class": build_class("lib/Stage2", class_refs=["java/net/HttpURLConnection", "java/net/URLClassLoader"]),
    })
    path = make_jar({"fabric.mod.json": FABRIC, "com/cool/CoolMod.class": build_class("com/cool/CoolMod"),
                     "META-INF/jars/innerlib.jar": inner})
    r = analyze_file(path, empty_db())
    [nested] = r.nested_jars
    assert nested.loader == "Fabric" and nested.mod_ids == ["innerlib"] and nested.sha256
    combo = [f for f in r.findings if f.rule_id == "combo.downloader"]
    assert combo and combo[0].location.startswith("META-INF/jars/innerlib.jar → ")
    assert r.primary_mod().mod_id == "coolmod"
    assert any(m.nested_in == "META-INF/jars/innerlib.jar" for m in r.mods)


def test_corrupt_nested_jar_is_error_not_crash(make_jar):
    path = make_jar({"META-INF/jars/bad.jar": b"PK\x03\x04garbage"})
    r = analyze_file(path, empty_db())
    assert r.nested_jars[0].error
    assert any("bad.jar" in e for e in r.errors)


def test_batch_and_folder(tmp_path, make_jar):
    make_jar({"fabric.mod.json": FABRIC}, name="a.jar")
    make_jar({"fabric.mod.json": FABRIC}, name="B.JAR")
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / "sub").mkdir()
    make_jar({"x": "y"}, name="sub/c.jar")
    assert [p.name for p in collect_jars(tmp_path)] == ["a.jar", "B.JAR"]
    assert len(collect_jars(tmp_path, recursive=True)) == 3
    progress = []
    results = analyze_files(collect_jars(tmp_path), empty_db(), progress=lambda *a: progress.append(a))
    assert all("batch.duplicate_mod_id" in rules(r) for r in results)
    assert progress[-1] == (2, 2, "")


def test_cancel_batch(make_jar):
    p = make_jar({"x": "y"})
    assert analyze_files([p, p], empty_db(), should_cancel=lambda: True) == []


def test_load_hash_database_fallback(tmp_path):
    bad = tmp_path / "db.json"
    bad.write_text("{broken")
    db, messages = load_hash_database(bad)
    assert db.entries == {} and "unavailable" in messages[0]
    db, messages = load_hash_database()  # the shipped database
    assert messages == []


def test_result_is_json_serializable(make_jar):
    path = make_jar({"fabric.mod.json": FABRIC})
    json.dumps(analyze_file(path, empty_db()).to_dict())
