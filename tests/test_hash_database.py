import json

import pytest

from analyzer.hash_database import HashDatabase, HashDatabaseError
from analyzer.hashing import sha256_file
from analyzer.models import HashClassification
from analyzer.resources import PROJECT_ROOT
from tools.add_hash import main as add_hash_main

SHA_A = "a" * 64
SHA_B = "b" * 64


def write_db(tmp_path, data):
    p = tmp_path / "hashes.json"
    p.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return p


def test_shipped_database_is_valid():
    db = HashDatabase.load(PROJECT_ROOT / "database" / "hashes.json")
    assert db.warnings == []


def test_lookup_hit_miss_and_case(tmp_path):
    p = write_db(tmp_path, {"schema_version": 1, "entries": {
        SHA_A.upper(): {"classification": "verified", "name": "Good Mod", "version": "1.0"},
        SHA_B: {"classification": "SUSPICIOUS", "notes": "incident 7"},
    }})
    db = HashDatabase.load(p)
    hit = db.lookup(SHA_A)
    assert hit.classification == HashClassification.VERIFIED and hit.name == "Good Mod"
    assert db.lookup(SHA_B.upper()).notes == "incident 7"
    miss = db.lookup("c" * 64)
    assert miss.classification == HashClassification.UNKNOWN  # unknown is NOT suspicious
    assert db.lookup(None).classification == HashClassification.UNKNOWN


def test_invalid_entries_skipped_with_warnings(tmp_path):
    p = write_db(tmp_path, {"schema_version": 1, "entries": {
        "not-a-hash": {"classification": "VERIFIED"},
        SHA_A: {"classification": "MALWARE"},
        SHA_B: "just a string",
    }})
    db = HashDatabase.load(p)
    assert db.entries == {} and len(db.warnings) == 3


@pytest.mark.parametrize("content", [
    "{not json",
    "[1, 2]",
    json.dumps({"schema_version": 99, "entries": {}}),
    json.dumps({"schema_version": 1, "entries": []}),
])
def test_malformed_database_raises_friendly_error(tmp_path, content):
    with pytest.raises(HashDatabaseError):
        HashDatabase.load(write_db(tmp_path, content))


def test_missing_database(tmp_path):
    with pytest.raises(HashDatabaseError, match="not found"):
        HashDatabase.load(tmp_path / "nope.json")


def test_save_roundtrip(tmp_path):
    db = HashDatabase(path=tmp_path / "db" / "hashes.json")
    db.set_entry(SHA_A.upper(), HashClassification.SUSPICIOUS, name="X", notes="n")
    db.save()
    again = HashDatabase.load(tmp_path / "db" / "hashes.json")
    assert again.lookup(SHA_A).classification == HashClassification.SUSPICIOUS
    assert not list((tmp_path / "db").glob("*.tmp"))  # temp file cleaned up
    with pytest.raises(ValueError):
        db.set_entry("xyz", HashClassification.VERIFIED)


def test_add_hash_tool(tmp_path, make_jar, capsys):
    jar = make_jar({"fabric.mod.json": '{"id": "cool", "name": "Cool Mod", "version": "2.1"}'})
    db_path = tmp_path / "hashes.json"
    assert add_hash_main([str(jar), "--classification", "verified", "--db", str(db_path)]) == 0
    db = HashDatabase.load(db_path)
    hit = db.lookup(sha256_file(jar))
    assert (hit.classification, hit.name, hit.version) == (HashClassification.VERIFIED, "Cool Mod", "2.1")

    assert add_hash_main(["--list", "--db", str(db_path)]) == 0
    assert "Cool Mod" in capsys.readouterr().out
    assert add_hash_main(["--remove", sha256_file(jar), "--db", str(db_path)]) == 0
    assert HashDatabase.load(db_path).entries == {}
