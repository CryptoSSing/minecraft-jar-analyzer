import json

import pytest

from analyzer.__main__ import main as cli_main
from analyzer.hash_database import HashDatabase
from analyzer.pipeline import analyze_file
from reports.exporter import summary_sentence, to_json, to_text, write_report
from tests.classbuilder import build_class

FABRIC = json.dumps({"id": "evilmod", "name": "Evil\x1b[2J Mod", "version": "1.0",
                     "description": "Line1\nLine2‮"})


@pytest.fixture
def results(make_jar, tmp_path):
    evil = build_class("x/Evil", strings=["https://discord.com/api/webhooks/1/a"])
    good = make_jar({"fabric.mod.json": FABRIC, "x/Evil.class": evil,
                     "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"}, name="evil.jar")
    broken = tmp_path / "broken.jar"
    broken.write_bytes(b"garbage")
    return [analyze_file(good, HashDatabase()), analyze_file(broken, HashDatabase())]


def test_json_report_contains_everything(results):
    data = json.loads(to_json(results))
    assert data["report"]["version"] == "0.1.0" and data["report"]["file_count"] == 2
    assert "not prove" in data["report"]["disclaimer"]
    first = data["results"][0]
    for key in ("analyzer_version", "analyzed_at", "file", "hash_lookup", "manifest", "mods",
                "contents", "classes", "nested_jars", "findings", "errors", "summary"):
        assert key in first, key
    assert len(first["file"]["sha256"]) == 64
    assert first["hash_lookup"]["classification"] == "UNKNOWN"
    assert first["findings"][0]["severity"] == "WARNING"
    assert {"severity", "title", "location", "explanation", "confidence"} <= set(first["findings"][0])
    assert data["results"][1]["errors"]


def test_json_has_no_full_paths(results, tmp_path):
    assert str(tmp_path) not in to_json(results)
    assert str(tmp_path) not in to_text(results)


def test_text_report_sections_and_sanitizing(results):
    text = to_text(results)
    for section in ("FILE", "HASH DATABASE", "MOD METADATA", "MANIFEST", "CONTENTS",
                    "CLASSES", "FINDINGS", "ERRORS", "SHA-256", "IMPORTANT:"):
        assert section in text, section
    assert "NOT an indication of malice" in text
    assert "⚠ WARNING" in text
    assert "\x1b" not in text and "‮" not in text  # control/bidi characters neutralised
    assert "Line1" in text and "Line2" in text


def test_summary_sentences(results):
    assert "warning" in summary_sentence(results[0])
    assert "could not be analyzed" in summary_sentence(results[1])


def test_write_report(results, tmp_path):
    j = write_report(tmp_path / "r.json", results, "json")
    t = write_report(tmp_path / "r.txt", results, "txt")
    assert json.loads(j.read_text(encoding="utf-8"))["results"]
    assert "Analysis Report" in t.read_text(encoding="utf-8")
    with pytest.raises(ValueError):
        write_report(tmp_path / "r.pdf", results, "pdf")


def test_cli(make_jar, tmp_path, capsys):
    jar = make_jar({"fabric.mod.json": FABRIC}, name="cli.jar")
    out_json = tmp_path / "out.json"
    assert cli_main([str(tmp_path), "--json", str(out_json)]) == 0
    captured = capsys.readouterr()
    assert "cli.jar" in captured.out and "Analyzing 1/1" in captured.err
    assert json.loads(out_json.read_text(encoding="utf-8"))["results"][0]["file"]["name"] == "cli.jar"
    assert cli_main([str(tmp_path / "missing.jar")]) == 1


def test_reports_explain_severity_and_confidence(results):
    data = json.loads(to_json(results))
    warning = data["results"][0]["findings"][0]
    assert warning["context"] and warning["rationale"]  # why this rating, not just what
    text = to_text(results)
    assert "Why this rating:" in text and "Context found:" in text
    assert "REVIEW  inspect this behavior" in text and "WARNING strong security concern" in text
    # INFO findings are facts: no confidence level is claimed for them.
    findings_section = text.split("FINDINGS (", 1)[1]
    info_block = findings_section.split(" INFO    ", 1)[1].split("\n\n", 1)[0]
    assert "Confidence: —" in info_block
