from analyzer.sanitize import REPLACEMENT, has_deceptive_chars, safe_text


def test_rtl_override_neutralised():
    name = "photo‮gpj.exe"
    assert has_deceptive_chars(name)
    assert "‮" not in safe_text(name)
    assert REPLACEMENT in safe_text(name)


def test_ansi_escape_neutralised():
    assert "\x1b" not in safe_text("\x1b[2Jcleared")


def test_newlines_optional():
    assert safe_text("a\nb") == f"a{REPLACEMENT}b"
    assert safe_text("a\nb", allow_newlines=True) == "a\nb"


def test_truncation_and_none():
    assert safe_text(None) == ""
    assert len(safe_text("x" * 5000, max_length=10)) < 30
