import base64

import pytest

from analyzer import indicators
from analyzer.classes import ParsedClass, parse_class
from analyzer.indicators import (ClassEvidence, RuleContext, add_batch_findings,
                                 classify_url, edit_distance, find_lookalike,
                                 run_rules, shannon_entropy)
from analyzer.limits import Limits
from analyzer.models import (AnalysisResult, ClassSummary, Confidence,
                             ContentsSummary, FileInfo, HashClassification,
                             HashLookup, ManifestInfo, ModInfo, Severity)
from tests.classbuilder import build_class


def pc(name, strings=(), refs=(), members=(), super_name="java/lang/Object", entry=None):
    return ParsedClass(entry_name=entry or f"{name}.class", name=name, super_name=super_name,
                       major_version=61, class_refs=set(refs), member_refs=set(members),
                       strings=list(strings))


def make_ctx(classes=(), contents=None, manifest=None, mods=(), hash_lookup=None,
             entry_names=None, limits=None, class_summary=None):
    ev = ClassEvidence()
    for c in classes:
        ev.add(c)
    names = entry_names if entry_names is not None else {c.entry_name for c in classes}
    return RuleContext(limits or Limits(), contents or ContentsSummary(), manifest or ManifestInfo(),
                       list(mods), class_summary or ClassSummary(), ev, hash_lookup or HashLookup(), names)


def findings_for(ctx):
    findings, errors = run_rules(ctx)
    assert errors == []
    return findings


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


FABRIC_MOD = ModInfo(loader="Fabric", source_file="fabric.mod.json", mod_id="coolmod",
                     name="Cool Mod", version="1.0.0",
                     extra={"entrypoints": "com.cool.CoolMod"})


# ---------------------------------------------------------------- negatives

def test_typical_legitimate_mod_has_no_review_or_warning():
    classes = [
        pc("com/cool/CoolMod", strings=["coolmod", "https://github.com/cool/coolmod/issues"],
           refs=["net/minecraft/class_1937", "java/lang/reflect/Field", "java/net/URI"]),
        pc("com/cool/UpdateChecker", strings=["https://api.modrinth.com/v2/project/coolmod"],
           refs=["java/net/URL", "java/net/HttpURLConnection", "java/net/URLEncoder"]),
        pc("com/cool/mixin/TitleScreenMixin", strings=["thisIsAVeryLongCamelCaseIdentifierName1234"],
           members=[("java/lang/Class", "forName")]),
        pc("com/cool/config/ConfigScreen", strings=["Save", "Cancel"]),
    ]
    ctx = make_ctx(classes, mods=[FABRIC_MOD])
    findings = findings_for(ctx)
    bad = [f for f in findings if f.severity != Severity.INFO]
    assert bad == [], bad
    assert ctx.evidence.references_minecraft
    rules = {f.rule_id for f in findings}
    assert {"metadata.detected", "api.reflection", "api.network", "strings.urls_other"} <= rules
    assert "strings.encoded" not in rules  # camelCase identifier is not "encoded"


def test_url_encoder_is_not_network():
    ctx = make_ctx([pc("a/B", refs=["java/net/URLEncoder", "java/net/URI"])])
    assert ctx.evidence.api_counts.get("network", 0) == 0


# ---------------------------------------------------------------- API usage

def test_process_execution_is_review():
    ctx = make_ctx([pc("a/Exec", members=[("java/lang/Runtime", "exec")])])
    [f] = by_rule(findings_for(ctx), "api.process_execution")
    assert f.severity == Severity.REVIEW and "a/Exec.class" in f.location


def test_custom_classloader_detected_via_superclass():
    ctx = make_ctx([pc("a/Loader", super_name="java/lang/ClassLoader")])
    assert by_rule(findings_for(ctx), "api.dynamic_loading")


def test_downloader_combo_same_class_is_warning():
    ctx = make_ctx([pc("a/Stage0", refs=["java/net/HttpURLConnection", "java/net/URLClassLoader"])])
    [f] = by_rule(findings_for(ctx), "combo.downloader")
    assert f.severity == Severity.WARNING


def test_downloader_combo_different_classes_is_review():
    ctx = make_ctx([pc("a/Net", members=[("java/net/URL", "openStream")]),
                    pc("a/Run", refs=["java/lang/ProcessBuilder"])])
    findings = findings_for(ctx)
    assert not by_rule(findings, "combo.downloader")
    assert by_rule(findings, "combo.downloader_spread")[0].severity == Severity.REVIEW


def test_session_token_access():
    ctx = make_ctx([pc("a/T", members=[("net/minecraft/class_320", "method_1674")])])
    assert by_rule(findings_for(ctx), "api.session_token")[0].severity == Severity.REVIEW


def test_reflective_sensitive_target():
    ctx = make_ctx([pc("a/R", strings=["java.lang.Runtime", "exec"])])
    assert by_rule(findings_for(ctx), "api.reflective_sensitive")


# ---------------------------------------------------------------- strings

def test_discord_webhook_is_warning():
    url = "https://discord.com/api/webhooks/123456/abcdef"
    ctx = make_ctx([pc("a/W", strings=[url])])
    [f] = by_rule(findings_for(ctx), "strings.url")
    assert f.severity == Severity.WARNING and f.confidence == Confidence.HIGH
    assert url in f.location


def test_credential_strings_plus_network_is_theft_combo():
    ctx = make_ctx([pc("a/Grab", strings=["\\discord\\Local Storage\\leveldb"],
                       refs=["java/net/HttpURLConnection"])])
    findings = findings_for(ctx)
    assert by_rule(findings, "strings.sensitive")[0].severity == Severity.WARNING
    [combo] = by_rule(findings, "combo.data_theft")
    assert combo.severity == Severity.WARNING and combo.confidence == Confidence.HIGH


def test_shell_string_alone_is_review():
    ctx = make_ctx([pc("a/S", strings=["cmd.exe /c start"])])
    [f] = by_rule(findings_for(ctx), "strings.sensitive")
    assert f.severity == Severity.REVIEW and f.confidence == Confidence.LOW


def test_encoded_class_payload_is_warning():
    payload = base64.b64encode(build_class("hidden/Stage2", strings=["x" * 50])).decode()
    ctx = make_ctx([pc("a/Packed", strings=[payload], members=[("java/util/Base64", "getDecoder")])])
    findings = findings_for(ctx)
    [f] = by_rule(findings, "strings.encoded_executable")
    assert f.severity == Severity.WARNING and f.confidence == Confidence.HIGH  # decoder in the same class
    assert by_rule(findings, "combo.packed_payload")[0].confidence == Confidence.HIGH


def test_base64_hidden_url_is_found():
    hidden = base64.b64encode(b"https://pastebin.com/raw/Xy12AbCd?token=QmFzZTY0").decode()
    ctx = make_ctx([pc("a/H", strings=[hidden])])
    findings = findings_for(ctx)
    [f] = by_rule(findings, "strings.url")
    assert f.severity == Severity.REVIEW and "Base64-decoded" in f.location
    assert by_rule(findings, "strings.encoded_url")[0].severity == Severity.REVIEW


def test_public_ip_port():
    ctx = make_ctx([pc("a/C2", strings=["connect 45.12.34.56:4444", "127.0.0.1:25565"])])
    [f] = by_rule(findings_for(ctx), "strings.ip_port")
    assert "45.12.34.56:4444" in f.location and "127.0.0.1" not in f.location


@pytest.mark.parametrize("url,severity", [
    ("https://github.com/x/y", Severity.INFO),
    ("https://raw.githubusercontent.com/x/y/main/v.json", Severity.INFO),
    ("https://my-mod-site.example/page", Severity.INFO),
    ("http://192.168.1.10/x", Severity.INFO),
    ("http://45.12.34.56/payload.jar", Severity.REVIEW),
    ("https://pastebin.com/raw/abc", Severity.REVIEW),
    ("https://abc.ngrok-free.app/x", Severity.REVIEW),
    ("https://cdn.discordapp.com/attachments/1/2/a.jar", Severity.REVIEW),
    ("https://api.telegram.org/bot123:ABC/sendDocument", Severity.WARNING),
    ("http://[not-valid", Severity.INFO),
])
def test_classify_url(url, severity):
    assert classify_url(url)[0] == severity


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9


# ---------------------------------------------------------------- class names

def test_obfuscated_names():
    classes = [pc(f"a/{chr(97 + i)}") for i in range(15)] + [pc("a/RealName")]
    [f] = by_rule(findings_for(make_ctx(classes)), "classes.obfuscated")
    assert f.severity == Severity.REVIEW


def test_confusable_default_package_reserved_and_mismatch():
    classes = [pc("x/IlIlIl"), pc("Main"), pc("net/minecraft/client/Hack"),
               pc("com/real/Name", entry="com/other/Place.class")]
    findings = findings_for(make_ctx(classes))
    for rule in ("classes.confusable_names", "classes.default_package",
                 "classes.reserved_namespace", "classes.name_mismatch"):
        assert by_rule(findings, rule), rule


def test_multi_release_path_is_not_mismatch():
    ctx = make_ctx([pc("com/a/B", entry="META-INF/versions/17/com/a/B.class")])
    assert ctx.evidence.name_mismatches == []


def test_cheat_features_and_known_client():
    classes = [pc("meteordevelopment/meteorclient/systems/modules/combat/KillAura", strings=["AutoClicker"])]
    findings = findings_for(make_ctx(classes))
    assert by_rule(findings, "classes.known_client")[0].severity == Severity.REVIEW
    assert by_rule(findings, "classes.cheat_feature_names")
    assert by_rule(findings, "classes.cheat_feature_strings")
    assert all(f.severity != Severity.WARNING for f in findings)  # rules, not malware


def test_malware_word_in_name():
    ctx = make_ctx([pc("a/TokenStealer")])
    assert by_rule(findings_for(ctx), "classes.malware_names")[0].confidence == Confidence.MEDIUM


# ---------------------------------------------------------------- metadata / manifest / hash

def test_lookalike_detection():
    assert find_lookalike("sodium") == ("sodium", "exact")
    assert find_lookalike("sodiurn") == ("sodium", "lookalike")      # rn -> m
    assert find_lookalike("L1thium") == ("lithium", "lookalike")
    assert find_lookalike("lithiun") == ("lithium", "lookalike")
    assert find_lookalike("sodium-extra-addons") is None             # addon naming
    assert find_lookalike("mycoolmod") is None
    assert edit_distance("kitten", "sitting", 5) == 3
    assert edit_distance("abc", "abcdefgh", 2) == 3


def test_impersonation_rule():
    fake = ModInfo(loader="Fabric", source_file="fabric.mod.json", mod_id="sodiurn", name="Sodium", version="1")
    findings = findings_for(make_ctx(mods=[fake]))
    assert by_rule(findings, "metadata.lookalike")[0].severity == Severity.REVIEW
    assert by_rule(findings, "metadata.popular_mod_claim")[0].severity == Severity.INFO


def test_popular_claim_suppressed_when_verified():
    real = ModInfo(loader="Fabric", source_file="fabric.mod.json", mod_id="sodium", version="1")
    ctx = make_ctx(mods=[real], hash_lookup=HashLookup(classification=HashClassification.VERIFIED))
    findings = findings_for(ctx)
    assert not by_rule(findings, "metadata.popular_mod_claim")
    assert by_rule(findings, "hash.verified")


def test_missing_entrypoint_and_inconsistent_metadata():
    forge = ModInfo(loader="Forge", source_file="META-INF/mods.toml", mod_id="othermod", version="2.0")
    findings = findings_for(make_ctx(mods=[FABRIC_MOD, forge], entry_names=set()))
    assert by_rule(findings, "metadata.missing_entrypoint")[0].location.endswith("com.cool.CoolMod")
    assert by_rule(findings, "metadata.inconsistent_id")
    assert by_rule(findings, "metadata.inconsistent_version")


def test_no_metadata_is_info_only():
    [f] = by_rule(findings_for(make_ctx()), "metadata.none")
    assert f.severity == Severity.INFO


def test_manifest_agent_and_main_class():
    m = ManifestInfo(present=True, attributes={"Main-Class": "a.B", "Premain-Class": "a.Agent"})
    findings = findings_for(make_ctx(manifest=m))
    assert by_rule(findings, "manifest.main_class")[0].severity == Severity.INFO
    assert by_rule(findings, "manifest.java_agent")[0].severity == Severity.REVIEW


def test_hash_suspicious_is_warning():
    h = HashLookup(classification=HashClassification.SUSPICIOUS, name="Bad", notes="seen in incident")
    [f] = by_rule(findings_for(make_ctx(hash_lookup=h)), "hash.suspicious")
    assert f.severity == Severity.WARNING and "incident" in f.explanation


def test_unknown_hash_produces_no_finding():
    findings = findings_for(make_ctx())
    assert not [f for f in findings if f.rule_id.startswith("hash.")]


# ---------------------------------------------------------------- contents

def test_contents_rules():
    c = ContentsSummary(executables_and_scripts=["run.bat"], native_libraries=["x.dll"],
                        disguised_files=["a.png (detected: Windows executable (PE))"],
                        unsafe_names=["../x"], duplicate_names=["a"], encrypted_entries=["e"])
    findings = findings_for(make_ctx(contents=c))
    # Stored but nothing in the JAR can run them: REVIEW, not WARNING.
    assert by_rule(findings, "contents.executables")[0].severity == Severity.REVIEW
    # Bundled native libraries are a fact; code that LOADS them is rated separately.
    assert by_rule(findings, "contents.native_libraries")[0].severity == Severity.INFO
    [disguised] = by_rule(findings, "contents.disguised")
    assert disguised.severity == Severity.WARNING and disguised.confidence == Confidence.MEDIUM
    for rule in ("contents.unsafe_paths", "contents.duplicates", "contents.encrypted"):
        assert by_rule(findings, rule)
    # Sorted most severe first.
    ranks = [{"WARNING": 0, "REVIEW": 1, "INFO": 2}[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_incomplete_and_invalid_classes():
    cs = ClassSummary(total=10, parsed=5, failed=2, skipped=3, failed_entries=["a.class (bad)"])
    findings = findings_for(make_ctx(class_summary=cs))
    assert by_rule(findings, "classes.invalid") and by_rule(findings, "classes.incomplete")


# ---------------------------------------------------------------- engine

def test_findings_are_capped():
    urls = [f"https://pastebin.com/raw/{i}" for i in range(10)]
    ctx = make_ctx([pc("a/B", strings=urls)], limits=Limits(max_findings_per_rule=3))
    url_findings = by_rule(findings_for(ctx), "strings.url")
    assert len(url_findings) == 4
    assert "7 more" in url_findings[-1].title


def test_broken_rule_does_not_crash(monkeypatch):
    def broken(ctx):
        raise KeyError("boom")
    monkeypatch.setattr(indicators, "RULES", [broken, indicators.rule_metadata_presence])
    findings, errors = run_rules(make_ctx())
    assert len(findings) == 1 and "broken" in errors[0]


def test_batch_duplicate_mod_ids():
    def result(name, mod_id):
        r = AnalysisResult("x", "0", "t", FileInfo(name=name))
        r.mods = [ModInfo(loader="Fabric", source_file="fabric.mod.json", mod_id=mod_id)]
        return r
    a, b, c = result("a.jar", "sodium"), result("b.jar", "Sodium"), result("c.jar", "other")
    add_batch_findings([a, b, c])
    assert by_rule(a.findings, "batch.duplicate_mod_id")[0].location == "b.jar"
    assert by_rule(b.findings, "batch.duplicate_mod_id")
    assert not c.findings


def test_evidence_from_real_class_bytes():
    parsed = parse_class(build_class("a/Evil", strings=["https://discord.com/api/webhooks/1/x"],
                                     method_refs=[("java/lang/Runtime", "exec")]), "a/Evil.class")
    ctx = make_ctx([parsed])
    rules = {f.rule_id for f in findings_for(ctx)}
    assert {"strings.url", "api.process_execution"} <= rules


# ---------------------------------------------------------------- real-world false-positive regressions

def test_fp_launcher_name_is_not_account_file():
    # Sodium mentions launcher names to show troubleshooting help.
    ctx = make_ctx([pc("net/caffeinemc/PreLaunchChecks", strings=["prismlauncher", ".tlauncher"],
                       members=[("java/net/URL", "openConnection")])])
    findings = findings_for(ctx)
    assert not by_rule(findings, "strings.sensitive") and not by_rule(findings, "combo.data_theft")


def test_launcher_account_file_path_is_warning():
    ctx = make_ctx([pc("a/G", strings=["/.lunarclient/settings/game/accounts.json"])])
    assert by_rule(findings_for(ctx), "strings.sensitive")[0].severity == Severity.WARNING


def test_fp_non_minecraft_getsessionid():
    # Sentry's crash reporter has its own Session.getSessionId().
    ctx = make_ctx([pc("io/sentry/cache/EnvelopeCache", members=[("io/sentry/Session", "getSessionId")])])
    assert ctx.evidence.api_counts.get("session_token", 0) == 0


def test_fp_dropper_block_mixin():
    ctx = make_ctx([pc("net/fabricmc/fabric/mixin/transfer/DropperBlockMixin")])
    assert not by_rule(findings_for(ctx), "classes.malware_names")


def test_fp_urlclassloader_with_url_is_not_downloader():
    ctx = make_ctx([pc("net/lenni0451/reflect/ClassLoaders", refs=["java/net/URL", "java/net/URLClassLoader"])])
    findings = findings_for(ctx)
    assert not by_rule(findings, "combo.downloader") and not by_rule(findings, "api.network")


def test_session_token_network_review_vs_warning():
    token = ("net/minecraft/class_320", "method_1674")
    net = ("java/net/URL", "openConnection")
    plain = make_ctx([pc("a/Auth", members=[token, net])])
    assert by_rule(findings_for(plain), "combo.session_token_network")[0].severity == Severity.REVIEW
    exfil = make_ctx([pc("a/Auth", members=[token, net], strings=["https://abc.ngrok-free.app/t"])])
    assert by_rule(findings_for(exfil), "combo.session_token_network")[0].severity == Severity.WARNING
