"""Tests for the severity/confidence model.

Severity = how security-relevant an observation is (INFO fact, REVIEW
capability to inspect, WARNING strong indicator or combination).
Confidence = how strongly the evidence shows it is security-significant.

The groups below:
  1. Sodium-style false-positive regressions (built from the constant-pool
     patterns found in the real Sodium JAR - no special-casing by name).
  2. Genuinely suspicious combinations still produce WARNING/HIGH.
  3. A single benign capability never becomes WARNING or HIGH by itself.
  4. Evidence correlation: related observations strengthen a finding.
  5. Every REVIEW/WARNING finding explains its context and rating.
"""

import base64

import pytest

from analyzer.indicators import _process_context, classify_url
from analyzer.models import Confidence, ContentsSummary, ManifestInfo, ModInfo, Severity
from tests.classbuilder import build_class
from tests.test_indicators import by_rule, findings_for, make_ctx, pc

INFO, REVIEW, WARNING = Severity.INFO, Severity.REVIEW, Severity.WARNING
LOW, MEDIUM, HIGH = Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH

PROCESS = ("java/lang/ProcessBuilder",)
NET = ("java/net/URL", "openConnection")
WRITE = ("java/nio/file/Files", "copy")
DEFINE = ("java/lang/invoke/MethodHandles$Lookup", "defineHiddenClass")
B64 = ("java/util/Base64", "getDecoder")

# ------------------------------------------------------------ 1. Sodium-style regressions

SODIUM_MOD = ModInfo(loader="Fabric", source_file="fabric.mod.json", mod_id="examplemod", version="1.0",
                     extra={"entrypoints": "net/example/Mod"})


def sodium_like_classes():
    """The four Sodium classes that used to produce REVIEW MEDIUM/HIGH findings."""
    return [
        # GPU detection on Linux: runs "lspci -vmm -d ...".
        pc("net/example/probe/GraphicsAdapterProbe", refs=PROCESS, strings=["lspci", "-vmm", "-d"]),
        # "Open in browser" on Linux.
        pc("net/example/browse/XDGImpl", refs=PROCESS, strings=["xdg-open"]),
        # Lists DLLs injected into the game process through JNA's Kernel32 binding.
        pc("net/example/checks/ModuleScanner",
           refs=["com/sun/jna/platform/win32/Kernel32", "com/sun/jna/platform/win32/Kernel32Util",
                 "com/sun/jna/platform/win32/Tlhelp32$MODULEENTRY32W"],
           strings=["RTSSHooks64.dll", "nvspcap64.dll"]),
        # Generates vertex serializers as bytecode in memory and defines them.
        pc("net/example/serializers/VertexSerializerFactory", members=[DEFINE],
           strings=["(JJ)V", "(J)J", "(JJI)V", "serialize"]),
    ]


def sodium_ctx():
    c = ContentsSummary(nested_jars=[f"META-INF/jars/lib{i}.jar" for i in range(9)])
    m = ManifestInfo(present=True, attributes={"Main-Class": "net.example.InstallerMessage"})
    return make_ctx(sodium_like_classes(), contents=c, manifest=m, mods=[SODIUM_MOD])


def test_sodium_metadata_main_class_and_bundled_jars_are_info():
    findings = findings_for(sodium_ctx())
    for rule in ("metadata.detected", "manifest.main_class", "contents.nested_jars"):
        [f] = by_rule(findings, rule)
        assert f.severity == INFO and f.confidence == LOW, rule


def test_sodium_helper_commands_are_review_low_and_named():
    process = by_rule(findings_for(sodium_ctx()), "api.process_execution")
    assert len(process) == 2  # one finding per class, not one vague finding for the JAR
    assert all(f.severity == REVIEW and f.confidence == LOW for f in process)
    titles = " ".join(f.title for f in process)
    assert "lspci" in titles and "xdg-open" in titles
    assert all("helper" in f.context for f in process)


def test_sodium_jna_os_calls_are_review_low():
    [f] = by_rule(findings_for(sodium_ctx()), "api.native_loading")
    assert f.severity == REVIEW and f.confidence == LOW
    assert "Kernel32" in f.context and "without loading a library file" in f.context


def test_sodium_generated_bytecode_is_review_low():
    [f] = by_rule(findings_for(sodium_ctx()), "api.dynamic_loading")
    assert f.severity == REVIEW and f.confidence == LOW
    assert "generate the bytecode" in f.context


def test_sodium_like_mod_has_no_warning_and_nothing_high():
    findings = findings_for(sodium_ctx())
    assert not [f for f in findings if f.severity == WARNING]
    assert not [f for f in findings if f.confidence == HIGH]


# ------------------------------------------------------------ 2. suspicious combinations stay WARNING/HIGH

def test_updater_style_download_and_hidden_script_is_warning_high():
    # Pattern of the real AnchorOptimizer/Silicon updater: download a .jar,
    # write a script, launch it hidden with the PowerShell policy bypassed.
    cls = pc("a/Updater", refs=PROCESS, members=[NET, WRITE],
             strings=["https://api.modrinth.com/v2/project/x/version", "update.jar", "update.ps1",
                      "powershell.exe", "-ExecutionPolicy Bypass", "-WindowStyle Hidden"])
    findings = findings_for(make_ctx([cls]))
    [down] = by_rule(findings, "combo.downloader")
    assert down.severity == WARNING and down.confidence == HIGH
    [hidden] = by_rule(findings, "combo.hidden_execution")
    assert hidden.severity == WARNING and hidden.confidence == HIGH
    assert "hides the PowerShell window" in hidden.context


def test_download_jar_and_load_it_is_warning_high():
    cls = pc("a/Stage0", refs=["java/net/URLClassLoader"], members=[NET, WRITE],
             strings=["http://example.org/stage2.jar"])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.downloader")
    assert f.severity == WARNING and f.confidence == HIGH


def test_downloaded_native_library_is_warning():
    cls = pc("a/NativeDropper", members=[NET, WRITE, ("java/lang/System", "load")], strings=["payload.dll"])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.downloader")
    assert f.severity == WARNING and f.confidence == HIGH


def test_persistence_plus_execution_is_warning_high():
    cls = pc("a/Persist", refs=PROCESS, strings=["schtasks", "/create /sc onlogon"])
    findings = findings_for(make_ctx([cls]))
    [f] = by_rule(findings, "combo.persistence_exec")
    assert f.severity == WARNING and f.confidence == HIGH


def test_encoded_payload_plus_class_loading_is_warning_high():
    payload = base64.b64encode(build_class("hidden/Stage2", strings=["x" * 50])).decode()
    cls = pc("a/Unpacker", members=[DEFINE], strings=[payload])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.decoded_exec")
    assert f.severity == WARNING and f.confidence == HIGH


def test_base64_hidden_url_plus_execution_is_warning_high():
    hidden = base64.b64encode(b"https://evil.example/stage2/payload/download").decode()
    cls = pc("a/Hidden", refs=PROCESS, strings=[hidden])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.decoded_exec")
    assert f.severity == WARNING and f.confidence == HIGH


def test_base64_decoding_plus_class_loading_is_warning_medium():
    cls = pc("a/Loader", members=[B64, DEFINE])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.decoded_exec")
    assert f.severity == WARNING and f.confidence == MEDIUM


def test_token_network_and_webhook_in_same_class_is_warning_high():
    token = ("net/minecraft/class_320", "method_1674")
    cls = pc("a/Grab", members=[token, NET], strings=["https://abc.ngrok-free.app/t"])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.session_token_network")
    assert f.severity == WARNING and f.confidence == HIGH


def test_executables_plus_code_that_runs_programs_is_warning_high():
    c = ContentsSummary(executables_and_scripts=["payload.exe"])
    [f] = by_rule(findings_for(make_ctx([pc("a/Run", refs=PROCESS)], contents=c)), "contents.executables")
    assert f.severity == WARNING and f.confidence == HIGH


def test_credential_theft_is_unchanged_warning_high():
    cls = pc("a/Grab", strings=["\\discord\\Local Storage\\leveldb"], refs=["java/net/HttpURLConnection"])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.data_theft")
    assert f.severity == WARNING and f.confidence == HIGH


# ------------------------------------------------------------ 3. single benign capabilities stay low

SINGLE_CAPABILITIES = {
    "ProcessBuilder": pc("a/C", refs=PROCESS),
    "Runtime.exec": pc("a/C", members=[("java/lang/Runtime", "exec")]),
    "URLClassLoader": pc("a/C", refs=["java/net/URLClassLoader"]),
    "custom ClassLoader": pc("a/C", super_name="java/lang/ClassLoader"),
    "defineClass": pc("a/C", members=[("java/lang/ClassLoader", "defineClass")]),
    "System.loadLibrary": pc("a/C", members=[("java/lang/System", "loadLibrary")]),
    "JNA": pc("a/C", refs=["com/sun/jna/Native"]),
    "network": pc("a/C", members=[NET]),
    "Base64 decoding": pc("a/C", members=[B64]),
    "Cipher": pc("a/C", refs=["javax/crypto/Cipher"]),
    "session token": pc("a/C", members=[("net/minecraft/class_320", "method_1674")]),
    "file writing": pc("a/C", members=[WRITE]),
    "persistence string": pc("a/C", strings=["schtasks"]),
    "shell string": pc("a/C", strings=["powershell"]),
    "reflection": pc("a/C", members=[("java/lang/Class", "forName")]),
    "stealth flag without execution": pc("a/C", strings=["-WindowStyle Hidden"]),
    "executable file name": pc("a/C", strings=["natives.dll", "library.jar"]),
    "normal URL": pc("a/C", strings=["https://github.com/example/mod"]),
    "Base64 text": pc("a/C", strings=[base64.b64encode(b"just some ordinary configuration data").decode()]),
}


@pytest.mark.parametrize("name", SINGLE_CAPABILITIES)
def test_single_capability_is_never_warning_or_high(name):
    findings = findings_for(make_ctx([SINGLE_CAPABILITIES[name]]))
    assert not [f for f in findings if f.severity == WARNING], name
    assert not [f for f in findings if f.confidence == HIGH], name


@pytest.mark.parametrize("contents", [
    ContentsSummary(native_libraries=["natives/x64/lib.dll"]),
    ContentsSummary(nested_jars=["META-INF/jars/lib.jar"]),
    ContentsSummary(unusual_files=["readme.xyz"]),
    ContentsSummary(signature_files=["META-INF/SIGNER.RSA"]),
])
def test_file_characteristics_are_info(contents):
    findings = findings_for(make_ctx(contents=contents))
    assert findings and all(f.severity == INFO and f.confidence == LOW for f in findings
                            if f.rule_id.startswith("contents."))


def test_bundled_native_library_loader_is_review_low():
    # Voice chat pattern: extract the mod's own native library and load it.
    c = ContentsSummary(native_libraries=["natives/opus.dll"])
    cls = pc("a/LibraryLoader", members=[WRITE, ("java/lang/System", "load")], strings=["opus.dll"])
    [f] = by_rule(findings_for(make_ctx([cls], contents=c)), "api.native_loading")
    assert f.severity == REVIEW and f.confidence == LOW
    assert "bundles its own" in f.context


def test_unbundled_native_library_load_is_review_medium():
    cls = pc("a/Debugger", members=[("java/lang/System", "load")], strings=["renderdoc.dll"])
    [f] = by_rule(findings_for(make_ctx([cls])), "api.native_loading")
    assert f.severity == REVIEW and f.confidence == MEDIUM


def test_unknown_command_is_review_medium():
    [f] = by_rule(findings_for(make_ctx([pc("a/C", refs=PROCESS)])), "api.process_execution")
    assert f.severity == REVIEW and f.confidence == MEDIUM and "not visible" in f.title


def test_shell_command_is_review_medium():
    [f] = by_rule(findings_for(make_ctx([pc("a/C", refs=PROCESS, strings=["cmd.exe", "/c"])])),
                  "api.process_execution")
    assert f.severity == REVIEW and f.confidence == MEDIUM and "cmd.exe" in f.context


def test_persistence_string_alone_is_review():
    [f] = by_rule(findings_for(make_ctx([pc("a/C", strings=["LaunchAgents"])])), "strings.sensitive")
    assert f.severity == REVIEW


# ------------------------------------------------------------ 4. evidence correlation

def test_url_correlation_ladder():
    paste = "https://pastebin.com/raw/abcdef"
    text_only = by_rule(findings_for(make_ctx([pc("a/C", strings=[paste])])), "strings.url")[0]
    with_net = by_rule(findings_for(make_ctx([pc("a/C", strings=[paste], members=[NET])])), "strings.url")[0]
    assert text_only.severity == with_net.severity == REVIEW
    assert text_only.confidence == LOW and with_net.confidence == MEDIUM


def test_download_correlation_ladder():
    def rated(cls):
        findings = findings_for(make_ctx([cls]))
        return [(f.rule_id, f.severity, f.confidence) for f in findings
                if f.rule_id in ("api.downloads", "combo.downloader")]

    # network alone: informational only
    assert rated(pc("a/C", members=[NET])) == []
    # + writing files: REVIEW/LOW
    assert rated(pc("a/C", members=[NET, WRITE])) == [("api.downloads", REVIEW, LOW)]
    # + executable content names: REVIEW/MEDIUM
    assert rated(pc("a/C", members=[NET, WRITE], strings=["mod.jar"])) == [("api.downloads", REVIEW, MEDIUM)]
    # + loading it: WARNING/HIGH
    assert rated(pc("a/C", members=[NET, WRITE, DEFINE], strings=["mod.jar"])) == \
        [("combo.downloader", WARNING, HIGH)]


def test_network_plus_execution_without_support_is_warning_medium():
    [f] = by_rule(findings_for(make_ctx([pc("a/C", refs=["java/net/URLClassLoader"], members=[NET])])),
                  "combo.downloader")
    assert f.severity == WARNING and f.confidence == MEDIUM


def test_network_plus_helper_program_is_review():
    # An update checker that opens the download page in the browser.
    cls = pc("a/UpdateChecker", refs=PROCESS, members=[NET], strings=["xdg-open"])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.downloader")
    assert f.severity == REVIEW


def test_dynamic_loading_with_outside_data_is_medium():
    cls = pc("a/C", members=[B64, ("java/lang/ClassLoader", "defineClass")])
    [f] = by_rule(findings_for(make_ctx([cls])), "api.dynamic_loading")
    assert f.confidence == MEDIUM and "outside the JAR" in f.context


def test_capabilities_in_different_classes_only_spread_review():
    classes = [pc("a/Net", members=[NET]), pc("a/Run", refs=PROCESS, strings=["cmd.exe"])]
    findings = findings_for(make_ctx(classes))
    assert not by_rule(findings, "combo.downloader")
    [f] = by_rule(findings, "combo.downloader_spread")
    assert f.severity == REVIEW and f.confidence == LOW


def test_disguised_file_confidence_rises_with_code_loading():
    c = ContentsSummary(disguised_files=["a.png (detected: Java class file)"])
    alone = by_rule(findings_for(make_ctx(contents=c)), "contents.disguised")[0]
    loader = by_rule(findings_for(make_ctx([pc("a/L", super_name="java/lang/ClassLoader")], contents=c)),
                     "contents.disguised")[0]
    assert alone.confidence == MEDIUM and loader.confidence == HIGH


def test_session_token_ladder():
    token = ("net/minecraft/class_320", "method_1674")
    alone = findings_for(make_ctx([pc("a/C", members=[token])]))
    assert by_rule(alone, "api.session_token")[0].confidence == LOW
    assert not by_rule(alone, "combo.session_token_network")
    with_net = by_rule(findings_for(make_ctx([pc("a/C", members=[token, NET])])), "combo.session_token_network")[0]
    assert with_net.severity == REVIEW and with_net.confidence == MEDIUM


def test_process_context_identifies_commands():
    seen = _process_context(["/usr/bin/xdg-open", "C:\\Windows\\System32\\cmd.exe", "certutil -urlcache",
                             "powershell -WindowStyle Hidden -EncodedCommand AAAA", "tool.exe", "hello world"])
    assert seen["helpers"] == ["xdg-open"]
    assert seen["shells"] == ["cmd.exe", "powershell"]
    assert seen["risky"] == ["certutil"]
    assert seen["programs"] == ["tool.exe"]
    assert "hides the PowerShell window" in seen["hidden"]
    assert "runs a Base64-encoded PowerShell command" in seen["hidden"]


# ------------------------------------------------------------ 5. every rating is explained

def _everything_ctx():
    """One context that triggers most REVIEW/WARNING rules."""
    payload = base64.b64encode(build_class("hidden/X", strings=["x" * 50])).decode()
    hidden_url = base64.b64encode(b"https://pastebin.com/raw/hidden-stage-two").decode()
    classes = [
        pc("a/Updater", refs=PROCESS, members=[NET, WRITE],
           strings=["x.jar", "powershell.exe", "-WindowStyle Hidden", "schtasks"]),
        pc("a/Unpacker", members=[B64, DEFINE], strings=[payload, hidden_url]),
        pc("a/Grab", members=[("net/minecraft/class_320", "method_1674"), NET],
           strings=["\\discord\\Local Storage\\leveldb", "https://discord.com/api/webhooks/1/x", "45.1.2.3:4444"]),
        pc("a/Native", members=[("java/lang/System", "load")]),
        pc("a/R", strings=["java.lang.Runtime"], members=[("java/lang/Class", "forName")]),
        pc("a/Agent", refs=["java/lang/instrument/Instrumentation", "javax/naming/InitialContext"]),
        pc("Main"), pc("a/IlIlIl"),
    ]
    c = ContentsSummary(executables_and_scripts=["x.exe"], disguised_files=["a.png (detected: Java class file)"],
                        unsafe_names=["../x"], duplicate_names=["d"], encrypted_entries=["e"],
                        deceptive_names=["\ufffdx"])
    m = ManifestInfo(present=True, attributes={"Premain-Class": "a.Agent", "Main-Class": "Main"})
    return make_ctx(classes, contents=c, manifest=m, mods=[SODIUM_MOD])


def test_every_review_and_warning_has_context_and_rationale():
    findings = findings_for(_everything_ctx())
    rated = [f for f in findings if f.severity != INFO]
    assert len({f.rule_id for f in rated}) >= 20  # the fixture really covers many rules
    for f in rated:
        assert f.context and f.rationale, f.rule_id


def test_info_findings_never_claim_confidence():
    assert all(f.confidence == LOW for f in findings_for(_everything_ctx()) if f.severity == INFO)


# ------------------------------------------------------------ 6. Discord webhook completeness


@pytest.mark.parametrize("url", [
    "https://discord.com/api/webhooks/",          # bare prefix (URL comes from config)
    "https://discordapp.com/api/webhooks",        # without trailing slash
    "https://discord.com/api/webhooks/%s/%s",     # format-string template
    "https://discord.com/api/webhooks/123456",    # ID but no token
])
def test_bare_or_incomplete_webhook_is_review(url):
    severity, confidence, label = classify_url(url)
    assert (severity, confidence) == (REVIEW, MEDIUM) and "incomplete" in label


@pytest.mark.parametrize("url", [
    "https://discord.com/api/webhooks/1/x",
    "https://discord.com/api/webhooks/1234567890123456789/AbC-dEf_123456789abcdefghijklmnopqrstuvwxyz",
    "https://canary.discord.com/api/webhooks/123/token?wait=true",
    "https://ptb.discordapp.com/api/webhooks/123/token/slack",
    "HTTPS://DISCORD.COM/API/WEBHOOKS/123/TOKEN",
])
def test_complete_webhook_stays_warning_high(url):
    assert classify_url(url) == (WARNING, HIGH, "Discord webhook")


@pytest.mark.parametrize("url,severity", [
    ("https://discord.gg/abcdef", INFO),
    ("https://discord.com/invite/abcdef", INFO),
    ("https://discord.com/api/v10/users/@me", INFO),
    ("https://discordapp.com/channels/1/2", INFO),
    ("https://cdn.discordapp.com/attachments/1/2/file.jar", REVIEW),  # file host rule, unchanged
])
def test_unrelated_discord_urls_are_not_webhooks(url, severity):
    got_severity, _confidence, label = classify_url(url)
    assert got_severity == severity and "webhook" not in label


def test_webhook_findings_end_to_end():
    bare = pc("a/DiscordRelay", members=[NET], strings=["https://discord.com/api/webhooks/"])
    [f] = by_rule(findings_for(make_ctx([bare])), "strings.url")
    assert f.severity == REVIEW and f.confidence == MEDIUM  # class can connect
    assert not [x for x in findings_for(make_ctx([bare])) if x.severity == WARNING]
    # A full webhook stays WARNING/HIGH even with no network code in the class.
    full = pc("a/W", strings=["https://discord.com/api/webhooks/123/abc"])
    [f] = by_rule(findings_for(make_ctx([full])), "strings.url")
    assert f.severity == WARNING and f.confidence == HIGH


def test_bare_webhook_still_escalates_session_token_combo():
    token = ("net/minecraft/class_320", "method_1674")
    cls = pc("a/Grab", members=[token, NET], strings=["https://discord.com/api/webhooks/"])
    [f] = by_rule(findings_for(make_ctx([cls])), "combo.session_token_network")
    assert f.severity == WARNING and f.confidence == HIGH


# ------------------------------------------------------------ 7. versioned Discord API webhook paths

@pytest.mark.parametrize("url", [
    "https://discord.com/api/v10/webhooks/1234567890123456789/AbC-dEf_123456789abcdefghijklmnopqrstuvwxyz",
    "https://discord.com/api/v9/webhooks/123/token",
    "https://discordapp.com/api/v6/webhooks/123/token",
    "https://canary.discord.com/api/v10/webhooks/123/token?wait=true",
    "https://ptb.discord.com/api/v8/webhooks/123/token?thread_id=456",
    "https://discord.com/api/v10/webhooks/123/token/slack",
    "https://discord.com/api/v10/webhooks/123/token/github",
    "HTTPS://DISCORD.COM/API/V10/WEBHOOKS/123/TOKEN",
    "https://discord.com/api/v10/webhooks/1/x",
])
def test_versioned_complete_webhook_is_warning_high(url):
    assert classify_url(url) == (WARNING, HIGH, "Discord webhook")


@pytest.mark.parametrize("url", [
    "https://discord.com/api/v10/webhooks/",
    "https://discord.com/api/v10/webhooks",
    "https://discordapp.com/api/v9/webhooks/123456",    # ID but no token
    "https://discord.com/api/v10/webhooks/%s/%s",       # format-string template
])
def test_versioned_incomplete_webhook_is_review(url):
    severity, confidence, label = classify_url(url)
    assert (severity, confidence) == (REVIEW, MEDIUM) and "incomplete" in label


@pytest.mark.parametrize("url", [
    "https://discord.com/api/v10/channels/123/messages",
    "https://discord.com/api/v10/oauth2/token",
    "https://discord.com/api/v10/gateway",
    "https://discord.com/api/v10/applications/123/commands",
])
def test_versioned_unrelated_discord_api_urls_are_info(url):
    severity, _confidence, label = classify_url(url)
    assert severity == INFO and "webhook" not in label


def test_versioned_webhook_findings_and_escalation():
    url = "https://discord.com/api/v10/webhooks/123/abc"
    [f] = by_rule(findings_for(make_ctx([pc("a/W", strings=[url])])), "strings.url")
    assert f.severity == WARNING and f.confidence == HIGH and url in f.location
    # Combination rules treat the versioned form like the unversioned one.
    token = ("net/minecraft/class_320", "method_1674")
    [combo] = by_rule(findings_for(make_ctx([pc("a/G", members=[token, NET], strings=[url])])),
                      "combo.session_token_network")
    assert combo.severity == WARNING and combo.confidence == HIGH
    # An exfil URL counts as a way to send data out for the credential-theft rule.
    [theft] = by_rule(findings_for(make_ctx([pc("a/S", strings=["\\discord\\Local Storage\\leveldb", url])])),
                      "combo.data_theft")
    assert theft.severity == WARNING
