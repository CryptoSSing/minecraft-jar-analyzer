"""Static security indicators: evidence for a human to review, never a verdict.

How it works
------------
1. While classes are being parsed, `ClassEvidence.add()` looks at each class
   once and records anything relevant (which risky APIs it references, URLs,
   sensitive strings...). The class itself is then discarded to save memory.
2. After all classes are scanned, `run_rules()` calls each rule function.
   A rule looks at the collected evidence plus the manifest, metadata and
   contents summary, and returns a list of `Finding`s.

Severity guide
--------------
  INFO     Informational: a fact about the JAR (metadata, bundled libraries,
           ordinary APIs). Not a security warning.
  REVIEW   A capability with security relevance that legitimate mods also
           use (running programs, loading native code...): inspect it.
  WARNING  A strong indicator or a COMBINATION of indicators, e.g. download
           something AND run it. Needs context, not a single keyword.

Confidence says how strongly the evidence shows the observation is
security-significant - NOT whether the API is present (a static match is
always certain). "Main-Class exists" is a sure fact of LOW significance;
"downloads a .jar and starts a hidden PowerShell" is HIGH. INFO findings
always use LOW.

Context matters: many "scary" techniques are normal in mods. Mixin and most big
mods use reflection; update checkers use the network. So while scanning,
each class also gets *context tags* (writes files, names .jar/.exe files,
generates bytecode, uses hidden-window flags...). Rules look at what else the
SAME class does: "loads classes it generated in memory" stays REVIEW/LOW,
while "loads classes AND downloads data" becomes a WARNING.

Every REVIEW/WARNING finding carries `context` (what surrounding evidence was
or was not found) and `rationale` (why it got this severity/confidence).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import posixpath
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import known_values as kv
from .classes import ParsedClass
from .limits import Limits
from .models import (AnalysisResult, ClassSummary, Confidence, ContentsSummary,
                     Finding, HashClassification, HashLookup, ManifestInfo,
                     ModInfo, Severity)
from .sanitize import safe_text

INFO, REVIEW, WARNING = Severity.INFO, Severity.REVIEW, Severity.WARNING
LOW, MEDIUM, HIGH = Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH

MAX_EXAMPLES = 20      # class names remembered per API group
MAX_URLS = 2000
MAX_STRING_HITS = 200

# ---------------------------------------------------------------------------
# API groups: which referenced classes/methods indicate which capability.
# ---------------------------------------------------------------------------

# Whole packages -> group (every class whose name starts with the prefix).
API_PACKAGE_PREFIXES = {
    "java/lang/reflect/": "reflection",
    "java/net/http/": "network",
    "okhttp3/": "network",
    "org/apache/http/": "network",
    "com/sun/jna/": "native_loading",
    "java/lang/instrument/": "instrumentation",
    "javax/naming/directory/": "jndi",
}
# Exact class names -> group.
API_CLASS_EXACT = {
    # Note: plain java/net/URL is NOT listed. URL objects are also used for
    # local files (e.g. every URLClassLoader takes them); only actually
    # opening a connection counts (see API_MEMBERS below).
    "java/net/URLConnection": "network",
    "java/net/HttpURLConnection": "network",
    "java/net/Socket": "network",
    "java/net/ServerSocket": "network",
    "java/net/DatagramSocket": "network",
    "javax/net/ssl/HttpsURLConnection": "network",
    "java/net/URLClassLoader": "dynamic_loading",
    "java/security/SecureClassLoader": "dynamic_loading",
    "java/lang/ProcessBuilder": "process_execution",
    "javax/naming/InitialContext": "jndi",
    "java/awt/datatransfer/Clipboard": "clipboard",
    "javax/crypto/Cipher": "crypto",
    "sun/misc/Unsafe": "unsafe",
    "jdk/internal/misc/Unsafe": "unsafe",
}
# (owner class, member name) -> group. Owner "*" means "any class".
API_MEMBERS = {
    ("java/net/URL", "openConnection"): "network",
    ("java/net/URL", "openStream"): "network",
    ("java/lang/Class", "forName"): "reflection",
    ("java/lang/Class", "getDeclaredMethod"): "reflection",
    ("java/lang/Class", "getDeclaredField"): "reflection",
    ("java/lang/Class", "getMethod"): "reflection",
    ("*", "defineClass"): "dynamic_loading",
    ("*", "defineHiddenClass"): "dynamic_loading",
    ("*", "defineAnonymousClass"): "dynamic_loading",
    ("java/lang/Runtime", "exec"): "process_execution",
    ("java/lang/System", "load"): "native_loading",
    ("java/lang/System", "loadLibrary"): "native_loading",
    ("java/lang/Runtime", "load"): "native_loading",
    ("java/lang/Runtime", "loadLibrary"): "native_loading",
    ("java/awt/Robot", "createScreenCapture"): "screen_capture",
    ("java/awt/Toolkit", "getSystemClipboard"): "clipboard",
    ("java/util/Base64", "getDecoder"): "base64",
    ("java/util/Base64", "getMimeDecoder"): "base64",
}
# Extending one of these means the class is a custom class loader.
CLASSLOADER_SUPERCLASSES = {"java/lang/ClassLoader", "java/net/URLClassLoader", "java/security/SecureClassLoader"}

# ---------------------------------------------------------------------------
# Context tags. These are not findings by themselves; they describe what ELSE
# a class does, so rules can tell "loads classes it generated in memory"
# apart from "loads classes it just downloaded".
# ---------------------------------------------------------------------------

# Writing files to disk.
FILE_WRITE_CLASSES = {"java/io/FileOutputStream", "java/io/RandomAccessFile", "java/io/FileWriter"}
FILE_WRITE_MEMBERS = {
    ("java/nio/file/Files", "write"), ("java/nio/file/Files", "writeString"),
    ("java/nio/file/Files", "newOutputStream"), ("java/nio/file/Files", "copy"),
    ("java/nio/file/Files", "newBufferedWriter"), ("java/net/http/HttpResponse$BodyHandlers", "ofFile"),
}
# Actually loading a native library (as opposed to calling OS functions
# through JNA's ready-made bindings such as Kernel32).
NATIVE_FILE_LOAD_MEMBERS = {
    ("java/lang/System", "load"), ("java/lang/System", "loadLibrary"),
    ("java/lang/Runtime", "load"), ("java/lang/Runtime", "loadLibrary"),
    ("com/sun/jna/Native", "load"), ("com/sun/jna/Native", "loadLibrary"),
    ("com/sun/jna/Native", "register"), ("com/sun/jna/NativeLibrary", "getInstance"),
}
# Libraries that generate bytecode in memory (ASM, ByteBuddy), possibly relocated.
_BYTECODE_GEN_RE = re.compile(r"(?:^|/)(?:objectweb/asm/ClassWriter|bytebuddy/)")
# A JVM method descriptor such as "(JJI)V" - the building blocks of bytecode
# that a class generates for itself.
_DESCRIPTOR_RE = re.compile(r"\((?:\[*(?:[BCDFIJSZ]|L[\w/$\x01]+;))*\)\[*(?:[BCDFIJSZV]|L[\w/$\x01]+;)")

# Tags that mean a class's data might come from OUTSIDE the JAR.
EXTERNAL_SOURCE_TAGS = {"network", "base64", "crypto", "encoded_payload", "encoded_url"}
# Ways of turning data into running code.
EXECUTION_TAGS = {"dynamic_loading", "process_execution", "native_file_load"}

# Class names mentioned as *strings* (e.g. Class.forName("java.lang.Runtime")),
# a way to use an API while hiding the direct reference.
SENSITIVE_REFLECTION_TARGETS = {
    "java.lang.Runtime", "java.lang.ProcessBuilder", "java.net.URLClassLoader",
    "java.lang.ClassLoader", "sun.misc.Unsafe", "java.lang.instrument.Instrumentation",
    "javax.naming.InitialContext",
}

# One regex for all prefixes: much faster than testing each prefix in a loop.
_PREFIX_RE = re.compile("|".join(re.escape(p) for p in API_PACKAGE_PREFIXES))

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s\"'<>\\^`{|}]{1,500}")
_IP_PORT_RE = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}):(\d{2,5})\b")
# Discord webhook URLs, on any Discord host (discord.com, discordapp.com and
# their canary./ptb. variants), with or without an API version in the path:
#   discord.com/api/webhooks/<id>/<token>
#   discord.com/api/v10/webhooks/<id>/<token>
# Group 1 is the "/<numeric id>/<token>" part; without it the URL is only a
# prefix. Any ID/token length counts so short or truncated real webhooks match.
_DISCORD_WEBHOOK_RE = re.compile(r"discord(?:app)?\.com/api/(?:v\d+/)?webhooks(/\d+/[\w-]+)?")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
_SENSITIVE_RE = re.compile("|".join(re.escape(s) for s in kv.SENSITIVE_STRINGS), re.IGNORECASE)
_MALWARE_WORD_RE = re.compile("|".join(kv.MALWARE_NAME_WORDS), re.IGNORECASE)
_CHEAT_WORD_RE = re.compile("|".join(kv.CHEAT_FEATURE_WORDS), re.IGNORECASE)
_CHEAT_WORDS = set(kv.CHEAT_FEATURE_WORDS)


def shannon_entropy(text: str) -> float:
    """Average "surprise" per character, in bits.

    English-like text scores about 3.5-4.2; random Base64 approaches 6.0
    (the maximum for a 64-character alphabet). High entropy in a long string
    suggests encoded or encrypted data rather than human-readable text.
    """
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def _decoded_magic(data: bytes) -> str | None:
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "Java class file"
    if data.startswith(b"MZ"):
        return "Windows executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP/JAR archive"
    if data.startswith(b"\x7fELF"):
        return "Linux executable"
    return None


def _try_base64(text: str) -> bytes | None:
    s = text.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


# ---------------------------------------------------------------------------
# Evidence collection (runs once per class while scanning)
# ---------------------------------------------------------------------------

@dataclass
class ClassEvidence:
    """Security-relevant facts gathered from all classes of one JAR."""
    api_counts: Counter = field(default_factory=Counter)
    api_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Groups used by each class (only for classes that use a "combo" group).
    class_groups: dict[str, set[str]] = field(default_factory=dict)
    class_names: list[str] = field(default_factory=list)
    name_mismatches: list[str] = field(default_factory=list)
    references_minecraft: bool = False
    urls: dict[str, str] = field(default_factory=dict)            # url -> location
    ip_ports: dict[str, str] = field(default_factory=dict)        # "1.2.3.4:25" -> location
    sensitive: dict[str, list[tuple[str, str]]] = field(default_factory=lambda: defaultdict(list))
    encoded_strings: list[tuple[str, str, float]] = field(default_factory=list)  # (preview, loc, entropy)
    encoded_payloads: list[tuple[str, str]] = field(default_factory=list)        # (kind, loc)
    reflective_targets: list[tuple[str, str]] = field(default_factory=list)
    cheat_strings: list[tuple[str, str]] = field(default_factory=list)
    encoded_urls: list[tuple[str, str]] = field(default_factory=list)            # (url, loc)
    # Per class that can run programs: what it appears to run (see _process_context).
    process_contexts: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # Per class that uses JNA: which JNA platform bindings (Kernel32...) it uses.
    jna_bindings: dict[str, list[str]] = field(default_factory=dict)

    # A class using any of these is remembered in class_groups together with
    # ALL its groups and context tags, so rules can correlate them.
    COMBO_GROUPS = {"network", "dynamic_loading", "process_execution", "session_token",
                    "sensitive_high", "base64", "encoded_payload", "encoded_url",
                    "native_loading", "persistence", "crypto"}

    def add(self, parsed: ParsedClass) -> None:
        loc = parsed.entry_name
        self.class_names.append(parsed.name)
        self._check_name_matches_path(parsed)

        groups: set[str] = set()
        for ref in parsed.class_refs:
            if ref.startswith(("net/minecraft/", "com/mojang/")):
                self.references_minecraft = True
            if ref in API_CLASS_EXACT:
                group = API_CLASS_EXACT[ref]
            elif m := _PREFIX_RE.match(ref):
                group = API_PACKAGE_PREFIXES[m.group(0)]
            else:
                group = None
            if group:
                groups.add(group)
            # Context tags from class references.
            if ref in FILE_WRITE_CLASSES:
                groups.add("file_write")
            if _BYTECODE_GEN_RE.search(ref):
                groups.add("bytecode_gen")
        for owner, member in parsed.member_refs:
            group = API_MEMBERS.get((owner, member)) or API_MEMBERS.get(("*", member))
            if group:
                groups.add(group)
            if member in kv.SESSION_TOKEN_MEMBERS and owner.startswith(("net/minecraft/", "com/mojang/")):
                groups.add("session_token")
            if (owner, member) in FILE_WRITE_MEMBERS:
                groups.add("file_write")
            if (owner, member) in NATIVE_FILE_LOAD_MEMBERS:
                groups.add("native_file_load")
        if parsed.super_name in CLASSLOADER_SUPERCLASSES:
            groups.add("dynamic_loading")

        for text in parsed.strings:
            groups |= self._scan_string(text, loc)
        groups |= self._string_tags(parsed.strings)

        if "process_execution" in groups:
            self.process_contexts[loc] = _process_context(parsed.strings)
        if "native_loading" in groups:
            bindings = sorted({ref.rsplit("/", 1)[-1].split("$", 1)[0] for ref in parsed.class_refs
                               if ref.startswith("com/sun/jna/platform/")})
            self.jna_bindings[loc] = bindings[:10]

        for group in groups:
            self.api_counts[group] += 1
            if len(self.api_examples[group]) < MAX_EXAMPLES:
                self.api_examples[group].append(loc)
        if groups & self.COMBO_GROUPS:
            self.class_groups[loc] = groups

    @staticmethod
    def _string_tags(strings: list[str]) -> set[str]:
        """Context tags that depend on a class's string literals as a whole."""
        tags: set[str] = set()
        descriptors = 0
        for text in strings:
            if len(text) > 300:
                lower = text.lower()
                if any(flag in lower for flag in kv.HIDDEN_EXECUTION_FLAGS):
                    tags.add("hidden_exec")
                continue
            lower = text.lower().strip()
            if lower.endswith(kv.EXECUTABLE_EXTENSIONS):
                tags.add("exec_content")
            if any(flag in lower for flag in kv.HIDDEN_EXECUTION_FLAGS):
                tags.add("hidden_exec")
            if _DESCRIPTOR_RE.fullmatch(text):
                descriptors += 1
        # A few descriptors are normal (e.g. reflection lookups); many mean
        # the class writes its own bytecode, as Sodium's vertex serializers do.
        if descriptors >= 3:
            tags.add("bytecode_gen")
        return tags

    def _check_name_matches_path(self, parsed: ParsedClass) -> None:
        # Multi-release JARs keep Java-version-specific copies under META-INF/versions/N/.
        path = re.sub(r"^META-INF/versions/\d+/", "", parsed.entry_name)
        if path != parsed.name + ".class" and len(self.name_mismatches) < MAX_STRING_HITS:
            self.name_mismatches.append(f"{parsed.entry_name} declares class {safe_text(parsed.name, 200)}")

    def _scan_string(self, text: str, loc: str, decoded: bool = False) -> set[str]:
        """Scan one string literal. Returns extra API groups it implies."""
        groups: set[str] = set()
        where = f"{loc} (Base64-decoded string)" if decoded else loc

        if "://" in text:
            for url in _URL_RE.findall(text):
                url = url.rstrip(".,;:)]}'\"")
                if url not in self.urls and len(self.urls) < MAX_URLS:
                    self.urls[url] = where
                if decoded:
                    groups.add("encoded_url")
                    if len(self.encoded_urls) < MAX_STRING_HITS:
                        self.encoded_urls.append((url, loc))
        if ":" in text:
            for ip, port in _IP_PORT_RE.findall(text):
                key = f"{ip}:{port}"
                if key not in self.ip_ports and len(self.ip_ports) < MAX_STRING_HITS:
                    self.ip_ports[key] = where

        for m in _SENSITIVE_RE.finditer(text):
            fragment = m.group(0).lower()
            category = kv.SENSITIVE_STRINGS[fragment]
            hits = self.sensitive[category]
            if len(hits) < MAX_STRING_HITS and (fragment, where) not in hits:
                hits.append((fragment, where))
            if category in kv.HIGH_RISK_CATEGORIES:
                groups.add("sensitive_high")
            elif category == kv.CATEGORY_PERSISTENCE:
                groups.add("persistence")
            elif category == kv.CATEGORY_SHELL:
                groups.add("shell")

        if text in SENSITIVE_REFLECTION_TARGETS and len(self.reflective_targets) < MAX_STRING_HITS:
            self.reflective_targets.append((text, where))

        normalized = re.sub(r"[^a-z]", "", text.lower())
        if normalized in _CHEAT_WORDS and len(self.cheat_strings) < MAX_STRING_HITS:
            self.cheat_strings.append((safe_text(text, 100), where))

        if not decoded and len(text) >= 40:
            groups |= self._check_encoded(text, loc)
        return groups

    def _check_encoded(self, text: str, loc: str) -> set[str]:
        if not _BASE64_RE.fullmatch(text):
            return set()
        # Step 1: decide whether to list it as "encoded-looking". Require a mix
        # of character types (long camelCase identifiers also match the Base64
        # alphabet but are not encoded data) and high randomness.
        mixed = bool(re.search(r"[A-Z]", text) and re.search(r"[a-z]", text) and re.search(r"\d", text))
        entropy = shannon_entropy(text)
        if mixed and entropy >= (4.5 if len(text) < 100 else 5.0) and len(self.encoded_strings) < MAX_STRING_HITS:
            preview = text[:60] + ("…" if len(text) > 60 else "")
            self.encoded_strings.append((preview, loc, round(entropy, 2)))
        # Step 2: ALWAYS try decoding, whatever the entropy. Gating this on
        # randomness would let a low-entropy payload (e.g. a class padded with
        # repeated bytes) slip through undetected.
        groups = set()
        data = _try_base64(text)
        if data:
            kind = _decoded_magic(data)
            if kind:
                self.encoded_payloads.append((kind, loc))
                groups.add("encoded_payload")
            else:
                # Look inside decoded text for hidden URLs or sensitive paths.
                decoded_text = data.decode("utf-8", errors="replace")
                if decoded_text.count("\ufffd") < len(decoded_text) * 0.1:
                    groups |= self._scan_string(decoded_text, loc, decoded=True)
        return groups


def _command_name(token: str) -> str:
    """"/usr/bin/xdg-open" -> "xdg-open"; "C:\\Windows\\cmd.exe" -> "cmd.exe"."""
    token = token.strip().strip("\"'").lower()
    if token in kv.SHELL_COMMANDS:  # keep "/bin/sh" as written
        return token
    return token.replace("\\", "/").rsplit("/", 1)[-1]


def _process_context(strings: list[str]) -> dict[str, list[str]]:
    """What a program-starting class appears to run, judged from its strings.

    Static analysis only sees string literals, so this is a best effort: a
    command built at runtime or passed in from another class stays invisible,
    and that is reported as such rather than guessed.
    """
    found: dict[str, set[str]] = {"helpers": set(), "shells": set(), "risky": set(),
                                  "programs": set(), "hidden": set()}
    for text in strings:
        lower = text.lower()
        for flag, meaning in kv.HIDDEN_EXECUTION_FLAGS.items():
            if flag in lower:
                found["hidden"].add(meaning)
        if not text.strip() or len(text) > 300:
            continue
        name = _command_name(text.split()[0])
        if name in kv.HELPER_COMMANDS:
            found["helpers"].add(name)
        elif name in kv.SHELL_COMMANDS:
            found["shells"].add(name)
        elif name in kv.RISKY_COMMANDS:
            found["risky"].add(name)
        elif name.endswith(".exe") and 4 < len(name) < 60:
            found["programs"].add(name)
    return {key: sorted(values)[:10] for key, values in found.items()}


# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------

@dataclass
class RuleContext:
    limits: Limits
    contents: ContentsSummary
    manifest: ManifestInfo
    mods: list[ModInfo]
    classes: ClassSummary
    evidence: ClassEvidence
    hash_lookup: HashLookup
    entry_names: set[str]


def _where(items: list[str], total: int | None = None, shown: int = 5) -> str:
    """"a, b, c (+12 more)" - a compact location list."""
    total = len(items) if total is None else total
    text = ", ".join(safe_text(i, 300) for i in items[:shown])
    if total > shown:
        text += f" (+{total - shown} more)"
    return text or "(archive)"


def _f(rule_id: str, severity: Severity, title: str, location: str,
       explanation: str, confidence: Confidence, context: str = "", rationale: str = "") -> Finding:
    # INFO is "a fact, not a concern", so its confidence is always LOW (the
    # GUI and TXT report show it as "—"). Enforced here so no rule can forget.
    if severity == INFO:
        confidence = LOW
    elif not rationale and rule_id in STANDALONE_RATIONALE:
        context, rationale = STANDALONE_RATIONALE[rule_id]
    return Finding(rule_id, severity, safe_text(title, 300), safe_text(location, 2000),
                   explanation, confidence, safe_text(context, 2000, allow_newlines=True),
                   safe_text(rationale, 1000))


def _top_level_mods(ctx: RuleContext) -> list[ModInfo]:
    return [m for m in ctx.mods if m.nested_in is None]


def _tags(ctx: RuleContext, loc: str) -> set[str]:
    """All API groups and context tags of one class (empty if unremarkable)."""
    return ctx.evidence.class_groups.get(loc, set())


def _classes_with(ctx: RuleContext, *required_any: set[str]) -> list[str]:
    """Classes that have at least one tag from EACH of the given sets."""
    return [loc for loc, groups in ctx.evidence.class_groups.items()
            if all(groups & req for req in required_any)]


def _class_of(location: str) -> str:
    """"a/B.class (Base64-decoded string)" -> "a/B.class"."""
    return location.split(" (", 1)[0]


def _suspicious_urls_in(ctx: RuleContext, loc: str) -> list[str]:
    return [u for u, where in ctx.evidence.urls.items()
            if _class_of(where) == loc and classify_url(u)[0] != INFO]


def _max_confidence(values: list[Confidence]) -> Confidence:
    order = [LOW, MEDIUM, HIGH]
    return max(values, key=order.index) if values else LOW


# ---------------------------------------------------------------------------
# Rules: metadata, manifest, hash
# ---------------------------------------------------------------------------

def rule_metadata_presence(ctx: RuleContext) -> list[Finding]:
    mods = _top_level_mods(ctx)
    if not mods:
        return [_f("metadata.none", INFO, "No Minecraft mod metadata found", "(archive)",
                   "No fabric.mod.json, quilt.mod.json, mods.toml, neoforge.mods.toml, mcmod.info or "
                   "plugin.yml was found. This is normal for libraries and some older mods, and is not "
                   "suspicious by itself. It does mean the file cannot be identified by its metadata.", LOW)]
    findings = []
    sources = sorted({f"{m.loader}: {m.source_file}" for m in mods})
    findings.append(_f("metadata.detected", INFO, "Mod metadata detected", ", ".join(sources),
                       "The JAR contains a mod/plugin descriptor. Remember that metadata is written by the "
                       "JAR's author and can be false.", LOW))
    for m in mods:
        missing = [label for label, value in (("id", m.mod_id), ("version", m.version)) if not value]
        if missing:
            findings.append(_f("metadata.incomplete", INFO, f"Metadata is missing: {', '.join(missing)}",
                               m.source_file, "Legitimate mods normally declare an ID and version. Missing "
                               "fields are usually just sloppiness, but make the file harder to identify.", LOW))
    return findings


def rule_metadata_consistency(ctx: RuleContext) -> list[Finding]:
    """Different descriptor files in the same JAR should agree with each other."""
    by_source: dict[str, ModInfo] = {}
    for m in _top_level_mods(ctx):
        by_source.setdefault(m.source_file, m)  # first mod per file
    if len(by_source) < 2:
        return []
    findings = []
    ids = {m.mod_id for m in by_source.values() if m.mod_id}
    versions = {m.version for m in by_source.values() if m.version and "${" not in m.version}
    if len(ids) > 1:
        findings.append(_f("metadata.inconsistent_id", REVIEW, "Descriptor files declare different mod IDs",
                           ", ".join(f"{s}: {m.mod_id}" for s, m in by_source.items()),
                           "Multi-loader mods ship several descriptors but normally use the same ID in each. "
                           "Different IDs can mean files were combined or metadata was tampered with.", LOW))
    if len(versions) > 1:
        findings.append(_f("metadata.inconsistent_version", REVIEW, "Descriptor files declare different versions",
                           ", ".join(f"{s}: {m.version}" for s, m in by_source.items()),
                           "Descriptors in one JAR usually share a version number. A mismatch may be an honest "
                           "packaging mistake or a sign that the JAR was modified.", LOW))
    return findings


def rule_entrypoints_exist(ctx: RuleContext) -> list[Finding]:
    """Classes named in metadata as the mod's starting point should exist in the JAR."""
    findings = []
    for m in _top_level_mods(ctx):
        declared = []
        if ep := m.extra.get("entrypoints"):
            declared += [e.strip() for e in ep.split(",")]
        if main := m.extra.get("main"):
            declared.append(main.strip())
        for entry in declared:
            class_name = entry.split("::", 1)[0]
            path = class_name.replace(".", "/") + ".class"
            if class_name and path not in ctx.entry_names:
                findings.append(_f("metadata.missing_entrypoint", REVIEW,
                                   "Declared entry-point class not found in JAR",
                                   f"{m.source_file}: {class_name}",
                                   "The metadata says this class starts the mod, but it is not in the archive. "
                                   "This can be a broken build, a class provided by another mod, or metadata "
                                   "copied from a different mod to look legitimate.", MEDIUM))
    return findings


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


# Characters/sequences that look alike ("rn" vs "m", "0" vs "o"...).
_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
               ("5", "s"), ("4", "a"), ("7", "t"), ("i", "l")]


def _skeleton(name: str) -> str:
    for a, b in _HOMOGLYPHS:
        name = name.replace(a, b)
    return name


def edit_distance(a: str, b: str, max_distance: int) -> int:
    """Levenshtein distance: the fewest single-character insertions, deletions
    or substitutions to turn `a` into `b`. Returns max_distance + 1 early if
    the strings clearly differ by more than max_distance."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def find_lookalike(name: str) -> tuple[str, str] | None:
    """Return (popular id, "exact"/"lookalike") if `name` matches or imitates a popular mod."""
    norm = _normalize(name)
    if len(norm) < 3:
        return None
    if norm in kv.POPULAR_MOD_IDS:
        return norm, "exact"
    skel = _skeleton(norm)
    for known in kv.POPULAR_MOD_IDS:
        if len(known) < 5 or norm.startswith(known):
            continue  # too short to compare fairly / addon naming like "sodium-extras"
        if skel == _skeleton(known):
            return known, "lookalike"
        limit = 1 if len(known) < 8 else 2
        if edit_distance(skel, _skeleton(known), limit) <= limit:
            return known, "lookalike"
    return None


def rule_impersonation(ctx: RuleContext) -> list[Finding]:
    findings = []
    verified = ctx.hash_lookup.classification == HashClassification.VERIFIED
    seen: set[tuple[str, str]] = set()
    for m in _top_level_mods(ctx):
        for label, value in (("ID", m.mod_id), ("name", m.name)):
            if not value or (match := find_lookalike(value)) is None:
                continue
            known, kind = match
            if (known, kind) in seen:
                continue
            seen.add((known, kind))
            if kind == "exact" and not verified:
                findings.append(_f("metadata.popular_mod_claim", INFO,
                                   f"Claims to be the popular mod/plugin '{known}'",
                                   f"{m.source_file} {label}: {value}",
                                   "Popular mods are the most common targets for fake, malware-laced copies. "
                                   "This is very likely the real thing, but confirm it came from the official "
                                   "Modrinth/CurseForge/GitHub page. Once checked, add its hash to the "
                                   "database as VERIFIED.", LOW))
            elif kind == "lookalike":
                findings.append(_f("metadata.lookalike", REVIEW,
                                   f"{label.capitalize()} closely resembles popular mod/plugin '{known}'",
                                   f"{m.source_file} {label}: {value}",
                                   "Names that differ from a well-known project by one or two characters "
                                   "(e.g. 'sodiurn' vs 'sodium') are a classic impersonation trick. It may "
                                   "also be an unrelated project with a similar name.", MEDIUM))
    return findings


def rule_manifest(ctx: RuleContext) -> list[Finding]:
    attrs = ctx.manifest.attributes
    findings = []
    if main := attrs.get("Main-Class"):
        findings.append(_f("manifest.main_class", INFO, "JAR is directly runnable (Main-Class)",
                           f"MANIFEST.MF Main-Class: {main}",
                           "The JAR can be launched on its own with `java -jar`. This is normal for installers "
                           "and tools, and some mods include one to show an 'install me in your mods folder' "
                           "message. Plain mods usually do not need it.", LOW))
    for key in ("Premain-Class", "Agent-Class", "Launcher-Agent-Class"):
        if value := attrs.get(key):
            findings.append(_f("manifest.java_agent", REVIEW, "JAR can act as a Java agent",
                               f"MANIFEST.MF {key}: {value}",
                               "A Java agent can inspect and rewrite other classes as they load. Profilers "
                               "and debugging tools use this; ordinary mods almost never do.", MEDIUM))
    if value := attrs.get("FMLCorePlugin"):
        findings.append(_f("manifest.coremod", INFO, "Legacy Forge coremod",
                           f"MANIFEST.MF FMLCorePlugin: {value}",
                           "Coremods patch Minecraft's own code while it loads. This was common for "
                           "older (1.12 and earlier) Forge mods, but it gives the mod deep control.", LOW))
    return findings


def rule_hash_database(ctx: RuleContext) -> list[Finding]:
    h = ctx.hash_lookup
    if h.classification == HashClassification.SUSPICIOUS:
        return [_f("hash.suspicious", WARNING, "File hash is marked SUSPICIOUS in the local database",
                   f"hashes.json: {h.name or ''} {h.version or ''}".strip(),
                   "Someone with access to your hash database previously flagged this exact file. "
                   f"Notes: {h.notes or '(none)'}", HIGH)]
    if h.classification == HashClassification.VERIFIED:
        return [_f("hash.verified", INFO, "File hash is marked VERIFIED in the local database",
                   f"hashes.json: {h.name or ''} {h.version or ''}".strip(),
                   "This exact file was previously checked and recorded as trusted. Any other findings "
                   "below still describe what the code does, and are expected for this file.", LOW)]
    return []


# ---------------------------------------------------------------------------
# Rules: archive contents
# ---------------------------------------------------------------------------

def rule_contents(ctx: RuleContext) -> list[Finding]:
    c = ctx.contents
    ev = ctx.evidence
    findings = []
    runners = ev.api_examples.get("process_execution", [])
    loaders = [loc for g in ("dynamic_loading", "process_execution", "native_file_load")
               for loc in ev.api_examples.get(g, [])]
    if c.executables_and_scripts:
        if runners:
            findings.append(_f("contents.executables", WARNING, "Executable files or scripts inside the JAR",
                               _where(c.executables_and_scripts),
                               "Files like .exe, .bat, .ps1 or .vbs can be run directly by the operating system. "
                               "A Minecraft mod has essentially no legitimate reason to carry them.", HIGH,
                               context=f"The JAR also contains code that starts programs: {_where(runners, shown=3)}.",
                               rationale="WARNING/HIGH: bundled executables plus code able to launch programs "
                                         "is a complete 'drop and run' capability."))
        else:
            findings.append(_f("contents.executables", REVIEW, "Executable files or scripts inside the JAR",
                               _where(c.executables_and_scripts),
                               "Files like .exe, .bat, .ps1 or .vbs can be run directly by the operating system. "
                               "Mods rarely need them; some ship helper scripts or installers.", MEDIUM,
                               context="No code that starts programs was found in this JAR, so nothing visible "
                                       "runs these files (another mod or the user could still run them).",
                               rationale="REVIEW/MEDIUM: unusual content, but without a way to execute it the "
                                         "files are only stored, not run."))
    if c.native_libraries:
        findings.append(_f("contents.native_libraries", INFO, "Embedded native libraries",
                           _where(c.native_libraries),
                           "Native libraries (.dll/.so/.dylib) run outside Java's safety checks. Some "
                           "legitimate mods ship them (e.g. voice chat, performance or controller mods), "
                           "so check that they fit the mod's stated purpose. Code that actually loads "
                           "native libraries is reported separately.", LOW))
    if c.disguised_files:
        risky = [d for d in c.disguised_files if "ZIP/JAR" not in d]
        if risky:
            findings.append(_f("contents.disguised", WARNING, "File contents do not match their extension",
                               _where(risky),
                               "These entries have an innocent-looking extension but actually contain "
                               "executable code (e.g. a Windows program named like an image, or Java classes "
                               "hidden as data). This is a known way to smuggle payloads.",
                               HIGH if loaders else MEDIUM,
                               context=(f"The JAR can also load or run code: {_where(loaders, shown=3)}."
                                        if loaders else "No code that loads classes, native libraries or "
                                        "programs was found in this JAR."),
                               rationale="WARNING: disguising executable content has no benign packaging "
                                         "reason. Confidence is HIGH only when the JAR can also load/run code."))
        hidden_zips = [d for d in c.disguised_files if "ZIP/JAR" in d]
        if hidden_zips:
            findings.append(_f("contents.hidden_archive", REVIEW, "Archive hidden under a different extension",
                               _where(hidden_zips),
                               "These entries are ZIP/JAR archives with a non-archive extension. Some formats "
                               "legitimately use ZIP internally, but it can also hide extra code.", MEDIUM))
    if c.encrypted_entries:
        findings.append(_f("contents.encrypted", REVIEW, "Encrypted entries", _where(c.encrypted_entries),
                           "Java cannot load encrypted JAR entries, so their only use is hiding data from "
                           "inspection. They could not be analyzed.", MEDIUM))
    if c.duplicate_names:
        findings.append(_f("contents.duplicates", REVIEW, "Duplicate entry names", _where(c.duplicate_names),
                           "The archive contains two entries with the same name. Different tools may pick "
                           "different copies, which can be used to show a clean file to scanners.", MEDIUM))
    if c.unsafe_names:
        findings.append(_f("contents.unsafe_paths", REVIEW, "Entry names with path traversal",
                           _where(c.unsafe_names),
                           "Names like '../../file' or 'C:/file' would escape the target folder if extracted "
                           "by a careless tool ('zip slip'). Normal build tools never create them; this "
                           "archive was likely crafted by hand. (This analyzer never extracts files.)", HIGH))
    if c.deceptive_names:
        findings.append(_f("contents.deceptive_names", REVIEW, "Entry names contain hidden Unicode characters",
                           _where(c.deceptive_names),
                           "Direction-override or zero-width characters make a name display differently "
                           "from what it really is. They are shown here as '\ufffd'.", HIGH))
    if c.high_ratio_entries:
        findings.append(_f("contents.compression_ratio", REVIEW, "Extremely high compression ratio",
                           _where([f"{e.path} ({e.size_bytes:,} bytes from {e.compressed_bytes:,})"
                                   for e in c.high_ratio_entries]),
                           f"These entries claim to expand more than {ctx.limits.suspicious_ratio:.0f}x. "
                           "Very repetitive data (e.g. blank images) can do this legitimately, but it is also "
                           "the signature of a zip bomb. Reading was capped safely.", MEDIUM))
    if c.large_files:
        findings.append(_f("contents.large_files", INFO, "Unusually large files",
                           _where([f"{e.path} ({e.size_bytes:,} bytes)" for e in c.large_files]),
                           "Large files are often textures, sounds or bundled libraries. Worth a glance if "
                           "the size does not fit the mod.", LOW))
    if c.nested_jars:
        findings.append(_f("contents.nested_jars", INFO, f"Contains {len(c.nested_jars)} bundled JAR(s)",
                           _where(c.nested_jars),
                           "Mods commonly bundle their libraries as JAR-in-JAR (Fabric 'jars', Forge "
                           "'jarjar'). They were analyzed too; their findings are included here with the "
                           "bundled JAR's path in the location.", LOW))
    if c.unusual_files:
        findings.append(_f("contents.unusual_files", INFO, "Uncommon file types", _where(c.unusual_files),
                           "These file types are not typical for Minecraft mods. Usually harmless, but worth "
                           "a look if nothing else explains them.", LOW))
    if c.signature_files:
        findings.append(_f("contents.signed", INFO, "JAR contains signature files", _where(c.signature_files),
                           "The JAR is (or was) digitally signed. This tool does not verify signatures, so "
                           "this says nothing about who signed it or whether it is still intact.", LOW))
    return findings


def rule_class_parsing(ctx: RuleContext) -> list[Finding]:
    cs = ctx.classes
    findings = []
    if cs.failed:
        findings.append(_f("classes.invalid", REVIEW, f"{cs.failed} class file(s) could not be parsed",
                           _where(cs.failed_entries, cs.failed),
                           "Normal compilers always produce valid class files. Invalid ones can be corrupted "
                           "downloads, or deliberately malformed files designed to break analysis tools.", MEDIUM))
    if cs.skipped:
        findings.append(_f("classes.incomplete", REVIEW, f"Analysis incomplete: {cs.skipped} class(es) not analyzed",
                           "(archive)",
                           "A safety limit (such as the total decompression budget) was reached or the "
                           "analysis was cancelled. Findings only cover the classes that were analyzed.", MEDIUM))
    if ctx.evidence.name_mismatches:
        findings.append(_f("classes.name_mismatch", REVIEW, "Class names do not match their file paths",
                           _where(ctx.evidence.name_mismatches),
                           "Java expects com/example/Foo.class to contain class com.example.Foo. A mismatch "
                           "means the class cannot be loaded normally - it may be hidden code that is loaded "
                           "manually at runtime.", MEDIUM))
    return findings


# ---------------------------------------------------------------------------
# Rules: class names and packages
# ---------------------------------------------------------------------------

def _simple_name(class_name: str) -> str:
    return class_name.rsplit("/", 1)[-1].split("$", 1)[0]


def rule_class_names(ctx: RuleContext) -> list[Finding]:
    names = [n for n in ctx.evidence.class_names
             if not n.endswith(("package-info", "module-info"))]
    findings = []
    if len(names) >= 10:
        short = [n for n in names if len(_simple_name(n)) <= 2]
        ratio = len(short) / len(names)
        if ratio >= 0.5:
            findings.append(_f("classes.obfuscated", REVIEW,
                               f"Obfuscated class names ({ratio:.0%} of classes)",
                               _where(short), "Most classes have meaningless one- or two-letter names (a, b, "
                               "aa...), the output of an obfuscator. Some legitimate (often paid) mods and "
                               "plugins are obfuscated to protect their code, but it also hides what malicious "
                               "code does. Manual review is harder.", MEDIUM))
        elif ratio >= 0.2 and len(short) >= 10:
            findings.append(_f("classes.partly_obfuscated", INFO,
                               f"Many very short class names ({ratio:.0%} of classes)", _where(short),
                               "Part of the code may be obfuscated, or it may bundle an obfuscated library.", LOW))

    confusable = [n for n in names if re.fullmatch(r"[Il1|]{4,}|[O0]{4,}", _simple_name(n))]
    if confusable:
        findings.append(_f("classes.confusable_names", REVIEW, "Confusable class names (e.g. IlIlIl)",
                           _where(confusable), "Names built from look-alike characters are an obfuscation "
                           "technique meant to make code hard to read.", MEDIUM))
    non_ascii = [n for n in names if not n.isascii()]
    if non_ascii:
        findings.append(_f("classes.non_ascii_names", REVIEW, "Non-ASCII class names", _where(non_ascii),
                           "Class names containing unusual Unicode characters are rare in normal Java code and "
                           "are used by some obfuscators. (Could also be a non-English developer.)", MEDIUM))
    default_pkg = [n for n in names if "/" not in n]
    if default_pkg:
        findings.append(_f("classes.default_package", REVIEW, "Classes without a package", _where(default_pkg),
                           "Real mods put their classes in a package (e.g. com.author.mod). Classes in the "
                           "'default package' are unusual and common in obfuscated or hastily made JARs.", LOW))
    reserved = [n for n in names if n.startswith(tuple(kv.RESERVED_PACKAGES))]
    if reserved:
        findings.append(_f("classes.reserved_namespace", REVIEW,
                           "Defines classes in a Java/Minecraft namespace", _where(reserved),
                           "The JAR contains its own classes under java/, sun/, net/minecraft/ or com/mojang/. "
                           "OptiFine and some legacy mods do this legitimately to replace game classes, but it "
                           "can also disguise code as part of the game or Java itself.", LOW))

    for prefix, client in kv.KNOWN_CLIENT_PACKAGES.items():
        matching = [n for n in names if n.startswith(prefix)]
        if matching:
            findings.append(_f("classes.known_client", REVIEW, f"Contains code from {client}",
                               _where(matching, len(matching), 3),
                               f"Classes are in the package used by {client}, a client that includes features "
                               "many servers prohibit. Check your server's rules; this says nothing about "
                               "malware.", MEDIUM))

    cheat_classes = [n for n in names if _CHEAT_WORD_RE.search(_simple_name(n))]
    if cheat_classes:
        findings.append(_f("classes.cheat_feature_names", REVIEW,
                           "Class names match gameplay-advantage features", _where(cheat_classes),
                           "Class names such as KillAura, AutoClicker or XRay usually implement features "
                           "that many servers prohibit. Some are false positives (e.g. an admin tool or a "
                           "mod that *detects* these). This concerns server rules, not malware.", MEDIUM))
    if ctx.evidence.cheat_strings:
        findings.append(_f("classes.cheat_feature_strings", REVIEW,
                           "Strings name gameplay-advantage features",
                           _where([f"'{s}' in {loc}" for s, loc in ctx.evidence.cheat_strings]),
                           "String literals exactly match names of features many servers prohibit (often "
                           "module names shown in a cheat client's menu). Could also be a mod that detects "
                           "or blocks them.", LOW))

    malware_named = [p for p in sorted(ctx.entry_names)
                     if _MALWARE_WORD_RE.search(posixpath.basename(p))]
    if malware_named:
        only_webhook = all("webhook" in p.lower() for p in malware_named)
        findings.append(_f("classes.malware_names", REVIEW,
                           "File or class names suggest malware tooling", _where(malware_named),
                           "Names containing words like 'stealer', 'grabber', 'keylog' or 'webhook' are "
                           "common in malware. 'Webhook' also appears in legitimate Discord-integration "
                           "mods.", LOW if only_webhook else MEDIUM))
    return findings


# ---------------------------------------------------------------------------
# Rules: API usage and strings
# ---------------------------------------------------------------------------

# group -> (severity, confidence, title, explanation). Process execution,
# native loading and dynamic loading have their own context-aware rules below.
API_FINDINGS = {
    "reflection": (INFO, LOW, "Reflection usage",
                   "Reflection lets code inspect and call methods by name at runtime. It is extremely "
                   "common in mods (Mixin, config libraries, compatibility code). On its own it means "
                   "little, but it can be used to hide what code calls."),
    "network": (INFO, LOW, "Network access",
                "Uses Java networking classes (URLs, HTTP, sockets). Common for update checkers, "
                "skin/cape loading and online features. Check the embedded URLs for where it connects. "
                "Downloading files, or combining the network with running code, is reported separately."),
    "instrumentation": (REVIEW, MEDIUM, "Java instrumentation API",
                        "Uses java.lang.instrument, which can rewrite classes of the whole program. "
                        "Typical for profilers and agents, unusual for mods."),
    "jndi": (REVIEW, MEDIUM, "JNDI lookups",
             "Uses JNDI (javax.naming), the mechanism abused by the Log4Shell exploit to load remote "
             "code. Very rarely needed by mods."),
    "screen_capture": (REVIEW, MEDIUM, "Screen capture",
                       "Uses java.awt.Robot to capture the screen. Minecraft screenshots do not need this. "
                       "Could be legitimate (e.g. screen-share) or spying."),
    "clipboard": (REVIEW, LOW, "System clipboard access (AWT)",
                  "Reads or writes the operating-system clipboard through AWT. Minecraft has its own "
                  "clipboard handling, so this is unusual; 'clipper' malware swaps copied crypto "
                  "addresses."),
    "crypto": (INFO, LOW, "Encryption API",
               "Uses javax.crypto ciphers. Legitimate for secure communication; also used to decrypt "
               "hidden payloads (decryption next to code loading is reported separately)."),
    "unsafe": (INFO, LOW, "sun.misc.Unsafe",
               "Uses low-level memory access. Common in performance libraries; rarely malicious by itself."),
    "session_token": (REVIEW, LOW, "Reads the Minecraft session token",
                      "References the method that returns the logged-in player's access token. Account "
                      "switchers and some authentication mods need this; token stealers use it to hijack "
                      "Minecraft accounts."),
}

# Context and rationale for REVIEW/WARNING rules that are judged on their own
# (no correlation with other evidence). Rules that DO correlate evidence pass
# their own context/rationale to _f(), which uses this table as a fallback.
STANDALONE_RATIONALE = {
    "metadata.inconsistent_id": ("Compared the IDs declared by each descriptor file in the JAR.",
                                 "REVIEW/LOW: usually a packaging quirk; tampering is the less likely explanation."),
    "metadata.inconsistent_version": ("Compared the versions declared by each descriptor file in the JAR.",
                                      "REVIEW/LOW: usually a packaging quirk; tampering is the less likely "
                                      "explanation."),
    "metadata.missing_entrypoint": ("Looked for the declared class among the JAR's entries.",
                                    "REVIEW/MEDIUM: breaks the link between metadata and code, which copied "
                                    "metadata would also do."),
    "metadata.lookalike": ("Compared the name with a list of popular mods, allowing for look-alike characters.",
                           "REVIEW/MEDIUM: a classic impersonation trick, but similar names also occur by chance."),
    "manifest.java_agent": ("Declared in META-INF/MANIFEST.MF; it only takes effect if the JAR is started as "
                            "an agent.", "REVIEW/MEDIUM: a powerful capability ordinary mods do not need."),
    "hash.suspicious": ("The file's SHA-256 matches an entry in your local hash database.",
                        "WARNING/HIGH: this exact file was previously judged suspicious."),
    "contents.hidden_archive": ("Checked the first bytes of each entry against its extension.",
                                "REVIEW/MEDIUM: some formats use ZIP internally, so this alone is ambiguous."),
    "contents.encrypted": ("Read from the ZIP directory; encrypted entries cannot be inspected.",
                           "REVIEW/MEDIUM: hides data from inspection, but loaders cannot run it directly."),
    "contents.duplicates": ("Read from the ZIP directory.",
                            "REVIEW/MEDIUM: normal build tools do not create duplicates; it enables showing "
                            "different content to different tools."),
    "contents.unsafe_paths": ("Read from the ZIP directory. This analyzer never extracts files.",
                              "REVIEW/HIGH: such names do not occur in normally built JARs, so the archive was "
                              "crafted."),
    "contents.deceptive_names": ("Read from the ZIP directory.",
                                 "REVIEW/HIGH: hidden Unicode in file names only serves to mislead a reader."),
    "contents.compression_ratio": ("Reading these entries was capped by the analyzer's safety limits.",
                                   "REVIEW/MEDIUM: repetitive data compresses well legitimately too."),
    "classes.invalid": ("Class files are parsed without ever loading or running them.",
                        "REVIEW/MEDIUM: may be corruption or deliberate anti-analysis."),
    "classes.incomplete": ("Findings cover only the classes that were analyzed.",
                           "REVIEW/MEDIUM: about analysis coverage, not about behaviour."),
    "classes.name_mismatch": ("Compared each class's declared name with its path in the JAR.",
                              "REVIEW/MEDIUM: such classes can only be loaded manually, which hides them."),
    "classes.obfuscated": ("Counted class names of one or two letters.",
                           "REVIEW/MEDIUM: obfuscation hides behaviour, but paid/closed mods use it legitimately."),
    "classes.confusable_names": ("Checked class names for look-alike character patterns.",
                                 "REVIEW/MEDIUM: only an obfuscation technique, not behaviour."),
    "classes.non_ascii_names": ("Checked class names for non-ASCII characters.",
                                "REVIEW/MEDIUM: used by obfuscators, but also by non-English developers."),
    "classes.default_package": ("Checked which classes have no package.",
                                "REVIEW/LOW: unusual style, weakly associated with hastily made JARs."),
    "classes.reserved_namespace": ("Checked class names against Java/Minecraft namespaces.",
                                   "REVIEW/LOW: some legacy mods do this legitimately."),
    "classes.known_client": ("Matched package names of well-known utility clients.",
                             "REVIEW/MEDIUM: concerns server rules, not malware."),
    "classes.cheat_feature_names": ("Matched class names against gameplay-advantage feature names.",
                                    "REVIEW/MEDIUM: concerns server rules, not malware."),
    "classes.cheat_feature_strings": ("Matched string literals against gameplay-advantage feature names.",
                                      "REVIEW/LOW: concerns server rules; detection mods contain these words too."),
    "classes.malware_names": ("Matched file and class names against malware-tooling words.",
                              "REVIEW: names are chosen by the author and prove nothing about behaviour."),
    "api.instrumentation": ("Judged on the API reference alone.",
                            "REVIEW/MEDIUM: powerful, and rarely needed by mods."),
    "api.jndi": ("Judged on the API reference alone.", "REVIEW/MEDIUM: rarely needed by mods, and "
                 "historically abused for remote code loading."),
    "api.screen_capture": ("Judged on the API reference alone.", "REVIEW/MEDIUM: rarely needed by mods."),
    "api.clipboard": ("Judged on the API reference alone.",
                      "REVIEW/LOW: unusual but mostly harmless; the risk is clipboard tampering."),
    "api.session_token": ("Session token access together with network access in the same class is "
                          "reported separately.", "REVIEW/LOW: account-related mods read it legitimately; "
                          "alone it is only a capability."),
    "batch.duplicate_mod_id": ("Compared the mod IDs of all files analyzed together.",
                               "REVIEW/LOW: usually two versions of the same mod."),
}


def _tag_list(tags: set[str]) -> str:
    """Human-readable description of a class's relevant context tags."""
    labels = {
        "network": "network access", "file_write": "writes files",
        "exec_content": "names executable/code files (.jar, .exe, .dll, .ps1...)",
        "bytecode_gen": "generates bytecode in memory", "base64": "Base64 decoding",
        "crypto": "decryption/encryption", "encoded_payload": "encoded executable data",
        "encoded_url": "a URL hidden in Base64", "shell": "shell/script-host strings",
        "hidden_exec": "hidden-window or policy-bypass options", "persistence": "startup-persistence strings",
        "process_execution": "starts programs", "dynamic_loading": "loads classes at runtime",
        "native_file_load": "loads a native library file", "session_token": "reads the session token",
    }
    found = [text for tag, text in labels.items() if tag in tags]
    return ", ".join(found) if found else "nothing else of note"


def rule_api_usage(ctx: RuleContext) -> list[Finding]:
    ev = ctx.evidence
    findings = []
    for group, (severity, confidence, title, explanation) in API_FINDINGS.items():
        count = ev.api_counts.get(group, 0)
        if count:
            findings.append(_f(f"api.{group}", severity, f"{title} ({count} class{'es' if count != 1 else ''})",
                               _where(ev.api_examples[group], count), explanation, confidence))
    if ev.reflective_targets:
        # A class name as text only matters if the class can also use reflection to act on it.
        with_reflection = [loc for _t, loc in ev.reflective_targets if "reflection" in _tags(ctx, loc)
                           or loc in ev.api_examples.get("reflection", [])]
        findings.append(_f("api.reflective_sensitive", REVIEW, "Sensitive class named in a string",
                           _where([f"'{t}' in {loc}" for t, loc in ev.reflective_targets]),
                           "The name of a powerful class (e.g. java.lang.Runtime) appears as text. Code can "
                           "use such strings with reflection to call that class without a visible direct "
                           "reference - a common way to hide behaviour.", MEDIUM if with_reflection else LOW,
                           context=("The same class also uses reflection." if with_reflection else
                                    "No reflection was seen in the class holding the string (it may be a "
                                    "log message or a list of names)."),
                           rationale="REVIEW: a possible way to hide API use. MEDIUM only when reflection "
                                     "appears alongside the string."))
    return findings


def rule_process_execution(ctx: RuleContext) -> list[Finding]:
    """One finding per class that can start programs, saying WHAT it starts.

    Only string literals are visible to static analysis, so the command is
    identified when it is written in the class (e.g. "xdg-open", "cmd.exe")
    and reported as unknown otherwise.
    """
    findings = []
    for loc, seen in ctx.evidence.process_contexts.items():
        helpers, shells, risky, programs, hidden = (seen.get(k, []) for k in
                                                    ("helpers", "shells", "risky", "programs", "hidden"))
        other = shells + risky + programs
        parts = []
        if helpers:
            parts.append("common helper commands: " + ", ".join(f"{h} ({kv.HELPER_COMMANDS[h]})" for h in helpers))
        if shells:
            parts.append("shells/script hosts: " + ", ".join(shells))
        if risky:
            parts.append("programs often abused by malware: " + ", ".join(risky))
        if programs:
            parts.append("other programs: " + ", ".join(programs))
        if hidden:
            parts.append("stealth options: " + ", ".join(hidden))
        if not parts:
            parts.append("no command name is visible in this class (it may be built at runtime or passed in "
                         "from another class)")
        if other or hidden:
            confidence = MEDIUM
            rationale = ("REVIEW/MEDIUM: it starts a shell, script host or other program, so what actually "
                         "runs depends on the command it is given.")
        elif helpers:
            confidence = LOW
            rationale = ("REVIEW/LOW: the only visible commands are common helpers that open URLs/folders or "
                         "query the system, which legitimate mods do.")
        else:
            confidence = MEDIUM
            rationale = "REVIEW/MEDIUM: the command could not be identified statically."
        seen_text = "; ".join(parts)
        shown = helpers + other
        title =f"Runs external programs ({', '.join(shown[:3])})" if shown else \
            "Runs external programs (command not visible)"
        findings.append(_f("api.process_execution", REVIEW, title, loc,
                           "Can start operating-system programs (Runtime.exec / ProcessBuilder). Mods use this "
                           "to open a browser or folder, or to query hardware; malware uses it to run "
                           "payloads. Combinations with downloading or stealth options are reported as "
                           "separate warnings.", confidence,
                           context=f"{seen_text[0].upper()}{seen_text[1:]}. The class also: "
                                   f"{_tag_list(_tags(ctx, loc) - {'process_execution'})}.",
                           rationale=rationale))
    return findings


def rule_native_loading(ctx: RuleContext) -> list[Finding]:
    """Native code: JNA bindings to the OS vs. bundled libraries vs. unknown files."""
    ev = ctx.evidence
    classes = [loc for loc, g in ev.class_groups.items() if "native_loading" in g]
    if not classes:
        return []
    bundled = bool(ctx.contents.native_libraries)
    jna_only, own_libs, external, unknown = [], [], [], []
    for loc in classes:
        tags = _tags(ctx, loc)
        if "native_file_load" not in tags:
            jna_only.append(loc)
        elif tags & EXTERNAL_SOURCE_TAGS:
            external.append(loc)
        elif bundled:
            own_libs.append(loc)
        else:
            unknown.append(loc)
    parts = []
    if jna_only:
        bindings = sorted({b for loc in jna_only for b in ev.jna_bindings.get(loc, [])})
        parts.append(f"{len(jna_only)} class(es) only call operating-system functions through JNA"
                     + (f" ({', '.join(bindings[:8])})" if bindings else "")
                     + " without loading a library file")
    if own_libs:
        parts.append(f"{len(own_libs)} class(es) load native library files, and the JAR bundles its own "
                     f"native libraries ({_where(ctx.contents.native_libraries, shown=3)})")
    if unknown:
        parts.append(f"{len(unknown)} class(es) load native library files that are not bundled in this JAR "
                     f"(system-installed or obtained elsewhere): {_where(unknown, shown=3)}")
    if external:
        parts.append(f"{len(external)} class(es) load native library files AND use network/decoding/"
                     f"decryption: {_where(external, shown=3)}")
    confidence = MEDIUM if (external or unknown) else LOW
    count = ev.api_counts.get("native_loading", len(classes))
    return [_f("api.native_loading", REVIEW, f"Loads native code ({count} class{'es' if count != 1 else ''})",
               _where(external + unknown + own_libs + jna_only, len(classes)),
               "Uses native code (System.load/loadLibrary or JNA). Native code runs outside Java's safety "
               "checks. Voice chat, performance and compatibility mods use it legitimately.", confidence,
               context="; ".join(parts) + ".",
               rationale=("REVIEW/MEDIUM: at least one class loads a native library that is not bundled with "
                          "the mod, or whose data may come from outside the JAR." if confidence == MEDIUM else
                          "REVIEW/LOW: only OS calls through JNA and/or the mod's own bundled libraries."))]


def rule_dynamic_loading(ctx: RuleContext) -> list[Finding]:
    """Runtime class loading: generated-in-memory vs. possibly obtained from outside."""
    ev = ctx.evidence
    classes = [loc for loc, g in ev.class_groups.items() if "dynamic_loading" in g]
    if not classes:
        return []
    external = [loc for loc in classes if _tags(ctx, loc) & EXTERNAL_SOURCE_TAGS]
    generated = [loc for loc in classes if loc not in external and "bytecode_gen" in _tags(ctx, loc)]
    plain = [loc for loc in classes if loc not in external and loc not in generated]
    parts = []
    if generated:
        parts.append(f"{len(generated)} class(es) generate the bytecode they load in memory (ASM/ByteBuddy "
                     "or JVM method descriptors), with no network, decoding or decryption")
    if plain:
        parts.append(f"{len(plain)} class(es) are class loaders or define classes with no network, decoding or "
                     "decryption in the same class (typical for libraries and mod loaders)")
    if external:
        parts.append(f"{len(external)} class(es) also use network/decoding/decryption, so the loaded code "
                     f"may come from outside the JAR: "
                     + "; ".join(f"{loc} ({_tag_list(_tags(ctx, loc) & EXTERNAL_SOURCE_TAGS)})"
                                 for loc in external[:3]))
    count = ev.api_counts.get("dynamic_loading", len(classes))
    return [_f("api.dynamic_loading", REVIEW, f"Dynamic class loading ({count} class{'es' if count != 1 else ''})",
               _where(external + plain + generated, len(classes)),
               "Defines or loads Java classes at runtime, bypassing the normal mod loader. Libraries, "
               "performance mods and loaders do this legitimately; malware uses it to run code downloaded "
               "from the internet or decrypted from hidden data.", MEDIUM if external else LOW,
               context="; ".join(parts) + ".",
               rationale=("REVIEW/MEDIUM: a class that loads code also handles data from outside the JAR."
                          if external else "REVIEW/LOW: no sign that the loaded code comes from outside the JAR."))]


def rule_downloads(ctx: RuleContext) -> list[Finding]:
    """Network access plus writing files in the same class (without running code there)."""
    findings = []
    for loc in _classes_with(ctx, {"network"}, {"file_write"}):
        tags = _tags(ctx, loc)
        if tags & EXECUTION_TAGS:
            continue  # reported by rule_combinations with more context
        executable = "exec_content" in tags
        findings.append(_f("api.downloads", REVIEW,
                           "Downloads executable content" if executable else "Network access and file writing",
                           loc,
                           "The class can fetch data from the network and write files. Mods do this for caches, "
                           "skins or updates; it is also the first half of a 'download and run' dropper.",
                           MEDIUM if executable else LOW,
                           context=f"The class also: {_tag_list(tags - {'network', 'file_write'})}. It does not "
                                   "load or run code itself.",
                           rationale=("REVIEW/MEDIUM: it names executable/code files, but nothing in the same "
                                      "class runs them." if executable else
                                      "REVIEW/LOW: saving downloaded data is common; nothing suggests it is code.")))
    return findings


def rule_combinations(ctx: RuleContext) -> list[Finding]:
    """Combinations of capabilities in the SAME class are far more telling than any one alone."""
    ev = ctx.evidence
    findings = []
    has = lambda g: ev.api_counts.get(g, 0) > 0  # noqa: E731
    exfil_urls = [u for u in ev.urls if classify_url(u)[0] == WARNING]

    # Downloader: fetch from the network, then load classes, run a program or load a native library.
    downloaders = _classes_with(ctx, {"network"}, EXECUTION_TAGS)
    for loc in downloaders:
        tags = _tags(ctx, loc)
        strong = []
        if "exec_content" in tags:
            strong.append("names executable/code files" + (" and writes files" if "file_write" in tags else ""))
        if "hidden_exec" in tags:
            strong.append("uses hidden-window or policy-bypass options")
        if "shell" in tags or ev.process_contexts.get(loc, {}).get("shells"):
            strong.append("starts a shell or script host")
        if tags & {"base64", "crypto", "encoded_payload", "encoded_url"}:
            strong.append("decodes or decrypts data")
        if urls := _suspicious_urls_in(ctx, loc):
            strong.append(f"contains suspicious URLs ({_where(urls, shown=2)})")
        runs = [text for tag, text in (("dynamic_loading", "loads classes"), ("process_execution", "starts programs"),
                                       ("native_file_load", "loads a native library")) if tag in tags]
        context = f"Same class: network access + {', '.join(runs)}." + (
            f" Also {'; '.join(strong)}." if strong else " Nothing else suspicious was found in the class.")
        seen = ev.process_contexts.get(loc, {})
        helper_only = (runs == ["starts programs"] and seen.get("helpers") and not
                       any(seen.get(k) for k in ("shells", "risky", "programs", "hidden")))
        if helper_only and not strong:
            # e.g. an update checker that opens the download page in the browser.
            findings.append(_f("combo.downloader", REVIEW, "Network access and a helper program in the same class",
                               loc, "The class can reach the network and start a program, but the only program "
                               "visible is a common helper that opens URLs/folders or queries the system.", MEDIUM,
                               context=context + f" Visible commands: {', '.join(seen['helpers'])}.",
                               rationale="REVIEW/MEDIUM: combines two capabilities, but what it runs looks benign."))
            continue
        findings.append(_f("combo.downloader", WARNING, "Downloads data and loads/runs code in the same class", loc,
                           "A class that both downloads data and loads classes or starts programs matches the "
                           "typical 'downloader' pattern: fetch a payload and run it. Legitimate auto-updaters "
                           "look similar - if this is one, check that it only contacts the mod's official "
                           "download site and what exactly it runs.", HIGH if strong else MEDIUM,
                           context=context,
                           rationale=("WARNING/HIGH: download-and-execute plus supporting evidence in the same "
                                      "class." if strong else "WARNING/MEDIUM: download-and-execute capability in "
                                      "one class, without further supporting evidence.")))
    if not downloaders and has("network") and (has("dynamic_loading") or has("process_execution")):
        findings.append(_f("combo.downloader_spread", REVIEW,
                           "Network access and code loading/execution in the same JAR", "(multiple classes)",
                           "The JAR can both reach the network and load classes or run programs, though "
                           "not in the same class. Worth checking how they are connected.", LOW,
                           context="No single class does both; the classes may be unrelated.",
                           rationale="REVIEW/LOW: capabilities are only co-located in the JAR, not correlated."))

    # Stealthy execution: starting programs with hidden-window / bypass options.
    for loc in _classes_with(ctx, {"process_execution"}, {"hidden_exec"}):
        tags = _tags(ctx, loc)
        flags = ev.process_contexts.get(loc, {}).get("hidden", [])
        backed = tags & {"network", "file_write", "base64", "encoded_payload", "encoded_url"}
        findings.append(_f("combo.hidden_execution", WARNING, "Starts programs with hidden or policy-bypass options",
                           loc, "The class starts programs and contains options that hide the window or bypass "
                           "script-safety settings (e.g. PowerShell -WindowStyle Hidden -ExecutionPolicy Bypass). "
                           "Malware uses these to run unnoticed; a few updaters use them to replace files quietly.",
                           HIGH if backed else MEDIUM,
                           context=f"Options: {', '.join(flags) or 'see strings'}. The class also: "
                                   f"{_tag_list(tags - {'process_execution', 'hidden_exec'})}.",
                           rationale=("WARNING/HIGH: stealthy execution combined with writing, downloading or "
                                      "decoding data." if backed else
                                      "WARNING/MEDIUM: stealthy execution, without other supporting evidence.")))

    # Persistence: "run me at every login" strings where programs are started.
    for loc in _classes_with(ctx, {"persistence"}, {"process_execution"}):
        findings.append(_f("combo.persistence_exec", WARNING, "Startup persistence combined with running programs",
                           loc, "The class names a startup/persistence location (Startup folder, Run key, "
                           "scheduled tasks, LaunchAgents) and can start programs - how malware makes itself "
                           "run again after every reboot.", HIGH,
                           context=f"The class also: {_tag_list(_tags(ctx, loc) - {'persistence'})}.",
                           rationale="WARNING/HIGH: two independent indicators in the same class."))

    # Decoded payload + execution in the same class.
    for loc in _classes_with(ctx, {"base64", "crypto", "encoded_payload", "encoded_url"}, EXECUTION_TAGS):
        tags = _tags(ctx, loc)
        if loc in downloaders and "network" in tags:
            continue  # already a downloader finding with this evidence
        payload = tags & {"encoded_payload", "encoded_url"}
        findings.append(_f("combo.decoded_exec", WARNING, "Decodes hidden data and loads/runs code in the same class",
                           loc, "The class decodes or decrypts data and can also load classes, native libraries or "
                           "start programs: the pattern of an unpacker that runs a hidden payload.",
                           HIGH if payload else MEDIUM,
                           context=f"The class: {_tag_list(tags)}.",
                           rationale=("WARNING/HIGH: an encoded payload or hidden URL is present where code is run."
                                      if payload else "WARNING/MEDIUM: decoding next to code execution; the "
                                      "decoded data itself was not identified.")))

    # Theft: touches credential files and can send data out.
    if has("sensitive_high") and (has("network") or exfil_urls):
        same = _classes_with(ctx, {"sensitive_high"}, {"network"})
        findings.append(_f("combo.data_theft", WARNING,
                           "Credential-store access combined with network access",
                           _where(same) if same else "(multiple classes)",
                           "The JAR references credential stores (browser, Discord, launcher or wallet files) "
                           "AND can send data over the network. This combination is the core of "
                           "credential stealers.", HIGH if same else MEDIUM,
                           context=("In the same class." if same else "In different classes of the JAR."),
                           rationale="WARNING: credential access plus a way to send data out. HIGH when both "
                                     "are in one class."))

    # Session token + network in the same class. Legitimate clients that log
    # in to their own services (e.g. Feather, Essential) do this too, so it is
    # only a WARNING when a suspicious/exfiltration URL is also present.
    token_net = _classes_with(ctx, {"session_token"}, {"network"})
    if token_net:
        near = [u for loc in token_net for u in _suspicious_urls_in(ctx, loc)]
        anywhere = [u for u in ev.urls if classify_url(u)[0] != INFO]
        severity = WARNING if anywhere else REVIEW
        confidence = HIGH if near else MEDIUM
        findings.append(_f("combo.session_token_network", severity,
                           "Session token access and network access in the same class",
                           _where(token_net),
                           "A class reads the Minecraft session token and can make network connections. "
                           "Launcher-like clients do this to log in to their own services; token stealers "
                           "do it to send the token to an attacker.", confidence,
                           context=(f"Suspicious URLs in the same class: {_where(near, shown=3)}." if near else
                                    f"Suspicious URLs elsewhere in the JAR: {_where(anywhere, shown=3)}." if anywhere
                                    else "No suspicious URLs were found (they could still be built at runtime)."),
                           rationale=("WARNING: token access, networking and suspicious destinations together."
                                      if anywhere else "REVIEW/MEDIUM: normal for clients with their own login; "
                                      "no suspicious destination was found.")))

    # Hidden payload: encoded executable data plus a way to decode/load it.
    if has("encoded_payload") and (has("dynamic_loading") or has("base64")):
        payload_classes = [loc for _k, loc in ev.encoded_payloads]
        same = [loc for loc in payload_classes if _tags(ctx, loc) & {"dynamic_loading", "base64"}]
        findings.append(_f("combo.packed_payload", WARNING,
                           "Encoded executable data with a way to decode/load it",
                           _where(payload_classes),
                           "Executable code stored as an encoded string, plus Base64 decoding or class "
                           "loading, matches a packed or hidden payload.", HIGH if same else MEDIUM,
                           context=("Decoding/loading happens in the same class as the payload." if same else
                                    "Decoding/loading happens in a different class than the payload."),
                           rationale="WARNING: hidden code plus the means to unpack it. HIGH when in one class."))
    return findings


def classify_url(url: str) -> tuple[Severity, Confidence, str]:
    """Return (severity, confidence, label) for one URL."""
    lower = url.lower()
    if webhook := _DISCORD_WEBHOOK_RE.search(lower):
        if webhook.group(1):
            return WARNING, HIGH, "Discord webhook"
        # Discord-integration mods keep just the prefix in code and read the
        # real URL from the user's config. Still worth a look (it can also be
        # completed at runtime), but not an embedded exfil channel.
        return REVIEW, MEDIUM, "incomplete Discord webhook URL (no ID/token in the code)"
    for fragment, label in kv.EXFIL_URL_FRAGMENTS.items():
        if fragment in lower:
            return WARNING, HIGH, label
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return INFO, LOW, "unparseable URL"

    def on(domains: set[str]) -> bool:
        return any(host == d or host.endswith("." + d) for d in domains)

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            return INFO, HIGH, "local/private IP address"
        return REVIEW, MEDIUM, "raw IP address instead of a domain name"
    if ("cdn.discordapp.com/attachments" in lower or "media.discordapp.net/attachments" in lower):
        return REVIEW, MEDIUM, "Discord file attachment (can host downloadable files)"
    if on(kv.PASTE_DOMAINS):
        return REVIEW, MEDIUM, "paste site (often hosts second-stage URLs or payloads)"
    if on(kv.TUNNEL_DOMAINS):
        return REVIEW, MEDIUM, "tunnel / dynamic-DNS service (often used for command servers)"
    if on(kv.FILE_HOST_DOMAINS):
        return REVIEW, MEDIUM, "anonymous file host (often hosts payloads)"
    if on(kv.IP_LOOKUP_DOMAINS):
        return REVIEW, MEDIUM, "public-IP lookup service"
    if on(kv.URL_SHORTENER_DOMAINS):
        return REVIEW, LOW, "URL shortener (hides the real destination)"
    if any(host.endswith(tld) for tld in kv.FREE_TLDS):
        return REVIEW, LOW, "free domain often used for throwaway sites"
    if on(kv.KNOWN_DOMAINS):
        return INFO, HIGH, "known domain"
    return INFO, MEDIUM, "other domain"


def rule_urls(ctx: RuleContext) -> list[Finding]:
    ev = ctx.evidence
    findings = []
    benign: list[str] = []
    explanations = {
        WARNING: "This URL is a channel for sending data to an attacker-controlled chat (Discord webhooks and "
                 "Telegram bots are the most common way Minecraft stealers send stolen tokens and files).",
        REVIEW: "This kind of address is rarely needed by legitimate mods and is frequently used by malware. "
                "It may still be harmless - check what the code does with it.",
    }
    for url, loc in ev.urls.items():
        severity, confidence, label = classify_url(url)
        if severity == INFO:
            benign.append(url)
            continue
        networked = "network" in _tags(ctx, _class_of(loc))
        if severity == REVIEW and not networked:
            confidence = LOW  # just text unless something connects to it
        title = "Data-exfiltration URL" if severity == WARNING else "Suspicious embedded URL"
        findings.append(_f("strings.url", severity, f"{title}: {label}", f"{loc}: {url}",
                           explanations[severity], confidence,
                           context=("The class containing it also has network code." if networked else
                                    "No network code was found in the class containing it."),
                           rationale=(f"WARNING/{confidence.value}: the destination itself is an exfiltration "
                                      "channel." if severity == WARNING else
                                      f"REVIEW/{confidence.value}: a risky kind of destination"
                                      + (" in a class that can connect." if networked else ", but only as text."))))
    if benign:
        findings.append(_f("strings.urls_other", INFO, f"Embedded URLs ({len(benign)})", _where(benign, shown=10),
                           "Web addresses found in the code (project pages, APIs, documentation...). Listed for "
                           "transparency; unknown domains are not suspicious by themselves.", LOW))
    public_ips = []
    networked_ip = False
    for ip_port, loc in ev.ip_ports.items():
        try:
            ip = ipaddress.ip_address(ip_port.split(":")[0])
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_unspecified):
            public_ips.append(f"{ip_port} in {loc}")
            networked_ip |= "network" in _tags(ctx, _class_of(loc))
    if public_ips:
        findings.append(_f("strings.ip_port", REVIEW, "Hard-coded IP address and port", _where(public_ips),
                           "A raw public IP address with a port is often a hard-coded server the code connects "
                           "to. Could be a Minecraft server address or a command server.",
                           MEDIUM if networked_ip else LOW,
                           context=("A class containing one also has network code." if networked_ip else
                                    "No network code was found in the classes containing them."),
                           rationale="REVIEW: a hard-coded destination. MEDIUM only if the same class can connect."))
    return findings


def rule_sensitive_strings(ctx: RuleContext) -> list[Finding]:
    findings = []
    for category, hits in ctx.evidence.sensitive.items():
        classes = sorted({_class_of(loc) for _frag, loc in hits})
        if category in kv.HIGH_RISK_CATEGORIES:
            severity, confidence = WARNING, MEDIUM
            advice = ("Legitimate Minecraft mods have no reason to access these; credential stealers and other "
                      "malware look for exactly these locations.")
            rationale = ("WARNING/MEDIUM: these strings name specific credential stores or attack tooling. "
                         "Combined with network access this is reported separately.")
        elif category == kv.CATEGORY_PERSISTENCE:
            severity, confidence = REVIEW, MEDIUM
            advice = ("Programs use these locations to start automatically at login. Installers and launchers "
                      "can use them legitimately.")
            rationale = ("REVIEW/MEDIUM: persistence strings alone. Where the same class also starts programs "
                         "a separate WARNING is reported.")
        else:
            severity, confidence = REVIEW, LOW
            advice = "This has legitimate uses but deserves a look in context."
            rationale = ("REVIEW/LOW: shell names alone are weak evidence. Classes that start programs report "
                         "the commands they run separately.")
        runs = [loc for loc in classes if _tags(ctx, loc) & EXECUTION_TAGS]
        net = [loc for loc in classes if "network" in _tags(ctx, loc)]
        context = (f"Found in {len(classes)} class(es). "
                   + (f"Classes that also load/run code: {_where(runs, shown=3)}. " if runs else
                      "None of them load or run code. ")
                   + (f"Classes that also have network access: {_where(net, shown=3)}." if net else
                      "None of them have network access."))
        findings.append(_f("strings.sensitive", severity, f"References to {category.lower()}",
                           _where([f"'{frag}' in {loc}" for frag, loc in hits]),
                           f"The code contains text associated with {category.lower()}. {advice}",
                           confidence, context=context, rationale=rationale))
    return findings


def rule_encoded_strings(ctx: RuleContext) -> list[Finding]:
    ev = ctx.evidence
    findings = []
    if ev.encoded_payloads:
        same = [loc for _k, loc in ev.encoded_payloads if _tags(ctx, loc) & {"base64", "dynamic_loading"}]
        findings.append(_f("strings.encoded_executable", WARNING, "Executable code hidden in an encoded string",
                           _where([f"{kind} in {loc}" for kind, loc in ev.encoded_payloads]),
                           "A Base64 string decodes to a class file, executable or archive. Storing code as "
                           "text is a way to hide a payload from scanners.", HIGH if same else MEDIUM,
                           context=("The same class also decodes Base64 or loads classes." if same else
                                    "No decoding or class loading was found in the same class."),
                           rationale="WARNING: hidden executable content has no ordinary packaging reason. HIGH "
                                     "when the class can also decode/load it."))
    if ev.encoded_urls:
        suspicious = [u for u, _loc in ev.encoded_urls if classify_url(u)[0] != INFO]
        networked = [loc for _u, loc in ev.encoded_urls if "network" in _tags(ctx, loc)]
        findings.append(_f("strings.encoded_url", REVIEW, f"URL hidden in Base64 ({len(ev.encoded_urls)})",
                           _where([f"{loc}: {u}" for u, loc in ev.encoded_urls]),
                           "A Base64 string decodes to a web address. Encoding a URL hides it from people "
                           "reading the code and from simple scanners; legitimate code rarely needs to.",
                           MEDIUM if (suspicious or networked) else LOW,
                           context=(f"Suspicious destinations: {_where(suspicious, shown=3)}. " if suspicious else "")
                                   + ("The class also has network code." if networked else
                                      "No network code was found in the class holding it."),
                           rationale="REVIEW: hiding a URL is an evasion technique. MEDIUM when the destination is "
                                     "risky or the class can connect; with code execution a WARNING is reported."))
    if ev.encoded_strings:
        many = len(ev.encoded_strings) >= 10
        holders = sorted({loc for _p, loc, _e in ev.encoded_strings})
        runs = [loc for loc in holders if _tags(ctx, loc) & EXECUTION_TAGS]
        review = many and bool(runs)
        findings.append(_f("strings.encoded", REVIEW if review else INFO,
                           f"Encoded-looking strings ({len(ev.encoded_strings)})",
                           _where([f"{loc}: {p} (entropy {e})" for p, loc, e in ev.encoded_strings]),
                           "Long strings of random-looking Base64 text. They are often keys, hashes, "
                           "textures or config data, but can also hide encrypted URLs or code. Entropy "
                           "measures randomness: readable text is ~4, random Base64 approaches 6.", LOW,
                           context=(f"Classes holding them also load/run code: {_where(runs, shown=3)}." if runs
                                    else "None of the classes holding them load or run code."),
                           rationale="REVIEW/LOW: many random-looking strings where code is loaded or run; they "
                                     "did not decode to anything recognizable."))
    return findings


RULES: list[Callable[[RuleContext], list[Finding]]] = [
    rule_hash_database,
    rule_metadata_presence,
    rule_metadata_consistency,
    rule_entrypoints_exist,
    rule_impersonation,
    rule_manifest,
    rule_contents,
    rule_class_parsing,
    rule_class_names,
    rule_api_usage,
    rule_process_execution,
    rule_native_loading,
    rule_dynamic_loading,
    rule_downloads,
    rule_combinations,
    rule_urls,
    rule_sensitive_strings,
    rule_encoded_strings,
]

SEVERITY_SORT = {WARNING: 0, REVIEW: 1, INFO: 2}


def run_rules(ctx: RuleContext) -> tuple[list[Finding], list[str]]:
    """Run every rule. A bug in one rule is reported as an error, not a crash."""
    findings: list[Finding] = []
    errors: list[str] = []
    for rule in RULES:
        try:
            produced = rule(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken rule must not stop the others
            errors.append(f"Internal error in rule {rule.__name__}: {exc!r}")
            continue
        findings.extend(_cap(produced, ctx.limits.max_findings_per_rule))
    findings.sort(key=lambda f: SEVERITY_SORT[f.severity])  # stable: keeps rule order within a severity
    return findings, errors


def _cap(findings: list[Finding], limit: int) -> list[Finding]:
    """Keep at most `limit` findings per rule_id, summarising the rest."""
    counts: Counter[str] = Counter()
    kept: list[Finding] = []
    for f in findings:
        counts[f.rule_id] += 1
        if counts[f.rule_id] <= limit:
            kept.append(f)
    for rule_id, n in counts.items():
        if n > limit:
            same_rule = [f for f in findings if f.rule_id == rule_id]
            worst = min((f.severity for f in same_rule), key=SEVERITY_SORT.get)
            kept.append(_f(rule_id, worst, f"{n - limit} more similar finding(s) not shown", "(various)",
                           "The per-rule finding limit was reached; see the limit in analyzer/limits.py.",
                           _max_confidence([f.confidence for f in same_rule[limit:]]),
                           context="Only the first findings of this rule are listed.",
                           rationale="Rated like the most severe of the hidden findings."))
    return kept


def add_batch_findings(results: list[AnalysisResult]) -> None:
    """Cross-file checks for a batch: the same mod ID in more than one file."""
    owners: dict[str, list[AnalysisResult]] = defaultdict(list)
    for result in results:
        ids = {m.mod_id.lower() for m in result.mods if m.nested_in is None and m.mod_id}
        for mod_id in ids:
            owners[mod_id].append(result)
    for mod_id, files in owners.items():
        if len(files) < 2:
            continue
        names = [r.file.name for r in files]
        for result in files:
            others = [n for n in names if n != result.file.name] or names
            result.findings.append(_f(
                "batch.duplicate_mod_id", REVIEW, f"Mod ID '{mod_id}' also appears in another selected file",
                ", ".join(others),
                "Two files claim the same mod ID. Often this is just two versions of one mod, but a fake "
                "copy of a mod also reuses the real mod's ID. Compare their hashes and contents.", LOW))
        for result in files:
            result.findings.sort(key=lambda f: SEVERITY_SORT[f.severity])
