"""Read Java .class files WITHOUT running them.

A .class file is compiled Java bytecode. We never load or execute it. We only
read its *constant pool*, a table at the start of every class file that lists
every class, method, field and string literal the code refers to. For example,
code that calls `Runtime.getRuntime().exec("cmd")` has these pool entries:

    Class      java/lang/Runtime
    Methodref  java/lang/Runtime . getRuntime
    Methodref  java/lang/Runtime . exec
    String     "cmd"

That is enough to know WHAT APIs a class uses and WHICH string literals it
contains - without the complexity (and risk) of decompiling or executing it.

Class file layout (all numbers are big-endian, "u2" = 2-byte unsigned int):

    u4  magic                 always 0xCAFEBABE
    u2  minor_version
    u2  major_version         52 = Java 8, 61 = Java 17, 65 = Java 21
    u2  constant_pool_count
        constant_pool[count - 1]   (index 0 is unused)
    u2  access_flags
    u2  this_class            pool index of this class's name
    u2  super_class
    ... (interfaces, fields, methods - we don't need them)

Limitation: strings built at runtime (e.g. decrypted or concatenated from
pieces) never appear in the constant pool. Heavily obfuscated malware can
therefore hide its strings from this kind of analysis.
"""

from __future__ import annotations

import struct
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from .jar import BudgetExceeded, EntryReadError, SafeJar
from .models import ClassSummary

CLASS_MAGIC = 0xCAFEBABE
MAX_ERRORS_LISTED = 20
MAX_FAILED_LISTED = 200

# Constant pool tags (see the Java Virtual Machine Specification, chapter 4.4).
TAG_UTF8 = 1
TAG_INTEGER, TAG_FLOAT = 3, 4
TAG_LONG, TAG_DOUBLE = 5, 6
TAG_CLASS = 7
TAG_STRING = 8
TAG_FIELDREF, TAG_METHODREF, TAG_INTERFACE_METHODREF = 9, 10, 11
TAG_NAME_AND_TYPE = 12
TAG_METHOD_HANDLE = 15
TAG_METHOD_TYPE = 16
TAG_DYNAMIC, TAG_INVOKE_DYNAMIC = 17, 18
TAG_MODULE, TAG_PACKAGE = 19, 20

# Bytes to skip for tags whose contents we don't need.
_SKIP_SIZES = {
    TAG_INTEGER: 4, TAG_FLOAT: 4, TAG_METHOD_HANDLE: 3, TAG_METHOD_TYPE: 2,
    TAG_DYNAMIC: 4, TAG_INVOKE_DYNAMIC: 4, TAG_MODULE: 2, TAG_PACKAGE: 2,
}


class ClassParseError(ValueError):
    """The bytes are not a valid class file."""


@dataclass
class ParsedClass:
    entry_name: str                 # path inside the JAR
    name: str                       # e.g. "com/example/Main"
    super_name: str | None
    major_version: int
    class_refs: set[str] = field(default_factory=set)               # classes referenced
    member_refs: set[tuple[str, str]] = field(default_factory=set)  # (owner class, member name)
    strings: list[str] = field(default_factory=list)                # string literals


class _Reader:
    """Reads big-endian numbers from bytes, with bounds checking.

    Every read checks there are enough bytes left, so a truncated or lying file
    raises ClassParseError instead of reading garbage or crashing.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ClassParseError("file is truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u1(self) -> int:
        return self.take(1)[0]

    def u2(self) -> int:
        return struct.unpack(">H", self.take(2))[0]  # ">" = big-endian

    def u4(self) -> int:
        return struct.unpack(">I", self.take(4))[0]


def _decode_java_utf8(raw: bytes) -> str:
    # Java uses "modified UTF-8", which is almost normal UTF-8. Invalid
    # sequences become "�" rather than raising or creating broken strings.
    return raw.decode("utf-8", errors="replace")


def _strip_array(name: str) -> str:
    """"[Ljava/lang/String;" -> "java/lang/String"; primitive arrays -> ""."""
    if not name.startswith("["):
        return name
    name = name.lstrip("[")
    if name.startswith("L") and name.endswith(";"):
        return name[1:-1]
    return ""


def parse_class(data: bytes, entry_name: str = "") -> ParsedClass:
    r = _Reader(data)
    if r.u4() != CLASS_MAGIC:
        raise ClassParseError("not a class file (bad magic number)")
    r.u2()  # minor version
    major = r.u2()
    count = r.u2()
    if count == 0:
        raise ClassParseError("empty constant pool")

    # pool[i] holds a tuple describing entry i; unused slots stay None.
    pool: list[tuple | None] = [None] * count
    i = 1
    while i < count:
        tag = r.u1()
        if tag == TAG_UTF8:
            pool[i] = ("utf8", _decode_java_utf8(r.take(r.u2())))
        elif tag == TAG_CLASS:
            pool[i] = ("class", r.u2())
        elif tag == TAG_STRING:
            pool[i] = ("string", r.u2())
        elif tag in (TAG_FIELDREF, TAG_METHODREF, TAG_INTERFACE_METHODREF):
            pool[i] = ("ref", r.u2(), r.u2())
        elif tag == TAG_NAME_AND_TYPE:
            pool[i] = ("nat", r.u2(), r.u2())
        elif tag in (TAG_LONG, TAG_DOUBLE):
            r.take(8)
            i += 1  # historical JVM quirk: 8-byte constants use two pool slots
        elif tag in _SKIP_SIZES:
            r.take(_SKIP_SIZES[tag])
        else:
            raise ClassParseError(f"unknown constant pool tag {tag} at index {i}")
        i += 1

    def utf8(index: int) -> str | None:
        entry = pool[index] if 0 < index < count else None
        return entry[1] if entry and entry[0] == "utf8" else None

    def class_name(index: int) -> str | None:
        entry = pool[index] if 0 < index < count else None
        return utf8(entry[1]) if entry and entry[0] == "class" else None

    r.u2()  # access flags
    name = class_name(r.u2())
    if not name:
        raise ClassParseError("invalid this_class reference")
    super_name = class_name(r.u2())  # None only for java/lang/Object and modules

    parsed = ParsedClass(entry_name=entry_name, name=name, super_name=super_name, major_version=major)
    for entry in pool:
        if entry is None:
            continue
        kind = entry[0]
        if kind == "class":
            ref = utf8(entry[1])
            if ref and (ref := _strip_array(ref)):
                parsed.class_refs.add(ref)
        elif kind == "string":
            text = utf8(entry[1])
            if text is not None:
                parsed.strings.append(text)
        elif kind == "ref":
            owner = class_name(entry[1])
            nat = pool[entry[2]] if 0 < entry[2] < count else None
            if owner and nat and nat[0] == "nat":
                member = utf8(nat[1])
                if member:
                    parsed.member_refs.add((_strip_array(owner), member))
    return parsed


def java_version_label(major: int) -> str:
    """Class file major version -> Java release (45 = Java 1.1, 52 = Java 8, ...)."""
    return f"Java {major - 44}" if major >= 49 else f"Java 1.{major - 44}"


def top_package(class_name: str) -> str:
    parts = class_name.split("/")
    if len(parts) == 1:
        return "(default package)"
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]


def scan_classes(jar: SafeJar, on_class: Callable[[ParsedClass], None],
                 should_cancel: Callable[[], bool] = lambda: False
                 ) -> tuple[ClassSummary, list[str]]:
    """Parse every .class entry, passing each parsed class to `on_class`.

    Classes are handled one at a time and then discarded, so memory use stays
    small even for mods with tens of thousands of classes.
    Returns (summary, errors).
    """
    summary = ClassSummary()
    errors: list[str] = []
    packages: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    budget_reported = False

    def note_failure(entry: str, reason: str) -> None:
        summary.failed += 1
        if len(summary.failed_entries) < MAX_FAILED_LISTED:
            summary.failed_entries.append(f"{entry} ({reason})")

    for info in jar.files():
        if not info.filename.endswith(".class"):
            continue
        summary.total += 1
        if should_cancel() or jar.budget.exhausted:
            summary.skipped += 1
            continue
        try:
            data = jar.read(info)
        except BudgetExceeded as exc:
            summary.skipped += 1
            if not budget_reported:
                errors.append(str(exc))
                budget_reported = True
            continue
        except EntryReadError as exc:
            note_failure(info.filename, "unreadable")
            if len(errors) < MAX_ERRORS_LISTED:
                errors.append(str(exc))
            continue
        try:
            parsed = parse_class(data, info.filename)
        except ClassParseError as exc:
            note_failure(info.filename, str(exc))
            continue
        summary.parsed += 1
        packages[top_package(parsed.name)] += 1
        versions[java_version_label(parsed.major_version)] += 1
        on_class(parsed)

    summary.packages = dict(packages.most_common())
    summary.java_versions = dict(versions.most_common())
    if summary.skipped and should_cancel():
        errors.append(f"Analysis cancelled; {summary.skipped} classes were not analyzed.")
    return summary, errors
