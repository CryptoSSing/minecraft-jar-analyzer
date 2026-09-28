"""Build minimal, valid Java class files as raw bytes for tests.

The resulting classes have no methods or fields - just a constant pool with
the references and strings a test needs. They are never executed (and could
not do anything if they were).
"""

import struct


class _Pool:
    def __init__(self):
        self.entries: list[bytes] = []
        self.cache: dict[tuple, int] = {}

    def _add(self, key: tuple, raw: bytes) -> int:
        if key not in self.cache:
            self.entries.append(raw)
            self.cache[key] = len(self.entries)  # pool indices start at 1
        return self.cache[key]

    def utf8(self, s: str) -> int:
        b = s.encode("utf-8")
        return self._add(("utf8", s), struct.pack(">BH", 1, len(b)) + b)

    def cls(self, name: str) -> int:
        return self._add(("class", name), struct.pack(">BH", 7, self.utf8(name)))

    def string(self, s: str) -> int:
        return self._add(("string", s), struct.pack(">BH", 8, self.utf8(s)))

    def methodref(self, owner: str, name: str, desc: str = "()V") -> int:
        nat = self._add(("nat", name, desc), struct.pack(">BHH", 12, self.utf8(name), self.utf8(desc)))
        return self._add(("mref", owner, name, desc), struct.pack(">BHH", 10, self.cls(owner), nat))


def build_class(name: str, super_name: str = "java/lang/Object", strings=(),
                class_refs=(), method_refs=(), major: int = 61) -> bytes:
    pool = _Pool()
    this_idx = pool.cls(name)
    super_idx = pool.cls(super_name)
    for s in strings:
        pool.string(s)
    for c in class_refs:
        pool.cls(c)
    for owner, member in method_refs:
        pool.methodref(owner, member)
    body = b"".join(pool.entries)
    return (struct.pack(">IHHH", 0xCAFEBABE, 0, major, len(pool.entries) + 1) + body
            + struct.pack(">HHHHHHH", 0x0021, this_idx, super_idx, 0, 0, 0, 0))
