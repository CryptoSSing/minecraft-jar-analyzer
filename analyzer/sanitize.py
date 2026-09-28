"""Make untrusted text safe to display and to write into reports.

Everything inside a JAR - file names, mod names, descriptions - is chosen by
whoever made the JAR. Two concrete tricks this module defends against:

1. Bidirectional-override characters. U+202E (RIGHT-TO-LEFT OVERRIDE) makes
   text after it display backwards, so "photo‮gpj.exe" is *shown* as
   "photoexe.jpg". Zero-width characters can make two different names look
   identical (e.g. a fake "sodium" that is really "sod​ium").
2. Control characters such as ANSI escape codes (ESC [ ...) that can rewrite a
   terminal's output when someone views a TXT report with `type` or `cat`.

Unicode sorts every character into a "general category". Categories starting
with "C" are control/format/unassigned characters - the invisible ones we want
to neutralise. We replace them with a visible marker instead of deleting them,
so an analyst can see that something was there.
"""

import unicodedata

REPLACEMENT = "�"  # the "�" replacement character

# Characters that change text direction or are invisible - classic spoofing tools.
DECEPTIVE_CHARS = frozenset(
    "‪‫‬‭‮"  # embeddings / overrides
    "⁦⁧⁨⁩"        # isolates
    "‎‏؜"              # direction marks
    "​‌‍⁠﻿"  # zero-width characters
)


def has_deceptive_chars(text: str) -> bool:
    """True if the text contains direction overrides or invisible characters."""
    return any(ch in DECEPTIVE_CHARS for ch in text)


def safe_text(value: object, max_length: int = 1000, allow_newlines: bool = False) -> str:
    """Return a display-safe version of `value`.

    - Converts non-strings with str().
    - Replaces control/format characters with a visible replacement mark.
    - Optionally keeps newlines (for multi-line descriptions).
    - Truncates very long values so one field cannot flood the UI or report.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if len(text) > max_length:
        text = text[:max_length] + "…[truncated]"

    out = []
    for ch in text:
        if allow_newlines and ch == "\n":
            out.append(ch)
        elif ch == "\t":
            out.append(" ")
        elif unicodedata.category(ch).startswith("C"):
            out.append(REPLACEMENT)
        else:
            out.append(ch)
    return "".join(out)
