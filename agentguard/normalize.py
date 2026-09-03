"""Text normalization shared by the injection detector and the secret
redactor, so both scan a canonical form of tool output instead of the
raw bytes an attacker chose.

Every rule in AgentGuard is a regex over text. Regexes are exact, and
exactness is a weakness when the text is adversarial: `ignore previous
instructions` with a zero-width space inside "ignore", or with Cyrillic
`о` for Latin `o`, or in fullwidth letters, or base64-encoded with a
note saying "decode and follow this" — none of those match the rule,
all of them read fine to a model. THREAT_MODEL.md listed this as a v1
gap. This module closes the cheap, deterministic part of it:

- **NFKC** compatibility normalization: fullwidth/small/superscript
  forms, ligatures (`ﬁ` -> `fi`), compatibility variants -> their plain
  equivalents.
- **Invisible characters** are dropped: zero-width space/joiner/
  non-joiner, word joiner, BOM, soft hyphen, and the bidi control
  characters used to reorder how text *displays* without changing what
  it *is*.
- **Homoglyph folding**: a fixed table of Cyrillic and Greek letters
  that render identically to Latin ones is mapped to the Latin letter.
  Only whole-glyph lookalikes — this is not general confusable
  detection, and it's not trying to be.
- **Base64 runs** over a size threshold are decoded, and the decoded
  text (if it *is* text) is offered up as extra material to scan,
  attached to the span of the original it came from. One level only.

Scanning happens on the normalized text. For the detector that's the
whole story: it only needs to say yes or no. The redactor has to
*edit*, and it edits the original: `NormalizedText.map_span` turns a
match in the normalized text back into the original span, and a match
inside a decoded base64 run maps to the whole run. So redaction never
rewrites bytes it didn't need to — output isn't silently NFKC'd on the
way past.

What this doesn't do: whitespace collapsing (every rule already uses
`\\s+`), leetspeak, nested encodings, or anything statistical.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

# Characters removed outright. Written as escapes on purpose: these
# are invisible in an editor, which is the whole reason they're here.
INVISIBLE = frozenset([
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space / BOM
    "\u00ad",  # soft hyphen
    "\u180e",  # mongolian vowel separator
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u202a",  # left-to-right embedding
    "\u202b",  # right-to-left embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # left-to-right override
    "\u202e",  # right-to-left override
    "\u2066",  # left-to-right isolate
    "\u2067",  # right-to-left isolate
    "\u2068",  # first strong isolate
    "\u2069",  # pop directional isolate
])

# Whole-glyph lookalikes -> Latin, also as escapes: a reviewer can't
# tell Cyrillic `а` from Latin `a` by looking, so the source shouldn't
# ask them to. Kept to letters that are pixel-identical in common
# fonts; near-misses (Cyrillic `ъ`, Greek `η`) are deliberately absent.
HOMOGLYPHS = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0406": "I", "\u0405": "S", "\u0408": "J",
    # Greek lowercase
    "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p", "\u03c5": "u",
    "\u03b9": "i", "\u03ba": "k",
    # Greek uppercase
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Latin-script lookalikes from other blocks
    "\u0261": "g",  # latin small letter script g
    "\u0578": "n",  # armenian small letter vo
}

# A base64 run: standard or URL-safe alphabet, at least this many
# characters (the threshold keeps ordinary words and short identifiers
# out), optional padding. 40 chars decodes to 30 bytes — enough to hold
# a short instruction or a key prefix, short enough that a base64-
# wrapped `ignore previous instructions` (36 chars -> 48 encoded) is
# caught.
BASE64_MIN_CHARS = 40
BASE64_MAX_RUNS = 64
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/\-_]{%d,}={0,2}" % BASE64_MIN_CHARS)
_MIN_PRINTABLE_RATIO = 0.9


@dataclass
class DecodedRun:
    """Text recovered from an encoded span of the original."""
    start: int
    end: int
    encoding: str
    text: str


@dataclass
class NormalizedText:
    original: str
    text: str
    # offsets[i] is the index into `original` of the character that
    # produced normalized character i. None means the normalization was
    # the identity and offsets are 1:1 (the common all-ASCII case).
    offsets: Optional[List[int]] = None
    decoded: List[DecodedRun] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.offsets is not None

    def map_span(self, start: int, end: int) -> Tuple[int, int]:
        """Maps a [start, end) span in the normalized text back to the
        original. A normalized char that came from a multi-char source
        (or the reverse) maps to the whole source character; invisible
        characters that were dropped between two mapped characters end
        up inside the span, which is what you want when redacting."""
        if self.offsets is None:
            return start, end
        if start >= end or not self.offsets:
            return 0, 0
        orig_start = self.offsets[start]
        orig_end = self.offsets[end - 1] + 1
        # A character like a ligature expands to several normalized chars
        # that all map to the same original index; the span end must
        # still cover that whole original char, which +1 does.
        return orig_start, orig_end

    def scan_targets(self) -> Iterator[Tuple[str, Optional[DecodedRun]]]:
        """Everything a scanner should look at: the normalized text, then
        each decoded run (paired with where it came from)."""
        yield self.text, None
        for run in self.decoded:
            yield run.text, run


def _fold_char(ch: str) -> str:
    if ch in INVISIBLE:
        return ""
    ch = HOMOGLYPHS.get(ch, ch)
    if ord(ch) < 128:
        return ch
    out = unicodedata.normalize("NFKC", ch)
    # NFKC can produce a homoglyph (rare) or an invisible (e.g. some
    # compatibility spaces); fold once more, but never recurse further.
    return "".join(HOMOGLYPHS.get(c, c) for c in out if c not in INVISIBLE)


def _normalize_chars(text: str) -> Tuple[str, Optional[List[int]]]:
    if text.isascii():
        return text, None
    out: List[str] = []
    offsets: List[int] = []
    for i, ch in enumerate(text):
        folded = _fold_char(ch)
        for c in folded:
            out.append(c)
            offsets.append(i)
    return "".join(out), offsets


def _try_decode_base64(run: str) -> Optional[str]:
    candidate = run.rstrip("=")
    if len(candidate) % 4 == 1:
        return None  # not a valid base64 length under any padding
    candidate = candidate.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
        return None
    printable = sum(1 for c in decoded if c.isprintable() or c in "\t\n\r")
    if printable / len(decoded) < _MIN_PRINTABLE_RATIO:
        return None
    return decoded


def decode_base64_runs(text: str) -> List[DecodedRun]:
    """Finds base64-looking runs in `text` and returns the ones that
    decode to plausible text. Bounded by BASE64_MAX_RUNS so a pathological
    output can't turn this into a CPU sink."""
    runs: List[DecodedRun] = []
    for match in _BASE64_RUN.finditer(text):
        if len(runs) >= BASE64_MAX_RUNS:
            break
        decoded = _try_decode_base64(match.group(0))
        if decoded is None:
            continue
        # The decoded payload gets the same character-level treatment as
        # the outer text (but no further base64 decoding).
        normalized, _ = _normalize_chars(decoded)
        runs.append(DecodedRun(match.start(), match.end(), "base64", normalized))
    return runs


def normalize(text: str) -> NormalizedText:
    """Full normalization: character folding plus base64 recovery. The
    base64 runs are located in the *original* text so their spans are
    already original offsets."""
    if not text:
        return NormalizedText(text, text)
    normalized, offsets = _normalize_chars(text)
    return NormalizedText(text, normalized, offsets, decode_base64_runs(text))
