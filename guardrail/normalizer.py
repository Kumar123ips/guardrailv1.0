"""
normalizer.py
-------------
Layer 1 of the guardrail: turn ANY input — encoded, obfuscated, mixed-script,
hidden with invisible characters — into a clean canonical form that the
detection layer can reason about.

Pure standard library only. No external dependencies.

The philosophy: attackers hide intent behind encodings and tricks. Instead of
trying to list every trick, we aggressively *peel back* every layer of
obfuscation we can recognise and expose the underlying text. Detection then
runs on BOTH the raw input and every decoded variant we uncover, so a payload
cannot survive simply by wearing a costume.
"""

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse


# --------------------------------------------------------------------------
# Invisible / zero-width / formatting characters that attackers use to break
# up keywords ("ig​nore") or smuggle hidden instructions.
# --------------------------------------------------------------------------
INVISIBLE_CHARS = [
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "‎",  # left-to-right mark
    "‏",  # right-to-left mark
    "‪", "‫", "‬", "‭", "‮",  # bidi overrides
    "⁠",  # word joiner
    "⁡", "⁢", "⁣", "⁤",  # invisible math operators
    "﻿",  # zero width no-break space / BOM
    "­",  # soft hyphen
    "͏",  # combining grapheme joiner
    "ᅟ", "ᅠ",  # hangul fillers
    "ㅤ",  # hangul filler
    "ﾠ",  # halfwidth hangul filler
    "᠎",  # mongolian vowel separator
]

# --------------------------------------------------------------------------
# Homoglyph map: characters from other scripts that LOOK like ASCII letters.
# Cyrillic/Greek/fullwidth are the classic "ignоre" (with Cyrillic о) trick.
# --------------------------------------------------------------------------
HOMOGLYPHS = {
    # Cyrillic -> Latin
    "а": "a", "ӓ": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "г": "r",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y",
    "К": "K", "М": "M", "Т": "T", "Н": "H", "В": "B", "І": "I", "Ј": "J",
    # Greek -> Latin
    "α": "a", "β": "b", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v",
    "ι": "i", "κ": "k", "Α": "A", "Β": "B", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Χ": "X", "γ": "y",
    # Fullwidth -> ASCII (handled broadly by NFKC too, kept for safety)
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｉ": "i", "ｏ": "o", "ｇ": "g",
    "ｎ": "n", "ｒ": "r", "ｅ": "e", "ｓ": "s", "ｔ": "t",
    # Misc lookalikes
    "ʟ": "l", "ɪ": "i", "ɢ": "g", "ɴ": "n", "ʀ": "r", "ѐ": "e",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
}

# --------------------------------------------------------------------------
# Leetspeak / symbol substitution used to dodge keyword matching.
# Applied only to build an *extra* normalized variant (it is lossy, so we keep
# the original around too).
# --------------------------------------------------------------------------
LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "|": "i", "+": "t", "(": "c",
    "9": "g", "8": "b",
}


def decode_tag_chars(text):
    """
    Decode 'Unicode Tag' smuggling (U+E0000–U+E007F). Attackers hide an entire
    instruction in these invisible tag characters, each = (visible ASCII +
    0xE0000). We map them back inline so the hidden message is exposed BEFORE
    the strip step would otherwise silently delete it. Returns the de-tagged
    string, or None if no tag characters are present.
    """
    if not any(0xE0000 <= ord(c) <= 0xE007F for c in text):
        return None
    out = []
    for c in text:
        o = ord(c)
        if 0xE0000 <= o <= 0xE007F:
            out.append(chr(o - 0xE0000))
        else:
            out.append(c)
    return "".join(out)


def strip_invisible(text):
    """Remove zero-width and bidi/formatting characters."""
    for ch in INVISIBLE_CHARS:
        text = text.replace(ch, "")
    # Strip any remaining Unicode "format" (Cf) characters generically.
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text


def map_homoglyphs(text):
    """Replace known lookalike characters with their ASCII counterparts."""
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def unicode_normalize(text):
    """NFKC fold: collapses fullwidth, ligatures, compatibility forms."""
    return unicodedata.normalize("NFKC", text)


def collapse_separators(text):
    """
    Collapse tricks like 'i.g.n.o.r.e', 'i g n o r e', 'i-g-n-o-r-e' where a
    single separator is wedged between every letter. We only collapse when the
    pattern is consistent, to avoid mangling normal text.
    """
    # letter sep letter sep letter ... -> remove the separators
    def _join(m):
        return re.sub(r"[\s\.\-_*~`'\"/\\|+]", "", m.group(0))
    pattern = re.compile(r"(?:[A-Za-z][\s\.\-_*~`'\"/\\|+]){2,}[A-Za-z]")
    return pattern.sub(_join, text)


def deleet(text):
    """Build a leetspeak-folded variant (lossy)."""
    return "".join(LEET.get(ch, ch) for ch in text.lower())


# --------------------------------------------------------------------------
# Decoders. Each tries to find and decode an embedded encoded payload and
# returns the decoded text (or None). They are intentionally permissive.
# --------------------------------------------------------------------------
def try_base64(text):
    out = []
    # candidate runs of base64-looking characters, length >= 16
    for m in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        s = m.strip("=")
        for pad in ("", "=", "==", "==="):
            try:
                raw = base64.b64decode(s + pad, validate=False)
                dec = raw.decode("utf-8", errors="strict")
                if dec and _mostly_printable(dec):
                    out.append(dec)
                    break
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
    return out


def try_hex(text):
    out = []
    for m in re.findall(r"(?:0x)?[0-9A-Fa-f]{12,}", text):
        h = m[2:] if m.lower().startswith("0x") else m
        if len(h) % 2:
            h = h[:-1]
        try:
            dec = bytes.fromhex(h).decode("utf-8", errors="strict")
            if dec and _mostly_printable(dec):
                out.append(dec)
        except (ValueError, UnicodeDecodeError):
            continue
    # space/comma separated hex bytes:  69 67 6e 6f 72 65
    for m in re.findall(r"(?:[0-9A-Fa-f]{2}[\s,]+){4,}[0-9A-Fa-f]{2}", text):
        try:
            parts = re.split(r"[\s,]+", m.strip())
            dec = bytes(int(p, 16) for p in parts).decode("utf-8", "strict")
            if _mostly_printable(dec):
                out.append(dec)
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def try_decimal(text):
    """Decimal char codes:  105 103 110 111 114 101"""
    out = []
    for m in re.findall(r"(?:\d{1,3}[\s,]+){4,}\d{1,3}", text):
        try:
            parts = re.split(r"[\s,]+", m.strip())
            nums = [int(p) for p in parts]
            if all(0 < n < 0x110000 for n in nums):
                dec = "".join(chr(n) for n in nums)
                if _mostly_printable(dec):
                    out.append(dec)
        except ValueError:
            continue
    return out


def try_url(text):
    if "%" in text:
        dec = urllib.parse.unquote(text)
        if dec != text:
            return [dec]
    return []


def try_html_entities(text):
    if "&" in text and ";" in text:
        dec = html.unescape(text)
        if dec != text:
            return [dec]
    return []


def try_unicode_escape(text):
    out = []
    if "\\u" in text or "\\x" in text or "\\U" in text:
        try:
            dec = codecs.decode(text, "unicode_escape")
            if dec != text and _mostly_printable(dec):
                out.append(dec)
        except (UnicodeDecodeError, ValueError):
            pass
    return out


def try_rot13(text):
    dec = codecs.decode(text, "rot_13")
    return [dec] if dec != text else []


def try_reversed(text):
    """Some attacks reverse the string. Cheap to check."""
    rev = text[::-1]
    return [rev]


def try_binary(text):
    """Binary char codes: 01101001 01100111 ..."""
    out = []
    for m in re.findall(r"(?:[01]{7,8}[\s]+){3,}[01]{7,8}", text):
        try:
            parts = m.split()
            dec = "".join(chr(int(p, 2)) for p in parts)
            if _mostly_printable(dec):
                out.append(dec)
        except ValueError:
            continue
    return out


def _mostly_printable(s):
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c.isspace())
    return printable / len(s) >= 0.85


# Decoders used to build detection views (include rot13 & reverse so those
# attacks are caught).
DECODERS = [
    try_base64, try_hex, try_decimal, try_binary, try_url,
    try_html_entities, try_unicode_escape, try_rot13, try_reversed,
]

# "Substantive" decoders only — these fire ONLY when a real encoded payload is
# present. rot13/reverse are excluded because they always transform any text and
# would otherwise mark every benign input as 'encoded'.
SUBSTANTIVE_DECODERS = [
    try_base64, try_hex, try_decimal, try_binary, try_url,
    try_html_entities, try_unicode_escape,
]


def substantive_decodings(text):
    """Decoded payloads from real encodings only (no rot13/reverse noise)."""
    found = set()
    for decoder in SUBSTANTIVE_DECODERS:
        try:
            for dec in decoder(text):
                if dec and dec != text and len(dec) < 100000:
                    found.add(dec)
        except Exception:
            continue
    return found


def substantive_expand(text, depth=3):
    """Recursively decode real encodings (no rot13/reverse), so nested payloads
    like base64(base64(...)) are fully surfaced for the technical-injection
    scanner. Bounded depth keeps it fast."""
    found = set()
    frontier = [text]
    seen = {text}
    while frontier and depth > 0:
        depth -= 1
        nxt = []
        for item in frontier:
            for dec in substantive_decodings(item):
                if dec not in seen:
                    seen.add(dec)
                    found.add(dec)
                    nxt.append(dec)
        frontier = nxt
    return found


def expand_encodings(text, depth=3):
    """
    Recursively decode embedded encodings. Returns a set of decoded strings
    discovered at any layer (so base64-inside-base64, url-encoded-base64, etc.
    are all surfaced). Bounded depth to stay fast and avoid loops.
    """
    found = set()
    frontier = [text]
    seen = {text}
    while frontier and depth > 0:
        depth -= 1
        nxt = []
        for item in frontier:
            for decoder in DECODERS:
                try:
                    for dec in decoder(item):
                        if dec and dec not in seen and len(dec) < 100000:
                            seen.add(dec)
                            found.add(dec)
                            nxt.append(dec)
                except Exception:
                    continue
        frontier = nxt
    return found


def canonical(text):
    """
    Primary canonical form WITH homoglyph mapping — catches Latin text disguised
    with Cyrillic/Greek lookalikes:
    invisible-stripped -> NFKC -> homoglyph-mapped -> separator-collapsed,
    lowercased and whitespace-normalized.
    """
    t = strip_invisible(text)
    t = unicode_normalize(t)
    t = map_homoglyphs(t)
    t = collapse_separators(t)
    t = re.sub(r"\s+", " ", t).strip().lower()
    return t


def canonical_native(text):
    """
    Canonical form WITHOUT homoglyph mapping — preserves genuine non-Latin
    scripts (Russian, Greek, ...) so their native keywords still match. We need
    both: the mapped view catches disguise, the native view catches real text.
    """
    t = strip_invisible(text)
    t = unicode_normalize(t)
    t = collapse_separators(t)
    t = re.sub(r"\s+", " ", t).strip().lower()
    return t


def normalize_keyword(kw):
    """Normalize a knowledge-base keyword the same way views are normalized
    (minus homoglyph mapping, since keywords are written in their true script)."""
    return re.sub(r"\s+", " ", unicode_normalize(kw)).strip().lower()


def all_views(text):
    """
    Return every textual 'view' of the input that detection should run against:
      - canonical (homoglyph-mapped) and canonical-native forms
      - their leetspeak-folded variants
      - their no-space variants (beat spacing tricks)
      - every decoded encoding variant, each canonicalized both ways
    De-duplicated. This is the heart of the de-obfuscation strategy.
    """
    views = set()

    def _add_forms(s):
        c = canonical(s)
        n = canonical_native(s)
        for base in (c, n):
            if base:
                views.add(base)
                views.add(deleet(base))
                views.add(re.sub(r"\s+", "", base))

    _add_forms(text)

    # decode Unicode-tag-smuggled instructions before encodings
    tagged = decode_tag_chars(text)
    if tagged:
        _add_forms(tagged)

    for dec in expand_encodings(text):
        _add_forms(dec)
    if tagged:
        for dec in expand_encodings(tagged):
            _add_forms(dec)

    return {v for v in views if v}
