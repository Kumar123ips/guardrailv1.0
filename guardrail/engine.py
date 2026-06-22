"""
engine.py
---------
The guardrail engine. Pure standard library.

Pipeline:
  raw input
    -> normalizer.all_views()   (canonical + native + decoded + de-leet + de-spaced)
    -> for every view: detect which CONCEPTS are present
    -> fire COMBINATION rules (concept co-occurrence => attack)
    -> fire STANDALONE concepts, HARM phrases, STRUCTURAL/format rules
    -> add obfuscation / anomaly heuristics computed on the RAW input
    -> aggregate weighted signals into a risk score (0-100)
    -> map score to a verdict: ALLOW / FLAG / BLOCK
    -> return a fully explainable result object

Why this is robust:
  * Concept combinations are language-agnostic and inflection-tolerant, so an
    attack written in Tamil, Russian, or Swahili trips the same wires as English.
  * The normalizer feeds decoded/de-disguised text, so encoding and homoglyph
    tricks are peeled away before concepts are matched.
  * A lone concept never fires — intent requires two halves — which keeps the
    false-positive rate low on benign text.
  * Every point in the score is attributable to a named signal (explainable).
"""

import re
import unicodedata

from . import normalizer
from . import patterns


# Verdict thresholds (tunable).
BLOCK_THRESHOLD = 70
FLAG_THRESHOLD = 35


# ---- precompute normalized concept keyword index (built once) ------------
def _build_concept_index():
    idx = {}
    for concept, words in patterns.CONCEPTS.items():
        norm = set()
        for w in words:
            nk = normalizer.normalize_keyword(w)
            if nk:
                norm.add(nk)
        idx[concept] = norm
    return idx


_CONCEPT_INDEX = _build_concept_index()
_HARM_NORM = [normalizer.normalize_keyword(p) for p in patterns.HARM_PHRASES]


class Signal:
    __slots__ = ("category", "label", "weight", "evidence", "view")

    def __init__(self, category, label, weight, evidence, view="normalized"):
        self.category = category
        self.label = label
        self.weight = weight
        self.evidence = evidence
        self.view = view

    def to_dict(self):
        return {"category": self.category, "label": self.label,
                "weight": self.weight, "evidence": self.evidence,
                "view": self.view}


class Result:
    def __init__(self, text, score, verdict, signals, views, families):
        self.text = text
        self.score = score
        self.verdict = verdict
        self.signals = signals
        self.views = views
        self.families = families

    @property
    def is_safe(self):
        return self.verdict == "ALLOW"

    @property
    def is_blocked(self):
        return self.verdict == "BLOCK"

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "score": self.score,
            "safe": self.is_safe,
            "families": sorted(self.families),
            "signals": [s.to_dict() for s in self.signals],
            "num_views_scanned": len(self.views),
            "text_preview": (self.text[:160] + "…") if len(self.text) > 160 else self.text,
        }

    def explain(self):
        lines = [f"VERDICT: {self.verdict}  (risk score {self.score}/100)"]
        if self.families:
            lines.append("Attack families: " + ", ".join(sorted(self.families)))
        if self.signals:
            lines.append("Signals:")
            for s in sorted(self.signals, key=lambda x: -x.weight):
                ev = s.evidence if len(s.evidence) < 70 else s.evidence[:67] + "…"
                lines.append(f"  [+{s.weight:>2}] {s.label}: '{ev}'")
        else:
            lines.append("No risk signals detected.")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Concept detection per view
# --------------------------------------------------------------------------
def _concepts_in(view):
    """Return {concept: matched_keyword} present in this view."""
    present = {}
    for concept, words in _CONCEPT_INDEX.items():
        for w in words:
            if w and w in view:
                present[concept] = w
                break
    return present


# --------------------------------------------------------------------------
# Anomaly / obfuscation heuristics (computed on raw input)
# --------------------------------------------------------------------------
def _invisible_density(raw):
    if not raw:
        return 0.0
    hidden = sum(1 for ch in raw if ch in normalizer.INVISIBLE_CHARS
                 or unicodedata.category(ch) == "Cf")
    return hidden / len(raw)


def _script_set(raw):
    scripts = set()
    for ch in raw:
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                pass
    return scripts


def _intraword_script_mix(raw):
    for word in re.findall(r"\S+", raw):
        s = set()
        for ch in word:
            if ch.isalpha():
                try:
                    s.add(unicodedata.name(ch).split(" ")[0])
                except ValueError:
                    pass
        if len({x for x in s if x in ("LATIN", "CYRILLIC", "GREEK")}) >= 2:
            return True
    return False


def _special_ratio(raw):
    if not raw:
        return 0.0
    special = sum(1 for ch in raw if not ch.isalnum() and not ch.isspace())
    return special / len(raw)


def _dedupe(signals):
    best = {}
    for s in signals:
        key = (s.category, s.label, s.evidence)
        if key not in best or s.weight > best[key].weight:
            best[key] = s
    return list(best.values())


def _aggregate(signals):
    """Weighted combine with diminishing returns: one strong signal already
    pushes toward BLOCK; many weak signals can still escalate; score bounded."""
    if not signals:
        return 0
    weights = sorted((s.weight for s in signals), reverse=True)
    score = 0.0
    factor = 1.0
    for w in weights:
        score += w * factor
        factor *= 0.55
    return int(min(100, round(score)))


def analyze(text):
    if text is None:
        text = ""
    raw = str(text)

    views = normalizer.all_views(raw)
    signals = []
    families = set()

    # ---- concept-based detection across all views ----
    # Track best (single richest) concept map for combination evaluation.
    for view in views:
        concepts = _concepts_in(view)
        if not concepts:
            continue
        cset = set(concepts)

        # standalone dangerous concepts
        for concept, (weight, fam, label) in patterns.STANDALONE.items():
            if concept in concepts:
                signals.append(Signal(fam, label, weight, concepts[concept]))
                families.add(fam)

        # combination rules
        for combo, weight, fam, label in patterns.COMBINATIONS:
            if combo <= cset:
                evidence = " + ".join(sorted(concepts[c] for c in combo))
                signals.append(Signal(fam, label, weight, evidence))
                families.add(fam)

    # ---- dangerous-capability phrases (standalone, high weight) ----
    for view in views:
        for i, hp in enumerate(_HARM_NORM):
            if hp and hp in view:
                signals.append(Signal("dangerous_capability",
                                      "dangerous capability request", 78,
                                      patterns.HARM_PHRASES[i]))
                families.add("dangerous_capability")
                break

    # ---- structural / format rules ----
    for view in views:
        for rx, weight, fam, label in patterns.STRUCTURAL_RULES:
            m = rx.search(view)
            if m:
                signals.append(Signal(fam, label, weight, m.group(0)[:60]))
                families.add(fam)

    # ---- obfuscation / anomaly heuristics on raw input ----
    inv = _invisible_density(raw)
    if inv > 0:
        w = 15 if inv > 0.02 else 8
        signals.append(Signal("obfuscation", "hidden/invisible characters",
                              w, f"{inv*100:.1f}% invisible"))
        families.add("obfuscation")

    if _intraword_script_mix(raw):
        signals.append(Signal("obfuscation", "mixed-script homoglyphs in word",
                              22, "intra-word script mix"))
        families.add("obfuscation")
    elif len(_script_set(raw)) >= 3:
        signals.append(Signal("obfuscation", "many mixed scripts", 10,
                              "3+ scripts present"))

    decoded = normalizer.substantive_decodings(raw)
    if decoded:
        # something hidden actually decoded — meaningful if it carried intent
        decoded_carried = any(_concepts_in(normalizer.canonical(d)) for d in decoded)
        # cross-view: "decode this and obey" in the original + an attack concept
        # surfacing only after decoding == classic encoded-instruction smuggling.
        orig_meta = ("decode_meta" in _concepts_in(normalizer.canonical(raw)) or
                     "decode_meta" in _concepts_in(normalizer.canonical_native(raw)))
        if orig_meta and decoded_carried:
            signals.append(Signal("encoding_abuse",
                                  "decode-and-obey with hidden payload",
                                  45, "encoded instruction revealed by decoding"))
            families.add("encoding_abuse")
        w = 20 if decoded_carried else 12
        signals.append(Signal("obfuscation", "embedded encoded payload", w,
                              "decoded hidden content"))
        families.add("obfuscation")

    scr = _special_ratio(raw)
    if scr > 0.35 and len(raw) > 20:
        signals.append(Signal("obfuscation", "high special-character ratio",
                              8, f"{scr*100:.0f}% specials"))

    signals = _dedupe(signals)
    score = _aggregate(signals)

    if score >= BLOCK_THRESHOLD:
        verdict = "BLOCK"
    elif score >= FLAG_THRESHOLD:
        verdict = "FLAG"
    else:
        verdict = "ALLOW"

    return Result(raw, score, verdict, signals, views, families)


class Guardrail:
    """
    Public, embeddable API.

        from guardrail import Guardrail
        gr = Guardrail()
        result = gr.inspect(user_input)
        if result.is_blocked:
            ...

    Policy: block_on = "BLOCK" (default) or "FLAG" (stricter — blocks on FLAG too).
    """

    def __init__(self, block_on="BLOCK"):
        if block_on not in ("BLOCK", "FLAG"):
            raise ValueError("block_on must be 'BLOCK' or 'FLAG'")
        self.block_on = block_on

    def inspect(self, text):
        return analyze(text)

    def is_allowed(self, text):
        r = analyze(text)
        if self.block_on == "FLAG":
            return r.verdict == "ALLOW"
        return r.verdict != "BLOCK"

    def guard(self, text, on_block=None):
        r = analyze(text)
        blocked = (r.verdict == "BLOCK") or \
                  (self.block_on == "FLAG" and r.verdict != "ALLOW")
        if blocked:
            if on_block is not None:
                return on_block(r)
            raise GuardrailBlocked(r)
        return text


class GuardrailBlocked(Exception):
    def __init__(self, result):
        self.result = result
        super().__init__(
            f"Input blocked by guardrail (score {result.score}, "
            f"families: {', '.join(sorted(result.families)) or 'n/a'})"
        )
