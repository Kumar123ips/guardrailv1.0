"""
report.py
---------
A minimal, dependency-free PDF writer used to export guardrail test reports.

It writes a valid PDF 1.4 file by hand: catalog, pages, page objects, a single
Helvetica font, and text content streams with simple word-wrapping and
automatic pagination. Standard library only (zlib for stream compression is
optional and used when available — it's in the stdlib anyway).

Non-ASCII note: the 14 standard PDF fonts use WinAnsi/Latin-1 encoding, so
glyphs outside Latin-1 (Devanagari, CJK, Arabic, etc.) cannot be drawn without
embedding a Unicode font. To keep this 100% dependency-free AND still produce a
readable report, non-Latin-1 characters are transliterated to a safe ASCII
placeholder of the form <U+XXXX> in the PDF body. The full original text is
always preserved in the companion JSON/TXT exports.
"""

import time
import zlib


PAGE_W, PAGE_H = 595, 842          # A4 in points
MARGIN = 50
LINE_H = 14
FONT_SIZE = 10
TITLE_SIZE = 20
HEAD_SIZE = 13
MAX_CHARS = int((PAGE_W - 2 * MARGIN) / (FONT_SIZE * 0.5))  # rough wrap width


def _pdf_escape(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _to_latin1(s):
    """Make a string safe for the standard PDF font encoding."""
    out = []
    for ch in s:
        o = ord(ch)
        if o == 9:
            out.append("    ")
        elif 32 <= o <= 126 or 160 <= o <= 255:
            out.append(ch)
        elif ch in "‘’":
            out.append("'")
        elif ch in "“”":
            out.append('"')
        elif ch in "–—":
            out.append("-")
        elif ch == "…":
            out.append("...")
        else:
            out.append("<U+%04X>" % o)
    return "".join(out)


def _wrap(text, width=MAX_CHARS):
    lines = []
    for raw_line in text.split("\n"):
        if raw_line == "":
            lines.append("")
            continue
        words = raw_line.split(" ")
        cur = ""
        for w in words:
            if len(w) > width:
                if cur:
                    lines.append(cur)
                    cur = ""
                for i in range(0, len(w), width):
                    lines.append(w[i:i + width])
                continue
            if not cur:
                cur = w
            elif len(cur) + 1 + len(w) <= width:
                cur += " " + w
            else:
                lines.append(cur)
                cur = w
        lines.append(cur)
    return lines


class _Line:
    __slots__ = ("text", "size", "color", "indent")

    def __init__(self, text, size=FONT_SIZE, color=(0, 0, 0), indent=0):
        self.text = text
        self.size = size
        self.color = color
        self.indent = indent


class PDFReport:
    """Accumulate styled lines, then save() to a real PDF file."""

    def __init__(self):
        self._lines = []

    # ---- content API ----
    def title(self, text):
        self._lines.append(_Line(text, TITLE_SIZE))
        self._lines.append(_Line(""))

    def heading(self, text):
        self._lines.append(_Line(""))
        self._lines.append(_Line(text, HEAD_SIZE, (0.1, 0.1, 0.5)))

    def text(self, text, color=(0, 0, 0), indent=0):
        for ln in _wrap(_to_latin1(text), MAX_CHARS - indent * 4):
            self._lines.append(_Line(ln, FONT_SIZE, color, indent))

    def rule(self):
        self._lines.append(_Line("-" * MAX_CHARS, FONT_SIZE, (0.6, 0.6, 0.6)))

    def blank(self):
        self._lines.append(_Line(""))

    # ---- rendering ----
    def _paginate(self):
        pages = []
        cur = []
        y = PAGE_H - MARGIN
        for line in self._lines:
            lh = line.size + 4
            if y - lh < MARGIN:
                pages.append(cur)
                cur = []
                y = PAGE_H - MARGIN
            cur.append((line, y))
            y -= lh
        if cur:
            pages.append(cur)
        return pages

    def _content_stream(self, page_lines):
        parts = []
        for line, y in page_lines:
            r, g, b = line.color
            x = MARGIN + line.indent * 16
            txt = _pdf_escape(_to_latin1(line.text))
            parts.append(
                f"BT /F1 {line.size} Tf {r:.2f} {g:.2f} {b:.2f} rg "
                f"{x} {y} Td ({txt}) Tj ET"
            )
        return "\n".join(parts).encode("latin-1", "replace")

    def save(self, path):
        pages = self._paginate()
        objects = []  # list of raw bytes per object (1-indexed via append order)

        def add(obj_bytes):
            objects.append(obj_bytes)
            return len(objects)  # object number

        # Reserve: 1=catalog, 2=pages tree, 3=font
        # We'll build content + page objects then fix references.
        font_obj = (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>"
        )

        # Build page + content objects
        page_obj_nums = []
        content_specs = []
        for pl in pages:
            content_specs.append(self._content_stream(pl))

        # Layout object numbers:
        # 1 catalog, 2 pages, 3 font, then for each page: content, page
        catalog_num = 1
        pages_num = 2
        font_num = 3
        objects = [None, None, None]  # placeholders for 1..3

        kids = []
        next_num = 4
        for content in content_specs:
            stream = content
            try:
                comp = zlib.compress(stream)
                stream_obj = (
                    b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp)
                    + comp + b"\nendstream"
                )
            except Exception:
                stream_obj = (
                    b"<< /Length %d >>\nstream\n" % len(stream)
                    + stream + b"\nendstream"
                )
            content_num = next_num
            objects.append(stream_obj)
            next_num += 1

            page_num = next_num
            page_obj = (
                b"<< /Type /Page /Parent %d 0 R "
                b"/MediaBox [0 0 %d %d] "
                b"/Resources << /Font << /F1 %d 0 R >> >> "
                b"/Contents %d 0 R >>"
                % (pages_num, PAGE_W, PAGE_H, font_num, content_num)
            )
            objects.append(page_obj)
            next_num += 1

            page_obj_nums.append(page_num)
            kids.append(b"%d 0 R" % page_num)

        # Fill reserved objects
        objects[catalog_num - 1] = (
            b"<< /Type /Catalog /Pages %d 0 R >>" % pages_num
        )
        objects[pages_num - 1] = (
            b"<< /Type /Pages /Kids [%s] /Count %d >>"
            % (b" ".join(kids), len(kids))
        )
        objects[font_num - 1] = font_obj

        # Serialize
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0] * (len(objects) + 1)
        for i, obj in enumerate(objects, start=1):
            offsets[i] = len(out)
            out += b"%d 0 obj\n" % i
            out += obj
            out += b"\nendobj\n"

        xref_pos = len(out)
        n = len(objects) + 1
        out += b"xref\n0 %d\n" % n
        out += b"0000000000 65535 f \n"
        for i in range(1, n):
            out += b"%010d 00000 n \n" % offsets[i]
        out += b"trailer\n<< /Size %d /Root %d 0 R >>\n" % (n, catalog_num)
        out += b"startxref\n%d\n%%%%EOF" % xref_pos

        with open(path, "wb") as f:
            f.write(out)
        return path


def build_report(path, summary, results, title="Guardrail v1.0 — Test Report"):
    """
    summary: dict with aggregate stats
    results: list of dicts {name, category, expected, verdict, score, passed,
                            families, text}
    """
    pdf = PDFReport()
    pdf.title(title)
    pdf.text("Generated: " + time.strftime("%Y-%m-%d %H:%M:%S"))
    pdf.text("Author: Abhishek-kumar")
    pdf.blank()

    pdf.heading("1. Summary")
    pdf.text(f"Total test cases : {summary['total']}")
    pdf.text(f"Passed           : {summary['passed']}")
    pdf.text(f"Failed           : {summary['failed']}")
    pdf.text(f"Detection rate   : {summary['detection_rate']:.2f}%")
    pdf.text(f"Categories tested: {summary['categories']}")
    pdf.text(f"Languages probed : {summary['languages']}")
    pdf.blank()

    pdf.heading("2. Results by difficulty")
    for diff, stat in summary.get("by_difficulty", {}).items():
        pdf.text(f"{diff:<14}: {stat['passed']}/{stat['total']} passed")
    pdf.blank()

    pdf.heading("3. Detailed results")
    for i, r in enumerate(results, 1):
        ok = "PASS" if r["passed"] else "FAIL"
        color = (0.0, 0.45, 0.0) if r["passed"] else (0.8, 0.0, 0.0)
        pdf.text(f"[{i:03d}] {ok}  ({r['difficulty']}/{r['category']})", color)
        pdf.text(f"      input   : {r['text']}", indent=1)
        pdf.text(f"      expected: {r['expected']}   got: {r['verdict']} "
                 f"(score {r['score']})", indent=1)
        if r.get("families"):
            pdf.text(f"      families: {', '.join(r['families'])}", indent=1)
        pdf.blank()

    pdf.save(path)
    return path
