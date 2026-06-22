"""
openwebui_guardrail.py
----------------------
Drop-in OpenWebUI **Filter function** that puts Guardrail v1.0 in front of the
chat input box. OpenWebUI calls `Filter.inlet(body)` on every request *before*
it reaches the model, so this is exactly where prompt-injection / unsafe input
must be stopped.

Install in OpenWebUI:
  1. Copy the `guardrail/` package somewhere importable (e.g. next to this file,
     or onto PYTHONPATH).
  2. Admin Panel -> Functions -> "+" -> paste this file -> Save -> enable it
     (globally, or per-model).
  3. Done. Malicious input now gets blocked at the input box with an explanation.

Behaviour:
  * Scans the latest user message (and optionally the whole user history).
  * Handles plain-string content AND OpenWebUI multimodal content (list of
    parts) — every text part is inspected.
  * On BLOCK (or FLAG, if `block_on_flag` is enabled) it raises an Exception,
    which OpenWebUI surfaces to the user as an error and stops the request.
  * Pure standard library; no extra pip installs beyond what OpenWebUI ships.
"""

import os
import sys

# Make the bundled guardrail package importable no matter where OpenWebUI loads
# this file from.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.dirname(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from guardrail import analyze  # noqa: E402

try:
    from pydantic import BaseModel, Field
    _HAS_PYDANTIC = True
except Exception:  # pragma: no cover - lets the file be tested without pydantic
    _HAS_PYDANTIC = False

    class BaseModel:  # minimal shim
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    def Field(default=None, **kw):  # noqa: N802
        return default


class GuardrailBlock(Exception):
    """Raised to stop a request; OpenWebUI shows the message to the user."""


def _iter_text_parts(content):
    """Yield every text string from an OpenWebUI message `content`, which may be
    a plain string or a list of multimodal parts."""
    if content is None:
        return
    if isinstance(content, str):
        yield content
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, str):
                yield part
            elif isinstance(part, dict):
                # {"type": "text", "text": "..."} parts
                if isinstance(part.get("text"), str):
                    yield part["text"]
                elif isinstance(part.get("content"), str):
                    yield part["content"]


class Filter:
    class Valves(BaseModel):
        enabled: bool = Field(
            default=True, description="Enable the guardrail.")
        block_on_flag: bool = Field(
            default=False,
            description="Also block FLAG verdicts (stricter / fail-closed).")
        scan_all_user_turns: bool = Field(
            default=True,
            description="Scan every user turn, not just the latest message.")
        scan_window: int = Field(
            default=0,
            description=("If > 0, ALSO scan the concatenation of the last N "
                         "user turns. Catches payloads split across multiple "
                         "messages, at the cost of some false positives when "
                         "unrelated turns happen to combine. 0 disables it."))
        refusal_message: str = Field(
            default=("⛔ Your message was blocked by the security guardrail "
                     "(possible prompt-injection or unsafe input)."),
            description="Message shown to the user when blocked.")

    def __init__(self):
        self.valves = self.Valves()
        # toggle shown next to the function in the OpenWebUI UI
        self.toggle = True
        self.icon = "🛡️"

    # ------------------------------------------------------------------ #
    def _check_text(self, text):
        """Return a Result if the text should be blocked, else None."""
        if not text or not text.strip():
            return None
        r = analyze(text)
        block = r.verdict == "BLOCK" or (
            self.valves.block_on_flag and r.verdict != "ALLOW")
        return r if block else None

    def _messages_to_scan(self, body):
        msgs = body.get("messages", []) if isinstance(body, dict) else []
        user_msgs = [m for m in msgs if isinstance(m, dict)
                     and m.get("role") == "user"]
        if not user_msgs:
            return []
        if self.valves.scan_all_user_turns:
            return user_msgs
        return user_msgs[-1:]

    # OpenWebUI entry point: runs before the model sees the message.
    def inlet(self, body: dict, __user__=None, **kwargs) -> dict:
        if not self.valves.enabled:
            return body
        for msg in self._messages_to_scan(body):
            for text in _iter_text_parts(msg.get("content")):
                result = self._check_text(text)
                if result is not None:
                    raise GuardrailBlock(self._refusal(result))

        # Optional defence against payloads split across multiple turns.
        if self.valves.scan_window and self.valves.scan_window > 0:
            user_texts = []
            for msg in self._messages_to_scan(body):
                user_texts.extend(_iter_text_parts(msg.get("content")))
            window = "\n".join(user_texts[-self.valves.scan_window:])
            result = self._check_text(window)
            if result is not None:
                raise GuardrailBlock(self._refusal(result))
        return body

    def _refusal(self, result):
        return (f"{self.valves.refusal_message}\n"
                f"[verdict={result.verdict} score={result.score} "
                f"reasons={', '.join(sorted(result.families)) or 'n/a'}]")

    # OpenWebUI also calls outlet() on the model's response; we pass it through
    # (you could additionally scan tool output / model output here if desired).
    def outlet(self, body: dict, __user__=None, **kwargs) -> dict:
        return body
