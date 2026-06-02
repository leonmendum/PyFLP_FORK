# PyFLP - FL Studio project file parser
# See pyproject.toml for license (GPL-3.0).

"""Opcode-classification overrides for FL Studio 25+.

FL 25 introduced events that do not follow the classic opcode-range rules
baked into :mod:`pyflp._events`:

* ``0-63``    → BYTE    (1-byte payload)
* ``64-127``  → WORD    (2-byte payload)
* ``128-191`` → DWORD   (4-byte payload)
* ``192-255`` → DATA    (VarInt size + payload)

Known violations so far are catalogued here. Each entry explicitly pins
both the size rule (how to read bytes off the stream) and the event
class (how to interpret them), taking precedence over the range-based
fallback when the FLP header reports FL major version >= 25.

Discovery methodology and evidence: ``docs/fl25-event-format.md`` in the
flpdiff repo. New overrides are added only when backed by a reproducible
harness sweep — never on speculation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SizeRule = Literal["byte", "word", "dword", "data", "byte3"]
"""Payload-size rule for an opcode.

* ``byte``   — 1-byte payload
* ``word``   — 2-byte payload (little-endian)
* ``dword``  — 4-byte payload (little-endian)
* ``data``   — VarInt size prefix + N-byte payload
* ``byte3``  — fixed 3-byte payload, no size prefix. Captured as
  raw bytes since the semantic content is not yet decoded.
"""


@dataclass(frozen=True)
class OpcodeOverride:
    """Explicit classification for one opcode on FL 25+."""

    size_rule: SizeRule
    #: Event class name (resolved at dispatch time) to decode the
    #: payload. ``None`` means "use the range-based default class"
    #: — useful when only the size rule needs overriding.
    event_class_name: str | None = None


# Opcode -> override. Keep this table tight: empirical evidence only.
FL25_OVERRIDES: dict[int, OpcodeOverride] = {
    # 0xAC (172 decimal) falls in the 0x80-0xBF "DWORD / 4-byte
    # payload" range under the classic rule, but actually carries 3
    # bytes (no size prefix). Treating it as 4 bytes consumes the
    # next event's opcode byte, which in minimal FL 25 saves is
    # always 0xC0 (the version banner). The earlier override was
    # `0x36 -> utf16_zterm` — that interpretation worked because
    # both readings consume the same byte range (the 0x36 byte is
    # actually the varint length of the 0xC0 banner event), but the
    # event identity was wrong. See flpdiff issue #1 for the
    # discovery and ``docs/fl25-event-format.md`` for evidence.
    #
    # Decoded as UnknownDataEvent (raw bytes); the semantic content
    # of 0xAC is not yet known.
    0xAC: OpcodeOverride(size_rule="byte3", event_class_name="UnknownDataEvent"),
    # 0xC0 (192) was ChannelID._Name (deprecated UTF-16 channel name)
    # through FL 24. In FL 25 the first 0xC0 carries the UTF-16
    # version banner (``"FL Studio 25.2.4.4960.4960\0"``); larger
    # 0xC0 payloads on FL 25 saves are an opaque project-properties
    # blob. It's already in the DATA range so the size rule is
    # correct; only the decoder changes from the string-default
    # fallback to opaque so the project-properties blob doesn't
    # raise StringError when UTF-16 decoding is attempted.
    0xC0: OpcodeOverride(size_rule="data", event_class_name="UnknownDataEvent"),
}


__all__ = ["FL25_OVERRIDES", "OpcodeOverride", "SizeRule"]
