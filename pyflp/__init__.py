# PyFLP - An FL Studio project file (.flp) parser
# Copyright (C) 2022 demberto
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details. You should have received a copy of the
# GNU General Public License along with this program. If not, see
# <https://www.gnu.org/licenses/>.

"""
PyFLP - FL Studio project file parser
=====================================

Load a project file:

    >>> import pyflp
    >>> project = pyflp.parse("/path/to/parse.flp")

Save the project:

    >>> pyflp.save(project, "/path/to/save.flp")

Full docs are available at https://pyflp.rtfd.io.
"""  # noqa

from __future__ import annotations

import io
import os
import pathlib
import struct
import sys

import construct as c

from pyflp._events import (
    DATA,
    DWORD,
    NEW_TEXT_IDS,
    TEXT,
    WORD,
    AnyEvent,
    AsciiEvent,
    EventEnum,
    EventTree,
    IndexedEvent,
    U8Event,
    U16Event,
    U32Event,
    UnicodeEvent,
    UnknownDataEvent,
)
from pyflp._fl25_overrides import FL25_OVERRIDES
from pyflp.exceptions import HeaderCorrupted, VersionNotDetected
from pyflp.plugin import PluginID, get_event_by_internal_name
from pyflp.project import VALID_PPQS, FileFormat, Project, ProjectID

# Name -> class mapping used when an FL25 override pins a specific
# event class. Kept here rather than in _fl25_overrides.py to avoid
# a circular import (events module wants to import override table
# eventually).
_FL25_EVENT_CLASSES: dict[str, type[AnyEvent]] = {
    "U8Event": U8Event,
    "U16Event": U16Event,
    "U32Event": U32Event,
    "AsciiEvent": AsciiEvent,
    "UnicodeEvent": UnicodeEvent,
    "UnknownDataEvent": UnknownDataEvent,
}

__all__ = ["parse", "save"]

FLP_HEADER = struct.Struct("4sIh2H")

if sys.version_info < (3, 11):  # https://github.com/Bobronium/fastenum/issues/2
    import fastenum

    fastenum.enable()  # 33% faster parse()


def parse(file: pathlib.Path | str) -> Project:
    with open(file, "rb") as flp:
        return parse(flp.read())


def parse(file_data: bytes) -> Project:
    """Parses an FL Studio project file and returns a parsed :class:`Project`.

    Args:
        file: Path to the FLP.

    Raises:
        HeaderCorrupted: When an invalid value is found in the file header.
        VersionNotDetected: A correct string type couldn't be determined.
    """
    stream = io.BytesIO(file_data)

    events: list[AnyEvent] = []
    header = stream.read(FLP_HEADER.size)

    try:
        hdr_magic, hdr_size, fmt, channel_count, ppq = FLP_HEADER.unpack(header)
    except struct.error as exc:
        raise HeaderCorrupted("Couldn't read the header entirely") from exc

    if hdr_magic != b"FLhd":
        raise HeaderCorrupted("Unexpected header chunk magic; expected 'FLhd'")

    if hdr_size != 6:
        raise HeaderCorrupted("Unexpected header chunk size; expected 6")

    try:
        file_format = FileFormat(fmt)
    except ValueError as exc:
        raise HeaderCorrupted("Unsupported project file format") from exc

    if ppq not in VALID_PPQS:
        raise HeaderCorrupted("Invalid PPQ")

    if stream.read(4) != b"FLdt":
        raise HeaderCorrupted("Unexpected data chunk magic; expected 'FLdt'")

    events_size = int.from_bytes(stream.read(4), "little")
    if not events_size:  # pragma: no cover
        raise HeaderCorrupted("Data chunk size couldn't be read")

    stream.seek(0, os.SEEK_END)
    file_size = stream.tell()
    if file_size != events_size + 22:
        raise HeaderCorrupted("Data chunk size corrupted")

    plug_name = None
    str_type: type[AsciiEvent] | type[UnicodeEvent] | None = None
    fl_major = 0  # filled in when the FLVersion event is seen (usually first).
    stream.seek(22)  # Back to start of events
    while stream.tell() < file_size:
        event_type: type[AnyEvent] | None = None
        id = EventEnum(int.from_bytes(stream.read(1), "little"))

        # FL 25+ size override: a handful of opcodes don't follow the
        # classic BYTE/WORD/DWORD/DATA range rules (see
        # pyflp/_fl25_overrides.py). When the header already told us
        # this is FL 25+ AND the opcode has an override, use the
        # override's size rule to read the payload; otherwise fall
        # back to the range-based rule.
        override = FL25_OVERRIDES.get(id.value) if fl_major >= 25 else None
        if override is not None:
            if override.size_rule == "byte":
                value = stream.read(1)
            elif override.size_rule == "word":
                value = stream.read(2)
            elif override.size_rule == "dword":
                value = stream.read(4)
            elif override.size_rule == "byte3":
                # Fixed 3-byte payload, no size prefix.
                value = stream.read(3)
            else:  # "data"
                size = c.VarInt.parse_stream(stream)
                value = stream.read(size)
        elif id < WORD:
            value = stream.read(1)
        elif id < DWORD:
            value = stream.read(2)
        elif id < TEXT:
            value = stream.read(4)
        else:
            size = c.VarInt.parse_stream(stream)
            value = stream.read(size)

        if id == ProjectID.FLVersion:
            parts = value.decode("ascii").rstrip("\0").split(".")
            version_nums = [int(part) for part in parts]
            fl_major = version_nums[0]
            if version_nums[0:2] >= [11, 5]:
                str_type = UnicodeEvent
            else:
                str_type = AsciiEvent

        # FL 25 override can also pin the event-class; if so, skip the
        # per-subclass lookup and range-based fallback entirely.
        if override is not None and override.event_class_name is not None:
            event_type = _FL25_EVENT_CLASSES[override.event_class_name]
        else:
            for enum_ in EventEnum.__subclasses__():
                if id in enum_:
                    event_type = getattr(enum_(id), "type")
                    break

            if event_type is None:
                if id < WORD:
                    event_type = U8Event
                elif id < DWORD:
                    event_type = U16Event
                elif id < TEXT:
                    event_type = U32Event
                elif id < DATA or id.value in NEW_TEXT_IDS:
                    if str_type is None:  # pragma: no cover
                        raise VersionNotDetected  # ! This should never happen
                    event_type = str_type
        if event_type is None:
            if id < WORD:
                event_type = U8Event
            elif id < DWORD:
                event_type = U16Event
            elif id < TEXT:
                event_type = U32Event
            elif id < DATA or id in NEW_TEXT_IDS:
                if str_type is None:  # pragma: no cover
                    raise VersionNotDetected  # ! This should never happen
                event_type = str_type

                if id == PluginID.InternalName:
                    plug_name = event_type(id, value).value
                elif id == PluginID.Data and plug_name is not None:
                    event_type = get_event_by_internal_name(plug_name)
                else:
                    event_type = UnknownDataEvent

        # if for some event_type is still None, default to UnknownDataEvent.
        if event_type is None:
            event_type = UnknownDataEvent

        events.append(event_type(id, value))

    return Project(
        EventTree(init=(IndexedEvent(r, e) for r, e in enumerate(events))),
        channel_count=channel_count,
        format=file_format,
        ppq=ppq,
    )


def save(project: Project, file: pathlib.Path | str) -> None:
    """Save a parsed project back into a file.

    Caution:
        Always have a backup ready, just in case 😉

    Args:
        project: The object returned by :meth:`parse`.
        file: The file in which the contents of :attr:`project` are serialised back.
    """
    buf = bytearray()
    num_channels = len(project.channels)
    header = FLP_HEADER.pack(b"FLhd", 6, project.format, num_channels, project.ppq)
    buf.extend(header)
    buf.extend(b"FLdt" + (b"\0" * 4))
    total_size = 0
    for event in project.events:
        raw = bytes(event)
        total_size += len(raw)
        buf.extend(raw)
    buf[18:22] = total_size.to_bytes(4, "little")

    with open(file, "wb") as fp:
        fp.write(buf)
