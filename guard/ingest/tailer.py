"""Restart-safe reading of the Nginx JSON access log (docs/SUBSYSTEMS.md section 2.2).

`read_next` is a pure function of the log file and the last committed `Position`. It reads only complete
lines (those ending in a newline), notices rotation and truncation, and reports gaps instead of hiding
them. It never writes anything; the caller commits the lines and the new position in one transaction
(`writer.write_batch`), which is what makes a crash harmless.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from guard.ingest.writer import Position

HEAD_BYTES = 256
MAX_LINE = 64 * 1024
MAX_READ = 1024 * 1024
MAX_LINES = 500
ROTATED_GRACE_S = 2.0
_I64 = 0x7FFFFFFFFFFFFFFF


@dataclass
class ReadResult:
    lines: list = field(default_factory=list)   # complete lines, without the trailing newline
    position: Position = field(default_factory=Position)
    gaps: list = field(default_factory=list)    # gap notices (strings) to record
    changed: bool = False                       # the position or gaps need saving even with no lines


def _ident(st: os.stat_result) -> tuple:
    return (st.st_dev & _I64, st.st_ino & _I64)


def _head_hash(fh) -> bytes | None:
    fh.seek(0)
    head = fh.read(HEAD_BYTES)
    return hashlib.sha256(head).digest() if len(head) == HEAD_BYTES else None


def _read_lines(path: str, start: Position, *, final: bool, max_lines: int, max_read: int) -> ReadResult:
    """Read up to `max_lines` complete lines from `path` at `start.offset`.

    `final` means no more data will ever arrive (a rotated file that has gone quiet), so a trailing
    partial line is delivered instead of waiting for its newline.
    """
    result = ReadResult(position=start)
    with open(path, "rb") as fh:
        head = start.head_hash if start.head_hash is not None else _head_hash(fh)
        fh.seek(start.offset)
        chunk = fh.read(max_read)
        size_known = os.fstat(fh.fileno()).st_size
    pieces = chunk.split(b"\n")
    partial = pieces.pop()  # text after the last newline (empty when the chunk ends with one)
    taken = pieces[:max_lines]
    consumed = sum(len(p) + 1 for p in taken)
    lines = list(taken)
    if len(taken) == len(pieces):
        reached_end = start.offset + len(chunk) >= size_known
        if partial and (len(partial) > MAX_LINE or (final and reached_end)):
            # An over-long unterminated run would otherwise grow without bound; a quiet rotated file
            # will never get its newline. Deliver it (the parser rejects it if it is unusable).
            lines.append(partial[: MAX_LINE + 1])
            consumed += len(partial)
    if lines or head != start.head_hash:
        result.lines = lines
        result.position = Position(start.dev, start.inode, head, start.offset + consumed)
        result.changed = bool(lines) or head != start.head_hash
    return result


def read_next(path: str, saved: Position, *, now: float, max_lines: int = MAX_LINES,
              max_read: int = MAX_READ, rotated_grace_s: float = ROTATED_GRACE_S) -> ReadResult:
    """Return the next batch of complete lines after `saved`, handling rotation and truncation."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        st = None
    saved_ident = (saved.dev, saved.inode) if saved.inode is not None else None

    def fresh(file_st: os.stat_result, gaps: list) -> ReadResult:
        dev, ino = _ident(file_st)
        res = _read_lines(path, Position(dev, ino, None, 0), final=False, max_lines=max_lines, max_read=max_read)
        res.position = Position(dev, ino, res.position.head_hash, res.position.offset)
        res.gaps = gaps
        res.changed = True
        return res

    if saved_ident is None:
        # First run (or after the old file was fully drained): start at the beginning of the file.
        return fresh(st, []) if st is not None else ReadResult(position=saved)

    if st is not None and _ident(st) == saved_ident:
        if st.st_size < saved.offset:
            return fresh(st, ["log file shrank (truncated); restarted at its beginning, "
                              "requests written before the truncation may be missing"])
        if saved.head_hash is not None:
            with open(path, "rb") as fh:
                if _head_hash(fh) != saved.head_hash:
                    return fresh(st, ["log file was replaced by a different file with the same identity; "
                                      "restarted at its beginning"])
        return _read_lines(path, saved, final=False, max_lines=max_lines, max_read=max_read)

    # The file we were reading is no longer at `path`: it was rotated (or removed).
    rotated = path + ".1"
    try:
        old = os.stat(rotated)
    except FileNotFoundError:
        old = None
    if old is not None and _ident(old) == saved_ident and old.st_size >= saved.offset:
        quiet = (now - old.st_mtime) >= rotated_grace_s
        res = _read_lines(rotated, saved, final=quiet, max_lines=max_lines, max_read=max_read)
        if res.lines:
            return res
        if not quiet:
            return ReadResult(position=saved)  # Nginx may still be writing to it; wait
        # Fully drained: move on to the new file without reporting a gap.
        if st is None:
            return ReadResult(position=Position(), changed=True)
        return fresh(st, [])
    if st is None:
        return ReadResult(position=saved)  # nothing to read yet; keep waiting
    return fresh(st, ["log file was rotated and the previous file could not be found; "
                      "requests written between the last read and the rotation may be missing"])
