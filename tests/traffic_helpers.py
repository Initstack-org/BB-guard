"""Seed traffic rows through the real ingest parser and writer, so the traffic tests see exactly what
production ingest would store (including the aggregate tables and rollups)."""

from guard.ingest import writer
from guard.ingest.parser import parse_line, parse_trusted
from tests.ingest_helpers import BASE_T, TRUSTED, log_line

T0_MS = BASE_T * 1000  # 2027-01-15T08:00:00Z, the same instant as the web test clock


def seed(conn, count, start=0, **over):
    """Write `count` requests numbered start..start+count-1 (one second apart from T0). Keyword overrides
    are log fields (ip, u, s, bi, bo, ua, ref, m, uid, un, gd, ...). Request ids are unique per number,
    so use a different `start` for each call."""
    trusted = parse_trusted(TRUSTED)
    settings = writer.IngestSettings()
    records = [parse_line(log_line(i, **over), trusted=trusted, managed_hosts=settings.managed_hosts)
               for i in range(start, start + count)]
    writer.write_batch(conn, records, [], [], writer.Position(), settings=settings, now_ms=T0_MS)
    return records
