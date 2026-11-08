"""Helpers shared by the ingest tests: build Nginx JSON access-log lines (docs/ARCHITECTURE.md section 9)."""

import json

TRUSTED = ["192.168.1.148"]
BASE_T = 1_800_000_000  # epoch seconds


def log_dict(i=0, **over):
    d = {
        "t": f"{BASE_T + i}.250", "ip": "203.0.113.7", "peer": "192.168.1.148", "m": "GET",
        "h": "initstack.org", "u": f"/forum-{i % 3}.html?page={i}", "s": "200", "bi": "300", "bo": "1500",
        "d": "0.012", "ua": "TestAgent/1.0", "ref": "https://example.org/a?b=1", "id": f"{i + 1:032x}",
        "gd": "allowed", "gt": "", "gr": "", "gx": "", "bd": "", "bt": "", "br": "", "bx": "",
        "uid": "", "un": "",
    }
    d.update(over)
    return d


def log_line(i=0, **over) -> bytes:
    """One complete log line including its newline."""
    return (json.dumps(log_dict(i, **over)) + "\n").encode()


def write_log(path, count, start=0, **over):
    with open(path, "ab") as fh:
        for i in range(start, start + count):
            fh.write(log_line(i, **over))
