"""Block page storage, versions and rendering (docs/SUBSYSTEMS.md section 5).

- Versions are immutable (a database trigger enforces it); restoring copies an old version into a NEW
  one, and exactly one version is published at a time.
- Rendering is a single-pass substitution over exactly five placeholders. Values are HTML-escaped
  first, and replaced text is never re-scanned, so a value cannot inject another placeholder. Admin
  HTML is never passed through Jinja or any other template engine (decision D12).
- A built-in default page is used when no version is published, the custom page is switched off, or
  the stored HTML is unusable.
"""

from __future__ import annotations

import html as html_lib
import re
import sqlite3
from urllib.parse import urlsplit

from . import audit, settings_read
from .db import transaction

MAX_BYTES = 204800
NOTE_MAX = 300
PLACEHOLDERS = ("visitor_ip", "block_reason", "detection_type", "timestamp", "appeal_url")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*(" + "|".join(PLACEHOLDERS) + r")\s*\}\}")

# CSP for the served block page and for the editor preview: no script, no third-party resources, no framing
# by other sites. The preview adds `sandbox` (no allow-scripts, no allow-same-origin).
BLOCK_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
             "form-action 'none'; frame-ancestors 'none'")
PREVIEW_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
               "form-action 'none'; frame-ancestors 'self'; sandbox")

SAMPLE_VALUES = {"visitor_ip": "203.0.113.7", "block_reason": "Example: VPN detected",
                 "detection_type": "vpn_detected", "timestamp": "2026-11-08 12:00:00 UTC",
                 "appeal_url": "https://example.org/appeal"}

DEFAULT_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access blocked</title>
<style>
body{font:16px/1.5 system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;
justify-content:center;background:#f5f5f7;color:#1d1d1f}
main{max-width:34rem;margin:1rem;padding:2rem;background:#fff;border-radius:18px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{font-size:1.6rem;letter-spacing:-.02em;margin:0 0 .5rem}
dl{margin:1.25rem 0 0;display:grid;grid-template-columns:auto 1fr;gap:.35rem 1rem;font-size:.9rem}
dt{color:#6e6e73}dd{margin:0;word-break:break-all}
@media (prefers-color-scheme:dark){body{background:#000;color:#f5f5f7}main{background:#1c1c1e;box-shadow:none}dt{color:#98989d}}
</style></head>
<body><main>
<h1>Access blocked</h1>
<p>{{ block_reason }}</p>
<dl>
<dt>Your address</dt><dd>{{ visitor_ip }}</dd>
<dt>Reason</dt><dd>{{ detection_type }}</dd>
<dt>Time</dt><dd>{{ timestamp }}</dd>
</dl>
<p>If you think this is a mistake, contact the site team: {{ appeal_url }}</p>
</main></body></html>
"""


class BlockPageError(ValueError):
    """A rejected change; the message is safe to show to an admin."""


def safe_appeal_url(value: str) -> str:
    """Only http, https and mailto links survive; anything else renders empty."""
    value = (value or "").strip()
    try:
        scheme = urlsplit(value).scheme.lower()
    except ValueError:
        return ""
    return value if scheme in ("http", "https", "mailto") and len(value) <= 300 else ""


def render(page_html: str, values: dict) -> str:
    """Single-pass substitution of the five placeholders with HTML-escaped values."""
    clean = {name: html_lib.escape(str(values.get(name, "")), quote=True) for name in PLACEHOLDERS}
    clean["appeal_url"] = html_lib.escape(safe_appeal_url(str(values.get("appeal_url", ""))), quote=True)
    return _PLACEHOLDER_RE.sub(lambda m: clean[m.group(1)], page_html)


def validate_html(text: str) -> str:
    if not isinstance(text, str) or not text.strip():
        raise BlockPageError("The page is empty.")
    if "\x00" in text:
        raise BlockPageError("The page contains a NUL character.")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise BlockPageError("The page is not valid text.") from None
    if size > MAX_BYTES:
        raise BlockPageError(f"The page is {size:,} bytes; the limit is {MAX_BYTES:,}.")
    return text


def save_version(conn: sqlite3.Connection, page_html: str, note: str, *, admin_id: int, admin_name: str,
                 ip: str, now_ms: int, restored_from: int | None = None) -> int:
    """Store a new version (not published). Returns its id."""
    page_html = validate_html(page_html)
    note = (note or "").strip()
    if len(note) > NOTE_MAX or any(ord(c) < 32 for c in note):
        raise BlockPageError(f"The note must be plain text of at most {NOTE_MAX} characters.")
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO block_page_versions(html, note, created_ms, created_by, restored_from, published)"
            " VALUES (?,?,?,?,?,0)", (page_html, note, now_ms, admin_id, restored_from))
        audit.record(conn, "block_page.save", "success", actor_admin_id=admin_id, actor_name=admin_name, ip=ip,
                     target_type="block_page", target_id=str(cur.lastrowid), ts_ms=now_ms,
                     detail={"bytes": len(page_html.encode("utf-8")), "restored_from": restored_from})
    return cur.lastrowid


def publish(conn: sqlite3.Connection, version_id: int, *, admin_id: int, admin_name: str, ip: str,
            now_ms: int) -> None:
    with transaction(conn):
        if conn.execute("SELECT 1 FROM block_page_versions WHERE id = ?", (version_id,)).fetchone() is None:
            raise BlockPageError("No such version.")
        conn.execute("UPDATE block_page_versions SET published = 0, published_ms = NULL WHERE published = 1")
        conn.execute("UPDATE block_page_versions SET published = 1, published_ms = ? WHERE id = ?",
                     (now_ms, version_id))
        audit.record(conn, "block_page.publish", "success", actor_admin_id=admin_id, actor_name=admin_name, ip=ip,
                     target_type="block_page", target_id=str(version_id), ts_ms=now_ms)


def unpublish(conn: sqlite3.Connection, *, admin_id: int, admin_name: str, ip: str, now_ms: int) -> None:
    """Go back to the built-in page."""
    with transaction(conn):
        conn.execute("UPDATE block_page_versions SET published = 0, published_ms = NULL WHERE published = 1")
        audit.record(conn, "block_page.unpublish", "success", actor_admin_id=admin_id, actor_name=admin_name,
                     ip=ip, target_type="block_page", ts_ms=now_ms)


def restore(conn: sqlite3.Connection, version_id: int, *, admin_id: int, admin_name: str, ip: str,
            now_ms: int) -> int:
    """Copy an old version into a new, unpublished one. History is never rewritten."""
    row = conn.execute("SELECT html FROM block_page_versions WHERE id = ?", (version_id,)).fetchone()
    if row is None:
        raise BlockPageError("No such version.")
    return save_version(conn, row["html"], f"Restored from version {version_id}", admin_id=admin_id,
                        admin_name=admin_name, ip=ip, now_ms=now_ms, restored_from=version_id)


def get_version(conn: sqlite3.Connection, version_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM block_page_versions WHERE id = ?", (version_id,)).fetchone()


def published_row(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM block_page_versions WHERE published = 1").fetchone()


def list_versions(conn: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT v.id, v.note, v.created_ms, v.restored_from, v.published, v.published_ms,"
        " length(CAST(v.html AS BLOB)) AS size, a.username AS author"
        " FROM block_page_versions v LEFT JOIN admins a ON a.id = v.created_by"
        " ORDER BY v.id DESC LIMIT ?", (limit,)).fetchall()


def active_html(conn: sqlite3.Connection) -> str:
    """The HTML to serve: the published version when the custom page is on and usable, else the default."""
    if not settings_read.get(conn, "block_page.use_custom"):
        return DEFAULT_HTML
    row = published_row(conn)
    if row is None:
        return DEFAULT_HTML
    try:
        return validate_html(row["html"])
    except BlockPageError:
        return DEFAULT_HTML


def render_active(conn: sqlite3.Connection, *, visitor_ip: str, reason: str, detection: str,
                  timestamp: str) -> str:
    return render(active_html(conn), {"visitor_ip": visitor_ip, "block_reason": reason,
                                      "detection_type": detection, "timestamp": timestamp,
                                      "appeal_url": settings_read.get(conn, "site.appeal_url")})
