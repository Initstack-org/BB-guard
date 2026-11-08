"""The internal listener Nginx calls (docs/ARCHITECTURE.md sections 5 to 7, docs/API.md section 3).

Bound to loopback only, and every request from a non-loopback peer is refused anyway. Three routes:

  GET /check    auth_request target. 204 = allow, 403 = deny. Reads four headers set by Nginx:
                X-Guard-Client-Ip, X-Guard-Host, X-Guard-Uri, X-Guard-Method.
  GET /block    the block page, always status 403, strict CSP, no scripts.
  GET /healthz  liveness.

/check FAILS OPEN: any error answers 204 with `X-Guard-Decision: error`, so a Guard bug or a database
problem can never take the forum down (GOAL.md rule 4, Stage 6 exit criterion). It reads the cache only
and never calls an external service. The Nginx side (auth_request, error_page, log_format) is not written
yet; see PROGRESS.md.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Callable

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from . import blockpage, db, enforce
from .config import Config
from .ingest.normalize import canonical_ip, clean_text

_HEADER_SAFE = "".join(chr(c) for c in range(32, 127))


def _ascii(text: str, limit: int = 120) -> str:
    """Header values must be printable ASCII with no line breaks."""
    return "".join(c if c in _HEADER_SAFE else "?" for c in clean_text(text, limit))


def _is_loopback(request: Request) -> bool:
    try:
        return bool(request.client) and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _split_uri(uri: str) -> tuple[str, str]:
    uri = uri.split("#", 1)[0]
    path, _, query = uri.partition("?")
    return path or "/", query


def _check_sync(request: Request, cfg: Config, clock: Callable[[], int], worker) -> Response:
    h = request.headers
    conn = db.connect(cfg.db_path)
    try:
        path, query = _split_uri(h.get("x-guard-uri", "/"))
        verdict = enforce.check(conn, h.get("x-guard-client-ip", ""), h.get("x-guard-host", ""), path, query,
                                h.get("x-guard-method", "GET"), clock())
    finally:
        conn.close()
    if verdict.needs_lookup and worker is not None:
        worker.enqueue(h.get("x-guard-client-ip", ""))
    headers = {"X-Guard-Decision": verdict.outcome, "X-Guard-Reason": _ascii(verdict.reason),
               "X-Guard-Detect": _ascii(verdict.detection, 40)}
    if verdict.rule_id is not None:
        headers["X-Guard-Rule"] = str(verdict.rule_id)
    return Response(status_code=403 if verdict.outcome == "denied" else 204, headers=headers)


def _block_sync(request: Request, cfg: Config, clock: Callable[[], int]) -> Response:
    h = request.headers
    try:
        ip = canonical_ip(h.get("x-guard-client-ip", ""))
    except ValueError:
        ip = ""
    stamp = datetime.fromtimestamp(clock() / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    conn = db.connect(cfg.db_path)
    try:
        page = blockpage.render_active(conn, visitor_ip=ip, reason=clean_text(h.get("x-guard-reason", ""), 200),
                                       detection=clean_text(h.get("x-guard-detect", ""), 40), timestamp=stamp)
    finally:
        conn.close()
    return HTMLResponse(page, status_code=403, headers={
        "Content-Security-Policy": blockpage.BLOCK_CSP, "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})


def create_internal_app(cfg: Config, *, clock: Callable[[], int] = db.now_ms, worker=None) -> Starlette:
    async def check(request: Request) -> Response:
        if not _is_loopback(request):
            return PlainTextResponse("Forbidden", status_code=403)
        try:
            return await run_in_threadpool(_check_sync, request, cfg, clock, worker)
        except Exception:  # noqa: BLE001 - fail open on anything at all
            return Response(status_code=204, headers={"X-Guard-Decision": "error"})

    async def block(request: Request) -> Response:
        if not _is_loopback(request):
            return PlainTextResponse("Forbidden", status_code=403)
        try:
            return await run_in_threadpool(_block_sync, request, cfg, clock)
        except Exception:  # noqa: BLE001 - the built-in page is the last resort
            return HTMLResponse(blockpage.render(blockpage.DEFAULT_HTML, {
                "block_reason": "Access blocked"}), status_code=403,
                headers={"Content-Security-Policy": blockpage.BLOCK_CSP, "Cache-Control": "no-store"})

    async def healthz(request: Request) -> Response:
        if not _is_loopback(request):
            return PlainTextResponse("Forbidden", status_code=403)
        return JSONResponse({"status": "ok"})

    return Starlette(routes=[Route("/check", check), Route("/block", block), Route("/healthz", healthz)])
