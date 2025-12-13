"""
aiohttp_proxy_server.py

Async reverse proxy with ML-based SQL injection detection.
"""

import argparse
import asyncio
import logging
import json
from typing import Tuple, Dict, Any, Optional
from urllib.parse import parse_qs

import aiohttp
from aiohttp import web

# -----------------------------------------------------------
# Logging
# -----------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("aiohttp-proxy")

# Hop-by-hop headers that must NOT be forwarded
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

# -----------------------------------------------------------
# Load SQL Injection ML Model
# -----------------------------------------------------------
import joblib

sql_model = joblib.load("sql_injection_model.pkl")

def detect_sql_injection(text: str) -> bool:
    """Returns True if ML model predicts SQLi."""
    try:
        if not text or not text.strip():
            return False
        pred = sql_model.predict([text])[0]
        return pred == 1
    except Exception:
        return False


def extract_json_values(obj):
    """Recursively extract all JSON scalar values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from extract_json_values(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from extract_json_values(item)
    else:
        yield None, obj


# -----------------------------------------------------------
# WAF Analyzer
# -----------------------------------------------------------
async def analyze_request(request, body_bytes):
    text_body = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""

    # -------------------------------------------------------
    # 1️⃣ Check URL query parameters
    # -------------------------------------------------------
    for key, value in request.query.items():
        if detect_sql_injection(value):
            logger.warning(f"Blocked SQLi in query parameter: {key}={value}")
            return False, {}, None

    # -------------------------------------------------------
    # 2️⃣ Check form-urlencoded without re-reading the body
    # -------------------------------------------------------
    if request.content_type == "application/x-www-form-urlencoded":
        try:
            form = parse_qs(text_body)
            for key, values in form.items():
                for value in values:
                    if detect_sql_injection(value):
                        logger.warning(f"Blocked SQLi in form field: {key}={value}")
                        return False, {}, None
        except:
            pass

    # -------------------------------------------------------
    # 3️⃣ Check JSON parameters
    # -------------------------------------------------------
    if request.content_type == "application/json":
        try:
            data = json.loads(text_body)
            for key, value in extract_json_values(data):
                val = "" if value is None else str(value)
                if detect_sql_injection(val):
                    logger.warning(f"Blocked SQLi in JSON field: {key}={val}")
                    return False, {}, None
        except:
            pass

    # -------------------------------------------------------
    # 4️⃣ Raw body fallback only if non-JSON non-form
    # -------------------------------------------------------
    if request.content_type not in ("application/json", "application/x-www-form-urlencoded"):
        if detect_sql_injection(text_body):
            logger.warning(f"Blocked SQLi in raw body")
            return False, {}, None

    # All good
    return True, {}, None


# -----------------------------------------------------------
# Forward Request to Upstream
# -----------------------------------------------------------
async def forward_request(request: web.Request, upstream_base: str, session: aiohttp.ClientSession) -> web.Response:
    path = request.rel_url.path
    query = request.rel_url.query_string

    upstream_url = upstream_base.rstrip("/") + path
    if query:
        upstream_url += "?" + query

    try:
        body = await request.read()
    except Exception as e:
        logger.exception("Failed to read request body: %s", e)
        body = b""

    # Analyze before forwarding
    allow, added_headers, modified_body = await analyze_request(request, body)
    if not allow:
        return web.Response(status=403, text="Request blocked by WAF")

    forward_body = modified_body if modified_body is not None else body

    # Filter hop-by-hop headers
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}

    # Add headers from analyzer
    forward_headers.update(added_headers)

    method = request.method

    logger.info(f"Forwarding {method} {request.rel_url} -> {upstream_url} (size={len(forward_body)})")

    try:
        async with session.request(method, upstream_url, headers=forward_headers, data=forward_body, allow_redirects=False) as resp:
            resp_body = await resp.read()
            resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP}
            return web.Response(status=resp.status, body=resp_body, headers=resp_headers)

    except aiohttp.ClientError as e:
        logger.exception("Upstream request failed: %s", e)
        return web.Response(status=502, text=f"Bad gateway: {e}")


async def proxy_handler(request: web.Request) -> web.Response:
    return await forward_request(
        request,
        request.app["upstream_base"],
        request.app["client_session"]
    )


# -----------------------------------------------------------
# Create Application
# -----------------------------------------------------------
async def create_app(upstream_base: str, timeout: int = 30) -> web.Application:
    app = web.Application()
    app["upstream_base"] = upstream_base

    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    client_session = aiohttp.ClientSession(timeout=timeout_cfg)
    app["client_session"] = client_session

    try:
        app.router.add_route("*", "/{tail:.*}", proxy_handler)

        async def on_shutdown(app: web.Application):
            logger.info("Shutting down client session")
            await app["client_session"].close()

        app.on_shutdown.append(on_shutdown)
        return app

    except Exception:
        await client_session.close()
        raise


# -----------------------------------------------------------
# CLI + Entry Point
# -----------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Async aiohttp ML-WAF proxy")
    p.add_argument("--upstream", required=True, help="Upstream base URL, e.g. http://localhost:8000")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--loglevel", default="INFO")
    return p.parse_args()


async def run_app():
    args = parse_args()
    logger.setLevel(args.loglevel.upper())

    app = await create_app(args.upstream, timeout=args.timeout)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, args.host, args.port)
    logger.info(f"Starting proxy on {args.host}:{args.port} → upstream {args.upstream}")
    await site.start()

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("Stopping...")
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run_app())
    except KeyboardInterrupt:
        logger.info("Interrupted, exiting...")
