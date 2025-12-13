"""
aiohttp_proxy_server.py

An async HTTP proxy using aiohttp that parses and analyses incoming requests
before forwarding them to an upstream server. Designed as a starting point for
building request-inspection, logging, modification, or policy-enforcement
middleware.

Usage:
    python aiohttp_proxy_server.py --upstream http://upstream.example.com --host 0.0.0.0 --port 8080

Requirements:
    pip install aiohttp

Features:
 - Accepts all HTTP methods and forwards them to an upstream server
 - Preserves method, path, query, headers, and body
 - Provides a place (`analyze_request`) to inspect/modify/block requests
 - Returns upstream response status, headers and body back to the client
 - Handles JSON bodies and streaming bodies
 - Basic logging and error handling

Important notes:
 - This is not a production-ready, secure reverse proxy. For production use,
   consider additional hardening: TLS termination, header sanitization,
   forwarding CONNECT for HTTPS, connection pooling limits, request size limits,
   authentication, and careful handling of hop-by-hop headers.

"""

import argparse
import asyncio
import logging
import json
from typing import Tuple, Dict, Any, Optional

import aiohttp
from aiohttp import web

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("aiohttp-proxy")

# Hop-by-hop headers that should not be forwarded. See RFC 7230.
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


async def analyze_request(request: web.Request, body_bytes: Optional[bytes]) -> Tuple[bool, Dict[str, str], Optional[bytes]]:
    """
    Inspect and optionally modify the request before it's forwarded.

    Returns:
      (allow_forward, modified_headers, modified_body)

    - allow_forward: if False, the proxy will return a 403 response (you can
      change the status/code and message as needed).
    - modified_headers: dictionary of headers to merge into the forwarded
      headers (overwrites existing keys).
    - modified_body: replace body bytes if you want to alter the payload; return
      None to keep original.

    This function is the place to add logging, security checks, simple IDS,
    request transformations, rate limiting hooks, etc.
    """
    # Example analyses:
    # 1) Block requests from a particular header value
    blocklist_header = request.headers.get("x-block-me")
    if blocklist_header == "true":
        logger.warning("Blocked request due to x-block-me header")
        return False, {}, None

    
    # 2) If JSON body contains a forbidden key, block
    if body_bytes:
        ctype = request.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
                # Example: block if JSON contains "forbidden": true
                if isinstance(payload, dict) and payload.get("forbidden") is True:
                    logger.warning("Blocked JSON request with forbidden=true")
                    return False, {}, None
            except Exception:
                # Not valid JSON; ignore here
                pass

    # 3) Add or overwrite header
    additional_headers = {"x-proxy-verified": "1"}

    # 4) Optionally modify the body (example: add a field to JSON)
    modified_body = None
    if body_bytes and "application/json" in request.headers.get("Content-Type", ""):
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
            if isinstance(payload, dict):
                payload["_proxied_by"] = "aiohttp-proxy"
                modified_body = json.dumps(payload).encode("utf-8")
                # adjust content-type header later if size or encoding changes
        except Exception:
            pass

    return True, additional_headers, modified_body


async def forward_request(request: web.Request, upstream_base: str, session: aiohttp.ClientSession) -> web.Response:
    """
    Forward the incoming aiohttp.web.Request to the upstream server and
    return a Response object to send back to the client.
    """
    # Build the upstream URL
    path = request.rel_url.path
    query = request.rel_url.query_string
    upstream_url = upstream_base.rstrip("/") + path
    if query:
        upstream_url += "?" + query

    # Read the incoming body (if any)
    try:
        body = await request.read()
    except Exception as e:
        logger.exception("Failed to read request body: %s", e)
        body = b""

    # Analyze (and possibly modify or block) the request
    allow, added_headers, modified_body = await analyze_request(request, body)
    if not allow:
        return web.Response(status=403, text="Request blocked by proxy analysis")

    if modified_body is not None:
        forward_body = modified_body
    else:
        forward_body = body

    # Forward headers (filter hop-by-hop headers)
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    # Merge/overwrite with additional headers from analyzer
    for k, v in added_headers.items():
        forward_headers[k] = v

    # Ensure the Host header matches upstream host (optional)
    # You might want to set or remove Host depending on upstream expectations
    # forward_headers['Host'] = urllib.parse.urlparse(upstream_base).netloc

    method = request.method

    logger.info("Forwarding %s %s -> %s (size=%d bytes)", method, request.rel_url, upstream_url, len(forward_body or b""))

    try:
        async with session.request(method, upstream_url, headers=forward_headers, data=forward_body, allow_redirects=False) as resp:
            # Read response content
            resp_body = await resp.read()

            # Filter hop-by-hop headers from upstream response
            resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP}

            # Optionally modify response headers/body here if needed

            return web.Response(status=resp.status, body=resp_body, headers=resp_headers)
    except aiohttp.ClientError as e:
        logger.exception("Upstream request failed: %s", e)
        return web.Response(status=502, text=f"Bad gateway: {e}")


async def proxy_handler(request: web.Request) -> web.Response:
    # Access the app context for upstream and session
    upstream_base = request.app["upstream_base"]
    session: aiohttp.ClientSession = request.app["client_session"]
    return await forward_request(request, upstream_base, session)


async def create_app(upstream_base: str, timeout: int = 30) -> web.Application:
    """
    Create the aiohttp app and a shared client session.

    This version fixes two issues:
    1. Registers a wildcard route correctly using '*' as the method so all HTTP
       methods are accepted. The previous code mistakenly used the route
       pattern as the method which raised `ValueError: {TAIL:.*} is not
       allowed HTTP method`.
    2. Ensures the client session is closed if route registration fails (so we
       don't leak an "Unclosed client session" warning when startup errors
       happen).
    """
    app = web.Application()
    app["upstream_base"] = upstream_base

    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    # Create a shared client session for re-use
    client_session = aiohttp.ClientSession(timeout=timeout_cfg)
    app["client_session"] = client_session

    try:
        # Use a wildcard route to catch all paths and methods. IMPORTANT: the
        # first argument is the HTTP method ("*" means match all methods), the
        # second is the path pattern.
        app.router.add_route("*", "/{tail:.*}", proxy_handler)

        # Clean up client session on shutdown
        async def on_shutdown(app: web.Application):
            logger.info("Shutting down client session")
            await app["client_session"].close()

        app.on_shutdown.append(on_shutdown)

        return app
    except Exception:
        # If anything fails during setup, make sure we close the session to
        # avoid unclosed-session warnings, then re-raise the error.
        await client_session.close()
        raise


def parse_args():
    p = argparse.ArgumentParser(description="Simple aiohttp proxy with request analysis")
    p.add_argument("--upstream", required=True, help="Upstream base URL, e.g. http://example.com")
    p.add_argument("--host", default="0.0.0.0", help="Host to bind")
    p.add_argument("--port", type=int, default=8080, help="Port to bind")
    p.add_argument("--timeout", type=int, default=30, help="Upstream request timeout in seconds")
    p.add_argument("--loglevel", default="INFO", help="Logging level")
    return p.parse_args()


async def run_app():
    args = parse_args()
    logger.setLevel(args.loglevel.upper())
    app = await create_app(args.upstream, timeout=args.timeout)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, args.host, args.port)
    logger.info("Starting aiohttp proxy on %s:%d -> upstream %s", args.host, args.port, args.upstream)
    await site.start()

    # Run forever
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("Received cancel, shutting down")
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run_app())
    except KeyboardInterrupt:
        logger.info("Interrupted, exiting")
