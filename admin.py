import os
from aiohttp import web
import redis.asyncio as redis
from pathlib import Path

# ---------------- REDIS ----------------

r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# ---------------- PATHS ----------------

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
LOG_FILE = BASE_DIR / "waf.log"

# ---------------- API HANDLERS ----------------

async def info_api(request):
    visit_count = await r.get("visit") or "0"
    waf_status = await r.get("waf_enabled") or "false"
    sqli_waf_status = await r.get("sql_waf_enabled") or "false"
    xss_waf_status = await r.get("xss_waf_enabled") or "false"
    enable_blocking = await r.get("enable_blocking") or "false"
    response = {
        "visit_count": int(visit_count),
        "waf_enabled": waf_status == "true",
        "sql_waf_enabled": sqli_waf_status == "true",
        "xss_waf_enabled": xss_waf_status == "true",
        "enable_blocking" : enable_blocking== "true"
    }

    return web.json_response(response)

async def logs(request):
    if not LOG_FILE.exists():
        return web.json_response({"logs": []})

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        # Fallback for Windows UTF-16 / mixed encodings
        with open(LOG_FILE, "r", encoding="utf-16", errors="ignore") as f:
            lines = f.readlines()

    lines = [line.rstrip("\n") for line in lines]

    return web.json_response({"logs": lines})


# ---------------- PAGE HANDLERS ----------------

async def panel(request):
    return web.FileResponse(STATIC_DIR / "panel.html")

async def login(request):
    return web.Response(text="Login page")

async def settings(request):
    return web.Response(text="Settings updated")

# ---------------- APP ----------------

app = web.Application()

# Pages
app.add_routes([
    web.get("/", panel),
    web.get("/panel", panel),
    web.get("/login", login),
])

# APIs
app.add_routes([
    web.get("/admin", info_api),
    web.post("/admin", settings),
    web.get("/api/logs", logs),
])

# Static files
app.router.add_static("/static/", STATIC_DIR, name="static")

# ---------------- RUN ----------------

if __name__ == "__main__":
    web.run_app(app, port=1337)
