import os
from aiohttp import web
import redis

r=redis.Redis(host="localhost",port=6379, decode_responses=True)

async def info_api(Request):
    return web.Response(text=r.get("visit"))

async def login(Request):
    pass

async def settings(Request):
    pass

async def login_fwd(Request):
    pass

app=web.Application()
app.add_routes([web.get('/',login_fwd),
                web.get('/login',login),
                web.post('/login',login),
                web.get('/admin',info_api),
                web.post('/admin',settings)])

if __name__ == '__main__':
    web.run_app(app, port=1337)
