"""Optional login for the dashboard (SNIFF_AUTH='user:pass').

Pure ASGI middleware so it covers every route including /ws and /api.  After a login form
POST a signed cookie (HMAC-SHA256, key derived from the credentials, valid 15 days) is set;
browsers send it on the WebSocket handshake too.  HTTP Basic auth is also accepted for
scripts/curl.  SNIFF_AUTH unset = no auth (local use unchanged).
"""
import asyncio
import base64
import hashlib
import hmac
import html
import time
import urllib.parse

COOKIE = "ss_auth"
MAX_AGE = 15 * 24 * 3600
OPEN_PATHS = ("/login", "/favicon.ico")

LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sniff-Sight login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;display:flex;min-height:90vh;align-items:center;justify-content:center;margin:0}
form{background:#161616;border:1px solid #333;padding:1.4rem 1.6rem;width:min(320px,86vw)}h1{color:#7cf;font-size:1.3rem;margin:0 0 1rem}
input{display:block;width:100%;box-sizing:border-box;margin:.3rem 0 .8rem;padding:.55rem;background:#222;color:#eee;border:1px solid #444;font-size:16px}
button{width:100%;padding:.6rem;background:#234;color:#eee;border:1px solid #456;font-size:16px}.e{color:#f66;font-size:13px}</style></head>
<body><form method="post" action="/login"><h1>Sniff-Sight</h1>%ERR%
<label>User<input name="user" autocomplete="username" autocapitalize="off" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<input type="hidden" name="next" value="%NEXT%"><button>Login</button></form></body></html>"""


class AuthMiddleware:
    def __init__(self, app, cred: str):
        self.app = app
        self.user, _, self.pw = cred.partition(":")
        self.key = hashlib.sha256(("sniff-sight|" + cred).encode()).digest()

    def _sign(self, exp: int) -> str:
        return f"{exp}.{hmac.new(self.key, f'{self.user}|{exp}'.encode(), hashlib.sha256).hexdigest()}"

    def _valid_cookie(self, headers) -> bool:
        for part in headers.get(b"cookie", b"").decode("latin-1").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                exp = v.partition(".")[0]
                if exp.isdigit() and int(exp) > time.time() and hmac.compare_digest(self._sign(int(exp)), v):
                    return True
        return False

    def _valid_basic(self, headers) -> bool:
        a = headers.get(b"authorization", b"").decode("latin-1")
        if not a.lower().startswith("basic "):
            return False
        try:
            u, _, p = base64.b64decode(a[6:]).decode().partition(":")
        except Exception:
            return False
        return hmac.compare_digest(u, self.user) and hmac.compare_digest(p, self.pw)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        path = scope.get("path", "/")
        if self._valid_cookie(headers) or self._valid_basic(headers):
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4401})
            return
        if path == "/login":
            return await self._login(scope, receive, send, headers)
        if path in OPEN_PATHS:
            return await self.app(scope, receive, send)
        if path.startswith("/api/"):
            return await self._respond(send, 401, b"unauthorized", [(b"www-authenticate", b'Basic realm="Sniff-Sight"')])
        qs = scope.get("query_string") or b""
        nxt = urllib.parse.quote(path + ("?" + qs.decode() if qs else ""))
        return await self._respond(send, 303, b"", [(b"location", b"/login?next=" + nxt.encode())])

    async def _login(self, scope, receive, send, headers):
        q = urllib.parse.parse_qs((scope.get("query_string") or b"").decode())
        nxt, err = q.get("next", ["/"])[0], ""
        if scope["method"] == "POST":
            body = b""
            while True:
                m = await receive()
                body += m.get("body", b"")
                if not m.get("more_body") or len(body) > 8192:
                    break
            f = urllib.parse.parse_qs(body.decode(errors="replace"))
            u, p = f.get("user", [""])[0], f.get("password", [""])[0]
            nxt = f.get("next", [nxt])[0]
            if hmac.compare_digest(u, self.user) and hmac.compare_digest(p, self.pw):
                if not nxt.startswith("/") or nxt.startswith("//"):
                    nxt = "/"
                exp = int(time.time()) + MAX_AGE
                secure = "; Secure" if headers.get(b"x-forwarded-proto", b"") == b"https" else ""
                ck = f"{COOKIE}={self._sign(exp)}; Max-Age={MAX_AGE}; Path=/; HttpOnly; SameSite=Lax{secure}"
                return await self._respond(send, 303, b"", [(b"location", nxt.encode()), (b"set-cookie", ck.encode())])
            await asyncio.sleep(1.0)            # slow down guessing
            err = '<p class="e">Wrong user or password</p>'
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = "/"
        page = LOGIN_HTML.replace("%ERR%", err).replace("%NEXT%", html.escape(nxt, quote=True))
        return await self._respond(send, 401 if err else 200, page.encode(), [(b"content-type", b"text/html; charset=utf-8")])

    @staticmethod
    async def _respond(send, status, body, headers):
        await send({"type": "http.response.start", "status": status,
                    "headers": headers + [(b"content-length", str(len(body)).encode()), (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})
