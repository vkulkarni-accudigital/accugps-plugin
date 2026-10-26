"""Local-only browser OAuth prototype. Memory-only, registered test client, no refresh tokens."""
import argparse
import asyncio
from dataclasses import dataclass, field
from html import escape
import hmac
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.concurrency import run_in_threadpool
import uvicorn

from accugps_tools import AccountClient
from authorization_core import AuthorizationDenied, AuthorizationStore, digest
from mcp_server import build_server

SCOPE = "accugps:read"
COOKIE = "accugps_local_browser"
# no-referrer makes browsers send Origin: null for ordinary form POSTs,
# conflicting with the exact-origin check. strict-origin keeps the origin
# while withholding paths and query strings (including flow/code values).
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "strict-origin",
           "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
           "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:9876; frame-ancestors 'none'; base-uri 'none'"}


@dataclass
class Browser:
    csrf: str
    expires: float
    grants: dict = field(default_factory=dict)
    grant_labels: dict = field(default_factory=dict)


@dataclass
class Flow:
    browser_key: str
    params: dict
    expires: float
    account: object = None
    subject: str = ""
    devices: list = field(default_factory=list)
    attempts: int = 0
    busy: bool = False


class MCPReadGate:
    """Fail fast instead of queuing overlapping reads in this single-process pilot."""
    def __init__(self, app):
        self.app = app
        self.lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/mcp" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        if self.lock.locked():
            return await Response("Connector busy; retry sequentially", status_code=429,
                                  headers={"Retry-After": "5", "Cache-Control": "no-store"})(scope, receive, send)
        async with self.lock:
            await self.app(scope, receive, send)


def page(title, content, status=200):
    return HTMLResponse(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>body{{font:16px system-ui;background:#f2f5f8;color:#182536;margin:0;padding:32px}}main{{max-width:620px;margin:30px auto;background:white;padding:32px;border-radius:16px}}h1{{font-size:26px}}label{{display:block;margin:18px 0}}input:not([type=checkbox]){{box-sizing:border-box;display:block;width:100%;padding:12px;margin-top:8px}}button{{padding:12px 20px;background:#1259b7;color:white;border:0;border-radius:7px;margin:12px 8px 0 0}}a{{color:#1259b7}}small{{color:#526175}}code{{overflow-wrap:anywhere}}</style>
<main><h1>{escape(title)}</h1>{content}</main></html>''', status_code=status, headers=HEADERS)


class LocalGateway:
    def __init__(self, port=8767, account_factory=AccountClient):
        if not 1024 <= port <= 65535:
            raise ValueError("Invalid local port")
        self.port, self.base = port, f"http://127.0.0.1:{port}"
        self.resource = self.base + "/mcp"
        self.redirect = "http://127.0.0.1:9876/callback"
        self.client_id = "accugps-local-test"
        self.store = AuthorizationStore(self.resource, {self.client_id: [self.redirect]}, allow_loopback=True)
        self.account_factory = account_factory
        self.browsers, self.flows, self.login_times = {}, {}, []
        self.headers = HEADERS
        self.secure_cookie = False
        self.allowed_hosts = ["127.0.0.1"]
        self.transport_security = None
        self.client_names = {self.client_id: "Local test client"}

    def page(self, title, content, status=200):
        response = page(title, content, status)
        response.headers.update(self.headers)
        return response

    def client_name(self, flow_id):
        flow = self.flows.get(digest(flow_id))
        return self.client_names.get(flow.params["client_id"], "Registered client") if flow else "Registered client"

    def callback(self, flow, values):
        return flow.params["redirect_uri"] + "?" + urlencode(values)

    def cleanup(self):
        now = time.time()
        self.browsers = {key: item for key, item in self.browsers.items() if item.expires > now}
        self.flows = {key: item for key, item in self.flows.items()
                      if item.expires > now and item.browser_key in self.browsers}
        self.login_times = [stamp for stamp in self.login_times if stamp > now - 60]

    def browser(self, request):
        self.cleanup()
        raw = request.cookies.get(COOKIE, "")
        return digest(raw), self.browsers.get(digest(raw)) if raw else None

    async def form(self, request, *, browser=None):
        if request.headers.get("origin") not in (None, self.base):
            raise AuthorizationDenied("Cross-origin request rejected")
        if browser is not None and request.headers.get("origin") != self.base:
            raise AuthorizationDenied("Browser origin required")
        if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
            raise AuthorizationDenied("URL-encoded form required")
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 16384:
                raise AuthorizationDenied("Request too large")
        parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=100)
        # Repeated fields are allowed only for device selections.
        if any(len(values) != 1 for key, values in parsed.items() if key != "device"):
            raise AuthorizationDenied("Duplicate form fields")
        form = {key: values if key == "device" else values[0] for key, values in parsed.items()}
        if browser is not None and not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), browser.csrf.encode("ascii")):
            raise AuthorizationDenied("Invalid browser approval")
        return form

    async def home(self, request):
        return self.page("AccuGPS connection test", '''
<p>The local prototype is running. To start sign-in, open a second terminal in
the AccuGPS_LLM-Connect project folder and run:</p>
<pre><code>.\\.venv\\Scripts\\python.exe .\\oauth_browser_client.py --check-disconnect</code></pre>
<p>The test client opens the sign-in page automatically. Sign in with your test
account, choose devices, and approve read access.</p>
<p><a href="/connections">Manage connections and disconnect</a></p>
<small>This prototype runs on your computer. The test client creates the secure
connection request needed to begin sign-in.</small>''')

    async def metadata(self, request):
        return JSONResponse({"issuer": self.base, "authorization_endpoint": self.base + "/authorize",
            "token_endpoint": self.base + "/token", "revocation_endpoint": self.base + "/revoke",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE]}, headers=self.headers)

    async def authorize(self, request):
        self.cleanup()
        params = dict(request.query_params)
        if (len(request.query_params.multi_items()) != len(params)
                or params.get("client_id") not in self.store.clients
                or params.get("redirect_uri") not in self.store.clients.get(params.get("client_id"), ())
                or params.get("resource") != self.resource or params.get("response_type") != "code"
                or params.get("scope") != SCOPE or params.get("code_challenge_method") != "S256"
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.get("code_challenge", ""))
                or not 16 <= len(params.get("state", "")) <= 512):
            return self.page("Connection request rejected", "<p>Unregistered client, callback or invalid request.</p>", 400)
        if len(self.flows) >= 100 or len(self.browsers) >= 100:
            return self.page("Please try again later", "<p>Local connection limit reached.</p>", 429)
        key, browser = self.browser(request)
        raw_cookie = None
        if browser is None:
            raw_cookie = secrets.token_urlsafe(32)
            key = digest(raw_cookie)
            self.browsers[key] = Browser(secrets.token_urlsafe(32), time.time() + 3600)
        flow_id = secrets.token_urlsafe(32)
        self.flows[digest(flow_id)] = Flow(key, params, time.time() + 600)
        response = RedirectResponse("/connect?" + urlencode({"flow": flow_id}), status_code=303, headers=self.headers)
        if raw_cookie:
            # Secure cookie is required on hosted HTTPS; this server cannot bind publicly.
            response.set_cookie(COOKIE, raw_cookie, httponly=True, secure=self.secure_cookie, samesite="lax", max_age=3600)
        return response

    def login_page(self, flow_id, browser, message=""):
        action = escape("/connect?" + urlencode({"flow": flow_id}), quote=True)
        return self.page("Connect AccuGPS", f'''<p>Authorize <strong>{escape(self.client_name(flow_id))}</strong> to read devices you choose.</p>
<p><small>This development page runs only on your computer. Your password goes to the AccuGPS login API and is not sent to GPT or Claude.</small></p><p>{escape(message)}</p>
<form method="post" action="{action}"><input type="hidden" name="csrf" value="{browser.csrf}"><input type="hidden" name="action" value="login">
<label>AccuGPS account email<input name="username" type="email" required maxlength="254" autocomplete="username"></label>
<label>Password<input name="password" type="password" required maxlength="4096" autocomplete="current-password"></label><button>Sign in</button></form>''')

    def consent_page(self, flow_id, browser, flow, message=""):
        action = escape("/connect?" + urlencode({"flow": flow_id}), quote=True)
        devices = "".join(f'<label><input type="checkbox" name="device" value="{escape(row["device_id"], quote=True)}"> {escape(str(row.get("alias") or row["device_id"]))} <small>({escape(row["device_id"])})</small></label>' for row in flow.devices)
        return self.page("Choose devices to share", f'''<p><strong>{escape(self.client_name(flow_id))}</strong> requests read-only access to locations, trips and alerts for selected devices.</p>
<p>Approved results will be available to the connected client. The callback is <code>{escape(flow.params["redirect_uri"])}</code>.</p><p>{escape(message)}</p>
<form method="post" action="{action}"><input type="hidden" name="csrf" value="{browser.csrf}">{devices}
<label><input type="checkbox" name="camera_metadata" value="on"> Also allow camera recorder status and recording metadata for selected devices. No video, audio, playback URLs or live streams.</label>
<button name="action" value="approve">Approve selected devices</button><button name="action" value="cancel">Cancel</button></form>''')

    async def connect(self, request):
        key, browser = self.browser(request)
        flow_id = request.query_params.get("flow", "")
        flow = self.flows.get(digest(flow_id))
        if not browser or not flow or flow.browser_key != key:
            return self.page("Connection expired", "<p>Start a new connection from your client.</p>", 400)
        if request.method == "GET":
            return self.consent_page(flow_id, browser, flow) if flow.account else self.login_page(flow_id, browser)
        try:
            form = await self.form(request, browser=browser)
        except (ValueError, UnicodeError):
            return self.page("Request rejected", "<p>Invalid browser request.</p>", 403)
        if flow.busy:
            return self.page("Please wait", "<p>A request is already running.</p>", 409)
        if form.get("action") == "cancel":
            self.flows.pop(digest(flow_id), None)
            return RedirectResponse(self.callback(flow, {"error": "access_denied", "state": flow.params["state"]}), status_code=303, headers=self.headers)
        flow.busy = True
        try:
            if form.get("action") == "login" and flow.account is None:
                if flow.attempts >= 5 or len(self.login_times) >= 20:
                    return self.page("Please try again later", "<p>Sign-in attempt limit reached.</p>", 429)
                username, password = form.get("username", "").strip(), form.pop("password", "")
                if not username or len(username) > 254 or not password or len(password) > 4096:
                    return self.login_page(flow_id, browser, "Enter your account email and password.")
                flow.attempts += 1
                self.login_times.append(time.time())
                try:
                    account = await run_in_threadpool(self.account_factory, username, password)
                    devices = await run_in_threadpool(account.list_devices)
                except Exception:
                    return self.login_page(flow_id, browser, "Sign-in or device lookup failed. Check your account details and try again.")
                finally:
                    password = None
                flow.account, flow.devices, flow.subject = account, devices, digest(username.casefold())
                browser.csrf = secrets.token_urlsafe(32)
                return self.consent_page(flow_id, browser, flow)
            if form.get("action") == "approve" and flow.account is not None:
                selected = form.get("device", [])
                if not selected or not set(selected).issubset({row["device_id"] for row in flow.devices}):
                    return self.consent_page(flow_id, browser, flow, "Choose at least one listed device.")
                try:
                    grant_id, code = await run_in_threadpool(self.store.approve, client_id=flow.params["client_id"],
                        redirect_uri=flow.params["redirect_uri"], subject=flow.subject, account_client=flow.account,
                        device_ids=selected, challenge=flow.params["code_challenge"], audience=self.resource,
                        camera_metadata=form.get("camera_metadata") == "on")
                except Exception:
                    return self.consent_page(flow_id, browser, flow, "Permissions could not be verified. Start again if access changed.")
                # Recheck browser/flow lifetime after a slow upstream request.
                if flow.expires <= time.time() or browser.expires <= time.time():
                    await run_in_threadpool(self.store.disconnect, subject=flow.subject, grant_id=grant_id)
                    return self.page("Connection expired", "<p>Please start again.</p>", 400)
                browser.grants[grant_id] = flow.subject
                browser.grant_labels[grant_id] = self.client_names.get(flow.params["client_id"], "Registered client")
                self.flows.pop(digest(flow_id), None)
                return RedirectResponse(self.callback(flow, {"code": code, "state": flow.params["state"]}), status_code=303, headers=self.headers)
            return self.page("Request rejected", "<p>Invalid connection step.</p>", 400)
        finally:
            flow.busy = False

    async def token(self, request):
        try:
            form = await self.form(request)
            if form.get("grant_type") != "authorization_code":
                raise AuthorizationDenied("Unsupported grant")
            token, expires = await run_in_threadpool(self.store.exchange, code=form.get("code", ""), client_id=form.get("client_id", ""),
                redirect_uri=form.get("redirect_uri", ""), verifier=form.get("code_verifier", ""), audience=form.get("resource", ""))
            return JSONResponse({"access_token": token, "token_type": "Bearer", "expires_in": max(0, int(expires - time.time())), "scope": SCOPE}, headers=self.headers)
        except (ValueError, UnicodeError):
            return JSONResponse({"error": "invalid_grant"}, status_code=400, headers=self.headers)

    async def revoke(self, request):
        try:
            form = await self.form(request)
            if form.get("client_id") not in self.store.clients:
                raise AuthorizationDenied("Unknown client")
            try:
                grant = await run_in_threadpool(self.store.resolve, form.get("token", ""), audience=self.resource, client_id=self.client_id)
                await run_in_threadpool(self.store.disconnect, subject=grant.subject, grant_id=grant.grant_id)
            except AuthorizationDenied:
                pass
            return Response(status_code=200, headers=self.headers)
        except (ValueError, UnicodeError):
            return JSONResponse({"error": "invalid_request"}, status_code=400, headers=self.headers)

    async def connections(self, request):
        _, browser = self.browser(request)
        if not browser:
            return self.page("Connections", "<p>No local browser connections. Start from the test client.</p>")
        if request.method == "POST":
            try:
                form = await self.form(request, browser=browser)
                grant_id = form.get("grant", "")
                if grant_id not in browser.grants:
                    raise AuthorizationDenied("Unknown connection")
                await run_in_threadpool(self.store.disconnect, subject=browser.grants.pop(grant_id), grant_id=grant_id)
                browser.grant_labels.pop(grant_id, None)
            except (ValueError, UnicodeError):
                return self.page("Request rejected", "<p>Invalid disconnect request.</p>", 403)
        forms = "".join(f'<form method="post"><input type="hidden" name="csrf" value="{browser.csrf}"><input type="hidden" name="grant" value="{escape(grant_id, quote=True)}"><p>{escape(browser.grant_labels.get(grant_id, "Registered client"))} — read-only</p><button>Disconnect</button></form>' for grant_id in browser.grants)
        return self.page("Your connections", forms or "<p>No connections in this browser session.</p>")

    async def verify_token(self, token):
        try:
            grant, expires = await run_in_threadpool(self.store.token_info, token, audience=self.resource)
            return AccessToken(token=token, client_id=grant.client_id, subject=grant.subject,
                               resource=self.resource, scopes=[SCOPE], expires_at=int(expires))
        except AuthorizationDenied:
            return None

    def current(self):
        token = get_access_token()
        if token is None:
            raise AuthorizationDenied("Authenticated connector token required")
        return token.token

    def app(self):
        gateway = self
        class RequestClient:
            scope = "selected_account_devices"
            def list_devices(self):
                grant = gateway.store.resolve(gateway.current(), audience=gateway.resource)
                return grant.client.list_devices()
            def query(self, device_id, kind, hours=24, end_time=None, **options):
                return gateway.store.query(gateway.current(), audience=gateway.resource, device_id=device_id,
                                           kind=kind, hours=hours, end_time=end_time, **options)
        settings = AuthSettings(issuer_url=self.base, resource_server_url=self.resource,
                                required_scopes=[SCOPE], validate_token_resource=True)
        server = build_server(RequestClient(), self.port, auth=settings, token_verifier=self, transport_security=self.transport_security)
        app = server.streamable_http_app()
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=self.allowed_hosts)
        app.add_middleware(MCPReadGate)
        app.routes.extend([Route("/", self.home),
            Route("/.well-known/oauth-authorization-server", self.metadata),
            Route("/authorize", self.authorize), Route("/connect", self.connect, methods=["GET", "POST"]),
            Route("/token", self.token, methods=["POST"]), Route("/revoke", self.revoke, methods=["POST"]),
            Route("/connections", self.connections, methods=["GET", "POST"])])
        return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8767)
    args = parser.parse_args()
    gateway = LocalGateway(args.port)
    print(f"Local authorization prototype: {gateway.base}; working demo remains on port 8766.")
    try:
        uvicorn.run(gateway.app(), host="127.0.0.1", port=args.port, access_log=False, log_level="warning")
    finally:
        gateway.store.shutdown()
