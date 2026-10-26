"""Invite-only, single-process HTTPS pilot. No database or public deployment implied."""
import hmac
import ipaddress
import json
import logging
import os
import re
import time
from urllib.parse import urlsplit

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.concurrency import run_in_threadpool

from accugps_tools import AccountClient
from authorization_core import AuthorizationDenied, AuthorizationStore, digest
from oauth_local import HEADERS, LocalGateway


CALLBACKS = {
    "https://claude.ai/api/mcp/auth_callback": "Claude callback",
    "https://chatgpt.com/connector_platform_oauth_redirect": "ChatGPT callback",
}


class HTTPSOnly:
    """Reject plaintext rather than redirecting passwords or authenticated calls."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("scheme") != "https":
            # Render's internal health probe carries no credentials.
            if scope["path"] == "/healthz" and scope["method"] in {"GET", "HEAD"}:
                await Response(status_code=200)(scope, receive, send)
            else:
                await Response("HTTPS required", status_code=400)(scope, receive, send)
            return
        await self.app(scope, receive, send)


class RemoteGateway(LocalGateway):
    def __init__(self, base, *, invite_hash, allowed_emails, account_factory=AccountClient,
                 callbacks=None, port=10000):
        parsed = urlsplit(base)
        try:
            ipaddress.ip_address(parsed.hostname or "")
            is_ip = True
        except ValueError:
            is_ip = False
        if (parsed.scheme != "https" or not parsed.hostname or is_ip
                or parsed.hostname == "localhost" or parsed.hostname.endswith(".localhost")
                or parsed.username or parsed.password or parsed.port not in (None, 443)
                or parsed.path or parsed.query or parsed.fragment
                or base != "https://" + parsed.netloc or base != base.lower()):
            raise ValueError("PUBLIC_BASE_URL must be an exact HTTPS hostname origin without a trailing slash")
        if not re.fullmatch(r"[0-9a-f]{64}", invite_hash):
            raise ValueError("PILOT_INVITE_SHA256 must be a SHA-256 hash of a random invite code")
        self.allowed_emails = frozenset(email.strip().casefold() for email in allowed_emails if email.strip())
        if not self.allowed_emails or len(self.allowed_emails) > 10:
            raise ValueError("Set 1-10 explicit pilot account emails")
        self.invite_hash = invite_hash
        self.port, self.base, self.resource = port, base, base + "/mcp"
        callbacks = CALLBACKS if callbacks is None else callbacks
        if not callbacks or len(callbacks) > 10:
            raise ValueError("Set 1-10 exact trusted HTTPS callbacks")
        clients = {}
        self.client_names, self.callback_clients = {}, {}
        for callback, name in callbacks.items():
            AuthorizationStore._validate_url(callback, False)
            uri = urlsplit(callback)
            if uri.query or not uri.path or uri.port not in (None, 443):
                raise ValueError("Pilot callbacks must be exact HTTPS paths without query strings")
            client_id = "pilot-" + digest(callback)[:32]
            clients[client_id] = [callback]
            self.client_names[client_id] = str(name)
            self.callback_clients[callback] = client_id
        self.store = AuthorizationStore(self.resource, clients)
        self.browsers, self.flows, self.login_times, self.registration_times = {}, {}, [], []
        self.secure_cookie = True
        self.allowed_hosts = [parsed.hostname]
        self.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=[parsed.netloc], allowed_origins=[base])
        self.headers = dict(HEADERS)
        self.headers["Strict-Transport-Security"] = "max-age=86400"
        origins = sorted({"https://" + urlsplit(uri).netloc for uri in callbacks})
        self.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' "
            + " ".join(origins) + "; frame-ancestors 'none'; base-uri 'none'")

        def restricted_account(username, password):
            if username.strip().casefold() not in self.allowed_emails:
                raise AuthorizationDenied("Pilot account required")
            return account_factory(username, password)
        self.account_factory = restricted_account

    async def home(self, request):
        return self.page("AccuGPS private connection test", '''
<p>Start the connection from your ChatGPT or Claude connector settings using
this site's <code>/mcp</code> address. You will then sign in, enter your pilot
invite code, and choose which devices to share.</p>
<p>Access is read-only. Locations, trips, alerts and explicitly approved camera
status/recording metadata you request are sent to your
chosen AI service. Only invited test accounts can connect.</p>
<p><a href="/connections">Manage connections and disconnect</a></p>
<small>Test service: sessions expire and are cleared whenever the server restarts.</small>''')

    def login_page(self, flow_id, browser, message=""):
        response = super().login_page(flow_id, browser, message)
        text = response.body.decode("utf-8").replace(
            "This development page runs only on your computer.",
            "This invite-only test gateway temporarily handles your credentials over HTTPS.")
        text = text.replace('<label>Password', '<label>Pilot invite code<input name="pilot_code" '
                            'type="password" required maxlength="256" autocomplete="off"></label><label>Password')
        response.body = text.encode("utf-8")
        response.headers["content-length"] = str(len(response.body))
        return response

    async def form(self, request, *, browser=None):
        form = await super().form(request, browser=browser)
        if browser is not None and form.get("action") == "login":
            invite = form.pop("pilot_code", "")
            if (not isinstance(invite, str) or len(invite) > 256
                    or not hmac.compare_digest(digest(invite), self.invite_hash)):
                raise AuthorizationDenied("Pilot invite required")
        return form

    def callback(self, flow, values):
        return super().callback(flow, {**values, "iss": self.base})

    async def metadata(self, request):
        response = await super().metadata(request)
        data = json.loads(response.body)
        data.update(registration_endpoint=self.base + "/register",
                    grant_types_supported=["authorization_code", "refresh_token"],
                    authorization_response_iss_parameter_supported=True)
        return JSONResponse(data, headers=self.headers)

    async def register(self, request):
        # This deliberately restricted registration endpoint selects an existing
        # public client for one administrator-approved callback. Names supplied
        # by callers never establish their identity or appear on consent pages.
        now = time.time()
        self.registration_times = [stamp for stamp in self.registration_times if stamp > now - 60]
        if len(self.registration_times) >= 20:
            return JSONResponse({"error": "temporarily_unavailable"}, status_code=429, headers=self.headers)
        self.registration_times.append(now)
        try:
            if request.headers.get("origin") not in (None, self.base):
                raise ValueError()
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                raise ValueError()
            raw = bytearray()
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > 4096:
                    raise ValueError()
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError()
                    result[key] = value
                return result
            data = json.loads(raw, object_pairs_hook=unique)
            redirects = data.get("redirect_uris")
            if (not isinstance(redirects, list) or len(redirects) != 1
                    or not isinstance(redirects[0], str) or redirects[0] not in self.callback_clients
                    or data.get("token_endpoint_auth_method", "none") != "none"
                    or not isinstance(data.get("grant_types", ["authorization_code"]), list)
                    or not set(data.get("grant_types", ["authorization_code"])).issubset({"authorization_code", "refresh_token"})
                    or "authorization_code" not in data.get("grant_types", ["authorization_code"])
                    or data.get("response_types", ["code"]) != ["code"]
                    or data.get("scope", "accugps:read") != "accugps:read"):
                raise ValueError()
            return JSONResponse({"client_id": self.callback_clients[redirects[0]],
                "redirect_uris": redirects, "token_endpoint_auth_method": "none",
                "grant_types": data.get("grant_types", ["authorization_code"]), "response_types": ["code"],
                "scope": "accugps:read"}, status_code=201, headers=self.headers)
        except (ValueError, TypeError, AttributeError, UnicodeError):
            return JSONResponse({"error": "invalid_client_metadata"}, status_code=400, headers=self.headers)

    async def token(self, request):
        try:
            form = await self.form(request)
            if form.get("grant_type") == "authorization_code":
                token, expires = await run_in_threadpool(self.store.exchange, code=form.get("code", ""), client_id=form.get("client_id", ""),
                    redirect_uri=form.get("redirect_uri", ""), verifier=form.get("code_verifier", ""),
                    audience=form.get("resource", ""))
                refresh = await run_in_threadpool(self.store.issue_refresh, token, audience=self.resource)
            elif form.get("grant_type") == "refresh_token":
                if form.get("scope", "accugps:read") != "accugps:read":
                    raise AuthorizationDenied("Scope expansion rejected")
                token, refresh, expires = await run_in_threadpool(self.store.renew, refresh_token=form.get("refresh_token", ""),
                    client_id=form.get("client_id", ""), audience=form.get("resource", ""))
            else:
                raise AuthorizationDenied("Unsupported grant")
            return JSONResponse({"access_token": token, "refresh_token": refresh, "token_type": "Bearer",
                "expires_in": max(0, int(expires - time.time())), "scope": "accugps:read"}, headers=self.headers)
        except (ValueError, UnicodeError):
            return JSONResponse({"error": "invalid_grant"}, status_code=400, headers=self.headers)

    async def health(self, request):
        return Response(status_code=200, headers=self.headers)

    async def revoke(self, request):
        try:
            form = await self.form(request)
            if form.get("client_id") not in self.store.clients:
                raise AuthorizationDenied("Unknown client")
            await run_in_threadpool(self.store.revoke_token, form.get("token", ""), audience=self.resource, client_id=form["client_id"])
            return Response(status_code=200, headers=self.headers)
        except (ValueError, UnicodeError):
            return JSONResponse({"error": "invalid_request"}, status_code=400, headers=self.headers)

    async def protected_metadata(self, request):
        # The SDK normalizes an origin URL by adding a slash. RFC 9207 needs
        # the discovery issuer and callback iss to match byte for byte.
        return JSONResponse({"resource": self.resource, "authorization_servers": [self.base],
                             "scopes_supported": ["accugps:read"], "bearer_methods_supported": ["header"]},
                            headers=self.headers)

    def app(self):
        app = super().app()
        app.routes[:] = [route for route in app.routes
                         if getattr(route, "path", None) != "/.well-known/oauth-protected-resource/mcp"]
        app.routes.extend([Route("/register", self.register, methods=["POST"]),
                           Route("/healthz", self.health),
                           Route("/.well-known/oauth-protected-resource/mcp", self.protected_metadata),
                           Route("/.well-known/oauth-protected-resource", self.protected_metadata)])
        app.add_middleware(HTTPSOnly)
        return app


def from_environment():
    callbacks = dict(CALLBACKS)
    if os.environ.get("PILOT_CALLBACKS_JSON"):
        callbacks = json.loads(os.environ["PILOT_CALLBACKS_JSON"])
        if not isinstance(callbacks, dict):
            raise ValueError("PILOT_CALLBACKS_JSON must map exact callbacks to display labels")
    return RemoteGateway(os.environ.get("PUBLIC_BASE_URL", os.environ.get("RENDER_EXTERNAL_URL", "")),
        invite_hash=os.environ.get("PILOT_INVITE_SHA256", ""),
        allowed_emails=os.environ.get("PILOT_ACCOUNT_EMAILS", "").split(","),
        callbacks=callbacks, port=int(os.environ.get("PORT", "10000")))


if __name__ == "__main__":
    # Do not log HTTP URLs, request bodies, tokens or upstream exceptions.
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    gateway = from_environment()
    try:
        # Render terminates TLS and supplies X-Forwarded-Proto. This setting is
        # for Render's isolated service ingress only, not an arbitrary public VM.
        uvicorn.run(gateway.app(), host="0.0.0.0", port=gateway.port, workers=1,
                    proxy_headers=True, forwarded_allow_ips="*", access_log=False, log_level="warning")
    finally:
        gateway.store.shutdown()
