"""Session-bound monitoring UI. No durable credentials, footage or location coordinates."""
import asyncio
import copy
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import secrets
import time
from urllib.parse import urlencode

from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from accugps_tools import AccuGPSTools
from authorization_core import AuthorizationDenied, digest, pkce_challenge
from oauth_local import Browser, COOKIE
from dashboard_view import HTML, SCRIPT


def now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Session:
    token: str = field(repr=False)
    refresh: str = field(repr=False)
    cameras: frozenset = field(default_factory=frozenset)
    renew_lock: object = field(default_factory=asyncio.Lock, repr=False)


@dataclass
class Collection:
    rows: dict = field(default_factory=dict)
    started: float = 0
    busy: bool = False
    last_view: float = 0
    error: str = ""


class Dashboard:
    interval = 300

    def __init__(self, gateway):
        self.g = gateway
        self.client_id = "accugps-monitoring-dashboard"
        self.callback_url = gateway.base + "/dashboard/callback"
        gateway.store.clients[self.client_id] = frozenset([self.callback_url])
        gateway.store.client_read_kinds[self.client_id] = frozenset(
            ["location", "camera-status", "camera-cloud-recordings"])
        gateway.client_names[self.client_id] = "Private monitoring dashboard"
        self.pending, self.sessions, self.collections = {}, {}, {}
        self.recording_attempts = {}
        self.tasks = set()
        # One dashboard collector for this small service; browser viewers share cached work.
        self.work_lock = asyncio.Lock()

    def cleanup(self):
        self.g.cleanup()
        self.pending = {s: p for s, p in self.pending.items()
                        if p[2] > time.time() and p[0] in self.g.browsers}
        self.sessions = {k: v for k, v in self.sessions.items() if k in self.g.browsers}
        self.collections = {k: v for k, v in self.collections.items()
                            if v.busy or time.time() - v.last_view < 3600}
        self.recording_attempts = {k: v for k, v in self.recording_attempts.items() if time.time() - v < 300}

    async def identity(self, request):
        self.cleanup()
        key, browser = self.g.browser(request)
        session = self.sessions.get(key)
        if browser is None or session is None:
            raise AuthorizationDenied("Dashboard sign-in required")
        async with session.renew_lock:
            try:
                grant, expiry = await run_in_threadpool(self.g.store.token_info, session.token, audience=self.g.resource)
            except AuthorizationDenied:
                expiry = 0
            if expiry - time.time() < 60:
                token, refresh, _ = await run_in_threadpool(self.g.store.renew, refresh_token=session.refresh,
                    client_id=self.client_id, audience=self.g.resource)
                session.token, session.refresh = token, refresh
                grant = await run_in_threadpool(self.g.store.resolve, session.token, audience=self.g.resource)
        return key, browser, session, grant

    async def start(self, request):
        self.cleanup()
        if len(self.pending) >= 100:
            return Response("Connection limit reached", 429, headers=self.g.headers)
        key, browser = self.g.browser(request)
        raw = None
        if browser is None:
            raw = secrets.token_urlsafe(32)
            key = digest(raw)
            self.g.browsers[key] = Browser(secrets.token_urlsafe(32), time.time() + 3600)
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(40)
        self.pending[state] = (key, verifier, time.time() + 600)
        params = dict(client_id=self.client_id, redirect_uri=self.callback_url, resource=self.g.resource,
                      scope="accugps:read", response_type="code", code_challenge_method="S256",
                      code_challenge=pkce_challenge(verifier), state=state)
        response = RedirectResponse("/authorize?" + urlencode(params), 303, headers=self.g.headers)
        if raw:
            response.set_cookie(COOKIE, raw, httponly=True, secure=True, samesite="lax", max_age=3600)
        return response

    async def callback(self, request):
        self.cleanup()
        key, browser = self.g.browser(request)
        q = request.query_params
        pending = self.pending.get(q.get("state", ""))
        if (not browser or not pending or pending[0] != key or q.get("iss") != self.g.base
                or len(q.multi_items()) != len(dict(q))):
            return self.g.page("Connection rejected", "<p>Start again from the dashboard.</p>", 400)
        self.pending.pop(q["state"], None)
        try:
            token, _ = await run_in_threadpool(self.g.store.exchange, code=q.get("code", ""),
                client_id=self.client_id, redirect_uri=self.callback_url, verifier=pending[1], audience=self.g.resource)
            refresh = await run_in_threadpool(self.g.store.issue_refresh, token, audience=self.g.resource)
            previous = self.sessions.get(key)
            if previous:
                await run_in_threadpool(self.g.store.revoke_token, previous.token,
                                        audience=self.g.resource, client_id=self.client_id)
            self.sessions[key] = Session(token, refresh)
            return RedirectResponse("/dashboard", 303, headers=self.g.headers)
        except ValueError:
            return self.g.page("Connection not completed", '<p><a href="/dashboard">Return to dashboard</a></p>', 400)

    async def home(self, request):
        try:
            await self.identity(request)
        except ValueError:
            return self.g.page("Private fleet monitoring", '''<p>GPS freshness and recorder connectivity for devices you explicitly approve.</p>
<p>Sign in with an invited AccuGPS account. Each team member must sign in separately;
access is based on the AccuGPS account and selected devices, not individual employee roles.</p>
<p><a href="/dashboard/start">Sign in and choose devices</a></p>
<small>Pilot: refreshes while open. Sessions and history are temporary. Camera metadata does not verify images or auxiliary camera placement.</small>''')
        headers = dict(self.g.headers)
        headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
            "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        return HTMLResponse(HTML, headers=headers)

    async def script(self, request):
        return Response(SCRIPT, media_type="application/javascript", headers=self.g.headers)

    def group(self, grant, session):
        return (grant.subject, grant.client.allowed_devices, grant.camera_metadata, session.cameras)

    def collection(self, grant, session):
        key = self.group(grant, session)
        if key not in self.collections:
            if len(self.collections) >= 100:
                raise AuthorizationDenied("Monitoring capacity reached")
            self.collections[key] = Collection()
        result = self.collections[key]
        result.last_view = time.time()
        return result

    def spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def tools(self, session):
        g = self.g
        class Client:
            scope = "selected_account_devices"
            def query(self, device_id, kind, hours=24, end_time=None, **options):
                return g.store.query(session.token, audience=g.resource, device_id=device_id,
                                     kind=kind, hours=hours, end_time=end_time, **options)
        return AccuGPSTools(Client())

    def event(self, row, check, outcome):
        history = row.setdefault("history", [])
        history.insert(0, {"at_utc": now(), "check": check, "outcome": outcome})
        del history[20:]

    async def collect(self, session, grant, collection):
        try:
            async with self.work_lock:
                collection.error = ""
                # A live grant is required even if this job waited behind another account.
                await run_in_threadpool(self.g.store.resolve, session.token, audience=self.g.resource)
                tools = self.tools(session)
                devices = await run_in_threadpool(grant.client.list_devices)
                devices = devices[:50]
                allowed = {d["device_id"] for d in devices}
                collection.rows = {k: v for k, v in collection.rows.items() if k in allowed}
                for device in devices:
                    identifier = device["device_id"]
                    row = collection.rows.setdefault(identifier, {"device_id": identifier})
                    row["alias"] = str(device.get("alias") or identifier)[:200]
                    for check, method in [("gps", tools.get_latest_location), ("recorder", tools.get_camera_status)]:
                        if check == "recorder" and identifier not in session.cameras:
                            continue
                        try:
                            result = await run_in_threadpool(method, identifier)
                            if check == "gps":
                                loc = result["location"]
                                value = {"reported_at_utc": loc["reported_at_utc"],
                                         "valid_coordinate_bounds": loc["valid_coordinate_bounds"]}
                                previous = row.get(check, {}).get("last_success", {}).get("reported_at_utc")
                                value["timestamp_change"] = ("first_observation" if previous is None else
                                    "advanced" if loc["reported_at_utc"] and loc["reported_at_utc"] > previous else
                                    "unchanged" if loc["reported_at_utc"] == previous else "regressed_or_missing")
                            else:
                                value = {k: result[k] for k in ("recorder_status", "ignition_status", "source_status_timestamp_utc")}
                            row[check] = {"check_state": "success", "checked_at_utc": now(), "last_success": value}
                            self.event(row, check, "Read succeeded")
                        except AuthorizationDenied:
                            collection.rows.clear()
                            collection.error = "Access expired or was revoked. Sign in again."
                            return
                        except Exception:
                            old = row.get(check, {})
                            row[check] = {**old, "check_state": "request_failed", "attempted_at_utc": now()}
                            self.event(row, check, "API check failed; device condition unverified")
        except Exception:
            # No raw upstream exception, URL or credentials may enter the browser or logs.
            collection.rows.clear()
            collection.error = "Inventory check failed. No monitoring verdict is available."
        finally:
            collection.busy = False
            collection.started = time.time()

    async def data(self, request):
        try:
            _, browser, session, grant = await self.identity(request)
            collection = self.collection(grant, session)
            # Cached observations never bypass a viewer's current upstream device access.
            # This single inventory read is per viewer; unit telemetry remains shared.
            try:
                current = {d["device_id"] for d in await run_in_threadpool(grant.client.list_devices)}
            except Exception:
                return JSONResponse({"error": "Current device access could not be verified. No observations are displayed."},
                                    503, headers=self.g.headers)
            await run_in_threadpool(self.g.store.resolve, session.token, audience=self.g.resource)
            if not collection.busy and time.time() - collection.started >= self.interval:
                collection.busy, collection.started = True, time.time()
                self.spawn(self.collect(session, grant, collection))
            return JSONResponse({"rows": [row for identifier, row in collection.rows.items() if identifier in current], "collecting": collection.busy,
                "csrf": browser.csrf, "camera_consent": grant.camera_metadata,
                "camera_devices": sorted(session.cameras), "refresh_seconds": self.interval,
                "server_time_utc": now(), "expires_at_utc": datetime.fromtimestamp(grant.expires_at, timezone.utc).isoformat(),
                "collection_error": collection.error,
                "device_count": len(grant.client.allowed_devices), "device_limit": 50}, headers=self.g.headers)
        except ValueError:
            return JSONResponse({"error": "Sign in again; dashboard session expired or access was revoked."}, 401, headers=self.g.headers)

    async def action(self, request):
        try:
            key, browser, session, grant = await self.identity(request)
            form = await self.g.form(request, browser=browser)
            action = form.get("action")
            if action == "disconnect":
                await run_in_threadpool(self.g.store.revoke_token, session.token,
                                        audience=self.g.resource, client_id=self.client_id)
                self.sessions.pop(key, None)
                return JSONResponse({"disconnected": True}, headers=self.g.headers)
            collection = self.collection(grant, session)
            if collection.busy or self.work_lock.locked():
                return JSONResponse({"error": "Checks are running; try again when finished."}, 409, headers=self.g.headers)
            if action == "configure":
                cameras = frozenset(form.get("device", []))
                if (not cameras.issubset(grant.client.allowed_devices)
                        or (cameras and not grant.camera_metadata)):
                    raise AuthorizationDenied("Selected camera permissions required")
                if cameras != session.cameras:
                    session.cameras = cameras
                    updated = self.collection(grant, session)
                    if not updated.rows:
                        updated.rows = copy.deepcopy(collection.rows)
                        for identifier, row in updated.rows.items():
                            if identifier not in cameras:
                                row.pop("recorder", None)
                                row.pop("recordings", None)
                return JSONResponse({"configured": True}, headers=self.g.headers)
            identifier = form.get("device_id")
            if identifier not in grant.client.allowed_devices:
                raise AuthorizationDenied("Device not approved")
            if action == "recordings" and identifier in session.cameras and grant.camera_metadata:
                row = collection.rows.get(identifier)
                if row is None:
                    raise AuthorizationDenied("Wait for the first status check")
                attempt_key = (grant.subject, identifier)
                last = self.recording_attempts.get(attempt_key, 0)
                if time.time() - last < 300:
                    return JSONResponse({"error": "Recording checks are limited to once per unit per five minutes."}, 429, headers=self.g.headers)
                # Deliberately cloud metadata only; no live stream, upload or footage retrieval.
                collection.busy = True
                self.recording_attempts[attempt_key] = time.time()
                row["recordings"] = {"attempt_epoch": time.time(), "check_state": "running"}
                self.spawn(self.recordings(session, collection, row, identifier))
                return JSONResponse({"started": True}, 202, headers=self.g.headers)
            raise AuthorizationDenied("Invalid action")
        except ValueError:
            return JSONResponse({"error": "Request rejected. Check sign-in and selected permissions."}, 403, headers=self.g.headers)

    async def recordings(self, session, collection, row, identifier):
        try:
            async with self.work_lock:
                result = await run_in_threadpool(self.tools(session).get_camera_recordings,
                                                identifier, hours=1, storage="cloud", limit=5)
                # Exact safe projection: never return URLs or arbitrary API fields.
                row["recordings"].update(check_state="success", checked_at_utc=now(),
                    window_start_utc=result.get("window_start_utc"), window_end_utc=result.get("window_end_utc"),
                    observed_channels=result.get("observed_channels", []), matching_records=result.get("matching_records"),
                    rejected_records=result.get("rejected_records"), truncated=result.get("truncated"),
                    note="Cloud metadata only; missing clips do not establish camera failure. Images and installation unverified.")
                self.event(row, "recordings", "Cloud metadata read succeeded; images remain unverified")
        except Exception:
            row["recordings"].update(check_state="request_failed", attempted_at_utc=now())
            self.event(row, "recordings", "Recording API check failed; camera operation unverified")
        finally:
            collection.busy = False

    def install(self, app):
        app.routes.extend([Route("/dashboard", self.home), Route("/dashboard/start", self.start),
            Route("/dashboard/callback", self.callback), Route("/dashboard/data", self.data),
            Route("/dashboard/action", self.action, methods=["POST"]), Route("/dashboard/app.js", self.script)])
        original = app.router.lifespan_context
        @asynccontextmanager
        async def lifespan(application):
            async with original(application):
                try:
                    yield
                finally:
                    for task in self.tasks:
                        task.cancel()
                    await asyncio.gather(*self.tasks, return_exceptions=True)
                    self.sessions.clear()
                    self.collections.clear()
                    self.pending.clear()
                    self.recording_attempts.clear()
        app.router.lifespan_context = lifespan
