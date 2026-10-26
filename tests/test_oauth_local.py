import asyncio
import re
import secrets
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from accugps_tools import window, iso
from authorization_core import pkce_challenge
from oauth_local import LocalGateway


class SyntheticAccount:
    scope = "authenticated_accugps_account"
    def __init__(self, username, password):
        if password != "synthetic-password":
            raise ValueError("Synthetic login rejected")
        self.owner = username
    def list_devices(self):
        return [{"device_id": self.owner + "-a", "alias": "<script>untrusted alias</script>"},
                {"device_id": self.owner + "-b", "alias": "Other device"}]
    def query(self, device_id, kind, hours=24, end_time=None, **options):
        if device_id not in {row["device_id"] for row in self.list_devices()}:
            raise ValueError("Outside synthetic account inventory")
        start, end = window(hours, end_time)
        data = {"segments": [], "stopping_points": [], "total": {"total_distance": 0}} if kind == "trip" else []
        if kind == "location":
            data = {"latitude": 0, "longitude": 0, "location_time": 0}
        if kind == "camera-status":
            data = {"status": 1, "acc_status": 1}
        if kind in {"camera-cloud-recordings", "camera-device-recordings"}:
            data = [{"channel": options.get("channel", 1), "start_time": end - 120,
                     "end_time": end - 60, "size": 123, "url": "https://private.example/SECRET"}]
        return {"device": {"device_id": device_id}, "data": data, "retrieved_at_utc": iso(end),
                "window_start_utc": iso(start), "window_end_utc": iso(end)}


class BrowserAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.gateway = LocalGateway(account_factory=SyntheticAccount)
        self.app = self.gateway.app()
        self.ready, self.stop = asyncio.Event(), asyncio.Event()
        async def lifespan():
            async with self.app.router.lifespan_context(self.app):
                self.ready.set()
                await self.stop.wait()
        self.lifespan_task = asyncio.create_task(lifespan())
        await self.ready.wait()
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=self.gateway.base, trust_env=False)
        self.verifier = "a" * 43

    async def asyncTearDown(self):
        await self.http.aclose()
        self.stop.set()
        await self.lifespan_task
        self.gateway.store.shutdown()

    async def begin(self, client=None, **overrides):
        client = client or self.http
        params = {"client_id": self.gateway.client_id, "redirect_uri": self.gateway.redirect,
            "resource": self.gateway.resource, "response_type": "code", "scope": "accugps:read",
            "code_challenge": pkce_challenge(self.verifier), "code_challenge_method": "S256", "state": secrets.token_urlsafe(24)}
        params.update(overrides)
        response = await client.get("/authorize", params=params)
        return response, params

    def csrf(self, response):
        return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)

    async def signin(self, owner="account-a", client=None):
        client = client or self.http
        response, params = await self.begin(client)
        target = response.headers["location"]
        login = await client.get(target)
        consent = await client.post(target, data={"csrf": self.csrf(login), "action": "login",
            "username": owner, "password": "synthetic-password"}, headers={"Origin": self.gateway.base})
        self.assertEqual(consent.status_code, 200)
        return target, consent, params

    async def approve(self, owner="account-a", client=None):
        client = client or self.http
        target, consent, params = await self.signin(owner, client)
        self.assertIn("&lt;script&gt;", consent.text)
        self.assertNotIn("<script>", consent.text)
        redirect = await client.post(target, data={"csrf": self.csrf(consent), "action": "approve", "device": owner + "-a"}, headers={"Origin": self.gateway.base})
        self.assertEqual(redirect.status_code, 303)
        returned = parse_qs(urlsplit(redirect.headers["location"]).query)
        self.assertEqual(returned["state"][0], params["state"])
        return returned["code"][0]

    async def exchange(self, code, **overrides):
        data = {"grant_type": "authorization_code", "client_id": self.gateway.client_id,
                "redirect_uri": self.gateway.redirect, "resource": self.gateway.resource,
                "code": code, "code_verifier": self.verifier}
        data.update(overrides)
        return await self.http.post("/token", data=data)

    async def test_metadata_and_unauthenticated_mcp(self):
        metadata = (await self.http.get("/.well-known/oauth-authorization-server")).json()
        self.assertEqual(metadata["grant_types_supported"], ["authorization_code"])
        self.assertNotIn("registration_endpoint", metadata)
        response = await self.http.post("/mcp", json={})
        self.assertEqual(response.status_code, 401)
        self.assertIn("resource_metadata", response.headers["www-authenticate"])
        discovery = await self.http.get("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(discovery.status_code, 200)
        self.assertEqual(discovery.json()["resource"], self.gateway.resource)

    async def test_csrf_origin_and_cookie_binding_before_login(self):
        response, _ = await self.begin()
        target = response.headers["location"]
        login = await self.http.get(target)
        # Native browser forms need a non-opaque Origin; avoid no-referrer,
        # which sends Origin: null even for same-origin form submissions.
        self.assertEqual(login.headers["referrer-policy"], "strict-origin")
        form = {"csrf": self.csrf(login), "action": "login", "username": "account-a", "password": "synthetic-password"}
        for headers, changes in [({"Origin": "https://evil.example"}, {}), ({"Origin": "null"}, {}), ({"Origin": self.gateway.base}, {"csrf": "wrong"}),
                                 ({"Origin": self.gateway.base}, {"csrf": "\u2603"}), ({}, {})]:
            rejected = await self.http.post(target, data={**form, **changes}, headers=headers)
            self.assertEqual(rejected.status_code, 403)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=self.gateway.base) as other:
            self.assertEqual((await other.get(target)).status_code, 400)
        self.assertTrue(all(flow.account is None for flow in self.gateway.flows.values()))

    async def test_host_body_limits_and_expired_browser_flow(self):
        rejected = await self.http.get("/.well-known/oauth-authorization-server", headers={"Host": "evil.example"})
        self.assertEqual(rejected.status_code, 400)
        rejected = await self.http.post("/token", content="x=" + "a" * 17000, headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(rejected.status_code, 400)
        response, _ = await self.begin()
        target = response.headers["location"]
        next(iter(self.gateway.flows.values())).expires = 0
        self.assertEqual((await self.http.get(target)).status_code, 400)

    async def test_unknown_client_callback_resource_scope_rejected(self):
        for override in [{"client_id": "unknown"}, {"redirect_uri": "https://evil.example/callback"},
                         {"resource": "https://other.example/mcp"}, {"scope": "accugps:write"}]:
            with self.subTest(override=override):
                response, _ = await self.begin(**override)
                self.assertEqual(response.status_code, 400)

    async def test_login_attempt_limit_and_no_secret_echo(self):
        response, _ = await self.begin()
        target = response.headers["location"]
        login = await self.http.get(target)
        for _ in range(5):
            rejected = await self.http.post(target, data={"csrf": self.csrf(login), "action": "login",
                "username": "account-a", "password": "do-not-echo-this"}, headers={"Origin": self.gateway.base})
            self.assertNotIn("do-not-echo-this", rejected.text)
        limited = await self.http.post(target, data={"csrf": self.csrf(login), "action": "login",
            "username": "account-a", "password": "synthetic-password"}, headers={"Origin": self.gateway.base})
        self.assertEqual(limited.status_code, 429)

    async def test_http_pkce_resource_replay_and_refresh_denials(self):
        code = await self.approve()
        self.assertEqual((await self.exchange(code, code_verifier="b" * 43)).status_code, 400)
        self.assertEqual((await self.exchange(code, resource="https://other.example/mcp")).status_code, 400)
        result = await self.exchange(code)
        self.assertEqual(result.status_code, 200)
        self.assertLessEqual(result.json()["expires_in"], 900)
        self.assertNotIn("refresh_token", result.json())
        self.assertEqual((await self.exchange(code)).status_code, 400)
        self.assertEqual((await self.exchange(code, grant_type="refresh_token")).status_code, 400)

    async def test_mcp_selected_device_scope_and_browser_disconnect(self):
        token = (await self.exchange(await self.approve())).json()["access_token"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), headers={"Authorization": "Bearer " + token}) as authenticated:
            async with streamable_http_client(self.gateway.resource, http_client=authenticated) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual(len(tools.tools), 7)
                    listed = await session.call_tool("list_vehicles", {})
                    self.assertEqual(listed.structuredContent["count"], 1)
                    for tool in ("get_latest_location", "get_trip_history", "get_alerts"):
                        self.assertFalse((await session.call_tool(tool, {"device_id": "account-a-a"})).isError)
                        self.assertTrue((await session.call_tool(tool, {"device_id": "account-a-b"})).isError)
        management = await self.http.get("/connections")
        grant = re.search(r'name="grant" value="([^"]+)"', management.text).group(1)
        forged = await self.http.post("/connections", data={"csrf": "wrong", "grant": grant}, headers={"Origin": self.gateway.base})
        self.assertEqual(forged.status_code, 403)
        disconnected = await self.http.post("/connections", data={"csrf": self.csrf(management), "grant": grant}, headers={"Origin": self.gateway.base})
        self.assertEqual(disconnected.status_code, 200)
        rejected = await self.http.post("/mcp", json={}, headers={"Authorization": "Bearer " + token})
        self.assertEqual(rejected.status_code, 401)

    async def test_two_accounts_and_revocation_endpoint(self):
        token_a = (await self.exchange(await self.approve())).json()["access_token"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=self.gateway.base) as other:
            token_b = (await self.exchange(await self.approve("account-b", other))).json()["access_token"]
            management = await self.http.get("/connections")
            grant_a = re.search(r'name="grant" value="([^"]+)"', management.text).group(1)
            browser_b = await other.get("/connections")
            denied = await other.post("/connections", data={"csrf": self.csrf(browser_b), "grant": grant_a}, headers={"Origin": self.gateway.base})
            self.assertEqual(denied.status_code, 403)
        grant_b = self.gateway.store.resolve(token_b, audience=self.gateway.resource)
        self.assertEqual(grant_b.client.allowed_devices, {"account-b-a"})
        self.assertEqual((await self.http.post("/revoke", data={"client_id": self.gateway.client_id, "token": token_a})).status_code, 200)
        self.assertIsNone(await self.gateway.verify_token(token_a))
        self.assertIsNotNone(await self.gateway.verify_token(token_b))

    async def test_changed_inventory_at_approval_and_cancel(self):
        target, consent, params = await self.signin()
        flow = next(iter(self.gateway.flows.values()))
        flow.account.list_devices = lambda: []
        rejected = await self.http.post(target, data={"csrf": self.csrf(consent), "action": "approve", "device": "account-a-a"}, headers={"Origin": self.gateway.base})
        self.assertNotIn("location", rejected.headers)
        self.assertFalse(self.gateway.store._grants)
        canceled = await self.http.post(target, data={"csrf": self.csrf(consent), "action": "cancel"}, headers={"Origin": self.gateway.base})
        self.assertEqual(canceled.status_code, 303)
        query = parse_qs(urlsplit(canceled.headers["location"]).query)
        self.assertEqual(query["error"], ["access_denied"])
        self.assertEqual(query["state"], [params["state"]])
