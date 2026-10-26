import asyncio
import re
import secrets
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from authorization_core import digest, pkce_challenge
from oauth_remote import CALLBACKS, RemoteGateway
from test_oauth_local import SyntheticAccount


class RemoteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls = []
        def account(email, password):
            self.calls.append(email)
            return SyntheticAccount(email, password)
        self.gateway = RemoteGateway("https://pilot.example.com", invite_hash=digest("synthetic-invite"),
                                     allowed_emails=["account-a", "account-b"], account_factory=account)
        self.app = self.gateway.app()
        self.ready, self.stop = asyncio.Event(), asyncio.Event()
        async def lifespan():
            async with self.app.router.lifespan_context(self.app):
                self.ready.set()
                await self.stop.wait()
        self.task = asyncio.create_task(lifespan())
        await self.ready.wait()
        self.http = self.client()

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                 base_url=self.gateway.base, trust_env=False)

    async def asyncTearDown(self):
        await self.http.aclose()
        self.stop.set()
        await self.task
        self.gateway.store.shutdown()

    def csrf(self, page):
        return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)

    async def start(self, client, callback):
        registered = await client.post("/register", json={"redirect_uris": [callback],
            "client_name": "<script>evil label</script>", "token_endpoint_auth_method": "none"})
        self.assertEqual(registered.status_code, 201)
        verifier = secrets.token_urlsafe(40)
        params = {"client_id": registered.json()["client_id"], "redirect_uri": callback,
            "resource": self.gateway.resource, "scope": "accugps:read", "response_type": "code",
            "code_challenge_method": "S256", "code_challenge": pkce_challenge(verifier),
            "state": secrets.token_urlsafe(24)}
        response = await client.get("/authorize", params=params)
        self.assertEqual(response.status_code, 303)
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        path = response.headers["location"]
        login = await client.get(path)
        self.assertIn('name="pilot_code"', login.text)
        self.assertNotIn("evil label", login.text)
        return path, login, params, verifier

    async def connect(self, client, callback, owner="account-a"):
        path, login, params, verifier = await self.start(client, callback)
        consent = await client.post(path, data={"csrf": self.csrf(login), "action": "login",
            "pilot_code": "synthetic-invite", "username": owner, "password": "synthetic-password"},
            headers={"Origin": self.gateway.base})
        self.assertEqual(consent.status_code, 200)
        self.assertIn("Choose devices", consent.text)
        self.assertNotIn("synthetic-password", consent.text)
        self.assertNotIn("synthetic-invite", consent.text)
        approved = await client.post(path, data={"csrf": self.csrf(consent), "action": "approve",
            "device": owner + "-a"}, headers={"Origin": self.gateway.base})
        self.assertEqual(approved.status_code, 303)
        returned = parse_qs(urlsplit(approved.headers["location"]).query)
        self.assertEqual(returned["iss"], [self.gateway.base])
        self.assertEqual(returned["state"], [params["state"]])
        data = {"client_id": params["client_id"], "redirect_uri": callback, "resource": self.gateway.resource,
                "grant_type": "authorization_code", "code": returned["code"][0], "code_verifier": verifier}
        wrong = await client.post("/token", data={**data, "code_verifier": "x" * 43})
        self.assertEqual(wrong.status_code, 400)
        response = await client.post("/token", data=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await client.post("/token", data=data)).status_code, 400)
        self.last_tokens, self.last_params = response.json(), params
        return response.json()["access_token"]

    async def test_refresh_scope_binding_and_revocation(self):
        await self.connect(self.http, next(iter(CALLBACKS)))
        data = {"grant_type": "refresh_token", "refresh_token": self.last_tokens["refresh_token"],
                "resource": self.gateway.resource, "client_id": self.last_params["client_id"]}
        for changed in [{"client_id": "other"}, {"resource": "https://evil.example/mcp"}, {"scope": "accugps:write"}]:
            self.assertEqual((await self.http.post("/token", data={**data, **changed})).status_code, 400)
        renewed = await self.http.post("/token", data=data)
        self.assertEqual(renewed.status_code, 200)
        self.assertNotEqual(renewed.json()["refresh_token"], data["refresh_token"])
        self.assertNotIn(renewed.json()["refresh_token"], self.gateway.store._refresh)
        self.assertEqual((await self.http.post("/revoke", data={"token": renewed.json()["refresh_token"],
            "client_id": data["client_id"]})).status_code, 200)
        self.assertIsNone(await self.gateway.verify_token(renewed.json()["access_token"]))
        self.assertEqual((await self.http.post("/token", data={**data,
            "refresh_token": renewed.json()["refresh_token"]})).status_code, 400)

    async def inventory(self, token):
        async with self.client() as http:
            http.headers["Authorization"] = "Bearer " + token
            async with streamable_http_client(self.gateway.resource, http_client=http) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self.assertEqual(len((await session.list_tools()).tools), 7)
                    result = await session.call_tool("list_vehicles", {})
                    self.assertEqual(result.structuredContent["count"], 1)
                    self.assertTrue((await session.call_tool("get_alerts", {"device_id": "account-a-b"})).isError)

    async def test_same_account_two_clients_disconnect_isolated(self):
        callbacks = list(CALLBACKS)
        token_a = await self.connect(self.http, callbacks[0])
        async with self.client() as other:
            token_b = await self.connect(other, callbacks[1])
            await self.inventory(token_a)
            await self.inventory(token_b)
            manage = await self.http.get("/connections")
            grant = re.search(r'name="grant" value="([^"]+)"', manage.text).group(1)
            other_manage = await other.get("/connections")
            forged = await other.post("/connections", data={"csrf": self.csrf(other_manage), "grant": grant},
                                      headers={"Origin": self.gateway.base})
            self.assertEqual(forged.status_code, 403)
            await self.http.post("/connections", data={"csrf": self.csrf(manage), "grant": grant},
                                 headers={"Origin": self.gateway.base})
            self.assertEqual((await self.http.post("/mcp", json={},
                headers={"Authorization": "Bearer " + token_a})).status_code, 401)
            await self.inventory(token_b)

    async def test_invite_account_and_origin_fail_before_upstream(self):
        path, login, _, _ = await self.start(self.http, next(iter(CALLBACKS)))
        data = {"csrf": self.csrf(login), "action": "login", "username": "account-a",
                "password": "synthetic-password", "pilot_code": "synthetic-invite"}
        for changed, origin in [({"pilot_code": "wrong"}, self.gateway.base), ({}, "null"),
                                 ({}, "https://evil.example"), ({"csrf": "wrong"}, self.gateway.base)]:
            response = await self.http.post(path, data={**data, **changed}, headers={"Origin": origin})
            self.assertEqual(response.status_code, 403)
        denied = await self.http.post(path, data={**data, "username": "not-invited"}, headers={"Origin": self.gateway.base})
        self.assertIn("Sign-in or device lookup failed", denied.text)
        self.assertEqual(self.calls, [])
        self.assertTrue(all(flow.account is None for flow in self.gateway.flows.values()))

    async def test_discovery_tls_hosts_and_registration_restrictions(self):
        metadata = (await self.http.get("/.well-known/oauth-authorization-server")).json()
        self.assertTrue(metadata["authorization_response_iss_parameter_supported"])
        self.assertEqual(metadata["registration_endpoint"], self.gateway.base + "/register")
        discovery = (await self.http.get("/.well-known/oauth-protected-resource/mcp")).json()
        self.assertEqual(discovery["resource"], self.gateway.resource)
        self.assertEqual(discovery["authorization_servers"], [self.gateway.base])
        self.assertEqual((await self.http.post("/mcp", json={})).status_code, 401)
        self.assertEqual((await self.http.get("/", headers={"Host": "evil.example"})).status_code, 400)
        self.assertEqual((await self.http.get("http://pilot.example.com/" )).status_code, 400)
        for data in [{"redirect_uris": ["https://evil.example/callback"]},
                     {"redirect_uris": ["http://127.0.0.1:9876/callback"]},
                     {"redirect_uris": list(CALLBACKS)},
                     {"redirect_uris": [next(iter(CALLBACKS))], "grant_types": ["refresh_token"]},
                     {"redirect_uris": [next(iter(CALLBACKS))], "scope": "accugps:write"}]:
            self.assertEqual((await self.http.post("/register", json=data)).status_code, 400)
        duplicate = await self.http.post("/register", content='{"redirect_uris":[],"redirect_uris":[]}',
                                        headers={"Content-Type": "application/json"})
        self.assertEqual(duplicate.status_code, 400)
        large = await self.http.post("/register", content="x" * 4097, headers={"Content-Type": "application/json"})
        self.assertEqual(large.status_code, 400)
        home = await self.http.get("/")
        self.assertNotIn("127.0.0.1", home.headers["content-security-policy"])
        self.assertEqual(home.headers["referrer-policy"], "strict-origin")

    async def test_cancel_issuer_and_client_stability_after_restart(self):
        path, login, params, _ = await self.start(self.http, next(iter(CALLBACKS)))
        canceled = await self.http.post(path, data={"csrf": self.csrf(login), "action": "cancel"},
                                        headers={"Origin": self.gateway.base})
        returned = parse_qs(urlsplit(canceled.headers["location"]).query)
        self.assertEqual(returned["iss"], [self.gateway.base])
        self.assertEqual(returned["error"], ["access_denied"])
        second = RemoteGateway(self.gateway.base, invite_hash=digest("synthetic-invite"), allowed_emails=["account-a"])
        self.assertIn(params["client_id"], second.store.clients)
        self.assertFalse(second.store._tokens)

    def test_bad_deployment_configuration(self):
        for base in ["http://pilot.example.com", "https://localhost", "https://127.0.0.1",
                     "https://pilot.example.com/", "https://pilot.example.com/path", "https://pilot.example.com:8443"]:
            with self.assertRaises(ValueError):
                RemoteGateway(base, invite_hash=digest("invite"), allowed_emails=["account-a"])
