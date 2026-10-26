import asyncio
import json
import re
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx

from authorization_core import digest
from oauth_remote import RemoteGateway
from test_oauth_local import SyntheticAccount


class DashboardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.accounts = []
        class Account(SyntheticAccount):
            fail = False
            def __init__(account, *args):
                super(Account, account).__init__(*args)
                account.calls = []
            def query(account, device_id, kind, *args, **kwargs):
                account.calls.append((device_id, kind))
                if account.fail:
                    raise ValueError("private upstream URL with SECRET")
                result = super(Account, account).query(device_id, kind, *args, **kwargs)
                if kind == "location":
                    import time
                    result["data"] = {"latitude": 40.123, "longitude": -74.456,
                                      "location_time": time.time() - 20, "name": "PRIVATE ADDRESS"}
                return result
        def factory(email, password):
            account = Account(email, password)
            self.accounts.append(account)
            return account
        self.g = RemoteGateway("https://pilot.example.com", invite_hash=digest("synthetic-invite"),
            allowed_emails=["account-a", "account-b"], account_factory=factory)
        self.app = self.g.app()
        self.http = self.client()

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=self.g.base, trust_env=False)

    async def asyncTearDown(self):
        await self.wait_jobs()
        await self.http.aclose()
        self.g.store.shutdown()

    async def wait_jobs(self):
        if self.g.dashboard.tasks:
            await asyncio.gather(*list(self.g.dashboard.tasks))

    def csrf(self, response):
        return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)

    async def sign_in(self, client=None, owner="account-a", camera=True):
        client = client or self.http
        start = await client.get("/dashboard/start")
        authorize = await client.get(start.headers["location"])
        path = authorize.headers["location"]
        login = await client.get(path)
        consent = await client.post(path, data={"csrf": self.csrf(login), "action": "login",
            "pilot_code": "synthetic-invite", "username": owner, "password": "synthetic-password"},
            headers={"Origin": self.g.base})
        fields = {"csrf": self.csrf(consent), "action": "approve", "device": owner + "-a"}
        if camera:
            fields["camera_metadata"] = "on"
        approved = await client.post(path, data=fields, headers={"Origin": self.g.base})
        self.assertEqual(approved.status_code, 303, approved.text)
        callback = approved.headers["location"]
        connected = await client.get(callback)
        self.assertEqual(connected.status_code, 303, connected.text)
        self.assertNotIn("token", connected.headers["location"])
        data = await client.get("/dashboard/data")
        await self.wait_jobs()
        return (await client.get("/dashboard/data")).json()

    async def act(self, data, values, client=None, origin=None):
        return await (client or self.http).post("/dashboard/action", data={"csrf": data["csrf"], **values},
                                               headers={"Origin": origin or self.g.base})

    async def test_private_signin_safe_projection_and_disconnect(self):
        self.assertEqual((await self.http.get("/dashboard/data")).status_code, 401)
        data = await self.sign_in()
        self.assertEqual(len(data["rows"]), 1)
        self.assertIn("account-a-a", json.dumps(data))
        for secret in ["PRIVATE ADDRESS", "40.123", "-74.456", "SECRET", "synthetic-password", "synthetic-invite"]:
            self.assertNotIn(secret, json.dumps(data))
        page = await self.http.get("/dashboard")
        self.assertIn("script-src 'self'", page.headers["content-security-policy"])
        self.assertIn("no-store", page.headers["cache-control"])
        self.assertNotIn("<script>untrusted alias", page.text)
        self.assertEqual((await self.act(data, {"action": "disconnect"})).status_code, 200)
        self.assertEqual((await self.http.get("/dashboard/data")).status_code, 401)

    async def test_csrf_device_scope_and_camera_opt_in(self):
        data = await self.sign_in(camera=False)
        self.assertEqual((await self.act(data, {"action": "configure", "device": "account-a-a"})).status_code, 403)
        self.assertEqual((await self.act(data, {"action": "configure"}, origin="https://evil.example")).status_code, 403)
        self.assertEqual((await self.act({"csrf": "wrong"}, {"action": "disconnect"})).status_code, 403)
        self.assertEqual((await self.act(data, {"action": "recordings", "device_id": "account-b-a"})).status_code, 403)
        self.assertFalse(any(kind.startswith("camera") for _, kind in self.accounts[0].calls))

    async def test_same_scope_shares_collection_different_account_does_not(self):
        first = await self.sign_in()
        async with self.client() as second:
            other = await self.sign_in(second)
            self.assertEqual(first["rows"], other["rows"])
            self.assertEqual(len(self.g.dashboard.collections), 1)
            self.assertEqual(self.accounts[-1].calls, [])
        async with self.client() as third:
            data = await self.sign_in(third, "account-b")
            self.assertNotIn("account-a-a", json.dumps(data))
            self.assertEqual(len(self.g.dashboard.collections), 2)

    async def test_camera_config_recording_metadata_and_failure_preserves_gps(self):
        data = await self.sign_in()
        response = await self.act(data, {"action": "configure", "device": "account-a-a"})
        self.assertEqual(response.status_code, 200)
        await self.http.get("/dashboard/data")
        await self.wait_jobs()
        data = (await self.http.get("/dashboard/data")).json()
        self.assertEqual(data["rows"][0]["recorder"]["last_success"]["recorder_status"], "online")
        response = await self.act(data, {"action": "recordings", "device_id": "account-a-a"})
        self.assertEqual(response.status_code, 202)
        await self.wait_jobs()
        data = (await self.http.get("/dashboard/data")).json()
        self.assertEqual(data["rows"][0]["recordings"]["observed_channels"], [1])
        self.assertNotIn("private.example", json.dumps(data))
        self.assertEqual((await self.act(data, {"action": "recordings", "device_id": "account-a-a"})).status_code, 429)
        previous = data["rows"][0]["gps"]["last_success"]
        self.accounts[0].fail = True
        for collection in self.g.dashboard.collections.values():
            collection.started = 0
        await self.http.get("/dashboard/data")
        await self.wait_jobs()
        data = (await self.http.get("/dashboard/data")).json()
        self.assertEqual(data["rows"][0]["gps"]["last_success"], previous)
        self.assertEqual(data["rows"][0]["gps"]["check_state"], "request_failed")
        self.assertNotIn("SECRET", json.dumps(data))

    async def test_callback_bound_to_browser_one_use_and_not_dcr_registered(self):
        start = await self.http.get("/dashboard/start")
        authorize = await self.http.get(start.headers["location"])
        q = parse_qs(urlsplit(start.headers["location"]).query)
        state = q["state"][0]
        async with self.client() as outsider:
            response = await outsider.get("/dashboard/callback", params={"state": state, "iss": self.g.base})
            self.assertEqual(response.status_code, 400)
        self.assertIn(state, self.g.dashboard.pending)
        response = await self.http.post("/register", json={"redirect_uris": [self.g.dashboard.callback_url]})
        self.assertEqual(response.status_code, 400)
        data = await self.sign_in()
        # Expiration/revocation must deny cached reads as well as new checks.
        self.g.store.shutdown()
        self.assertEqual((await self.http.get("/dashboard/data")).status_code, 401)

    async def test_duplicate_refresh_requests_do_not_duplicate_queries(self):
        await self.sign_in()
        calls = len(self.accounts[0].calls)
        for _ in range(4):
            await self.http.get("/dashboard/data")
        await self.wait_jobs()
        self.assertEqual(len(self.accounts[0].calls), calls)

    async def test_multiple_tabs_renew_once_and_expired_grant_denies_cache(self):
        await self.sign_in()
        session = next(iter(self.g.dashboard.sessions.values()))
        from authorization_core import IssuedToken
        issued = self.g.store._tokens[digest(session.token)]
        self.g.store._tokens[digest(session.token)] = IssuedToken(issued.grant_id, 0)
        replies = await asyncio.gather(self.http.get("/dashboard/data"), self.http.get("/dashboard/data"))
        self.assertEqual([r.status_code for r in replies], [200, 200])
        self.assertEqual(len(self.g.store._spent_refresh), 1)
        self.g.store.clock = lambda: 10**12
        self.assertEqual((await self.http.get("/dashboard/data")).status_code, 401)

    async def test_selections_and_consent_partition_cache(self):
        await self.sign_in()
        async with self.client() as other:
            await self.sign_in(other, camera=False)
            self.assertEqual(len(self.g.dashboard.collections), 2)
        data = (await self.http.get("/dashboard/data")).json()
        # A device present in the account but not selected is still forbidden.
        self.assertEqual((await self.act(data, {"action": "configure", "device": "account-a-b"})).status_code, 403)

    async def test_invalid_invite_cannot_open_dashboard(self):
        start = await self.http.get("/dashboard/start")
        authorize = await self.http.get(start.headers["location"])
        path = authorize.headers["location"]
        login = await self.http.get(path)
        rejected = await self.http.post(path, data={"csrf": self.csrf(login), "action": "login",
            "username": "account-a", "password": "synthetic-password", "pilot_code": "wrong"},
            headers={"Origin": self.g.base})
        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(self.accounts, [])
        self.assertEqual((await self.http.get("/dashboard/data")).status_code, 401)

    async def test_dashboard_token_cannot_request_trips_or_alerts(self):
        await self.sign_in()
        session = next(iter(self.g.dashboard.sessions.values()))
        for kind in ["trip", "alerts", "fuel-summary", "camera-device-recordings"]:
            with self.assertRaises(ValueError):
                self.g.store.query(session.token, audience=self.g.resource, device_id="account-a-a", kind=kind)

    async def test_cached_observations_recheck_upstream_device_permissions(self):
        await self.sign_in()
        self.accounts[0].list_devices = lambda: []
        data = (await self.http.get("/dashboard/data")).json()
        self.assertEqual(data["rows"], [])
        def unavailable():
            raise ValueError("upstream private details")
        self.accounts[0].list_devices = unavailable
        response = await self.http.get("/dashboard/data")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private details", response.text)
