import asyncio
import json
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from starlette.responses import Response

from accugps_connect import ConnectionCheckError
from accugps_tools import AccountClient, AccuGPSTools, ScopedClient
from authorization_core import AuthorizationDenied
from fixture_server import FixtureClient
from oauth_local import MCPReadGate
import test_oauth_local as browser_tests


class CameraTests(unittest.TestCase):
    def setUp(self):
        self.client = FixtureClient()
        self.tools = AccuGPSTools(self.client)

    def test_status_unknown_values_and_no_source_timestamp(self):
        status = self.tools.get_camera_status("test-device")
        self.assertEqual(status["recorder_status"], "online")
        self.assertIsNone(status["source_status_timestamp_utc"])
        self.assertFalse(status["camera_image_verified"])
        raw = self.client.query("test-device", "camera-status")
        raw["data"] = {"status": "1", "acc_status": True, "url": "SECRET"}
        with patch.object(self.client, "query", return_value=raw):
            status = self.tools.get_camera_status("test-device")
        self.assertEqual(status["recorder_status"], "unknown")
        self.assertEqual(status["ignition_status"], "unknown")
        self.assertNotIn("SECRET", json.dumps(status))

    def test_recordings_redact_sensitive_fields_and_preserve_counts(self):
        raw = self.client.query("test-device", "camera-cloud-recordings")
        raw["data"] *= 3
        with patch.object(self.client, "query", return_value=raw):
            result = self.tools.get_camera_recordings("test-device", channel=2, limit=1)
        self.assertEqual(result["matching_records"], 3)
        self.assertEqual(result["returned_records"], 1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["observed_channels"], [2])
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(result))

    def test_invalid_records_and_out_of_window_data_do_not_count(self):
        raw = self.client.query("test-device", "camera-cloud-recordings")
        row = raw["data"][0]
        raw["data"] = [None, {**row, "channel": True}, {**row, "size": -1},
                       {**row, "end_time": row["start_time"] - 1},
                       {**row, "start_time": 1, "end_time": 2}]
        with patch.object(self.client, "query", return_value=raw):
            result = self.tools.get_camera_recordings("test-device")
        self.assertEqual(result["matching_records"], 0)
        self.assertEqual(result["rejected_records"], 4)
        self.assertFalse(result["camera_image_verified"])

    def test_invalid_arguments_make_no_requests(self):
        with patch.object(self.client, "query") as query:
            for options in [{"storage": "live"}, {"storage": "device"}, {"channel": True},
                            {"channel": 17}, {"hours": 25}, {"limit": 501},
                            {"end_time": "2026-10-01T12:00:00"}]:
                with self.subTest(options=options), self.assertRaises(ValueError):
                    self.tools.get_camera_recordings("test-device", **options)
            for channels in [[], [1, 1], [True], [1, 2, 3, 4]]:
                with self.assertRaises(ValueError):
                    self.tools.check_camera_channels("test-device", channels)
            query.assert_not_called()

    def test_scope_checked_before_camera_request(self):
        tools = AccuGPSTools(ScopedClient(self.client, ["test-device"]))
        with patch.object(self.client, "query") as query:
            for method in [tools.get_camera_status, tools.get_camera_recordings]:
                with self.assertRaisesRegex(ValueError, "selected"):
                    method("outside")
            query.assert_not_called()

    def test_only_documented_passive_routes_and_current_inventory_used(self):
        client = AccountClient.__new__(AccountClient)
        device = {"device_id": "camera/one", "alias": "Synthetic camera"}
        with patch.object(client, "list_devices", return_value=[device]), patch.object(client, "read", return_value=[]) as read:
            client.query("camera/one", "camera-status", 1)
            self.assertEqual(read.call_args.args[0], "/api/open/v1/devices/camera%2Fone/status")
            client.query("camera/one", "camera-cloud-recordings", 1)
            self.assertEqual(urlsplit(read.call_args.args[0]).path, "/api/open/v1/devices/camera%2Fone/cloud_video_list")
            client.query("camera/one", "camera-device-recordings", 1, channel=3)
            path = read.call_args.args[0]
            self.assertEqual(urlsplit(path).path, "/api/open/v1/devices/camera%2Fone/videos")
            self.assertEqual(parse_qs(urlsplit(path).query)["channel"], ["3"])
            read.reset_mock()
            with self.assertRaises(ValueError):
                client.query("outside", "camera-status", 1)
            read.assert_not_called()

    def test_channel_checks_are_sequential_and_stop_on_failure(self):
        active = []
        original = self.client.query
        def query(device_id, kind, *args, **kwargs):
            active.append(kind)
            if kind == "camera-device-recordings":
                raise ConnectionCheckError("Network timeout")
            return original(device_id, kind, *args, **kwargs)
        with patch.object(self.client, "query", side_effect=query):
            result = self.tools.check_camera_channels("test-device", [1, 2, 3])
        self.assertEqual(active, ["camera-status", "camera-device-recordings"])
        self.assertEqual(result["channels"][0]["assessment"], "unable_to_verify_request_failed")
        self.assertEqual(result["channels"][1]["assessment"], "not_checked_after_request_failure")
        self.assertFalse(result["installation_layout_confirmed"])

    def test_offline_recorder_does_not_trigger_channel_queries(self):
        raw = self.client.query("test-device", "camera-status")
        raw["data"] = {"status": 0, "acc_status": 0}
        with patch.object(self.client, "query", return_value=raw) as query:
            result = self.tools.check_camera_channels("test-device", [1, 2, 3])
        self.assertEqual(query.call_count, 1)
        self.assertTrue(all(row["assessment"] == "not_checked_recorder_not_confirmed_online" for row in result["channels"]))


class CameraConsentTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = browser_tests.BrowserAuthTests.asyncSetUp
    asyncTearDown = browser_tests.BrowserAuthTests.asyncTearDown
    begin = browser_tests.BrowserAuthTests.begin
    csrf = browser_tests.BrowserAuthTests.csrf
    signin = browser_tests.BrowserAuthTests.signin
    approve = browser_tests.BrowserAuthTests.approve
    exchange = browser_tests.BrowserAuthTests.exchange

    async def test_camera_opt_in_enforced_on_browser_grant(self):
        target, consent, params = await self.signin()
        self.assertIn('name="camera_metadata"', consent.text)
        for selected in [False, True]:
            if selected:
                target, consent, params = await self.signin()
            form = {"csrf": self.csrf(consent), "action": "approve", "device": "account-a-a"}
            if selected:
                form["camera_metadata"] = "on"
            response = await self.http.post(target, data=form, headers={"Origin": self.gateway.base})
            code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
            token = (await self.exchange(code)).json()["access_token"]
            if selected:
                result = self.gateway.store.query(token, audience=self.gateway.resource,
                    device_id="account-a-a", kind="camera-status")
                self.assertEqual(result["data"]["status"], 1)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), headers={"Authorization": "Bearer " + token}) as http:
                    async with browser_tests.streamable_http_client(self.gateway.resource, http_client=http) as (read, write, _):
                        async with browser_tests.ClientSession(read, write) as session:
                            await session.initialize()
                            for tool, options in [("get_camera_status", {}), ("get_camera_recordings", {}),
                                                  ("check_camera_channels", {"channels": [1, 2, 3]})]:
                                response = await session.call_tool(tool, {"device_id": "account-a-a", **options})
                                self.assertFalse(response.isError)
                                self.assertNotIn("SECRET", json.dumps(response.structuredContent))
                            denied = await session.call_tool("get_camera_status", {"device_id": "account-a-b"})
                            self.assertTrue(denied.isError)
                with self.assertRaises(ValueError):
                    self.gateway.store.query(token, audience=self.gateway.resource,
                        device_id="account-a-b", kind="camera-status")
                # Revoke the camera-enabled grant directly; all camera access must stop.
                grant = self.gateway.store.resolve(token, audience=self.gateway.resource)
                self.gateway.store.disconnect(subject=grant.subject, grant_id=grant.grant_id)
                with self.assertRaises(AuthorizationDenied):
                    self.gateway.store.query(token, audience=self.gateway.resource,
                        device_id="account-a-a", kind="camera-status")
            else:
                with self.assertRaisesRegex(AuthorizationDenied, "explicitly approve"):
                    self.gateway.store.query(token, audience=self.gateway.resource,
                        device_id="account-a-a", kind="camera-status")

    async def test_auth_verification_does_not_block_event_loop_on_store_lock(self):
        token = (await self.exchange(await self.approve())).json()["access_token"]
        acquired, release = threading.Event(), threading.Event()
        def hold_lock():
            with self.gateway.store._lock:
                acquired.set()
                release.wait(3)
        worker = threading.Thread(target=hold_lock)
        worker.start()
        try:
            await asyncio.to_thread(acquired.wait, 1)
            verification = asyncio.create_task(self.gateway.verify_token(token))
            # A second loop task must run before the store lock is released.
            await asyncio.wait_for(asyncio.sleep(0.05), timeout=1)
            self.assertFalse(verification.done())
            release.set()
            self.assertIsNotNone(await verification)
        finally:
            release.set()
            await asyncio.to_thread(worker.join)


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def test_overlapping_mcp_request_rejected_but_health_remains_available(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def endpoint(scope, receive, send):
            if scope["path"] == "/mcp":
                started.set()
                await release.wait()
            await Response("ok")(scope, receive, send)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=MCPReadGate(endpoint)), base_url="https://pilot.example") as client:
            first = asyncio.create_task(client.post("/mcp"))
            await started.wait()
            try:
                second = await asyncio.wait_for(client.post("/mcp"), timeout=1)
                self.assertEqual(second.status_code, 429)
                self.assertEqual(second.headers["retry-after"], "5")
                self.assertEqual((await asyncio.wait_for(client.get("/healthz"), timeout=1)).status_code, 200)
            finally:
                release.set()
                await first
