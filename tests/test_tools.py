import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_server import FixtureClient
from accugps_connect import ConnectionCheckError
from accugps_tools import AccuGPSTools, AccountClient, BridgeClient, ScopedClient, iso, window


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.tools = AccuGPSTools(FixtureClient())

    def test_scope_and_search(self):
        result = self.tools.list_vehicles("VEHICLE")
        self.assertEqual(result["scope"], "synthetic_test_data")
        self.assertEqual(result["count"], 1)
        self.assertEqual(self.tools.list_vehicles("absent")["count"], 0)

    def test_location_age_and_invalid_fix(self):
        self.assertTrue(self.tools.get_latest_location("test-device")["location"]["valid_coordinate_bounds"])
        result = self.tools.client.query("test-device", "location")
        result["data"].update(latitude=0, longitude=0, location_time=0)
        with patch.object(self.tools.client, "query", return_value=result):
            location = self.tools.get_latest_location("test-device")["location"]
            self.assertFalse(location["valid_coordinate_bounds"])
            self.assertIsNone(location["reported_at_utc"])

    def test_replay_gap_and_point_limit(self):
        result = self.tools.get_trip_history("test-device", max_points=2)
        self.assertNotEqual(result["points"][0]["segment_id"], result["points"][1]["segment_id"])
        client_result = self.tools.client.query("test-device", "trip")
        point = client_result["data"]["segments"][0][1]
        client_result["data"]["segments"][0] = [dict(point, location_time=point["location_time"]-i*10) for i in range(20)]
        with patch.object(self.tools.client, "query", return_value=client_result):
            reduced = self.tools.get_trip_history("test-device", max_points=5)
            self.assertEqual(reduced["returned_point_count"], 5)
            self.assertTrue(reduced["downsampled"])
            self.assertEqual(reduced["api_totals"]["total_distance"], 12)

    def test_missing_alert_location_and_truncation(self):
        result = self.tools.get_alerts("test-device")
        self.assertFalse(result["alerts"][0]["has_usable_location"])
        self.assertIsNone(result["alerts"][0]["latitude"])
        source = self.tools.client.query("test-device", "alerts")
        source["data"] *= 3
        with patch.object(self.tools.client, "query", return_value=source):
            result = self.tools.get_alerts("test-device", limit=1)
            self.assertEqual(result["matching_records"], 3)
            self.assertEqual(result["returned_records"], 1)
            self.assertTrue(result["truncated"])
            self.assertEqual(sum(result["counts_by_type"].values()), 3)

    def test_account_device_authorization_before_read(self):
        client = AccountClient.__new__(AccountClient)
        with patch.object(client, "list_devices", return_value=[{"device_id": "allowed"}]), patch.object(client, "read") as read:
            with self.assertRaises(ValueError):
                client.query("other-account-device", "trip")
            read.assert_not_called()

    def test_revoked_device_is_rechecked_for_every_operation(self):
        client = AccountClient.__new__(AccountClient)
        device = {"device_id": "allowed", "alias": "Synthetic vehicle"}
        with patch.object(client, "list_devices", side_effect=[[device], [], [], []]) as inventory, patch.object(client, "read", return_value={}) as read:
            client.query("allowed", "location")
            read.reset_mock()
            for kind in ("location", "trip", "alerts"):
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "outside"):
                    client.query("allowed", kind)
            read.assert_not_called()
            self.assertEqual(inventory.call_count, 4)

    def test_inventory_failure_never_falls_back_to_old_access(self):
        client = AccountClient.__new__(AccountClient)
        for failure in (ConnectionCheckError("API reported status 401"), ConnectionCheckError("Network unavailable")):
            with self.subTest(failure=str(failure)), patch.object(client, "list_devices", side_effect=failure), patch.object(client, "read") as read:
                with self.assertRaises(ConnectionCheckError):
                    client.query("formerly-allowed", "location")
                read.assert_not_called()

    def test_selected_devices_hide_and_deny_other_authorized_devices(self):
        base = FixtureClient()
        devices = [{"device_id": "test-device", "alias": "Selected"}, {"device_id": "other", "alias": "Not selected"}]
        client = ScopedClient(base, ["test-device"])
        with patch.object(base, "list_devices", return_value=devices), patch.object(base, "query") as query:
            self.assertEqual([row["device_id"] for row in client.list_devices()], ["test-device"])
            for kind in ("location", "trip", "alerts"):
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "selected"):
                    client.query("other", kind)
            query.assert_not_called()
        self.assertEqual(AccuGPSTools(client).get_latest_location("test-device")["scope"], "selected_account_devices")

    def test_selected_device_still_requires_current_upstream_access(self):
        base = FixtureClient()
        client = ScopedClient(base, ["test-device"])
        with patch.object(base, "list_devices", return_value=[]):
            self.assertEqual(client.list_devices(), [])
        with patch.object(base, "query", side_effect=ValueError("Device is outside current account inventory")):
            with self.assertRaisesRegex(ValueError, "account"):
                client.query("test-device", "location")
        with self.assertRaises(ValueError):
            ScopedClient(base, [])

    def test_account_rate_limit_retry_is_bounded(self):
        client = AccountClient.__new__(AccountClient)
        client.base, client.token = "https://i.accugps.com", "synthetic-token"
        client._read_lock, client._last_read = threading.Lock(), 0.0
        with patch("accugps_tools.time.sleep") as sleep, patch("accugps_tools.request_json", side_effect=[
            {"status": 429}, {"status": 200, "data": ["ok"]}
        ]) as request:
            self.assertEqual(client.read("/test"), ["ok"])
            self.assertEqual(request.call_count, 2)
            self.assertIn(unittest.mock.call(10), sleep.call_args_list)
        with patch("accugps_tools.time.sleep"), patch("accugps_tools.request_json", return_value={"status": 429}) as request:
            with self.assertRaisesRegex(Exception, "rate limit persisted"):
                client.read("/test")
            self.assertEqual(request.call_count, 3)
        with patch("accugps_tools.time.sleep"), patch("accugps_tools.request_json", return_value={"status": 403}) as request:
            with self.assertRaisesRegex(Exception, "403"):
                client.read("/test")
            self.assertEqual(request.call_count, 1)

    def test_bridge_device_authorization_before_query(self):
        client = BridgeClient()
        with patch.object(client, "list_devices", return_value=[{"device_id": "allowed"}]), patch.object(client, "read") as read:
            with self.assertRaises(ValueError):
                client.query("other-device", "alerts")
            read.assert_not_called()

    def test_explicit_timezone_and_history_limits(self):
        for hours, end in [(169, None), (24, "2026-10-01T00:00:00"), (24, iso(int(time.time())+86400)), (168, iso(int(time.time())-89*86400))]:
            with self.subTest(hours=hours, end=end), self.assertRaises(ValueError):
                window(hours, end)


if __name__ == "__main__":
    unittest.main()
