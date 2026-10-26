"""Synthetic MCP server used only for protocol tests; no AccuGPS login."""
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_server import build_server
from accugps_tools import iso, window


class FixtureClient:
    scope = "synthetic_test_data"

    def list_devices(self):
        return [{"device_id": "test-device", "alias": "Test vehicle", "serial_number": "test-device"}]

    def query(self, device_id, kind, hours=24, end_time=None, **options):
        if device_id != "test-device":
            raise ValueError("Device is outside the test scope")
        start, end = window(hours, end_time)
        t = end - 600
        values = {
            "location": {"latitude": 40, "longitude": -74, "location_time": t, "name": "Test location"},
            "trip": {"total": {"total_distance": 12, "total_driving_time": 600}, "segments": [[
                {"latitude": 40, "longitude": -74, "location_time": t - 1800, "speed": 50},
                {"latitude": 40.1, "longitude": -74.1, "location_time": t, "speed": 60},
            ]], "stopping_points": []},
            "alerts": [{"type": "Fatigue driving (OBD)", "event_time": t, "latitude": 0, "longitude": 0, "note": ""}],
        }
        values["camera-status"] = {"status": 1, "acc_status": 1}
        recording = {"channel": options.get("channel", 2), "start_time": t, "end_time": t + 30, "size": 128, "url": "https://private.example/SECRET", "access_token": "DO_NOT_EXPOSE"}
        values["camera-cloud-recordings"] = [recording]
        values["camera-device-recordings"] = [recording]
        return {"device": self.list_devices()[0], "retrieved_at_utc": iso(int(time.time())),
                "window_start_utc": iso(start), "window_end_utc": iso(end), "data": values[kind]}


if __name__ == "__main__":
    build_server(FixtureClient(), int(sys.argv[2]) if len(sys.argv) > 2 else 8766).run(
        transport=sys.argv[1] if len(sys.argv) > 1 else "stdio")
