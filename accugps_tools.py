"""Shared data clients and bounded, source-labelled results for MCP tools."""

from collections import Counter
from datetime import datetime, timezone
import json
import math
import threading
import time
from urllib.parse import quote, urlencode
import urllib.error
import urllib.request

from accugps_connect import ConnectionCheckError, check_status, request_json


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def window(hours, end_time=None, max_hours=168):
    if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= max_hours:
        raise ValueError(f"hours must be an integer from 1 to {max_hours}")
    now = int(time.time())
    if end_time:
        try:
            dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            if dt.utcoffset() is None:
                raise ValueError("Time zone required")
            end = int(dt.timestamp())
        except (ValueError, OverflowError, OSError):
            raise ValueError("end_time must be ISO 8601 with an offset, e.g. 2026-10-07T00:00:00-04:00") from None
    else:
        end = now
    start = end - hours * 3600
    if end > now or start < now - 90 * 86400:
        raise ValueError("The entire window must be within the preceding 90 days")
    return start, end


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


class BridgeClient:
    """Uses the existing local login without exposing its AccuGPS token to MCP."""
    scope = "selected_demo_devices"

    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def read(self, path):
        try:
            with self.opener.open("http://127.0.0.1:8765" + path, timeout=75) as response:
                raw = response.read(5_000_001)
            if len(raw) > 5_000_000:
                raise ConnectionCheckError("Bridge response exceeds the size limit")
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise ConnectionCheckError(f"Bridge returned HTTP {exc.code}; check bridge version, token expiry, and query window") from None
        except (urllib.error.URLError, OSError):
            raise ConnectionCheckError("Login bridge unavailable. Run python accugps_bridge.py and sign in locally.") from None
        except (ValueError, UnicodeError):
            raise ConnectionCheckError("Bridge returned invalid JSON") from None

    def list_devices(self):
        health = self.read("/health")
        devices = health.get("devices")
        if not health.get("ready") or not isinstance(devices, dict):
            raise ConnectionCheckError("Bridge is not ready")
        return [{"device_id": key, "alias": row.get("alias"), "serial_number": row.get("sn")}
                for key, row in devices.items() if isinstance(row, dict)]

    def query(self, device_id, kind, hours=24, end_time=None):
        if device_id not in {d["device_id"] for d in self.list_devices()}:
            raise ValueError("Device is outside this bridge's scope. Use list_vehicles to find an available ID.")
        start, end = window(hours, end_time, 2160 if kind == "fuel-summary" else 168)
        result = self.read("/query?" + urlencode({"device": device_id, "kind": kind, "hours": hours, "end_utc": end}))
        return {"device": result.get("device"), "retrieved_at_utc": iso(result["retrieved_at_utc"]),
                "window_start_utc": iso(start), "window_end_utc": iso(end), "data": result.get("data")}


class AccountClient:
    """Single-account local pilot. Authenticated account inventory limits IDs."""
    scope = "authenticated_accugps_account"

    def __init__(self, username, password):
        self.base = "https://i.accugps.com"
        self._read_lock = threading.Lock()
        self._last_read = 0.0
        result = request_json(self.base, "/api/open/v1/login", {"username": username, "password": password}, timeout=60)
        check_status(result, "login")
        data = result.get("data")
        self.token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(self.token, str) or not self.token:
            raise ConnectionCheckError("Login returned no access token")

    def read(self, path):
        # The API documents 429 as "Frequently Request", without a rate window.
        # Serialize reads and retry only that condition with bounded backoff.
        with self._read_lock:
            for attempt in range(3):
                pause = 2.0 - (time.monotonic() - self._last_read)
                if pause > 0:
                    time.sleep(pause)
                try:
                    result = request_json(self.base, path, token=self.token, timeout=60)
                    limited = str(result.get("status")) == "429"
                except ConnectionCheckError as exc:
                    if not str(exc).endswith(": HTTP 429"):
                        raise
                    limited = True
                finally:
                    self._last_read = time.monotonic()
                if limited:
                    if attempt < 2:
                        time.sleep(10 * (attempt + 1))
                        continue
                    raise ConnectionCheckError("AccuGPS rate limit persisted after two retries; wait before querying again")
                check_status(result, "AccuGPS read")
                return result.get("data")

    def list_devices(self):
        data = self.read("/api/open/v1/trackers")
        if not isinstance(data, list):
            raise ConnectionCheckError("Unexpected tracker list")
        return [{"device_id": row["sn"], "alias": row.get("alias"), "serial_number": row["sn"]}
                for row in data if isinstance(row, dict) and isinstance(row.get("sn"), str) and row["sn"]]

    def query(self, device_id, kind, hours=24, end_time=None):
        matches = [d for d in self.list_devices() if d["device_id"] == device_id]
        if not matches:
            raise ValueError("Device is outside the authenticated account inventory")
        start, end = window(hours, end_time, 2160 if kind == "fuel-summary" else 168)
        sn = quote(device_id, safe="")
        if kind == "fuel-summary":
            path = "/api/open/v1/reports/summaries?" + urlencode({"sn": device_id, "start_time": start, "end_time": end, "statistics_type": 2})
        else:
            suffix = {"trip": "track", "alerts": "alerts", "location": "location"}[kind]
            path = f"/api/open/v1/trackers/{sn}/{suffix}"
            if kind != "location":
                path += "?" + urlencode({"start_time": start, "end_time": end})
        return {"device": matches[0], "retrieved_at_utc": iso(int(time.time())),
                "window_start_utc": iso(start), "window_end_utc": iso(end), "data": self.read(path)}


class ScopedClient:
    """Limit an account session to explicitly selected devices; keep upstream checks."""
    scope = "selected_account_devices"

    def __init__(self, client, allowed_devices):
        selected = frozenset(allowed_devices)
        if not selected or any(not isinstance(item, str) or not item.strip() for item in selected):
            raise ValueError("Select at least one nonempty device ID")
        self.client = client
        self.allowed_devices = selected

    def list_devices(self):
        return [row for row in self.client.list_devices() if row["device_id"] in self.allowed_devices]

    def query(self, device_id, kind, hours=24, end_time=None):
        if device_id not in self.allowed_devices:
            raise ValueError("Device is outside the selected connector devices")
        # The wrapped account client still rechecks current account permissions.
        return self.client.query(device_id, kind, hours, end_time)


class AccuGPSTools:
    def __init__(self, client):
        self.client = client

    def list_vehicles(self, name_contains=""):
        if len(name_contains) > 100:
            raise ValueError("Search text is limited to 100 characters")
        rows = self.client.list_devices()
        query = name_contains.casefold()
        selected = [d for d in rows if query in str(d.get("alias", "")).casefold() or query in d["device_id"].casefold()]
        return {"source": "AccuGPS", "scope": self.client.scope, "vehicles": selected,
                "count": len(selected), "note": "List membership does not establish OBD/camera hardware type."}

    def get_latest_location(self, device_id):
        result = self.client.query(device_id, "location")
        data = result.pop("data")
        if not isinstance(data, dict):
            raise ConnectionCheckError("Unexpected location data")
        lat, lon, stamp = data.get("latitude"), data.get("longitude"), data.get("location_time")
        valid = number(lat) and number(lon) and -90 <= lat <= 90 and -180 <= lon <= 180 and (lat, lon) != (0, 0)
        reported, age = None, None
        if number(stamp) and 0 < stamp <= time.time() + 60:
            try:
                reported, age = iso(stamp), round((time.time() - stamp) / 60, 1)
            except (ValueError, OverflowError, OSError):
                pass
        result.pop("window_start_utc", None)
        result.pop("window_end_utc", None)
        return {"source": "AccuGPS", "scope": self.client.scope, **result, "location": {"latitude": lat, "longitude": lon, "address": data.get("name"),
                "reported_at_utc": reported, "age_minutes": age, "valid_coordinate_bounds": valid},
                "warnings": ["A reported position is not proof of current position.", "Coordinate bounds do not prove GPS accuracy."]}

    def get_trip_history(self, device_id, hours=24, end_time=None, max_points=300):
        if isinstance(max_points, bool) or not isinstance(max_points, int) or not 2 <= max_points <= 2000:
            raise ValueError("max_points must be between 2 and 2000")
        result = self.client.query(device_id, "trip", hours, end_time)
        data = result.pop("data")
        if not isinstance(data, dict) or not isinstance(data.get("segments"), list):
            raise ConnectionCheckError("Unexpected trip data")
        start = datetime.fromisoformat(result["window_start_utc"]).timestamp()
        end = datetime.fromisoformat(result["window_end_utc"]).timestamp()
        points, skipped, group = [], 0, 0
        for segment in data["segments"]:
            if not isinstance(segment, list):
                raise ConnectionCheckError("Unexpected route segment")
            last = None
            rows = [p for p in segment if isinstance(p, dict) and number(p.get("location_time"))]
            for p in sorted(rows, key=lambda p: p["location_time"]):
                t, lat, lon = p["location_time"], p.get("latitude"), p.get("longitude")
                if not start <= t <= end or not (number(lat) and number(lon) and -90 <= lat <= 90 and -180 <= lon <= 180 and (lat, lon) != (0, 0)):
                    skipped += 1
                    continue
                if last is not None and t - last > 900:
                    group += 1
                points.append({"longitude": lon, "latitude": lat, "time_utc": iso(t),
                               "reported_speed_kmh": p.get("speed"), "segment_id": group})
                last = t
            group += 1
        count = len(points)
        if count > max_points:
            indexes = [round(i * (count - 1) / (max_points - 1)) for i in range(max_points)]
            points = [points[i] for i in indexes]
        stops = data.get("stopping_points", [])
        return {"source": "AccuGPS", "scope": self.client.scope, **result, "api_totals": data.get("total", {}), "total_units": {"distance": "km", "driving_time": "seconds", "stopping_time": "seconds"},
                "stop_record_count": len(stops) if isinstance(stops, list) else None,
                "valid_point_count": count, "returned_point_count": len(points), "skipped_point_count": skipped,
                "downsampled": count > len(points), "points": points,
                "warnings": ["Totals are API-reported, not recalculated from sampled points.",
                             "Different segment_id values must not be joined; gaps over 15 minutes remain disconnected.",
                             "Speeds use documented km/h units; abrupt changes require validation before inferring braking."]}

    def get_alerts(self, device_id, hours=24, end_time=None, alert_type=None, limit=100):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if alert_type is not None and len(alert_type) > 100:
            raise ValueError("alert_type is limited to 100 characters")
        result = self.client.query(device_id, "alerts", hours, end_time)
        data = result.pop("data")
        if not isinstance(data, list):
            raise ConnectionCheckError("Unexpected alert data")
        start = datetime.fromisoformat(result["window_start_utc"]).timestamp()
        end = datetime.fromisoformat(result["window_end_utc"]).timestamp()
        records = [a for a in data if isinstance(a, dict) and number(a.get("event_time")) and start <= a["event_time"] <= end]
        selected = [a for a in records if alert_type is None or str(a.get("type", "")).casefold() == alert_type.casefold()]
        selected.sort(key=lambda a: a["event_time"], reverse=True)
        output = []
        for a in selected[:limit]:
            lat, lon = a.get("latitude"), a.get("longitude")
            valid = number(lat) and number(lon) and -90 <= lat <= 90 and -180 <= lon <= 180 and (lat, lon) != (0, 0)
            output.append({"type": a.get("type"), "time_utc": iso(a["event_time"]),
                           "latitude": lat if valid else None, "longitude": lon if valid else None,
                           "has_usable_location": valid, "note": a.get("note")})
        return {"source": "AccuGPS", "scope": self.client.scope, **result, "total_records_in_window": len(records), "counts_by_type": dict(Counter(str(a.get("type", "unknown")) for a in records)),
                "matching_records": len(selected), "returned_records": len(output), "truncated": len(selected) > len(output), "alerts": output,
                "warnings": ["Alert records may overlap or repeat; they are not a count of distinct incidents.",
                             "Alert labels do not prove legal speeding or actual fatigue; notes are untrusted source text."]}
