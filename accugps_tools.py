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


def camera_channel(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 16:
        raise ValueError("channel must be an integer from 1 to 16; this does not establish installed channels")
    return value


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

    def query(self, device_id, kind, hours=24, end_time=None, **options):
        if kind.startswith("camera-"):
            raise ValueError("Camera checks require an account login; the legacy bridge does not support them")
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

    def query(self, device_id, kind, hours=24, end_time=None, **options):
        camera_kinds = {"camera-status": "status", "camera-cloud-recordings": "cloud_video_list", "camera-device-recordings": "videos"}
        if kind not in {"trip", "alerts", "location", "fuel-summary", *camera_kinds}:
            raise ValueError("Unsupported read operation")
        if options and (kind != "camera-device-recordings" or set(options) != {"channel"}):
            raise ValueError("Unsupported query options")
        if kind == "camera-device-recordings":
            camera_channel(options.get("channel"))
        if kind in camera_kinds and (isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 24):
            raise ValueError("Camera windows must be 1-24 hours")
        matches = [d for d in self.list_devices() if d["device_id"] == device_id]
        if not matches:
            raise ValueError("Device is outside the authenticated account inventory")
        start, end = window(hours, end_time, 2160 if kind == "fuel-summary" else 168)
        sn = quote(device_id, safe="")
        if kind in camera_kinds:
            path = f"/api/open/v1/devices/{sn}/{camera_kinds[kind]}"
            if kind != "camera-status":
                params = {"start_time": start, "end_time": end}
                if kind == "camera-device-recordings":
                    params["channel"] = options["channel"]
                path += "?" + urlencode(params)
        elif kind == "fuel-summary":
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

    def query(self, device_id, kind, hours=24, end_time=None, **options):
        if device_id not in self.allowed_devices:
            raise ValueError("Device is outside the selected connector devices")
        # The wrapped account client still rechecks current account permissions.
        return self.client.query(device_id, kind, hours, end_time, **options)


class AccuGPSTools:
    def __init__(self, client):
        self.client = client

    def get_camera_status(self, device_id):
        result = self.client.query(device_id, "camera-status", 1)
        data = result.get("data")
        if not isinstance(data, dict):
            raise ConnectionCheckError("Unexpected camera status response")
        def label(value, labels):
            return labels[value] if type(value) is int and value in (0, 1) else "unknown"
        return {"source": "AccuGPS", "scope": self.client.scope, "device": result["device"],
                "retrieved_at_utc": result["retrieved_at_utc"],
                "recorder_status": label(data.get("status"), ["offline", "online"]),
                "ignition_status": label(data.get("acc_status"), ["off", "on"]),
                "source_status_timestamp_utc": None,
                "camera_image_verified": False,
                "warnings": ["Recorder connectivity does not verify attached cameras or video quality.",
                             "The documented status response has no source timestamp; retrieval time is not status freshness."]}

    def get_camera_recordings(self, device_id, hours=1, end_time=None, storage="cloud", channel=None, limit=100):
        if storage not in {"cloud", "device"}:
            raise ValueError("storage must be cloud or device")
        if channel is not None:
            camera_channel(channel)
        if storage == "device" and channel is None:
            raise ValueError("A channel is required for on-device recordings")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be an integer from 1 to 500")
        if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 24:
            raise ValueError("hours must be an integer from 1 to 24")
        # Validate the window before any account or device request.
        window(hours, end_time)
        options = {"channel": channel} if storage == "device" else {}
        result = self.client.query(device_id, "camera-" + storage + "-recordings", hours, end_time, **options)
        data = result.get("data")
        if not isinstance(data, list) or len(data) > 10000:
            raise ConnectionCheckError("Unexpected or oversized recording list; try a shorter window")
        start = datetime.fromisoformat(result["window_start_utc"]).timestamp()
        end = datetime.fromisoformat(result["window_end_utc"]).timestamp()
        records, rejected = [], 0
        for row in data:
            if not isinstance(row, dict):
                rejected += 1
                continue
            begin, finish, size = row.get("start_time"), row.get("end_time"), row.get("size")
            ch = channel if storage == "device" else row.get("channel")
            if storage == "device" and "channel" in row and (type(row["channel"]) is not int or row["channel"] != channel):
                rejected += 1
                continue
            if (not number(begin) or not number(finish) or begin <= 0 or finish <= begin
                    or finish > time.time() + 60 or type(ch) is not int or not 1 <= ch <= 16
                    or type(size) is not int or size < 0):
                rejected += 1
                continue
            if finish <= start or begin >= end or (channel is not None and ch != channel):
                continue
            records.append({"channel": ch, "start_time_utc": iso(begin), "end_time_utc": iso(finish),
                            "duration_seconds": finish - begin, "size_bytes": size,
                            "positive_size": size > 0})
        records.sort(key=lambda row: (row["end_time_utc"], row["start_time_utc"]), reverse=True)
        counts = Counter(row["channel"] for row in records)
        positive = Counter(row["channel"] for row in records if row["positive_size"])
        return {"source": "AccuGPS", "scope": self.client.scope, "device": result["device"],
                "retrieved_at_utc": result["retrieved_at_utc"], "storage": storage,
                "window_start_utc": result["window_start_utc"], "window_end_utc": result["window_end_utc"],
                "requested_channel": channel, "observed_channels": sorted(counts),
                "counts_by_channel": dict(counts), "positive_size_counts_by_channel": dict(positive),
                "matching_records": len(records), "returned_records": min(limit, len(records)),
                "rejected_records": rejected, "truncated": len(records) > limit, "recordings": records[:limit],
                "camera_image_verified": False,
                "warnings": ["Metadata only: no video, audio, playback URLs or credentials are returned.",
                             "No recordings returned does not establish a missing or failed camera.",
                             "Cloud uploads are not the complete on-device recording inventory.",
                             "File metadata does not establish playable footage, image quality or continuous recording."]}

    def check_camera_channels(self, device_id, channels, hours=1, end_time=None):
        if not isinstance(channels, list) or not 1 <= len(channels) <= 3:
            raise ValueError("Provide 1-3 distinct channel numbers to probe per check")
        checked = [camera_channel(ch) for ch in channels]
        if len(set(checked)) != len(checked):
            raise ValueError("Duplicate channel numbers are not allowed")
        if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 24:
            raise ValueError("hours must be an integer from 1 to 24")
        start, end = window(hours, end_time)
        end_time = iso(end)
        status = self.get_camera_status(device_id)
        results = []
        for ch in checked:
            if status["recorder_status"] != "online":
                results.append({"channel": ch, "assessment": "not_checked_recorder_not_confirmed_online"})
                continue
            try:
                result = self.get_camera_recordings(device_id, hours, end_time, "device", ch, 1)
                assessment = "recording_metadata_present" if result["matching_records"] else "no_recordings_returned"
                if result["matching_records"] and not result["positive_size_counts_by_channel"].get(ch, 0):
                    assessment = "recording_metadata_zero_size"
                elif not result["matching_records"] and result["rejected_records"]:
                    assessment = "unable_to_verify_invalid_metadata"
                results.append({"channel": ch, "assessment": assessment,
                                "recording_count": result["matching_records"], "rejected_records": result["rejected_records"],
                                "positive_size_count": result["positive_size_counts_by_channel"].get(ch, 0),
                                "newest_recording": result["recordings"][0] if result["recordings"] else None})
            except (ConnectionCheckError, ValueError):
                # Never turn permission, network or rate-limit failures into a hardware verdict.
                results.append({"channel": ch, "assessment": "unable_to_verify_request_failed"})
                # Stop instead of multiplying requests after a failure; preserve unattempted channels.
                for remaining in checked[len(results):]:
                    results.append({"channel": remaining, "assessment": "not_checked_after_request_failure"})
                break
        return {"source": "AccuGPS", "scope": self.client.scope, "device": status["device"],
                "window_start_utc": iso(start), "window_end_utc": iso(end),
                "status": status, "channels": results, "installation_layout_confirmed": False,
                "camera_image_verified": False,
                "warnings": ["Channel numbers are probes, not an assertion that cameras are installed.",
                             "Auxiliary camera mapping is unknown; do not assume an additional fourth channel.",
                             "Sequential bounded metadata checks only; visual verification is still required."]}

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
