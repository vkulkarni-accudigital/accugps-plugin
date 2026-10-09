"""Local AccuGPS connectivity check. Credentials and tokens stay in memory."""

import argparse
import getpass
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


class ConnectionCheckError(Exception):
    pass


def network_failure(reason, timeout):
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return f"request timed out (socket timeout: {timeout:g}s)"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed"
    if isinstance(reason, ssl.SSLError):
        return "TLS connection failed"
    if isinstance(reason, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(reason, ConnectionRefusedError):
        return "connection refused"
    if isinstance(reason, ConnectionResetError):
        return "connection reset by peer"
    code = getattr(reason, "winerror", None) or getattr(reason, "errno", None)
    return f"network connection failed ({type(reason).__name__}, code {code})"


def request_json(base_url, path, payload=None, token=None, timeout=20):
    headers = {"Accept": "application/json"}
    if token:
        headers["access_token"] = token
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base_url + path, data=body, headers=headers)
    # Do not forward credentials to a different URL through redirects.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(5_000_001)
    except urllib.error.HTTPError as exc:
        raise ConnectionCheckError(f"{path}: HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        raise ConnectionCheckError(
            f"{path}: {network_failure(reason, timeout)}"
        ) from None
    if len(raw) > 5_000_000:
        raise ConnectionCheckError(f"{path}: response exceeds the size limit")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ConnectionCheckError(
            f"{path}: response is not JSON; this may be the website host rather than the API host."
        ) from None
    if not isinstance(result, dict):
        raise ConnectionCheckError(f"{path}: unexpected response format")
    return result


def check_status(result, path):
    # The documentation includes both 0 and 200 as success examples.
    if str(result.get("status")) not in {"0", "200"}:
        status = result.get("status")
        if not isinstance(status, (int, str)) or len(str(status)) > 12:
            status = "unknown"
        raise ConnectionCheckError(f"{path}: API reported status {status}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://i.accugps.com",
                        help="HTTPS API host, without /api/open/v1")
    parser.add_argument("--probe", action="store_true",
                        help="Check the unauthenticated tracker endpoint without credentials")
    parser.add_argument("--timeout", type=float, default=20,
                        help="Socket timeout in seconds (default: 20)")
    parser.add_argument("--diagnose-location", action="store_true",
                        help="Also check one tracker location; use --timeout 60 for a longer wait")
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("--timeout must be greater than 0 and at most 300")
    base_url = args.base_url.rstrip("/")
    parsed = urllib.parse.urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        parser.error("--base-url must be an HTTPS host without credentials, path, or query")

    print(f"Checking API host: {base_url}")
    if args.probe:
        try:
            result = request_json(base_url, "/api/open/v1/trackers", timeout=args.timeout)
            print("Tracker endpoint returned JSON. Authentication is still untested.")
            print("Response fields:", ", ".join(sorted(result.keys())))
            status = result.get("status")
            if isinstance(status, int) or (isinstance(status, str) and status.isdigit()):
                print("API status:", status)
        except ConnectionCheckError as exc:
            print(exc)
            print("HTTP 401/403 suggests an authentication gate, but does not prove this is the API host.")
            return 1
        return 0

    username = input("Demo account email: ").strip()
    password = getpass.getpass("Demo account password (hidden): ")
    if not username or not password:
        print("Email and password are required.")
        return 1
    try:
        login = request_json(base_url, "/api/open/v1/login",
                             {"username": username, "password": password}, timeout=args.timeout)
        password = None
        check_status(login, "login")
        data = login.get("data")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise ConnectionCheckError("Login returned no access token")
        print("Login succeeded. Token received (not displayed or saved).")
        successful_reads = 0
        trackers = []
        for path, label in [("/api/open/v1/trackers", "Trackers"),
                            ("/api/open/v1/trackers/location", "Tracker locations"),
                            ("/api/open/v1/devices", "Devices")]:
            started = time.monotonic()
            print(f"Checking {label} (socket timeout: {args.timeout:g}s)...", flush=True)
            try:
                result = request_json(base_url, path, token=token, timeout=args.timeout)
                check_status(result, path)
                records = result.get("data")
                if not isinstance(records, list):
                    raise ConnectionCheckError(f"{path}: expected a list of records")
                print(f"{label}: OK, {len(records)} records ({time.monotonic() - started:.1f}s)")
                if path == "/api/open/v1/trackers":
                    trackers = records
                successful_reads += 1
            except ConnectionCheckError as exc:
                print(f"{label}: {exc} ({time.monotonic() - started:.1f}s)")
        if args.diagnose_location:
            candidates = [r for r in trackers if isinstance(r, dict) and isinstance(r.get("sn"), str) and r["sn"]]
            candidates.sort(key=lambda r: str(r.get("login", 0)) in {"0", "None"})
            if not candidates:
                print("Single tracker location: skipped; no tracker serial number available")
            else:
                sn = urllib.parse.quote(candidates[0]["sn"], safe="")
                path = f"/api/open/v1/trackers/{sn}/location"
                started = time.monotonic()
                print("Checking one tracker location (preferring an online tracker)...", flush=True)
                try:
                    result = request_json(base_url, path, token=token, timeout=args.timeout)
                    check_status(result, "single tracker location")
                    if not isinstance(result.get("data"), dict):
                        raise ConnectionCheckError("unexpected location response format")
                    location = result["data"]
                    required = {"latitude", "longitude", "location_time"}
                    if not required.issubset(location):
                        raise ConnectionCheckError("location response lacks coordinates or timestamp")
                    print(f"Single tracker location: OK, coordinates and timestamp returned ({time.monotonic() - started:.1f}s)")
                    print("Values are not printed; freshness and coordinate validity are not yet checked.")
                    successful_reads += 1
                except ConnectionCheckError as exc:
                    print(f"Single tracker location: {str(exc).replace(sn, '{sn}')} ({time.monotonic() - started:.1f}s)")
        print("Check complete. Only authentication and read endpoints were called.")
        return 0 if successful_reads else 1
    except ConnectionCheckError as exc:
        print(f"Connection check failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
