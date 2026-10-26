import asyncio
from pathlib import Path
import socket
import subprocess
import sys
import unittest

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixture_server.py"


async def exercise(session):
    await session.initialize()
    listed = await session.list_tools()
    assert {t.name for t in listed.tools} == {"list_vehicles", "get_latest_location", "get_trip_history", "get_alerts", "get_camera_status", "get_camera_recordings", "check_camera_channels"}
    assert all(t.annotations.readOnlyHint and not t.annotations.destructiveHint for t in listed.tools)
    result = await session.call_tool("list_vehicles", {"name_contains": "test"})
    assert not result.isError and result.structuredContent["count"] == 1
    for name in ("get_latest_location", "get_trip_history", "get_alerts", "get_camera_status", "get_camera_recordings"):
        result = await session.call_tool(name, {"device_id": "test-device"})
        assert not result.isError and result.structuredContent
    channels = await session.call_tool("check_camera_channels", {"device_id": "test-device", "channels": [1, 2, 3]})
    assert not channels.isError and not channels.structuredContent["camera_image_verified"]
    denied = await session.call_tool("get_trip_history", {"device_id": "outside-scope"})
    assert denied.isError


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_discovery_calls_and_denial(self):
        params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE)], cwd=str(ROOT))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await exercise(session)

    async def test_streamable_http_discovery_calls_and_denial(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        child = subprocess.Popen([sys.executable, str(FIXTURE), "streamable-http", str(port)],
                                 cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
        try:
            ready = False
            for _ in range(100):
                if child.poll() is not None:
                    raise AssertionError("Fixture HTTP server exited before startup")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        ready = True
                        break
                except OSError:
                    await asyncio.sleep(.1)
            self.assertTrue(ready, "Fixture server did not start")
            async with httpx.AsyncClient(timeout=30, trust_env=False) as http_client:
                async with streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http_client) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await exercise(session)
        finally:
            child.terminate()
            child.wait(timeout=10)
