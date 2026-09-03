#!/usr/bin/env python3
"""
SOC Telemetry Detection Lab - Live Endpoint Telemetry Bridge & CLI Forwarder
Connects your local machine (processes, network connections, hardware specs)
directly to the central SOC Detection Engine for real-time telemetry streaming and threat monitoring.
"""
import os
import sys
import time
import argparse
import socket
import urllib.request
import urllib.parse
import json
import subprocess
import threading
from typing import Optional

# Set UTF-8 encoding on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from agent.collector import EndpointCollectorAgent


def print_banner(server_url: str, agent_id: str, hostname: str):
    print("=" * 72)
    print("   🛡️  SOC TELEMETRY DETECTION LAB - LIVE TELEMETRY BRIDGE 🛡️")
    print("=" * 72)
    print(f"  ⚡ Host Endpoint : {hostname}")
    print(f"  ⚡ Bridge Agent  : {agent_id}")
    print(f"  ⚡ SOC Engine    : {server_url}")
    print(f"  ⚡ Mode          : Continuous Real-Time Host Telemetry Stream")
    print("=" * 72)


def is_server_online(server_url: str) -> bool:
    """Checks if the target SOC Detection server is reachable."""
    try:
        req = urllib.request.Request(
            f"{server_url.rstrip('/')}/api/metrics",
            headers={"User-Agent": "SOC-Bridge-HealthCheck/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def launch_local_server(port: int = 8000):
    """Spawns the local FastAPI SOC detection engine."""
    print(f"[*] Booting local SOC Detection Engine on http://127.0.0.1:{port} ...")
    cmd = [sys.executable, "-m", "uvicorn", "web.server:app", "--host", "127.0.0.1", "--port", str(port)]
    process = subprocess.Popen(cmd, cwd=CURRENT_DIR)
    # Wait for server to bind
    for _ in range(20):
        time.sleep(0.5)
        if is_server_online(f"http://127.0.0.1:{port}"):
            print(f"[+] SOC Detection Engine is ONLINE at http://127.0.0.1:{port}")
            return process
    return process


def query_server_status(server_url: str):
    """Queries and displays the active devices and metrics from the SOC server."""
    base = server_url.rstrip("/")
    try:
        # Query metrics
        req_metrics = urllib.request.Request(f"{base}/api/metrics")
        with urllib.request.urlopen(req_metrics, timeout=4.0) as resp:
            metrics = json.loads(resp.read().decode("utf-8"))

        # Query devices
        req_devs = urllib.request.Request(f"{base}/api/v1/devices")
        with urllib.request.urlopen(req_devs, timeout=4.0) as resp:
            devices_data = json.loads(resp.read().decode("utf-8"))

        print("\n--- [ SOC SERVER HEALTH & METRICS ] ---")
        print(f"Status           : ONLINE ({base})")
        print(f"Total Events     : {metrics.get('total_events_processed', 0)}")
        print(f"Total Alerts     : {metrics.get('total_alerts_generated', 0)}")
        print(f"MTTD (Detection) : {metrics.get('mean_time_to_detect_ms', 0)} ms")
        print(f"Active Devices   : {devices_data.get('active_devices_count', 0)}")
        
        print("\n--- [ MONITORED ENDPOINTS ] ---")
        for dev in devices_data.get("devices", []):
            print(f" - [{dev.get('status', 'ONLINE')}] {dev.get('hostname')} | {dev.get('device_type')} | {dev.get('ip_address')} | {dev.get('os')}")
        print("---------------------------------------\n")
    except Exception as e:
        print(f"[!] Failed to fetch status from {server_url}: {e}")


def trigger_cli_simulation(server_url: str, scenario: str):
    """Triggers an attack simulation scenario on the SOC Detection server via API."""
    base = server_url.rstrip("/")
    payload = {
        "scenario": scenario,
        "hostname": socket.gethostname(),
        "target_user": "root",
        "num_failures": 8
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/api/simulate",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            print(f"\n[+] Successfully triggered attack scenario: {scenario.upper()}")
            print(f"    Emitted Events : {res.get('emitted_events_count', 0)}")
            print(f"    Total Alerts   : {len(res.get('alerts', []))}")
            if res.get("alerts"):
                latest = res["alerts"][0]
                print(f"    Latest Alert   : [{latest.get('severity')}] {latest.get('rule_name')} (ID: {latest.get('alert_id')})")
    except Exception as e:
        print(f"[!] Failed to trigger simulation: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="SOC Telemetry Detection Lab - Live Endpoint Telemetry Bridge & Forwarder"
    )
    parser.add_argument(
        "--server",
        default=os.environ.get("SOC_SERVER_URL", "http://127.0.0.1:8000"),
        help="Base URL of the SOC Detection Engine server (default: http://127.0.0.1:8000)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Telemetry collection and streaming interval in seconds (default: 3.0s)"
    )
    parser.add_argument(
        "--agent-id",
        default=None,
        help="Custom identifier for this endpoint bridge agent"
    )
    parser.add_argument(
        "--start-server",
        action="store_true",
        help="Automatically launch local SOC Detection Server if it is not already running"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Check SOC engine connection and display active telemetry stats and monitored devices"
    )
    parser.add_argument(
        "--simulate",
        type=str,
        default=None,
        help="Trigger an attack scenario (e.g. brute_force, lsass_dump, kernel_driver_tampering, privilege_escalation)"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect and transmit a single batch of endpoint telemetry, then exit"
    )

    args = parser.parse_args()
    server_url = args.server.rstrip("/")

    # Handle status query
    if args.status:
        query_server_status(server_url)
        return

    # Handle CLI attack scenario trigger
    if args.simulate:
        trigger_cli_simulation(server_url, args.simulate)
        return

    # Check if server is running
    server_proc = None
    if not is_server_online(server_url):
        if args.start_server or server_url.startswith("http://127.0.0.1") or server_url.startswith("http://localhost"):
            print(f"[*] Local SOC Server at {server_url} is not running. Starting it now...")
            server_proc = launch_local_server(port=8000)
        else:
            print(f"[!] Warning: Remote SOC Server at {server_url} is not responding.")
            print("    The bridge will continue and retry streaming automatically.")

    # Initialize agent collector
    agent = EndpointCollectorAgent(server_url=server_url, agent_id=args.agent_id)
    print_banner(server_url=server_url, agent_id=agent.agent_id, hostname=agent.hostname)

    try:
        agent.start_collecting(interval_seconds=args.interval, run_once=args.once)
    except KeyboardInterrupt:
        print("\n[*] Bridge stopped by user.")
    finally:
        if server_proc:
            try:
                server_proc.terminate()
            except Exception:
                pass


if __name__ == "__main__":
    main()
