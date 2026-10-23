#!/usr/bin/env python3
"""
Remote Agentless IP & Host Prober
Allows monitoring any remote device (router, server, IoT device, VM, or PC)
from your system by probing its IP, latency, reachability, and open ports,
and streaming telemetry into the SOC Detection Engine.
"""
import os
import sys
import time
import socket
import argparse
import urllib.request
import json
import datetime
from typing import List, Dict

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def get_utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

# Common service ports to probe
STANDARD_PROBE_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (53, "DNS"),
    (80, "HTTP"),
    (135, "RPC"),
    (139, "NetBIOS"),
    (443, "HTTPS"),
    (445, "SMB"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (8080, "HTTP-Proxy"),
]

class RemoteDeviceMonitor:
    def __init__(self, target_ip: str, hostname: str = None, server_url: str = "http://127.0.0.1:8000", custom_ports: List[int] = None):
        self.target_ip = target_ip.strip()
        self.server_url = server_url.rstrip("/")
        self.register_endpoint = f"{self.server_url}/api/v1/client-device/register"
        self.ingest_endpoint = f"{self.server_url}/api/v1/ingest"
        
        # Resolve hostname or assign identifier
        if not hostname:
            try:
                resolved = socket.gethostbyaddr(self.target_ip)[0]
                self.hostname = resolved
            except Exception:
                self.hostname = f"host-{self.target_ip.replace('.', '-')}"
        else:
            self.hostname = hostname

        self.device_id = f"remote-{self.target_ip.replace('.', '-')}"
        self.probe_ports = custom_ports or [p[0] for p in STANDARD_PROBE_PORTS]
        self.seen_open_ports = set()
        self.last_status = "UNKNOWN"

    def probe_port(self, port: int, timeout: float = 0.6) -> bool:
        """Attempts a non-intrusive TCP SYN/Connect to check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def probe_device(self) -> Dict:
        """Probes the remote IP for latency and active listening ports."""
        t_start = time.perf_counter()
        open_ports = []
        is_reachable = False

        for port in self.probe_ports:
            if self.probe_port(port):
                open_ports.append(port)
                is_reachable = True

        # Quick ICMP ping fallback if no standard TCP port responded
        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        if not is_reachable:
            # Check single ping
            try:
                import subprocess
                flag = "-n" if sys.platform == "win32" else "-c"
                cmd = ["ping", flag, "1", "-w", "1000", self.target_ip]
                res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                is_reachable = (res.returncode == 0)
            except Exception:
                pass

        return {
            "target_ip": self.target_ip,
            "hostname": self.hostname,
            "is_reachable": is_reachable,
            "open_ports": open_ports,
            "latency_ms": latency_ms,
            "status": "ONLINE" if is_reachable else "OFFLINE"
        }

    def register_device(self, initial_probe: Dict) -> bool:
        """Registers the target IP as an active monitored device in the SOC dashboard."""
        os_guess = "Remote Network Host (Agentless)"
        if 445 in initial_probe["open_ports"] or 3389 in initial_probe["open_ports"]:
            os_guess = "Windows Host / Server (Remote)"
        elif 22 in initial_probe["open_ports"]:
            os_guess = "Linux / Unix Host (Remote SSH)"
        elif 80 in initial_probe["open_ports"] or 443 in initial_probe["open_ports"]:
            os_guess = "Network Appliance / Web Service"

        payload = {
            "device_id": self.device_id,
            "device_type": "Remote Probed Host (Agentless)",
            "hostname": self.hostname,
            "os": os_guess,
            "browser": f"Agentless Probe (Ports: {','.join(map(str, initial_probe['open_ports'])) or 'ICMP'})",
            "ip_address": self.target_ip,
            "cpu_cores": 1,
            "device_memory_gb": 0,
            "screen_res": f"Latency: {initial_probe['latency_ms']}ms",
            "user": "remote-monitor",
            "status": initial_probe["status"]
        }

        try:
            req = urllib.request.Request(
                self.register_endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[!] Warning registering remote device: {e}")
            return False

    def emit_telemetry(self, probe_result: Dict):
        """Sends remote host health & network telemetry events to the SOC Detection Engine."""
        now = get_utc_now_iso()
        ports_str = ", ".join(str(p) for p in probe_result["open_ports"]) or "None (ICMP only)"
        
        events = [
            {
                "id": f"evt-{int(time.time()*1000)}",
                "timestamp": now,
                "log_type": "network.log",
                "hostname": self.hostname,
                "source_ip": self.target_ip,
                "user": "system",
                "process_name": "remote-probe",
                "process_id": 0,
                "command_line": f"probe --target {self.target_ip} --latency {probe_result['latency_ms']}ms",
                "event_id": "REMOTE_HOST_HEALTH",
                "raw_message": f"Remote host {self.hostname} ({self.target_ip}) is {probe_result['status']} | Latency: {probe_result['latency_ms']}ms | Active Ports: [{ports_str}]",
                "details": {
                    "target_ip": self.target_ip,
                    "status": probe_result["status"],
                    "latency_ms": probe_result["latency_ms"],
                    "open_ports": probe_result["open_ports"]
                }
            }
        ]

        batch = {
            "agent_id": self.device_id,
            "hostname": self.hostname,
            "device_info": {
                "device_type": "Remote Probed Host (Agentless)",
                "os_name": "Remote Device",
                "ip_address": self.target_ip,
                "architecture": "Remote Network"
            },
            "events": events
        }

        try:
            req = urllib.request.Request(
                self.ingest_endpoint,
                data=json.dumps(batch).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                pass
        except Exception as e:
            print(f"[!] Warning sending telemetry: {e}")

    def start_monitoring(self, interval_seconds: float = 5.0):
        print("=" * 70)
        print(f"  🔍 REMOTE AGENTLESS IP MONITOR")
        print(f"  Target IP  : {self.target_ip}")
        print(f"  Hostname   : {self.hostname}")
        print(f"  SOC Server : {self.server_url}")
        print(f"  Interval   : {interval_seconds}s")
        print("=" * 70)

        initial = self.probe_device()
        print(f"[+] Initial Probe Result: Status={initial['status']} | Latency={initial['latency_ms']}ms | Open Ports={initial['open_ports']}")
        self.register_device(initial)
        print(f"[+] Registered {self.hostname} ({self.target_ip}) in SOC Dashboard -> Monitored Devices!\n")

        cycle = 1
        while True:
            try:
                res = self.probe_device()
                status_icon = "🟢" if res["is_reachable"] else "🔴"
                ports_desc = f"Open Ports: {res['open_ports']}" if res['open_ports'] else "Reachability: Active"
                print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] #{cycle} {status_icon} [{res['status']}] {self.target_ip} ({self.hostname}) - Latency: {res['latency_ms']}ms | {ports_desc}")
                
                self.emit_telemetry(res)
                cycle += 1
                time.sleep(interval_seconds)
            except KeyboardInterrupt:
                print("\n[*] Monitoring stopped by user.")
                break

def main():
    parser = argparse.ArgumentParser(description="Remote Agentless IP & Host Prober for SOC Lab")
    parser.add_argument("--ip", required=True, help="Target remote IP address to monitor (e.g. 192.168.1.1)")
    parser.add_argument("--name", default=None, help="Optional friendly name/hostname for the device")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="SOC engine URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5.0)")
    parser.add_argument("--ports", default=None, help="Comma-separated custom TCP ports to probe (e.g. 80,443,22,445)")

    args = parser.parse_args()
    
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    monitor = RemoteDeviceMonitor(
        target_ip=args.ip,
        hostname=args.name,
        server_url=args.server,
        custom_ports=ports
    )
    monitor.start_monitoring(interval_seconds=args.interval)

if __name__ == "__main__":
    main()
