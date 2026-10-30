#!/usr/bin/env python3
"""
SOC Telemetry Detection Lab - One-Command Local Quickstart Launcher
Automatically boots the SOC Detection Server, starts autonomous host endpoint telemetry monitoring,
and opens the live analyst workstation in your browser.
"""
import sys
import subprocess
import os
import webbrowser
import time
import threading
import socket

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def check_dependencies():
    print("[*] Checking Python dependencies...")
    try:
        import fastapi
        import uvicorn
        import yaml
        import pydantic
        import psutil
        print("[+] Dependencies verified successfully (FastAPI, Uvicorn, PyYAML, Pydantic, psutil).")
    except ImportError:
        print("[!] Missing requirements. Installing from requirements.txt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        except Exception:
            subprocess.check_call(["uv", "pip", "install", "-r", "requirements.txt", "--python", sys.executable])

def start_embedded_endpoint_collector(server_url: str):
    """Starts the local host endpoint collector in a daemon background worker."""
    time.sleep(1.5)  # Wait for uvicorn to bind
    try:
        from agent.collector import EndpointCollectorAgent
        agent = EndpointCollectorAgent(server_url=server_url)
        print(f"[+] Autonomous Host Telemetry Collector active for {agent.hostname} -> Streaming to {server_url}")
        agent.start_collecting(interval_seconds=3.0)
    except Exception as e:
        print(f"[!] Endpoint collector notice: {e}")

def main():
    print("=" * 70)
    print("      🛡️  SOC TELEMETRY DETECTION LAB - ALWAYS LIVE ENGINE  🛡️")
    print("=" * 70)
    
    check_dependencies()

    host = "0.0.0.0"
    port = 8000
    local_url = f"http://127.0.0.1:{port}"

    # Discover LAN IP so other devices on the network can connect
    lan_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    network_url = f"http://{lan_ip}:{port}"

    print(f"\n[+] Starting SOC Telemetry Detection Engine & Web UI ...")
    print(f"    - Local Console : {local_url}")
    print(f"    - Network Listen: {network_url} (for remote endpoints)")
    print(f"\n[+] To monitor a different machine on your network, run on that device:")
    print(f"    python collector.py --server {network_url}\n")
    print("[+] Autonomous Host Monitoring: ACTIVE")
    print("[+] Press Ctrl+C to terminate the lab.\n")

    # Start autonomous host endpoint collector in background
    threading.Thread(target=start_embedded_endpoint_collector, args=(local_url,), daemon=True).start()

    # Open browser automatically after 1.5 seconds
    def open_browser():
        time.sleep(1.8)
        webbrowser.open(local_url)

    threading.Thread(target=open_browser, daemon=True).start()

    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    reload_dirs = [
        project_root,
        os.path.join(project_root, "rules"),
        os.path.join(project_root, "engine"),
        os.path.join(project_root, "generator"),
        os.path.join(project_root, "web"),
        os.path.join(project_root, "agent"),
    ]
    reload_dirs = [d for d in reload_dirs if os.path.isdir(d)]

    print("[+] Auto-Update / Hot Reloading: ACTIVE (Watching Python code, SIGMA YAML rules, and web assets)")

    # Launch Uvicorn server with hot reload
    import uvicorn
    uvicorn.run(
        "web.server:app",
        host=host,
        port=port,
        reload=True,
        reload_dirs=reload_dirs,
        reload_includes=["*.py", "*.yml", "*.yaml", "*.html", "*.js", "*.css", "*.json"],
    )

if __name__ == "__main__":
    main()

