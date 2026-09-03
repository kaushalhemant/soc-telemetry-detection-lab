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

    host = "127.0.0.1"
    port = 8000
    url = f"http://{host}:{port}"

    print(f"\n[+] Starting SOC Telemetry Detection Engine & Web UI at {url} ...")
    print("[+] Autonomous Host Monitoring: ACTIVE")
    print("[+] Press Ctrl+C to terminate the lab.\n")

    # Start autonomous host endpoint collector in background
    threading.Thread(target=start_embedded_endpoint_collector, args=(url,), daemon=True).start()

    # Open browser automatically after 1.5 seconds
    def open_browser():
        time.sleep(1.8)
        webbrowser.open(url)

    threading.Thread(target=open_browser, daemon=True).start()

    # Launch Uvicorn server
    import uvicorn
    from web.server import app
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main()

