#!/usr/bin/env python3
"""
SOC Telemetry Detection Lab - One-Command Local Quickstart Launcher
"""
import sys
import subprocess
import os
import webbrowser
import time

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
        print("[+] Dependencies verified successfully.")
    except ImportError:
        print("[!] Missing requirements. Installing from requirements.txt...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def main():
    print("=" * 65)
    print("      🛡️  SOC TELEMETRY DETECTION LAB - QUICKSTART  🛡️")
    print("=" * 65)
    
    check_dependencies()

    host = "127.0.0.1"
    port = 8000
    url = f"http://{host}:{port}"

    print(f"\n[+] Starting SOC Telemetry Detection Engine & Web UI at {url} ...")
    print("[+] Press Ctrl+C to terminate the lab.\n")

    # Open browser automatically after 1.5 seconds
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(url)

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    # Launch Uvicorn server
    import uvicorn
    from web.server import app
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main()
