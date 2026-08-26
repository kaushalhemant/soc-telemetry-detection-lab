import os
import sys
import traceback

# Ensure root directory is in sys.path for Vercel serverless environment
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in [ROOT_DIR, os.getcwd()]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

try:
    from web.server import app
except Exception as err:
    err_tb = traceback.format_exc()
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    
    app = FastAPI(title="SOC Lab Engine Error Diagnostics")
    
    @app.get("/{full_path:path}", response_class=HTMLResponse)
    def catch_all_error(full_path: str):
        return HTMLResponse(
            f"<html><head><title>SOC Lab Engine Diagnostic</title></head>"
            f"<body style='font-family: sans-serif; padding: 20px; background: #0d1117; color: #c9d1d9;'>"
            f"<h2 style='color: #f85149;'>⚠️ SOC Detection Lab Engine Startup Error</h2>"
            f"<p>An exception occurred while loading module <code>web.server</code> on Vercel:</p>"
            f"<pre style='background: #161b22; padding: 15px; border-radius: 6px; overflow-x: auto; color: #ff7b72;'>{err_tb}</pre>"
            f"</body></html>"
        )
