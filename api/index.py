import os
import sys

# Ensure root directory is in sys.path for Vercel serverless environment
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in [ROOT_DIR, os.getcwd()]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

from web.server import app

# Export ASGI app entrypoint for Vercel
app = app
