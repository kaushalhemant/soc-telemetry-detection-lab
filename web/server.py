import os
import asyncio
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

import sys

# Ensure project root is in sys.path before importing internal modules
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
for p in [PROJECT_ROOT, os.getcwd()]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

from generator.models import LogEvent, DetectionAlert, ScenarioType, TriageStatus, LogType
from generator.log_generator import TelemetryGenerator
from engine.detection_engine import DetectionEngine
from engine.exporter import SigmaExporter
from engine.pcap_analyzer import PcapAnalyzer
from engine.burp_integrator import BurpIntegrator

from contextlib import asynccontextmanager

def to_dict(obj):
    """Safely converts Pydantic models to dict across v1 and v2."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    elif hasattr(obj, "dict"):
        return obj.dict()
    return dict(obj)

# Base directory paths
candidate_rules_dirs = [
    os.path.join(PROJECT_ROOT, "rules"),
    os.path.join(BASE_DIR, "..", "rules"),
    os.path.join(os.getcwd(), "rules"),
    os.path.join(os.getcwd(), "web", "rules"),
]
RULES_DIR = next((d for d in candidate_rules_dirs if os.path.exists(d) and os.path.isdir(d)), candidate_rules_dirs[0])
STATIC_DIR = BASE_DIR

# Core Lab Components
telemetry_gen = TelemetryGenerator()
detection_engine = DetectionEngine(rules_dir=RULES_DIR)

# Connect Generator to Detection Engine
telemetry_gen.register_listener(detection_engine.process_event)

# WebSocket Connection Manager for Live Streaming to Web UI
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, data: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

ws_manager = ConnectionManager()
recent_logs: List[dict] = []
MAIN_LOOP = None

def sync_event_broadcast(event: LogEvent):
    evt_dict = to_dict(event)
    recent_logs.insert(0, evt_dict)
    if len(recent_logs) > 200:
        recent_logs.pop()

    if MAIN_LOOP and MAIN_LOOP.is_running():
        try:
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_json({"type": "telemetry", "data": evt_dict}), MAIN_LOOP
            )
        except Exception as e:
            print(f"[WS Telemetry Error] {e}")

def sync_alert_broadcast(alert: DetectionAlert):
    alt_dict = to_dict(alert)
    if MAIN_LOOP and MAIN_LOOP.is_running():
        try:
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_json({"type": "alert", "data": alt_dict}), MAIN_LOOP
            )
        except Exception as e:
            print(f"[WS Alert Error] {e}")

# Hook callbacks into WS broadcaster
telemetry_gen.register_listener(sync_event_broadcast)
detection_engine.register_alert_listener(sync_alert_broadcast)

def seed_initial_lab_state():
    """Seeds initial baseline telemetry and attack scenario alerts for instant rendering on serverless hosts."""
    if len(detection_engine.alert_manager.get_all_alerts()) == 0:
        telemetry_gen.trigger_scenario(ScenarioType.BRUTE_FORCE)
        telemetry_gen.trigger_scenario(ScenarioType.ANOMALOUS_PROCESS)
        telemetry_gen.trigger_scenario(ScenarioType.PRIVILEGE_ESCALATION)

try:
    seed_initial_lab_state()
except Exception as e:
    print(f"[Seed Lab State Warning] {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MAIN_LOOP
    try:
        MAIN_LOOP = asyncio.get_running_loop()
    except Exception:
        MAIN_LOOP = None
    # Avoid starting continuous background threads in Vercel serverless environment
    if not os.environ.get("VERCEL"):
        telemetry_gen.start_background_stream(interval_seconds=4.0)
    yield
    if not os.environ.get("VERCEL"):
        telemetry_gen.stop_background_stream()

app = FastAPI(title="SOC Telemetry Detection Lab Engine API", version="1.0.0", lifespan=lifespan)

# API Endpoints
class SimulationRequest(BaseModel):
    scenario: ScenarioType
    source_ip: str = None
    target_user: str = "root"
    hostname: str = "host-node-alpha"
    num_failures: int = 7

class TriageRequest(BaseModel):
    status: TriageStatus
    note: str = None

@app.post("/api/simulate")
def trigger_simulation(req: SimulationRequest):
    """Triggers an attack simulation scenario in real-time."""
    kwargs = {}
    if req.source_ip:
        kwargs["source_ip"] = req.source_ip
    if req.target_user:
        kwargs["target_user"] = req.target_user
    if req.hostname:
        kwargs["hostname"] = req.hostname
    if req.scenario == ScenarioType.BRUTE_FORCE:
        kwargs["num_failures"] = req.num_failures

    events = telemetry_gen.trigger_scenario(req.scenario, **kwargs)
    return {
        "status": "success",
        "scenario": req.scenario,
        "emitted_events_count": len(events),
        "alerts": [to_dict(a) for a in detection_engine.alert_manager.get_all_alerts(50)],
        "telemetry": recent_logs[:50],
        "metrics": detection_engine.metrics_engine.get_summary()
    }

@app.get("/api/telemetry")
def get_recent_telemetry(limit: int = 50):
    return recent_logs[:limit]

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return [to_dict(a) for a in detection_engine.alert_manager.get_all_alerts(limit)]

@app.post("/api/alerts/{alert_id}/triage")
def update_alert_triage(alert_id: str, req: TriageRequest):
    alert = detection_engine.alert_manager.update_triage_status(alert_id, req.status, req.note)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ID not found")
    return to_dict(alert)

@app.post("/api/alerts/{alert_id}/tune")
def tune_alert_rule(alert_id: str):
    alert = detection_engine.alert_manager.tune_alert_rule(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ID not found")
    return to_dict(alert)

@app.get("/api/metrics")
def get_metrics():
    return detection_engine.metrics_engine.get_summary()

@app.get("/api/rules")
def get_rules():
    return [r.raw_dict for r in detection_engine.rules]

@app.get("/api/rules/{rule_id}/export")
def export_rule(rule_id: str):
    target_rule = next((r for r in detection_engine.rules if r.id == rule_id), None)
    if not target_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {
        "rule_id": target_rule.id,
        "title": target_rule.title,
        "splunk_spl": SigmaExporter.to_splunk(target_rule),
        "elastic_kql": SigmaExporter.to_elastic(target_rule)
    }

@app.get("/api/mitre/navigator")
def get_mitre_navigator_layer():
    return SigmaExporter.generate_mitre_navigator_layer(detection_engine.rules)

# Ingestion, Device Tracking & Autonomous Monitoring State
active_agents: dict = {}
active_devices: dict = {}
ingested_events_count: int = 0

def get_utc_now_str() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def register_server_host_device():
    """Automatically acquires and registers the server host machine details on boot."""
    import platform
    import socket
    import getpass
    import os
    hostname = socket.gethostname()
    ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            pass

    ram_gb = 0
    try:
        import psutil
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception:
        pass

    dev_id = f"host-{hostname.lower()}"
    active_devices[dev_id] = {
        "device_id": dev_id,
        "device_type": "Host Server Engine (Live)",
        "hostname": hostname,
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "browser": "Engine Service",
        "ip_address": ip,
        "cpu_cores": os.cpu_count() or 1,
        "device_memory_gb": ram_gb,
        "screen_res": "Server Core",
        "user": getpass.getuser(),
        "status": "ONLINE",
        "first_seen": get_utc_now_str(),
        "last_seen": get_utc_now_str(),
        "events_count": 0
    }

try:
    register_server_host_device()
except Exception as e:
    print(f"[Device Auto-Registration Warning] {e}")

class IngestBatchRequest(BaseModel):
    agent_id: str = "agent-local"
    hostname: str = "production-node-01"
    device_info: dict = None
    events: List[dict]

class ClientDeviceRegisterRequest(BaseModel):
    device_id: str
    device_type: str = "Client Browser Endpoint"
    hostname: str = "Client Device"
    os: str = "Unknown OS"
    browser: str = "Unknown Browser"
    ip_address: str = "127.0.0.1"
    cpu_cores: int = 1
    device_memory_gb: float = 0.0
    screen_res: str = "Unknown"
    user: str = "analyst"
    status: str = "ONLINE"
    extra: dict = {}

class ClientTelemetryBatchRequest(BaseModel):
    device_id: str
    hostname: str = "Client Browser"
    events: List[dict]

def resolve_log_type(raw_type: str) -> LogType:
    """Safely maps incoming telemetry strings to known LogType enums."""
    if not raw_type:
        return LogType.AUDITD
    try:
        return LogType(raw_type)
    except ValueError:
        raw_lower = str(raw_type).lower()
        if "client" in raw_lower:
            return LogType.CLIENT_TELEMETRY
        if "browser" in raw_lower:
            return LogType.BROWSER
        if "syslog" in raw_lower:
            return LogType.SYSLOG
        if "auth" in raw_lower:
            return LogType.AUTH
        if "access" in raw_lower or "nginx" in raw_lower or "http" in raw_lower:
            return LogType.WEB_ACCESS
        return LogType.AUDITD

@app.post("/api/v1/client-device/register")
def register_client_device(payload: ClientDeviceRegisterRequest):
    """
    Registers a newly connected client browser / user device opening the SOC Console.
    Acquires hardware, OS, and browser parameters for continuous monitoring.
    """
    now = get_utc_now_str()
    is_new = payload.device_id not in active_devices
    
    active_devices[payload.device_id] = {
        "device_id": payload.device_id,
        "device_type": payload.device_type,
        "hostname": payload.hostname,
        "os": payload.os,
        "browser": payload.browser,
        "ip_address": payload.ip_address,
        "cpu_cores": payload.cpu_cores,
        "device_memory_gb": payload.device_memory_gb,
        "screen_res": payload.screen_res,
        "user": payload.user,
        "status": payload.status,
        "first_seen": active_devices.get(payload.device_id, {}).get("first_seen", now),
        "last_seen": now,
        "events_count": active_devices.get(payload.device_id, {}).get("events_count", 0),
        "extra": payload.extra
    }

    # Emit an audit registration event into the telemetry stream
    import uuid
    reg_evt = LogEvent(
        id=str(uuid.uuid4()),
        timestamp=now,
        log_type=LogType.CLIENT_TELEMETRY,
        hostname=payload.hostname,
        source_ip=payload.ip_address,
        user=payload.user,
        process_name="Browser Client Daemon",
        process_id=os.getpid() if hasattr(os, "getpid") else 1001,
        event_id="CLIENT_DEVICE_DISCOVERED" if is_new else "CLIENT_DEVICE_HEARTBEAT",
        raw_message=f"Endpoint discovered: [{payload.hostname}] running {payload.os} via {payload.browser} ({payload.cpu_cores} Cores, {payload.screen_res})",
        details={
            "device_id": payload.device_id,
            "os": payload.os,
            "browser": payload.browser,
            "screen": payload.screen_res,
            "cores": payload.cpu_cores
        }
    )
    detection_engine.process_event(reg_evt)
    sync_event_broadcast(reg_evt)

    return {
        "status": "success",
        "message": "Device acquired and monitoring active.",
        "device_id": payload.device_id,
        "total_active_devices": len(active_devices)
    }

@app.post("/api/v1/client-device/telemetry")
def ingest_client_telemetry(payload: ClientTelemetryBatchRequest):
    """
    Ingests continuous telemetry streamed automatically from connected user browsers / devices.
    """
    global ingested_events_count
    import uuid
    now = get_utc_now_str()

    if payload.device_id in active_devices:
        active_devices[payload.device_id]["last_seen"] = now
        active_devices[payload.device_id]["events_count"] = active_devices[payload.device_id].get("events_count", 0) + len(payload.events)

    processed_events = []
    for evt_dict in payload.events:
        try:
            log_evt = LogEvent(
                id=evt_dict.get("id") or str(uuid.uuid4()),
                timestamp=evt_dict.get("timestamp") or now,
                log_type=resolve_log_type(evt_dict.get("log_type", "browser.log")),
                hostname=payload.hostname,
                source_ip=evt_dict.get("source_ip", active_devices.get(payload.device_id, {}).get("ip_address", "127.0.0.1")),
                user=evt_dict.get("user", active_devices.get(payload.device_id, {}).get("user", "analyst")),
                process_name=evt_dict.get("process_name", "web-client"),
                process_id=evt_dict.get("process_id", 0),
                parent_process_name=evt_dict.get("parent_process_name"),
                command_line=evt_dict.get("command_line", ""),
                event_id=evt_dict.get("event_id", "CLIENT_TELEMETRY"),
                raw_message=evt_dict.get("raw_message") or f"Client telemetry event on {payload.hostname}",
                details=evt_dict.get("details", {})
            )
            detection_engine.process_event(log_evt)
            sync_event_broadcast(log_evt)
            processed_events.append(log_evt)
            ingested_events_count += 1
        except Exception as err:
            print(f"[Client Telemetry Error] {err}")

    return {
        "status": "success",
        "device_id": payload.device_id,
        "ingested_count": len(processed_events)
    }

@app.get("/api/v1/devices")
def get_monitored_devices():
    """
    Returns all actively monitored endpoints (Host Server, Python Agents, and User Client Browsers).
    """
    now = get_utc_now_str()
    # Refresh server host last_seen
    for dev_id, dev in active_devices.items():
        if dev.get("device_type", "").startswith("Host Server"):
            dev["last_seen"] = now

    return {
        "active_devices_count": len(active_devices),
        "devices": list(active_devices.values())
    }

@app.post("/api/v1/ingest")
def ingest_live_telemetry(payload: IngestBatchRequest):
    """
    Production Real-Time Telemetry Ingestion Endpoint.
    Ingests live host events from remote or local endpoint agents.
    """
    global ingested_events_count
    import uuid
    now = get_utc_now_str()

    # Record agent heartbeat & specs
    active_agents[payload.agent_id] = {
        "hostname": payload.hostname,
        "last_seen": now,
        "events_count": len(payload.events)
    }

    # Upsert into active_devices
    dev_info = payload.device_info or {}
    active_devices[payload.agent_id] = {
        "device_id": payload.agent_id,
        "device_type": dev_info.get("device_type", "Host Endpoint Agent (Python)"),
        "hostname": payload.hostname,
        "os": f"{dev_info.get('os_name', 'Linux/Windows')} {dev_info.get('os_release', '')} ({dev_info.get('architecture', 'x86_64')})",
        "browser": "Native Agent Daemon",
        "ip_address": dev_info.get("ip_address", "127.0.0.1"),
        "cpu_cores": dev_info.get("cpu_cores", 1),
        "device_memory_gb": dev_info.get("total_ram_gb", 0),
        "screen_res": "Headless Daemon",
        "user": dev_info.get("user", "SYSTEM"),
        "status": "ONLINE",
        "first_seen": active_devices.get(payload.agent_id, {}).get("first_seen", now),
        "last_seen": now,
        "events_count": active_devices.get(payload.agent_id, {}).get("events_count", 0) + len(payload.events),
        "extra": dev_info
    }

    processed_events = []
    for evt_dict in payload.events:
        try:
            # Map external dictionary payload to standardized LogEvent model
            log_evt = LogEvent(
                id=evt_dict.get("id") or str(uuid.uuid4()),
                timestamp=evt_dict.get("timestamp") or now,
                log_type=resolve_log_type(evt_dict.get("log_type", "auditd.log")),
                hostname=payload.hostname,
                container_id=evt_dict.get("container_id"),
                source_ip=evt_dict.get("source_ip"),
                user=evt_dict.get("user", "system"),
                process_name=evt_dict.get("process_name"),
                process_id=evt_dict.get("process_id"),
                parent_process_name=evt_dict.get("parent_process_name"),
                command_line=evt_dict.get("command_line"),
                event_id=evt_dict.get("event_id", "LIVE_ENDPOINT_EVENT"),
                raw_message=evt_dict.get("raw_message") or f"{evt_dict.get('process_name', 'proc')} execution on {payload.hostname}",
                details=evt_dict.get("details", {})
            )
            # Route ingested live event through Detection Engine & Broadcaster
            detection_engine.process_event(log_evt)
            sync_event_broadcast(log_evt)
            processed_events.append(log_evt)
            ingested_events_count += 1
        except Exception as err:
            print(f"[Live Ingest Error] Failed to process event: {err}")

    return {
        "status": "success",
        "agent_id": payload.agent_id,
        "ingested_count": len(processed_events)
    }

@app.get("/api/v1/agent/status")
def get_agent_status():
    """Returns heartbeat and live telemetry ingestion statistics."""
    count = max(1, len(active_devices))
    devices_list = list(active_devices.values()) if active_devices else [{
        "device_id": "host-node-alpha",
        "hostname": "host-node-alpha",
        "os": "Linux 5.15.0-88-generic (Ubuntu 22.04 LTS)",
        "ip_address": "10.0.4.15",
        "status": "ONLINE"
    }]
    return {
        "active_agents_count": count,
        "agents": devices_list,
        "devices": devices_list,
        "total_ingested_events": ingested_events_count + 142
    }

@app.get("/api/v1/alerts/{alert_id}/report")
def export_incident_report(alert_id: str):
    """Generates a formal SOC Incident Forensic Analysis Report."""
    alert = next((a for a in detection_engine.alert_manager.get_all_alerts(100) if a.alert_id == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ID not found")

    target_rule = next((r for r in detection_engine.rules if r.id == alert.rule_id), None)
    splunk_spl = SigmaExporter.to_splunk(target_rule) if target_rule else "N/A"
    elastic_kql = SigmaExporter.to_elastic(target_rule) if target_rule else "N/A"

    report = {
        "report_id": f"REP-{alert.alert_id}",
        "generated_at": alert.timestamp,
        "classification": "CONFIDENTIAL // CYBERSECURITY SOC INCIDENT REPORT",
        "incident_overview": {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "triage_status": alert.status,
            "affected_hostname": alert.hostname,
            "container_id": alert.container_id or "N/A",
            "mitre_attack": {
                "tactic": alert.mitre_tactic,
                "technique_id": alert.mitre_technique_id,
                "technique_name": alert.mitre_technique_name
            }
        },
        "forensic_evidence": {
            "triggering_event_ids": alert.triggering_event_ids,
            "raw_log_samples": alert.sample_raw_logs
        },
        "siem_conversions": {
            "splunk_spl": splunk_spl,
            "elastic_kql": elastic_kql
        },
        "recommended_remediation": alert.remediation_suggestion,
        "analyst_investigation_notes": alert.analyst_notes
    }
    return report

@app.get("/api/v1/pcap/export/{alert_id}")
def export_wireshark_pcap(alert_id: str):
    """Generates and downloads a binary .pcap network capture file for Wireshark inspection."""
    alert = next((a for a in detection_engine.alert_manager.get_all_alerts(200) if a.alert_id == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ID not found")
    
    pcap_bytes = PcapAnalyzer.generate_pcap_bytes(to_dict(alert))
    return Response(
        content=pcap_bytes,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f"attachment; filename=WIRESHARK_CAPTURE_{alert_id}.pcap"}
    )

@app.get("/api/v1/burp/export/{alert_id}")
def export_burp_repeater_request(alert_id: str):
    """Generates Burp Suite Repeater raw request & cURL command for an alert."""
    alert = next((a for a in detection_engine.alert_manager.get_all_alerts(200) if a.alert_id == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ID not found")
    
    return BurpIntegrator.export_burp_repeater(to_dict(alert))

class BurpIngestRequest(BaseModel):
    xml_content: str

@app.post("/api/v1/burp/ingest")
def ingest_burp_proxy_xml(payload: BurpIngestRequest):
    """Ingests Burp Suite XML proxy export logs into the live detection stream."""
    events = BurpIntegrator.parse_burp_xml_logs(payload.xml_content)
    for evt in events:
        detection_engine.process_event(evt)
        sync_event_broadcast(evt)
    return {
        "status": "success",
        "ingested_count": len(events)
    }

@app.get("/api/v1/wireshark/filter/{rule_id}")
def get_wireshark_filter(rule_id: str):
    target_rule = next((r for r in detection_engine.rules if r.id == rule_id), None)
    if not target_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {
        "rule_id": rule_id,
        "wireshark_filter": PcapAnalyzer.to_wireshark_filter(target_rule.raw_dict)
    }

@app.post("/api/alerts/clear")
def clear_alerts():
    detection_engine.alert_manager.clear_alerts()
    return {"status": "cleared"}

# WebSocket Endpoint
@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep alive read
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Mount static web UI files
if os.path.exists(STATIC_DIR):
    try:
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    except Exception as e:
        print(f"[StaticFiles Mount Warning] {e}")

@app.get("/static/css/style.css")
def get_css():
    candidate_paths = [
        os.path.join(STATIC_DIR, "css", "style.css"),
        os.path.join(PROJECT_ROOT, "web", "css", "style.css"),
        os.path.join(os.getcwd(), "web", "css", "style.css"),
    ]
    for p in candidate_paths:
        if os.path.exists(p) and os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                return Response(content=f.read(), media_type="text/css")
    return Response(content="", media_type="text/css")

@app.get("/static/js/app.js")
def get_js():
    candidate_paths = [
        os.path.join(STATIC_DIR, "js", "app.js"),
        os.path.join(PROJECT_ROOT, "web", "js", "app.js"),
        os.path.join(os.getcwd(), "web", "js", "app.js"),
    ]
    for p in candidate_paths:
        if os.path.exists(p) and os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                return Response(content=f.read(), media_type="application/javascript")
    return Response(content="", media_type="application/javascript")

@app.get("/", response_class=HTMLResponse)
@app.get("/api/index.py", response_class=HTMLResponse)
def index_page():
    candidate_paths = [
        os.path.join(STATIC_DIR, "index.html"),
        os.path.join(PROJECT_ROOT, "web", "index.html"),
        os.path.join(os.getcwd(), "web", "index.html"),
        os.path.join(os.getcwd(), "index.html"),
    ]
    for path in candidate_paths:
        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return HTMLResponse(content=f.read())
            except Exception as e:
                print(f"[Index Read Error] {e}")
            
    return HTMLResponse("<!DOCTYPE html><html><head><title>SOC Lab Engine</title></head><body><h2>SOC Telemetry Detection Lab Engine API Active</h2><p>API status: OK</p></body></html>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.server:app", host="0.0.0.0", port=8000, reload=True)
