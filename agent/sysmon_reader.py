"""
Windows Sysmon Telemetry Reader and Checkpoint Manager
Integrates Microsoft Sysmon (Microsoft-Windows-Sysmon/Operational) on Windows 11
into the SOC Telemetry Detection Lab.

Collects and normalizes Event IDs 1, 3, 5, and 22 into standardized LogEvent payloads
with persistent atomic checkpointing, deduplication, and graceful error recovery.
"""

import os
import sys
import json
import uuid
import socket
import logging
import datetime
import xml.etree.ElementTree as ET
from collections import deque
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("SysmonReader")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

EVENT_ID_MAP = {
    1: "SYSMON_PROCESS_CREATE",
    3: "SYSMON_NETWORK_CONNECT",
    5: "SYSMON_PROCESS_TERMINATE",
    22: "SYSMON_DNS_QUERY"
}


def _clean_tag(tag: str) -> str:
    """Strips XML namespaces from tag names."""
    return tag.split("}")[-1] if "}" in tag else tag


def _safe_int(val: Any) -> Optional[int]:
    """Safely parses integers from decimal or hex strings."""
    if val is None:
        return None
    val_str = str(val).strip()
    if not val_str:
        return None
    try:
        if val_str.startswith("0x") or val_str.startswith("0X"):
            return int(val_str, 16)
        return int(val_str)
    except (ValueError, TypeError):
        return None


def parse_sysmon_xml(xml_content: str) -> List[Dict[str, Any]]:
    """
    Parses Windows Event Log XML string into structured event dictionaries.
    Supports a single <Event> or multiple <Event> tags wrapped in <Events>.
    Handles missing or optional fields safely without crashing.
    """
    if not xml_content or not xml_content.strip():
        return []

    content = xml_content.strip()
    if not content.startswith("<Events") and not content.startswith("<events"):
        content = f"<Events>{content}</Events>"

    try:
        root = ET.fromstring(content)
    except ET.ParseError as err:
        logger.warning(f"Sysmon XML parse error: {err}")
        return []

    parsed_events = []
    events_elements = root if _clean_tag(root.tag).lower() == "event" else root.findall(".//{*}Event")
    if not events_elements:
        events_elements = [child for child in root if _clean_tag(child.tag).lower() == "event"]

    for ev_elem in events_elements:
        raw_xml_str = ET.tostring(ev_elem, encoding="utf-8").decode("utf-8", errors="replace")
        event_dict: Dict[str, Any] = {
            "EventID": None,
            "EventRecordID": None,
            "TimeCreated": None,
            "Computer": None,
            "Channel": SYSMON_CHANNEL,
            "raw_xml": raw_xml_str
        }

        # 1. Parse <System> element
        system_elem = ev_elem.find(".//{*}System")
        if system_elem is None:
            system_elem = next((child for child in ev_elem if _clean_tag(child.tag).lower() == "system"), None)

        if system_elem is not None:
            for child in system_elem:
                tag = _clean_tag(child.tag)
                if tag == "EventID":
                    event_dict["EventID"] = _safe_int(child.text)
                elif tag == "EventRecordID":
                    event_dict["EventRecordID"] = _safe_int(child.text)
                elif tag == "TimeCreated":
                    event_dict["TimeCreated"] = child.attrib.get("SystemTime")
                elif tag == "Computer":
                    event_dict["Computer"] = child.text
                elif tag == "Channel":
                    event_dict["Channel"] = child.text

        # 2. Parse <EventData> element
        event_data_elem = ev_elem.find(".//{*}EventData")
        if event_data_elem is None:
            event_data_elem = next((child for child in ev_elem if _clean_tag(child.tag).lower() == "eventdata"), None)

        if event_data_elem is not None:
            for data_elem in event_data_elem:
                if _clean_tag(data_elem.tag) == "Data":
                    name = data_elem.attrib.get("Name")
                    if name:
                        event_dict[name] = data_elem.text or ""

        # Safe integer casts for known numeric fields
        for int_field in ["ProcessId", "ParentProcessId", "SourcePort", "DestinationPort"]:
            if int_field in event_dict:
                event_dict[int_field] = _safe_int(event_dict[int_field])

        parsed_events.append(event_dict)

    return parsed_events


def normalize_sysmon_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes a parsed Sysmon event dictionary into the project's LogEvent schema.
    Assigns stable unique IDs, maps Sysmon Event IDs to standardized identifiers,
    and formats human-readable raw messages.
    """
    eid = event_data.get("EventID")
    record_id = event_data.get("EventRecordID") or 0
    hostname = event_data.get("Computer") or socket.gethostname()
    channel = event_data.get("Channel") or SYSMON_CHANNEL
    timestamp = event_data.get("TimeCreated") or datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Stable unique event ID derived from host, channel, and EventRecordID
    stable_id = f"sysmon-{hostname.lower()}-{record_id}"

    normalized_event_id = EVENT_ID_MAP.get(eid, f"SYSMON_EVENT_{eid}")

    # Process names
    image = event_data.get("Image") or ""
    process_name = os.path.basename(image) if image else None

    parent_image = event_data.get("ParentImage") or ""
    parent_process_name = os.path.basename(parent_image) if parent_image else None

    cmdline = event_data.get("CommandLine") or None
    user = event_data.get("User") or None
    pid = event_data.get("ProcessId")
    src_ip = event_data.get("SourceIp") or None

    # Construct descriptive raw message
    if eid == 1:
        raw_msg = (
            f"Sysmon EID 1 (ProcessCreate): Image='{image}' PID={pid} "
            f"Parent='{parent_image}' User='{user or 'UNKNOWN'}' Cmd='{cmdline or ''}'"
        )
    elif eid == 3:
        src_port = event_data.get("SourcePort")
        dst_ip = event_data.get("DestinationIp", "")
        dst_port = event_data.get("DestinationPort")
        proto = event_data.get("Protocol", "tcp")
        raw_msg = (
            f"Sysmon EID 3 (NetworkConnect): {process_name or image} (PID: {pid}) "
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})"
        )
    elif eid == 5:
        raw_msg = f"Sysmon EID 5 (ProcessTerminate): Image='{image}' PID={pid} User='{user or 'UNKNOWN'}'"
    elif eid == 22:
        qname = event_data.get("QueryName", "")
        qstatus = event_data.get("QueryStatus", "")
        qresults = event_data.get("QueryResults", "")
        raw_msg = (
            f"Sysmon EID 22 (DnsQuery): Process='{process_name or image}' (PID: {pid}) "
            f"QueryName='{qname}' QueryStatus={qstatus} Results='{qresults}'"
        )
    else:
        raw_msg = f"Sysmon EID {eid}: RecordID={record_id} Process='{process_name}' User='{user}'"

    # Deep details dictionary for investigation and MITRE correlation
    details: Dict[str, Any] = {
        "sysmon_event_id": eid,
        "EventRecordID": record_id,
        "Channel": channel,
        "Computer": hostname,
        "ProcessGuid": event_data.get("ProcessGuid"),
        "ProcessId": pid,
        "Image": image,
        "CommandLine": cmdline,
        "User": user,
        "ParentProcessGuid": event_data.get("ParentProcessGuid"),
        "ParentProcessId": event_data.get("ParentProcessId"),
        "ParentImage": parent_image,
        "ParentCommandLine": event_data.get("ParentCommandLine"),
        "SourceIp": src_ip,
        "SourcePort": event_data.get("SourcePort"),
        "DestinationIp": event_data.get("DestinationIp"),
        "DestinationPort": event_data.get("DestinationPort"),
        "Protocol": event_data.get("Protocol"),
        "Initiated": event_data.get("Initiated"),
        "QueryName": event_data.get("QueryName"),
        "QueryStatus": event_data.get("QueryStatus"),
        "QueryResults": event_data.get("QueryResults"),
        "Hashes": event_data.get("Hashes"),
        "CurrentDirectory": event_data.get("CurrentDirectory"),
        "RuleName": event_data.get("RuleName"),
        "raw_xml": event_data.get("raw_xml")
    }

    # Clean out None values from details
    details = {k: v for k, v in details.items() if v is not None}

    return {
        "id": stable_id,
        "timestamp": timestamp,
        "log_type": "windows.sysmon",
        "hostname": hostname,
        "user": user,
        "process_name": process_name,
        "process_id": pid,
        "parent_process_name": parent_process_name,
        "command_line": cmdline,
        "source_ip": src_ip,
        "event_id": normalized_event_id,
        "raw_message": raw_msg,
        "details": details,
        "telemetry_source": "live",
        "ground_truth": None
    }


class SysmonCheckpointManager:
    """
    Persistent atomic checkpoint tracker for Windows Event Log ingestion.
    Remembers the last successfully ingested EventRecordID across agent restarts.
    Writes atomically to an external application directory outside git version control.
    """
    def __init__(
        self,
        checkpoint_path: Optional[str] = None,
        hostname: Optional[str] = None,
        channel: str = SYSMON_CHANNEL
    ):
        self.hostname = hostname or socket.gethostname()
        self.channel = channel
        self.checkpoint_path = checkpoint_path or self._get_default_checkpoint_path()
        self.last_record_id: int = 0
        self.last_timestamp: str = ""
        self.load()

    def _get_default_checkpoint_path(self) -> str:
        base_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
        safe_channel = self.channel.replace("/", "_").replace("\\", "_")
        return os.path.join(
            base_dir,
            "soc_telemetry_lab",
            "checkpoints",
            f"sysmon_{safe_channel}_{self.hostname.lower()}_checkpoint.json"
        )

    def load(self) -> int:
        if os.path.exists(self.checkpoint_path):
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if (
                        data.get("channel") == self.channel
                        and data.get("hostname", "").lower() == self.hostname.lower()
                    ):
                        self.last_record_id = int(data.get("last_record_id", 0))
                        self.last_timestamp = data.get("last_timestamp", "")
                        logger.info(
                            f"[SysmonCheckpoint] Loaded checkpoint: EventRecordID={self.last_record_id} "
                            f"from {self.checkpoint_path}"
                        )
            except Exception as e:
                logger.warning(f"[SysmonCheckpoint] Error reading {self.checkpoint_path}: {e}. Starting at 0.")
                self.last_record_id = 0
        return self.last_record_id

    def commit(self, record_id: int, timestamp: str = "") -> bool:
        """
        Atomically commits the new checkpoint to disk.
        Does NOT advance if record_id is less than or equal to current checkpoint.
        """
        if record_id <= self.last_record_id:
            return False

        self.last_record_id = record_id
        if timestamp:
            self.last_timestamp = timestamp

        try:
            target_dir = os.path.dirname(os.path.abspath(self.checkpoint_path))
            os.makedirs(target_dir, exist_ok=True)
            tmp_path = os.path.join(target_dir, f".ckpt_{uuid.uuid4().hex[:8]}.tmp")
            payload = {
                "hostname": self.hostname,
                "channel": self.channel,
                "last_record_id": self.last_record_id,
                "last_timestamp": self.last_timestamp,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, self.checkpoint_path)
            return True
        except Exception as e:
            logger.error(f"[SysmonCheckpoint] Failed to write atomic checkpoint: {e}")
            return False

    def reset(self, new_record_id: int = 0):
        """Resets the checkpoint (e.g. after event log clear detection)."""
        self.last_record_id = new_record_id
        self.commit(new_record_id)


class SysmonReader:
    """
    Production Windows Sysmon event log reader.
    Streams Process Create (1), Network Connect (3), Process Terminate (5), and DNS Query (22)
    events from Microsoft-Windows-Sysmon/Operational with persistent atomic checkpointing.
    """
    def __init__(
        self,
        channel: str = SYSMON_CHANNEL,
        checkpoint_dir: Optional[str] = None,
        checkpoint_file: Optional[str] = None,
        batch_size: int = 100,
        max_backlog: int = 500,
        mock_event_xmls: Optional[List[str]] = None
    ):
        self.channel = channel
        self.batch_size = min(max(batch_size, 1), 500)
        self.max_backlog = max_backlog
        self.hostname = socket.gethostname()
        self.mock_event_xmls = mock_event_xmls  # For unit tests and offline simulations

        ckpt_path = checkpoint_file
        if not ckpt_path and checkpoint_dir:
            safe_channel = channel.replace("/", "_").replace("\\", "_")
            ckpt_path = os.path.join(checkpoint_dir, f"sysmon_{safe_channel}_{self.hostname.lower()}_checkpoint.json")

        self.checkpoint = SysmonCheckpointManager(checkpoint_path=ckpt_path, hostname=self.hostname, channel=self.channel)
        self.seen_record_ids: deque = deque(maxlen=10000)

        # Pending uncommitted checkpoint watermark
        self.pending_commit_record_id: Optional[int] = None
        self._access_denied_warned = False
        self._channel_missing_warned = False

    @staticmethod
    def is_supported() -> bool:
        """Sysmon reading is native to Windows."""
        return sys.platform == "win32"

    def read_events(self, limit: Optional[int] = None) -> Tuple[List[Dict[str, Any]], int]:
        """
        Reads a batch of new Sysmon events occurring after the current checkpoint.
        Returns:
            Tuple of (list_of_normalized_events, max_record_id_in_batch).
        Note: The checkpoint is NOT advanced automatically here; the caller must
        call `commit_checkpoint(max_record_id)` after the SOC API successfully accepts the batch.
        """
        batch_limit = limit or self.batch_size
        batch_limit = min(batch_limit, 500)

        raw_xml_list = self._query_events(min_record_id=self.checkpoint.last_record_id, limit=batch_limit)
        if not raw_xml_list:
            return [], self.checkpoint.last_record_id

        normalized_events = []
        max_record_id = self.checkpoint.last_record_id

        for xml_str in raw_xml_list:
            parsed_list = parse_sysmon_xml(xml_str)
            for parsed in parsed_list:
                eid = parsed.get("EventID")
                if eid not in EVENT_ID_MAP:
                    continue

                rec_id = parsed.get("EventRecordID")
                if rec_id is None:
                    continue

                # Deduplication check
                if rec_id <= self.checkpoint.last_record_id or rec_id in self.seen_record_ids:
                    continue

                self.seen_record_ids.append(rec_id)
                norm_evt = normalize_sysmon_event(parsed)
                normalized_events.append(norm_evt)

                if rec_id > max_record_id:
                    max_record_id = rec_id

        # Sort in strict chronological order by EventRecordID
        normalized_events.sort(key=lambda x: x.get("details", {}).get("EventRecordID", 0))

        self.pending_commit_record_id = max_record_id
        return normalized_events, max_record_id

    def commit_checkpoint(self, record_id: int):
        """
        Advances and saves the checkpoint to disk after verified API ingestion.
        """
        if record_id > self.checkpoint.last_record_id:
            self.checkpoint.commit(record_id)
            self.pending_commit_record_id = None

    def _query_events(self, min_record_id: int, limit: int) -> List[str]:
        """
        Queries Windows Event Log for events where EventRecordID > min_record_id.
        Tries native Win32 EvtQuery/EvtRender first, falls back to wevtutil.
        """
        if self.mock_event_xmls is not None:
            # Test fixture / mock mode
            return self.mock_event_xmls

        if not self.is_supported():
            return []

        # 1. Try native ctypes Win32 wevtapi query
        try:
            events = self._query_events_win32(min_record_id=min_record_id, limit=limit)
            if events:
                return events
        except Exception as e:
            logger.debug(f"Win32 ctypes query attempt failed: {e}. Trying wevtutil.")

        # 2. Fallback to wevtutil.exe
        return self._query_events_wevtutil(min_record_id=min_record_id, limit=limit)

    def _query_events_win32(self, min_record_id: int, limit: int) -> List[str]:
        """
        Direct Win32 API implementation using ctypes and wevtapi.dll.
        Executes without subprocess overhead.
        """
        import ctypes
        from ctypes import wintypes

        wevtapi = ctypes.windll.wevtapi
        EVT_HANDLE = wintypes.HANDLE
        EVT_QUERY_FLAGS = 1  # EvtQueryChannelPath
        EVT_QUERY_FORWARD = 0x100  # Chronological order
        EvtRenderEventXml = 1

        wevtapi.EvtQuery.argtypes = [EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        wevtapi.EvtQuery.restype = EVT_HANDLE

        wevtapi.EvtNext.argtypes = [
            EVT_HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(EVT_HANDLE),
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)
        ]
        wevtapi.EvtNext.restype = wintypes.BOOL

        wevtapi.EvtRender.argtypes = [
            EVT_HANDLE,
            EVT_HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD)
        ]
        wevtapi.EvtRender.restype = wintypes.BOOL

        wevtapi.EvtClose.argtypes = [EVT_HANDLE]
        wevtapi.EvtClose.restype = wintypes.BOOL

        if min_record_id > 0:
            xpath = f"*[System[(EventRecordID > {min_record_id}) and (EventID=1 or EventID=3 or EventID=5 or EventID=22)]]"
        else:
            xpath = "*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=22)]]"

        hQuery = wevtapi.EvtQuery(None, self.channel, xpath, EVT_QUERY_FLAGS | EVT_QUERY_FORWARD)
        if not hQuery:
            err = ctypes.GetLastError()
            if err == 5:  # ERROR_ACCESS_DENIED
                if not self._access_denied_warned:
                    logger.warning(
                        f"[SysmonReader] Access denied reading '{self.channel}'. "
                        "To collect live Windows Sysmon telemetry, run the agent with Administrator "
                        "privileges or add the current user to the 'Event Log Readers' group."
                    )
                    self._access_denied_warned = True
            elif err == 15007:  # ERROR_EVT_CHANNEL_NOT_FOUND
                if not self._channel_missing_warned:
                    logger.warning(
                        f"[SysmonReader] Channel '{self.channel}' not found. "
                        "Verify Microsoft Sysmon is installed and its operational log is enabled."
                    )
                    self._channel_missing_warned = True
            elif err == 1722:  # RPC_S_SERVER_UNAVAILABLE
                logger.warning("[SysmonReader] Windows Event Log RPC server unavailable (service may be stopped).")
            return []

        xml_results = []
        try:
            hEvents = (EVT_HANDLE * limit)()
            returned_count = wintypes.DWORD(0)

            if wevtapi.EvtNext(hQuery, limit, hEvents, 1000, 0, ctypes.byref(returned_count)):
                for i in range(returned_count.value):
                    hEvent = hEvents[i]
                    buf_size = wintypes.DWORD(65536)
                    buf = ctypes.create_unicode_buffer(buf_size.value)
                    used = wintypes.DWORD(0)
                    prop_count = wintypes.DWORD(0)

                    if wevtapi.EvtRender(None, hEvent, EvtRenderEventXml, buf_size.value * 2, buf, ctypes.byref(used), ctypes.byref(prop_count)):
                        xml_results.append(buf.value)
                    wevtapi.EvtClose(hEvent)
        finally:
            wevtapi.EvtClose(hQuery)

        return xml_results

    def _query_events_wevtutil(self, min_record_id: int, limit: int) -> List[str]:
        """
        CLI fallback using wevtutil.exe to query XML records.
        """
        import subprocess

        if min_record_id > 0:
            xpath = f"*[System[(EventRecordID > {min_record_id}) and (EventID=1 or EventID=3 or EventID=5 or EventID=22)]]"
        else:
            xpath = "*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=22)]]"

        cmd = [
            "wevtutil",
            "qe",
            self.channel,
            f"/q:{xpath}",
            "/f:xml",
            f"/c:{limit}",
            "/rd:false"
        ]

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8.0)
            if res.returncode == 0:
                output = res.stdout.strip()
                if not output:
                    # Check for log clearing if empty output but min_record_id > 0
                    if min_record_id > 0:
                        self._check_for_log_reset_wevtutil()
                    return []
                return [output]
            else:
                err_text = res.stderr.strip()
                if "Access is denied" in err_text or "access is denied" in err_text.lower():
                    if not self._access_denied_warned:
                        logger.warning(
                            f"[SysmonReader] Access denied reading '{self.channel}'. "
                            "Please run agent as Administrator or add user to 'Event Log Readers' group."
                        )
                        self._access_denied_warned = True
                elif "could not be found" in err_text.lower():
                    if not self._channel_missing_warned:
                        logger.warning(f"[SysmonReader] Channel '{self.channel}' not found.")
                        self._channel_missing_warned = True
                return []
        except subprocess.TimeoutExpired:
            logger.warning("[SysmonReader] wevtutil command timed out.")
            return []
        except Exception as e:
            logger.warning(f"[SysmonReader] Error querying via wevtutil: {e}")
            return []

    def _check_for_log_reset_wevtutil(self):
        """
        Detects if Sysmon event log was cleared or EventRecordID reset.
        Queries the single newest event in the channel.
        """
        import subprocess
        cmd = ["wevtutil", "qe", self.channel, "/c:1", "/rd:true", "/f:xml"]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4.0)
            if res.returncode == 0 and res.stdout.strip():
                parsed = parse_sysmon_xml(res.stdout)
                if parsed:
                    newest_id = parsed[0].get("EventRecordID")
                    if newest_id and newest_id < self.checkpoint.last_record_id:
                        logger.warning(
                            f"[SysmonReader] Log reset detected on '{self.channel}'! "
                            f"Checkpoint was {self.checkpoint.last_record_id}, newest is {newest_id}. Resetting to 0."
                        )
                        self.checkpoint.reset(0)
                        self.seen_record_ids.clear()
        except Exception:
            pass
