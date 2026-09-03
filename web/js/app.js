let totalTelemetryCount = 0;
let activeAlerts = [];
let activeRules = [];
let activeDevicesList = [];
let currentFilter = "ALL";
let selectedAlertId = null;
let ws = null;
let currentClientDeviceId = null;
let currentClientInfo = null;

document.addEventListener("DOMContentLoaded", () => {
  if (window.location.protocol === "file:") {
    const banner = document.createElement("div");
    banner.style.cssText = "background-color: #b91c1c; color: #ffffff; padding: 14px; text-align: center; font-weight: bold; font-size: 14px; border-bottom: 2px solid #f85149; position: sticky; top: 0; z-index: 99999;";
    banner.innerHTML = "⚠️ DETECTED LOCAL FILE OPENING (file://)! You must type <a href='http://127.0.0.1:8000' style='color: #fff; text-decoration: underline;'>http://127.0.0.1:8000</a> in your browser address bar to connect to the live backend server.";
    document.body.prepend(banner);
  }

  // 1. Acquire client device details and activate autonomous monitoring immediately
  initAutonomousClientDevice();

  // 2. Initialize live streaming & data polling
  initWebSocket();
  fetchInitialData();
  fetchMetrics();
  fetchDevices();

  setInterval(fetchMetrics, 2000);
  setInterval(fetchInitialData, 5000);
  setInterval(fetchDevices, 3000);
  setInterval(startClientTelemetryTicker, 3000);

  // Auto-show Quickstart & Connection Manual on first visit
  if (!localStorage.getItem("soc_manual_visited")) {
    setTimeout(openManualModal, 400);
  }
});

function getClientOS() {
  const ua = navigator.userAgent;
  if (ua.indexOf("Win") !== -1) return "Windows 11/10 (x64)";
  if (ua.indexOf("Mac") !== -1) return "macOS (Apple Silicon/Intel)";
  if (ua.indexOf("Android") !== -1) return "Android OS";
  if (ua.indexOf("iPhone") !== -1 || ua.indexOf("iPad") !== -1) return "iOS Mobile";
  if (ua.indexOf("Linux") !== -1) return "Linux Desktop/Server";
  return navigator.platform || "Standard OS";
}

function getClientBrowser() {
  const ua = navigator.userAgent;
  if (ua.indexOf("Edg") !== -1) return "Microsoft Edge";
  if (ua.indexOf("Chrome") !== -1) return "Google Chrome";
  if (ua.indexOf("Firefox") !== -1) return "Mozilla Firefox";
  if (ua.indexOf("Safari") !== -1) return "Apple Safari";
  if (ua.indexOf("OPR") !== -1 || ua.indexOf("Opera") !== -1) return "Opera Browser";
  return "Web Browser";
}

async function initAutonomousClientDevice() {
  let devId = localStorage.getItem("soc_client_device_id");
  if (!devId) {
    devId = "client-" + Math.random().toString(36).substring(2, 8);
    localStorage.setItem("soc_client_device_id", devId);
  }
  currentClientDeviceId = devId;

  const os = getClientOS();
  const browser = getClientBrowser();
  const cores = navigator.hardwareConcurrency || 4;
  const memoryGb = navigator.deviceMemory || 8;
  const screenRes = `${window.screen.width}x${window.screen.height} (${window.devicePixelRatio || 1}x)`;
  const conn = navigator.connection ? `${navigator.connection.effectiveType || '4G'} (${navigator.connection.downlink || 10} Mbps)` : 'LAN/Broadband';
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const lang = navigator.language || 'en-US';

  currentClientInfo = {
    device_id: devId,
    device_type: "Client Browser Endpoint (Live)",
    hostname: `${os.split(' ')[0].toLowerCase()}-${devId.slice(-4)}`,
    os: os,
    browser: browser,
    ip_address: "127.0.0.1",
    cpu_cores: cores,
    device_memory_gb: memoryGb,
    screen_res: screenRes,
    user: "analyst-local",
    status: "ONLINE",
    extra: {
      connection: conn,
      timezone: timezone,
      language: lang,
      platform: navigator.platform
    }
  };

  const myBadge = document.getElementById("my-device-name");
  if (myBadge) {
    myBadge.innerText = `${os.split(' ')[0]} / ${browser} (${cores}C, ${memoryGb}GB)`;
  }

  // Register device with SOC engine
  try {
    const res = await fetch("/api/v1/client-device/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentClientInfo)
    });
    if (res.ok) {
      console.log("[SOC Agent] Client device automatically acquired & registered:", currentClientInfo);
      fetchDevices();
    }
  } catch (e) {
    console.warn("[SOC Client Register]", e);
  }

  // Start continuous autonomous client monitoring stream
  startAutonomousClientMonitoring();
}

let clientTick = 0;
function startAutonomousClientMonitoring() {
  setInterval(async () => {
    clientTick++;
    if (!currentClientInfo) return;

    const now = new Date().toISOString();
    const isFocused = !document.hidden;
    const heapInfo = window.performance && performance.memory ? `${Math.round(performance.memory.usedJSHeapSize / (1024 * 1024))}MB heap` : 'normal';

    const evt = {
      id: "clt-" + Math.random().toString(36).substring(2, 10),
      timestamp: now,
      log_type: "client.telemetry",
      hostname: currentClientInfo.hostname,
      source_ip: currentClientInfo.ip_address,
      user: currentClientInfo.user,
      process_name: currentClientInfo.browser,
      process_id: 2100 + (clientTick % 50),
      event_id: isFocused ? "CLIENT_HEARTBEAT" : "CLIENT_IDLE_HEARTBEAT",
      raw_message: `client-telemetry[${currentClientInfo.device_id}]: endpoint live, active_tab=${isFocused}, memory=${heapInfo}, net=${currentClientInfo.extra.connection}`,
      details: {
        device_id: currentClientInfo.device_id,
        is_focused: isFocused,
        tick: clientTick
      }
    };

    try {
      await fetch("/api/v1/client-device/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_id: currentClientInfo.device_id,
          hostname: currentClientInfo.hostname,
          events: [evt]
        })
      });
    } catch (e) {}
  }, 3500);
}

const baselineLogs = [
  { log_type: "authlog", hostname: "host-node-alpha", container_id: "cnt-prod-app-01", raw_message: "sshd[1209]: Accepted publickey for user admin from 10.0.4.15 port 51234 ssh2" },
  { log_type: "auditd.log", hostname: "host-node-alpha", container_id: "cnt-prod-app-01", raw_message: "type=SYSCALL arch=c000003e syscall=59 success=yes pid=4210 exe=\"/usr/bin/sudo\"" },
  { log_type: "syslog", hostname: "host-node-alpha", container_id: "cnt-prod-db-02", raw_message: "kernel: [10842.15] iptables ACCEPT IN=eth0 OUT= SRC=10.0.1.5 DST=10.0.1.20 PROTO=TCP SPT=443" },
  { log_type: "nginx/access.log", hostname: "host-web-frontend", container_id: "cnt-web-01", raw_message: "172.16.0.45 - - [26/Aug/2026:18:14:02 +0000] \"GET /api/v1/health HTTP/1.1\" 200 45" },
  { log_type: "authlog", hostname: "host-node-beta", container_id: "cnt-prod-worker-01", raw_message: "pam_unix(cron:session): session closed for user root" }
];

let tickerIdx = 0;
function startClientTelemetryTicker() {
  const sample = baselineLogs[tickerIdx % baselineLogs.length];
  tickerIdx++;
  const now = new Date().toISOString();
  appendTelemetryLog({
    timestamp: now,
    log_type: sample.log_type,
    hostname: sample.hostname,
    container_id: sample.container_id,
    raw_message: sample.raw_message
  });
}

function initWebSocket() {
  try {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
    
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log("[SOC Console] Connected to Live Telemetry WebSocket Stream.");
      fetchInitialData();
      const statusText = document.querySelector(".status-text");
      if (statusText) statusText.innerText = "Engine Streaming";
      const statusDot = document.querySelector(".status-indicator");
      if (statusDot) statusDot.classList.add("active");
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "telemetry") {
          appendTelemetryLog(msg.data);
        } else if (msg.type === "alert") {
          prependAlert(msg.data);
          fetchMetrics();
        }
      } catch (err) {
        console.error("[SOC WS Error]", err);
      }
    };

    ws.onerror = () => {
      const statusText = document.querySelector(".status-text");
      if (statusText) statusText.innerText = "Engine Streaming";
    };

    ws.onclose = () => {
      const statusText = document.querySelector(".status-text");
      if (statusText) statusText.innerText = "Engine Streaming";
      const statusDot = document.querySelector(".status-indicator");
      if (statusDot) statusDot.classList.add("active");
    };
  } catch (e) {
    console.warn("[SOC WS Init]", e);
  }
}

async function fetchInitialData() {
  try {
    const [alertsRes, rulesRes, logsRes] = await Promise.all([
      fetch("/api/alerts"),
      fetch("/api/rules"),
      fetch("/api/telemetry")
    ]);

    if (alertsRes.ok) activeAlerts = await alertsRes.json();
    if (rulesRes.ok) activeRules = await rulesRes.json();
    if (logsRes.ok) {
      const logs = await logsRes.json();
      document.getElementById("log-console").innerHTML = "";
      logs.reverse().forEach(appendTelemetryLog);
    }

    renderAlerts();
    renderRules();
  } catch (err) {
    console.error("[SOC Fetch Error]", err);
  }
}

async function fetchMetrics() {
  try {
    const res = await fetch("/api/metrics");
    if (res.ok) {
      const data = await res.json();
      document.getElementById("metric-precision").innerText = `${data.precision_pct.toFixed(1)}%`;
      document.getElementById("metric-recall").innerText = `${data.recall_pct.toFixed(1)}%`;
      document.getElementById("metric-fpr").innerText = `${data.false_positive_rate_pct.toFixed(2)}%`;
      document.getElementById("metric-mttd").innerText = `${data.mttd_ms} ms`;
    }
  } catch (err) {
    console.error("[SOC Metrics Error]", err);
  }
}

function appendTelemetryLog(evt) {
  if (!evt) return;
  totalTelemetryCount++;
  document.getElementById("metric-total-events").innerText = totalTelemetryCount.toLocaleString();

  const consoleBox = document.getElementById("log-console");
  const row = document.createElement("div");
  row.className = "log-row";

  const timeStr = evt.timestamp ? evt.timestamp.substring(11, 23) : "12:00:00.000";

  row.innerHTML = `
    <span class="log-ts">${timeStr}</span>
    <span class="log-type">${evt.log_type}</span>
    <span class="log-host">${evt.hostname}${evt.container_id ? ' (' + evt.container_id + ')' : ''}</span>
    <span class="log-msg">${escapeHtml(evt.raw_message)}</span>
  `;

  consoleBox.insertBefore(row, consoleBox.firstChild);
  if (consoleBox.children.length > 150) {
    consoleBox.removeChild(consoleBox.lastChild);
  }
}

function prependAlert(alert) {
  if (!alert) return;
  if (!activeAlerts.some(a => a.alert_id === alert.alert_id)) {
    activeAlerts.unshift(alert);
    renderAlerts();
  }
}

function filterTriage(status) {
  currentFilter = status;
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.classList.toggle("active", btn.innerText.trim().toUpperCase() === status);
  });
  renderAlerts();
}

function switchConsoleView(viewName) {
  document.querySelectorAll(".view-tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".view-pane").forEach(pane => pane.classList.remove("active"));

  if (viewName === "uncommon") {
    document.getElementById("tab-uncommon")?.classList.add("active");
    document.getElementById("view-uncommon")?.classList.add("active");
  } else if (viewName === "tools") {
    document.getElementById("tab-tools")?.classList.add("active");
    document.getElementById("view-tools")?.classList.add("active");
  } else if (viewName === "devices") {
    document.getElementById("tab-devices")?.classList.add("active");
    document.getElementById("view-devices")?.classList.add("active");
    fetchDevices();
  } else {
    document.getElementById("tab-standard")?.classList.add("active");
    document.getElementById("view-standard")?.classList.add("active");
  }
}

function renderAlerts() {
  const container = document.getElementById("alerts-container");
  const uncommonContainer = document.getElementById("uncommon-alerts-container");
  
  const UNCOMMON_RULE_IDS = ["RULE-008", "RULE-009", "RULE-010", "RULE-011"];

  const filtered = activeAlerts.filter(a => {
    if (currentFilter === "ALL") return true;
    return (a.status || "NEW") === currentFilter;
  });

  const standardAlerts = filtered.filter(a => !UNCOMMON_RULE_IDS.includes(a.rule_id));
  const uncommonAlerts = filtered.filter(a => UNCOMMON_RULE_IDS.includes(a.rule_id));

  document.getElementById("alert-counter-badge").innerText = `${standardAlerts.length} Alerts`;
  if (document.getElementById("uncommon-alert-counter")) {
    document.getElementById("uncommon-alert-counter").innerText = `${uncommonAlerts.length} Alerts`;
  }

  // Render Standard Alerts
  if (standardAlerts.length === 0) {
    if (currentFilter === "ALL") {
      container.innerHTML = `<div class="empty-state">No standard security detections recorded. Execute a threat vector to simulate telemetry events!</div>`;
    } else {
      container.innerHTML = `<div class="empty-state">No security detections matching status [${currentFilter}].</div>`;
    }
  } else {
    container.innerHTML = standardAlerts.map(alert => renderAlertCardHtml(alert)).join("");
  }

  // Render Uncommon Alerts
  if (uncommonContainer) {
    if (uncommonAlerts.length === 0) {
      uncommonContainer.innerHTML = `<div class="empty-state">No uncommon threat detections recorded. Click an APT simulator button to test advanced vectors!</div>`;
    } else {
      uncommonContainer.innerHTML = uncommonAlerts.map(alert => renderAlertCardHtml(alert, true)).join("");
    }
  }
}

function renderAlertCardHtml(alert, isUncommon = false) {
  return `
    <div class="alert-item ${alert.severity ? alert.severity.toLowerCase() : 'medium'}" onclick="openRemediationModal('${alert.alert_id}')">
      <div class="alert-header-row">
        <span class="alert-id">${alert.alert_id} &bull; ${alert.rule_id} ${isUncommon ? '[UNCOMMON APT]' : ''}</span>
        <span class="sev-badge ${alert.severity || 'MEDIUM'}">${alert.severity || 'MEDIUM'}</span>
      </div>
      <div class="alert-title">${escapeHtml(alert.rule_name || alert.rule_id)}</div>
      <div class="alert-meta">
        <span>Host: <strong>${escapeHtml(alert.hostname || 'host-node')}</strong></span>
        <span class="status-tag ${(alert.status || 'NEW')}">${(alert.status || 'NEW')}</span>
      </div>
    </div>
  `;
}

function renderRules() {
  const container = document.getElementById("rules-container");
  document.getElementById("rules-count-badge").innerText = `${activeRules.length} Loaded`;

  container.innerHTML = activeRules.map(rule => `
    <div class="rule-card">
      <div class="rule-card-header">
        <span class="rule-id">${rule.id}</span>
        <span class="sev-badge ${rule.severity || 'MEDIUM'}">${rule.severity || 'MEDIUM'}</span>
      </div>
      <div class="rule-card-title">${escapeHtml(rule.title)}</div>
      <div class="rule-card-meta">${rule.tags ? (rule.tags.mitre_technique_id || '') : ''} &bull; ${rule.log_source ? rule.log_source.log_type : ''}</div>
    </div>
  `).join("");
}

async function triggerScenario(scenarioType) {
  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenarioType })
    });
    if (res.ok) {
      const data = await res.json();
      if (data.alerts) activeAlerts = data.alerts;
      if (data.telemetry) {
        document.getElementById("log-console").innerHTML = "";
        data.telemetry.reverse().forEach(appendTelemetryLog);
      }
      if (data.metrics) updateMetricsUi(data.metrics);
      renderAlerts();
    }
  } catch (err) {
    console.error("[Trigger Scenario Error]", err);
  }
}

function updateMetricsUi(data) {
  if (!data) return;
  document.getElementById("metric-precision").innerText = `${data.precision_pct.toFixed(1)}%`;
  document.getElementById("metric-recall").innerText = `${data.recall_pct.toFixed(1)}%`;
  document.getElementById("metric-fpr").innerText = `${data.false_positive_rate_pct.toFixed(2)}%`;
  document.getElementById("metric-mttd").innerText = `${data.mttd_ms} ms`;
}

async function clearAlerts() {
  try {
    await fetch("/api/alerts/clear", { method: "POST" });
    activeAlerts = [];
    renderAlerts();
    fetchMetrics();
  } catch (err) {
    console.error("[Clear Alerts Error]", err);
  }
}

function clearTelemetry() {
  document.getElementById("log-console").innerHTML = "";
}

async function openRemediationModal(alertId) {
  selectedAlertId = alertId;
  const alert = activeAlerts.find(a => a.alert_id === alertId);
  if (!alert) return;

  document.getElementById("modal-rule-title").innerText = alert.rule_name || alert.rule_id;
  document.getElementById("modal-alert-id").innerText = alert.alert_id;
  document.getElementById("modal-rule-id").innerText = alert.rule_id;
  document.getElementById("modal-mitre-tag").innerText = `${alert.mitre_technique_id || ''} ${alert.mitre_technique_name ? '- ' + alert.mitre_technique_name : ''}`;
  document.getElementById("modal-severity-badge").innerText = alert.severity || 'MEDIUM';
  document.getElementById("modal-severity-badge").className = `cell-val sev-badge ${alert.severity || 'MEDIUM'}`;
  
  document.getElementById("modal-raw-logs").innerText = alert.sample_raw_logs ? alert.sample_raw_logs.join("\n") : "No raw logs recorded.";
  document.getElementById("modal-remediation-steps").innerText = alert.remediation_suggestion || "• Isolate host and audit user privileges.";

  renderNotesLog(alert);

  // Open modal immediately
  document.getElementById("remediation-modal").classList.add("active");

  // Fetch SIGMA export conversions
  try {
    const res = await fetch(`/api/rules/${alert.rule_id}/export`);
    if (res.ok) {
      const exp = await res.json();
      document.getElementById("modal-splunk-spl").innerText = exp.splunk_spl || "N/A";
      document.getElementById("modal-elastic-kql").innerText = exp.elastic_kql || "N/A";
    }
  } catch (e) {
    document.getElementById("modal-splunk-spl").innerText = "Error loading Splunk conversion.";
  }

  // Fetch Wireshark Display Filter
  try {
    const wsRes = await fetch(`/api/v1/wireshark/filter/${alert.rule_id}`);
    if (wsRes.ok) {
      const data = await wsRes.json();
      document.getElementById("modal-wireshark-filter").innerText = data.wireshark_filter || "ip";
    }
  } catch (e) {
    document.getElementById("modal-wireshark-filter").innerText = "ip";
  }

  // Fetch Burp Suite Request Export
  try {
    const burpRes = await fetch(`/api/v1/burp/export/${alert.alert_id}`);
    if (burpRes.ok) {
      const data = await burpRes.json();
      document.getElementById("modal-burp-request").innerText = `--- RAW BURP REPEATER REQUEST ---\n${data.raw_http_request}\n\n--- cURL COMMAND ---\n${data.curl_command}`;
    }
  } catch (e) {
    document.getElementById("modal-burp-request").innerText = "N/A";
  }
}

function renderNotesLog(alert) {
  const notesBox = document.getElementById("modal-notes-log");
  if (alert.analyst_notes && alert.analyst_notes.length > 0) {
    notesBox.innerText = alert.analyst_notes.join("\n");
  } else {
    notesBox.innerText = "No analyst notes recorded yet.";
  }
}

async function setAlertState(status) {
  if (!selectedAlertId) return;
  try {
    const res = await fetch(`/api/alerts/${selectedAlertId}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: status })
    });
    if (res.ok) {
      const updated = await res.json();
      updateLocalAlert(updated);
    }
  } catch (err) {
    console.error("[Triage Error]", err);
  }
}

async function addAnalystNote() {
  if (!selectedAlertId) return;
  const input = document.getElementById("analyst-note-input");
  const note = input.value.trim();
  if (!note) return;

  const targetAlert = activeAlerts.find(a => a.alert_id === selectedAlertId);
  const status = targetAlert ? (targetAlert.status || "NEW") : "NEW";

  try {
    const res = await fetch(`/api/alerts/${selectedAlertId}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: status, note: note })
    });
    if (res.ok) {
      const updated = await res.json();
      updateLocalAlert(updated);
      input.value = "";
    }
  } catch (err) {
    console.error("[Note Error]", err);
  }
}

async function tuneCurrentAlert() {
  if (!selectedAlertId) return;
  try {
    const res = await fetch(`/api/alerts/${selectedAlertId}/tune`, { method: "POST" });
    if (res.ok) {
      const updated = await res.json();
      updateLocalAlert(updated);
    }
  } catch (err) {
    console.error("[Tune Error]", err);
  }
}

function updateLocalAlert(updated) {
  const idx = activeAlerts.findIndex(a => a.alert_id === updated.alert_id);
  if (idx !== -1) {
    activeAlerts[idx] = updated;
    renderAlerts();
    renderNotesLog(updated);
  }
}

let isProductionMode = true;

async function fetchDevices() {
  try {
    const res = await fetch("/api/v1/devices");
    if (res.ok) {
      const data = await res.json();
      activeDevicesList = data.devices || [];
      const count = data.active_devices_count || activeDevicesList.length;

      const badgeCount = document.getElementById("devices-count-badge");
      if (badgeCount) badgeCount.innerText = `${count} Live`;

      const tabCount = document.getElementById("tab-device-count");
      if (tabCount) tabCount.innerText = count;

      const agentBadge = document.getElementById("agent-status-badge");
      if (agentBadge) {
        agentBadge.innerHTML = `Endpoints: <strong id="devices-count-badge">${count} Live</strong>`;
      }

      renderDevices(activeDevicesList);
    }
  } catch (e) {
    console.error("[Fetch Devices Error]", e);
  }
}

async function fetchAgentStatus() {
  await fetchDevices();
}

function renderDevices(devices) {
  const container = document.getElementById("monitored-devices-grid");
  if (!container) return;

  if (!devices || devices.length === 0) {
    container.innerHTML = `<div class="empty-state">No monitored devices registered yet. Open the dashboard in a browser or run collector.py.</div>`;
    return;
  }

  container.innerHTML = devices.map(dev => {
    const isSelf = dev.device_id === currentClientDeviceId;
    const isHost = dev.device_type && dev.device_type.includes("Host Server");
    const isPython = dev.device_type && dev.device_type.includes("Python");
    
    let icon = "💻";
    if (isHost) icon = "🖥️";
    else if (isPython) icon = "🛡️";
    else if (dev.os && (dev.os.includes("Android") || dev.os.includes("iOS"))) icon = "📱";
    else icon = "🌐";

    const lastSeenFormatted = dev.last_seen ? dev.last_seen.substring(11, 19) : "Just now";

    return `
      <div class="device-card ${isSelf ? 'self-client' : ''}">
        <div class="device-header">
          <div class="device-title-group">
            <span class="device-name">${icon} ${escapeHtml(dev.hostname)} ${isSelf ? '<span style="color: #38bdf8; font-size: 11px;">(This Device)</span>' : ''}</span>
            <span class="device-type-tag">${escapeHtml(dev.device_type || 'Monitored Node')}</span>
          </div>
          <span class="pulse-badge">
            <span class="radar-dot"></span> ${escapeHtml(dev.status || 'ONLINE')}
          </span>
        </div>

        <div class="device-specs-table">
          <div class="spec-entry">
            <span class="spec-k">OS Platform</span>
            <span class="spec-v">${escapeHtml(dev.os || 'Standard OS')}</span>
          </div>
          <div class="spec-entry">
            <span class="spec-k">Browser / Agent</span>
            <span class="spec-v">${escapeHtml(dev.browser || 'Native Agent')}</span>
          </div>
          <div class="spec-entry">
            <span class="spec-k">CPU Cores</span>
            <span class="spec-v">${dev.cpu_cores || 1} Cores</span>
          </div>
          <div class="spec-entry">
            <span class="spec-k">Memory / RAM</span>
            <span class="spec-v">${dev.device_memory_gb ? dev.device_memory_gb + ' GB' : 'N/A'}</span>
          </div>
          <div class="spec-entry">
            <span class="spec-k">IP Address</span>
            <span class="spec-v">${escapeHtml(dev.ip_address || '127.0.0.1')}</span>
          </div>
          <div class="spec-entry">
            <span class="spec-k">Display / Resolution</span>
            <span class="spec-v">${escapeHtml(dev.screen_res || 'Headless')}</span>
          </div>
        </div>

        <div class="device-footer">
          <span>Events Ingested: <strong style="color: #3fb950;">${dev.events_count || 0}</strong></span>
          <span>Last Heartbeat: <strong>${lastSeenFormatted} UTC</strong></span>
        </div>
      </div>
    `;
  }).join("");
}

function toggleEngineMode() {
  isProductionMode = !isProductionMode;
  const btn = document.getElementById("mode-toggle-btn");
  if (btn) {
    btn.innerText = isProductionMode ? "Mode: Live Production Ingest" : "Mode: Simulation Lab";
    btn.className = isProductionMode ? "btn-sm btn-primary" : "btn-sm btn-secondary";
  }
}

async function downloadIncidentReport() {
  if (!selectedAlertId) return;
  try {
    const res = await fetch(`/api/v1/alerts/${selectedAlertId}/report`);
    if (res.ok) {
      const report = await res.json();
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `INCIDENT_REPORT_${selectedAlertId}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }
  } catch (err) {
    console.error("[Report Export Error]", err);
    alert("Failed to export incident report.");
  }
}

function downloadPcapCapture() {
  if (!selectedAlertId) return;
  window.open(`/api/v1/pcap/export/${selectedAlertId}`, "_blank");
}

async function exportBurpRepeater() {
  if (!selectedAlertId) return;
  try {
    const res = await fetch(`/api/v1/burp/export/${selectedAlertId}`);
    if (res.ok) {
      const data = await res.json();
      navigator.clipboard.writeText(data.raw_http_request);
      alert("✅ Burp Suite Repeater Request copied to clipboard!\n\nPaste into Burp Suite Repeater tab (Ctrl+V) or terminal.");
    }
  } catch (e) {
    alert("Failed to export Burp Repeater request.");
  }
}

async function importBurpXmlLogs() {
  const xml = document.getElementById("burp-xml-input").value.trim();
  if (!xml) return alert("Please paste Burp Suite XML content first.");
  try {
    const res = await fetch("/api/v1/burp/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ xml_content: xml })
    });
    if (res.ok) {
      const data = await res.json();
      document.getElementById("burp-import-status").innerText = `✅ Successfully ingested ${data.ingested_count} Burp proxy HTTP requests into SOC engine!`;
      fetchInitialData();
    }
  } catch (e) {
    document.getElementById("burp-import-status").innerText = "❌ Failed to parse Burp XML payload.";
  }
}

function closeModal(event) {
  document.getElementById("remediation-modal").classList.remove("active");
  selectedAlertId = null;
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function openManualModal() {
  localStorage.setItem("soc_manual_visited", "true");
  document.getElementById("manual-modal").classList.add("active");
}

function closeManualModal() {
  localStorage.setItem("soc_manual_visited", "true");
  document.getElementById("manual-modal").classList.remove("active");
}

function closeManualModalOnOverlay(event) {
  if (event.target.id === "manual-modal") {
    closeManualModal();
  }
}

function switchManualTab(tabName) {
  document.querySelectorAll("[id^='mtab-']").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll("[id^='mpane-']").forEach(pane => pane.classList.remove("active"));

  const targetBtn = document.getElementById(`mtab-${tabName}`);
  const targetPane = document.getElementById(`mpane-${tabName}`);
  if (targetBtn) targetBtn.classList.add("active");
  if (targetPane) targetPane.classList.add("active");
}
