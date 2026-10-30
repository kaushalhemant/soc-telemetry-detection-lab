let totalTelemetryCount = 0;
let activeAlerts = [];
let activeRules = [];
let activeDevicesList = [];
let currentWorkflow = "test";
let currentFilter = "ALL";
let currentSeverity = "ALL";
let currentSource = "ALL";
let alertSearchTerm = "";
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

  // Keyboard accessibility: Escape key closes modals
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeModal();
      closeManualModal();
    }
  });

  // 1. Acquire client device details and activate client monitoring
  initAutonomousClientDevice();

  // 2. Initialize live streaming & data polling
  initWebSocket();
  fetchInitialData();
  fetchMetrics();
  fetchDevices();

  setInterval(fetchMetrics, 2500);
  setInterval(fetchInitialData, 5000);
  setInterval(fetchDevices, 4000);
  setInterval(startClientTelemetryTicker, 4000);

  // Auto-show Quickstart on first visit
  if (!localStorage.getItem("soc_manual_visited")) {
    setTimeout(openManualModal, 500);
  }
});

/* ==========================================================================
   Workflow Navigation
   ========================================================================== */
function switchWorkflow(workflowName) {
  currentWorkflow = workflowName;

  document.querySelectorAll(".workflow-tab-btn, .view-tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".workflow-pane, .view-pane").forEach(pane => pane.classList.remove("active"));

  const targetTab = document.getElementById(`tab-workflow-${workflowName}`);
  const targetPane = document.getElementById(`view-workflow-${workflowName}`);

  if (targetTab) targetTab.classList.add("active");
  if (targetPane) targetPane.classList.add("active");

  if (workflowName === "explore") {
    renderRules();
    fetchDevices();
  } else if (workflowName === "investigate") {
    renderAlerts();
  }
}

function switchExploreTab(tabName) {
  document.querySelectorAll("[id^='subtab-explore-']").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll("[id^='subpane-explore-']").forEach(pane => pane.classList.remove("active"));

  const targetBtn = document.getElementById(`subtab-explore-${tabName}`);
  const targetPane = document.getElementById(`subpane-explore-${tabName}`);

  if (targetBtn) targetBtn.classList.add("active");
  if (targetPane) targetPane.classList.add("active");

  if (tabName === "devices") {
    fetchDevices();
  }
}

/* ==========================================================================
   Action Feedback Banner
   ========================================================================== */
let bannerTimeout = null;
function showActionStatus(message, type = "success") {
  const banner = document.getElementById("action-status-banner");
  if (!banner) return;

  if (bannerTimeout) clearTimeout(bannerTimeout);

  banner.className = `action-status-banner active ${type}`;
  let icon = "✅";
  if (type === "loading") icon = '<span class="spinner"></span>';
  else if (type === "error") icon = "❌";
  else if (type === "warning") icon = "⚠️";

  banner.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;

  if (type !== "loading") {
    bannerTimeout = setTimeout(() => {
      banner.classList.remove("active");
    }, 4500);
  }
}

/* ==========================================================================
   Client Device Telemetry & Specs
   ========================================================================== */
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

  try {
    const res = await fetch("/api/v1/client-device/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentClientInfo)
    });
    if (res.ok) {
      fetchDevices();
    }
  } catch (e) {
    console.warn("[SOC Client Register]", e);
  }

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
      raw_message: `client-telemetry[${currentClientInfo.device_id}]: endpoint live, active_tab=${isFocused}, memory=${heapInfo}`,
      details: {
        device_id: currentClientInfo.device_id,
        is_focused: isFocused,
        tick: clientTick
      },
      telemetry_source: "live"
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
  }, 4000);
}

const baselineLogs = [
  { log_type: "authlog", hostname: "host-node-alpha", container_id: "cnt-prod-app-01", raw_message: "sshd[1209]: Accepted publickey for user admin from 10.0.4.15 port 51234 ssh2", source: "simulated" },
  { log_type: "auditd.log", hostname: "host-node-alpha", container_id: "cnt-prod-app-01", raw_message: "type=SYSCALL arch=c000003e syscall=59 success=yes pid=4210 exe=\"/usr/bin/sudo\"", source: "simulated" },
  { log_type: "syslog", hostname: "host-node-alpha", container_id: "cnt-prod-db-02", raw_message: "kernel: [10842.15] iptables ACCEPT IN=eth0 OUT= SRC=10.0.1.5 DST=10.0.1.20 PROTO=TCP SPT=443", source: "simulated" },
  { log_type: "nginx/access.log", hostname: "host-web-frontend", container_id: "cnt-web-01", raw_message: "172.16.0.45 - - [26/Aug/2026:18:14:02 +0000] \"GET /api/v1/health HTTP/1.1\" 200 45", source: "simulated" },
  { log_type: "authlog", hostname: "host-node-beta", container_id: "cnt-prod-worker-01", raw_message: "pam_unix(cron:session): session closed for user root", source: "simulated" }
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
    raw_message: sample.raw_message,
    telemetry_source: sample.source
  });
}

/* ==========================================================================
   WebSocket Streaming
   ========================================================================== */
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
    };
  } catch (e) {
    console.warn("[SOC WS Init]", e);
  }
}

/* ==========================================================================
   Data Fetching & Metrics Handling
   ========================================================================== */
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
      const consoles = [document.getElementById("log-console"), document.getElementById("log-console-test")];
      consoles.forEach(c => { if (c) c.innerHTML = ""; });
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
      updateMetricsUi(data);
    }
  } catch (err) {
    console.error("[SOC Metrics Error]", err);
  }
}

function updateMetricsUi(data) {
  if (!data) return;

  // Total Processed Telemetry (with live vs simulated breakdown)
  const totalCounter = document.getElementById("metric-total-events");
  if (totalCounter) {
    const total = data.total_events_processed || 0;
    const sim = data.simulated_events || 0;
    const live = data.live_events || 0;
    totalCounter.innerHTML = `${total.toLocaleString()} <span class="metric-sub">${live} live, ${sim} sim</span>`;
  }

  // Precision
  const precElem = document.getElementById("metric-precision");
  if (precElem) {
    if (data.precision_pct === null || data.precision_pct === undefined) {
      precElem.innerHTML = `<span class="text-muted" title="Requires validated ground-truth observations">N/A — insufficient data</span>`;
    } else {
      const sample = data.precision_denominator !== undefined ? ` <span class="metric-sample">(TP: ${data.true_positives}, FP: ${data.false_positives})</span>` : '';
      precElem.innerHTML = `<span class="text-bright">${data.precision_pct.toFixed(1)}%</span>${sample}`;
    }
  }

  // Recall
  const recallElem = document.getElementById("metric-recall");
  if (recallElem) {
    if (data.recall_pct === null || data.recall_pct === undefined) {
      recallElem.innerHTML = `<span class="text-muted" title="Requires validated ground-truth observations">N/A — insufficient data</span>`;
    } else {
      const sample = data.recall_denominator !== undefined ? ` <span class="metric-sample">(TP: ${data.true_positives}, FN: ${data.false_negatives})</span>` : '';
      recallElem.innerHTML = `<span class="text-bright">${data.recall_pct.toFixed(1)}%</span>${sample}`;
    }
  }

  // False Positive Rate
  const fprElem = document.getElementById("metric-fpr");
  if (fprElem) {
    if (data.false_positive_rate_pct === null || data.false_positive_rate_pct === undefined) {
      fprElem.innerHTML = `<span class="text-muted" title="Requires validated benign baseline events">N/A — insufficient data</span>`;
    } else {
      const sample = data.fpr_denominator !== undefined ? ` <span class="metric-sample">(FP: ${data.false_positives}, TN: ${data.true_negatives})</span>` : '';
      fprElem.innerHTML = `<span class="text-bright">${data.false_positive_rate_pct.toFixed(2)}%</span>${sample}`;
    }
  }

  // MTTD
  const mttdElem = document.getElementById("metric-mttd");
  if (mttdElem) {
    if (data.mttd_ms === null || data.mttd_ms === undefined) {
      mttdElem.innerHTML = `<span class="text-muted" title="Requires alerts with valid chronological event and alert timestamps">N/A — insufficient data</span>`;
    } else {
      const sample = data.mttd_sample_count ? ` <span class="metric-sample">(n=${data.mttd_sample_count})</span>` : '';
      mttdElem.innerHTML = `<span class="text-bright">${data.mttd_ms.toFixed(1)} ms</span>${sample}`;
    }
  }
}

/* ==========================================================================
   Telemetry Stream Rendering
   ========================================================================== */
function appendTelemetryLog(evt) {
  if (!evt) return;
  const consoleBoxes = [
    document.getElementById("log-console"),
    document.getElementById("log-console-test")
  ].filter(Boolean);

  const timeStr = evt.timestamp ? evt.timestamp.substring(11, 23) : "12:00:00.000";
  const source = evt.telemetry_source || "simulated";
  const sourceLabel = source === "live" ? "LIVE" : source === "replayed" ? "REPLAY" : "SIM";
  const isSysmon = evt.log_type === "windows.sysmon" || (evt.details && evt.details.sysmon_event_id);
  const sysmonEid = evt.details && evt.details.sysmon_event_id ? evt.details.sysmon_event_id : (evt.event_id && evt.event_id.startsWith("SYSMON_") ? evt.event_id.replace("SYSMON_", "") : "");

  let sourceBadgeHtml = `<span class="source-badge ${source}">${sourceLabel}</span>`;
  if (isSysmon) {
    sourceBadgeHtml = `<span class="source-badge sysmon" title="Windows Sysmon Operational Telemetry">SYSMON ${sysmonEid ? 'EID ' + sysmonEid : 'LIVE'}</span>`;
  }

  consoleBoxes.forEach(consoleBox => {
    const row = document.createElement("div");
    row.className = "log-row";
    row.innerHTML = `
      ${sourceBadgeHtml}
      <span class="log-ts">${timeStr}</span>
      <span class="log-type ${isSysmon ? 'sysmon' : ''}">${escapeHtml(evt.log_type)}</span>
      <span class="log-host">${escapeHtml(evt.hostname)}${evt.container_id ? ' (' + escapeHtml(evt.container_id) + ')' : ''}</span>
      <span class="log-msg">${escapeHtml(evt.raw_message)}</span>
    `;

    consoleBox.insertBefore(row, consoleBox.firstChild);
    if (consoleBox.children.length > 150) {
      consoleBox.removeChild(consoleBox.lastChild);
    }
  });

  totalTelemetryCount++;
}

function clearTelemetry() {
  const consoleBoxes = [
    document.getElementById("log-console"),
    document.getElementById("log-console-test")
  ].filter(Boolean);
  consoleBoxes.forEach(c => { c.innerHTML = ""; });
  showActionStatus("Live log console stream cleared.", "success");
}

/* ==========================================================================
   Alert Filtering & Rendering
   ========================================================================== */
function filterTriage(status) {
  currentFilter = status;
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.classList.toggle("active", btn.innerText.trim().toUpperCase() === status);
  });
  renderAlerts();
}

function setSeverityFilter(sev) {
  currentSeverity = sev;
  renderAlerts();
}

function setSourceFilter(src) {
  currentSource = src;
  renderAlerts();
}

function filterAlerts() {
  const searchInput = document.getElementById("alert-search");
  alertSearchTerm = (searchInput ? searchInput.value : "").trim().toLowerCase();
  renderAlerts();
}

function prependAlert(alert) {
  if (!alert) return;
  if (!activeAlerts.some(a => a.alert_id === alert.alert_id)) {
    activeAlerts.unshift(alert);
    renderAlerts();
  }
}

function renderAlerts() {
  const container = document.getElementById("alerts-container");
  if (!container) return;

  const filtered = activeAlerts.filter(a => {
    // 1. Triage status filter
    if (currentFilter !== "ALL" && (a.status || "NEW") !== currentFilter) return false;

    // 2. Severity filter
    if (currentSeverity !== "ALL" && (a.severity || "MEDIUM").toUpperCase() !== currentSeverity) return false;

    // 3. Telemetry source filter
    if (currentSource !== "ALL") {
      const src = (a.telemetry_source || "simulated").toUpperCase();
      if (src !== currentSource) return false;
    }

    // 4. Search query
    if (alertSearchTerm) {
      const haystack = `${a.alert_id} ${a.rule_id} ${a.rule_name} ${a.hostname} ${a.mitre_technique_id || ''} ${a.mitre_technique_name || ''} ${a.description}`.toLowerCase();
      if (!haystack.includes(alertSearchTerm)) return false;
    }

    return true;
  });

  const totalAlerts = activeAlerts.length;
  const countBadge = document.getElementById("alert-counter-badge");
  if (countBadge) {
    countBadge.innerText = `Showing ${filtered.length} of ${totalAlerts} Alerts`;
  }

  const wfAlertCount = document.getElementById("workflow-alert-count");
  if (wfAlertCount) {
    wfAlertCount.innerText = totalAlerts;
  }

  if (filtered.length === 0) {
    if (totalAlerts === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <p style="font-weight: 600; color: var(--text-bright); margin-bottom: 6px;">No Security Detections Recorded</p>
          <p style="color: var(--text-muted); font-size: 11px;">Switch to <strong>Workflow 1: Run Detection Test</strong> to execute attack scenarios, or run the deterministic validation suite.</p>
        </div>
      `;
    } else {
      container.innerHTML = `
        <div class="empty-state">
          <p style="font-weight: 600; color: var(--text-bright); margin-bottom: 6px;">No Alerts Matching Filter</p>
          <p style="color: var(--text-muted); font-size: 11px;">Clear your search or adjust status/severity/source filter.</p>
        </div>
      `;
    }
  } else {
    container.innerHTML = filtered.map(alert => renderAlertCardHtml(alert)).join("");
  }
}

function renderAlertCardHtml(alert) {
  const source = alert.telemetry_source || "simulated";
  const sourceLabel = source === "live" ? "LIVE" : source === "replayed" ? "REPLAY" : "SIMULATED";
  const sev = alert.severity || "MEDIUM";

  return `
    <div class="alert-item ${sev.toLowerCase()}" onclick="openRemediationModal('${alert.alert_id}')" tabindex="0" role="button" aria-label="Alert ${alert.alert_id} ${alert.rule_name}">
      <div class="alert-header-row">
        <span class="alert-id">${alert.alert_id} &bull; ${alert.rule_id}</span>
        <div style="display: flex; gap: 4px; align-items: center;">
          <span class="source-badge ${source}">${sourceLabel}</span>
          <span class="sev-badge ${sev}">${sev}</span>
        </div>
      </div>
      <div class="alert-title">${escapeHtml(alert.rule_name || alert.rule_id)}</div>
      <div class="alert-meta">
        <span>Host: <strong>${escapeHtml(alert.hostname || 'host-node')}</strong></span>
        <span class="status-tag ${(alert.status || 'NEW')}">${(alert.status || 'NEW')}</span>
      </div>
    </div>
  `;
}

/* ==========================================================================
   Simulation & Testing Triggers
   ========================================================================== */
async function triggerScenario(scenarioType, btn) {
  const originalText = btn ? btn.innerText : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Simulating...`;
  }
  showActionStatus(`Simulating threat vector [${scenarioType}]...`, "loading");

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenarioType })
    });
    if (res.ok) {
      const data = await res.json();
      if (data.alerts) activeAlerts = data.alerts;
      if (data.metrics) updateMetricsUi(data.metrics);
      renderAlerts();
      showActionStatus(`Simulation completed: ${data.scenario} emitted ${data.emitted_events_count} events.`, "success");
    } else {
      showActionStatus(`Failed to execute simulation: Server error (${res.status}).`, "error");
    }
  } catch (err) {
    console.error("[Trigger Scenario Error]", err);
    showActionStatus(`Simulation request error: ${err.message}`, "error");
  } finally {
    if (btn) {
      setTimeout(() => {
        btn.disabled = false;
        btn.innerText = originalText;
      }, 1000);
    }
  }
/* ==========================================================================
   Master 1-Click Demonstration Workflow
   ========================================================================== */
async function runMasterDemonstration(btn) {
  const originalText = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Running Master Demo...`;
  }
  const resultsBox = document.getElementById("demo-results-box");
  if (resultsBox) {
    resultsBox.style.display = "block";
    resultsBox.innerHTML = `
      <div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 12px;">
        <span class="spinner" style="margin-right: 8px;"></span>
        Executing Master SOC Demonstration (feeding 50+ labelled events through SIGMA engine)...
      </div>
    `;
  }
  showActionStatus("Executing Master SOC Demonstration Workflow...", "loading");

  try {
    const res = await fetch("/api/demo/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reset_first: true })
    });

    if (res.ok) {
      const data = await res.json();
      if (data.alerts) activeAlerts = data.alerts;
      if (data.metrics) updateMetricsUi(data.metrics);
      renderAlerts();
      renderDemoResults(data);

      const prec = data.metrics.precision_pct !== null ? `${data.metrics.precision_pct.toFixed(1)}%` : 'N/A';
      const rec = data.metrics.recall_pct !== null ? `${data.metrics.recall_pct.toFixed(1)}%` : 'N/A';
      showActionStatus(`Master Demo complete: ${data.events_processed} events processed, ${data.alerts_generated} alerts created. Precision: ${prec}, Recall: ${rec}.`, "success");
    } else {
      if (resultsBox) {
        resultsBox.innerHTML = `<div class="empty-state" style="color: #f85149;">Failed to run demonstration (${res.status}).</div>`;
      }
      showActionStatus("Failed to run master demonstration workflow.", "error");
    }
  } catch (err) {
    console.error("[Master Demo Error]", err);
    if (resultsBox) {
      resultsBox.innerHTML = `<div class="empty-state" style="color: #f85149;">Demo error: ${err.message}</div>`;
    }
    showActionStatus(`Demo error: ${err.message}`, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalText || `⚡ Run Master Demonstration (50+ Events)`;
    }
  }
}

function renderDemoResults(data) {
  const resultsBox = document.getElementById("demo-results-box");
  if (!resultsBox) return;

  const m = data.metrics || {};
  const cm = data.confusion_matrix || {};
  const prec = m.precision_pct !== null && m.precision_pct !== undefined ? `${m.precision_pct.toFixed(1)}%` : 'N/A';
  const rec = m.recall_pct !== null && m.recall_pct !== undefined ? `${m.recall_pct.toFixed(1)}%` : 'N/A';
  const fpr = m.false_positive_rate_pct !== null && m.false_positive_rate_pct !== undefined ? `${m.false_positive_rate_pct.toFixed(2)}%` : 'N/A';
  const mttd = m.mttd_ms !== null && m.mttd_ms !== undefined ? `${m.mttd_ms.toFixed(1)} ms` : 'N/A';

  resultsBox.innerHTML = `
    <div class="val-summary-row" style="background-color: #0d1522; border-color: #26364b;">
      <div class="val-stat">
        <span class="val-stat-label">Total Events Processed</span>
        <span class="val-stat-val" style="color: #58a6ff;">${data.events_processed}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">Detections Generated</span>
        <span class="val-stat-val text-green">${data.alerts_generated}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">True Positives (TP)</span>
        <span class="val-stat-val text-green">${cm.true_positives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">False Positives (FP)</span>
        <span class="val-stat-val" style="color: ${cm.false_positives > 0 ? '#f85149' : 'var(--text-muted)'};">${cm.false_positives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">False Negatives (FN)</span>
        <span class="val-stat-val" style="color: #d29922;">${cm.false_negatives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">True Negatives (TN)</span>
        <span class="val-stat-val">${cm.true_negatives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">Precision (TP / TP+FP)</span>
        <span class="val-stat-val text-green">${prec}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">Recall (TP / TP+FN)</span>
        <span class="val-stat-val text-green">${rec}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">False Positive Rate</span>
        <span class="val-stat-val" style="color: #79c0ff;">${fpr}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">MTTD</span>
        <span class="val-stat-val" style="color: #e3b341;">${mttd}</span>
      </div>
    </div>

    <div class="val-table-container" style="margin-top: 10px;">
      <table class="val-table">
        <thead>
          <tr>
            <th>Scenario ID</th>
            <th>Threat Vector Description</th>
            <th>Ground Truth</th>
            <th>Target SIGMA Rule</th>
            <th>Outcome & Efficacy</th>
          </tr>
        </thead>
        <tbody>
          ${(data.scenarios_evaluated || []).map(sc => `
            <tr>
              <td><code>${sc.id}</code></td>
              <td><strong>${escapeHtml(sc.name)}</strong></td>
              <td><span class="tag tag-${sc.ground_truth === 'malicious' ? 'tp' : 'tn'}">${(sc.ground_truth || '').toUpperCase()}</span></td>
              <td><code>${sc.target_rule || 'NONE (Baseline)'}</code></td>
              <td>
                <span class="tag ${sc.outcome.includes('DETECTED') ? 'tag-tp' : sc.outcome.includes('EVADED') ? 'tag-fn' : 'tag-tn'}">
                  ${escapeHtml(sc.outcome)}
                </span>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px; font-size: 11px;">
      <span style="color: var(--text-muted);">
        💡 Next Step: Switch to <strong>"2. Investigate Alerts"</strong> tab to triage alerts, download Wireshark PCAPs, export Burp requests, and tune rules.
      </span>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-sm btn-secondary" onclick="downloadDemoReport('markdown')">📄 Download Markdown Report</button>
        <a class="btn btn-sm btn-outline" href="/api/demo/report?format=html" target="_blank" rel="noopener noreferrer">🌐 Open HTML Report</a>
      </div>
    </div>
  `;
}

async function resetDemoSession() {
  showActionStatus("Resetting demonstration session and metrics...", "loading");
  try {
    const res = await fetch("/api/demo/reset", { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      activeAlerts = [];
      renderAlerts();
      if (data.metrics) updateMetricsUi(data.metrics);
      clearTelemetry();
      const demoBox = document.getElementById("demo-results-box");
      if (demoBox) demoBox.style.display = "none";
      const valBox = document.getElementById("validation-results-box");
      if (valBox) valBox.style.display = "none";
      showActionStatus("Demonstration session reset successfully. Metrics cleared.", "success");
    } else {
      showActionStatus("Failed to reset demonstration session.", "error");
    }
  } catch (err) {
    showActionStatus(`Reset error: ${err.message}`, "error");
  }
}

function downloadDemoReport(format = "markdown") {
  window.open(`/api/demo/report?format=${format}`, "_blank");
}

async function runDeterministicValidation() {
  const btn = document.getElementById("btn-run-validation");
  const resultsBox = document.getElementById("validation-results-box");

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Running 13 Validation Scenarios...`;
  }
  if (resultsBox) {
    resultsBox.style.display = "block";
    resultsBox.innerHTML = `
      <div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 12px;">
        <span class="spinner" style="margin-right: 8px;"></span>
        Executing deterministic test suite against active SIGMA detection rules...
      </div>
    `;
  }
  showActionStatus("Executing deterministic detection validation suite...", "loading");

  try {
    const res = await fetch("/api/detection-tests/run", { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      renderValidationResults(data);
      showActionStatus(`Validation Suite complete: ${data.passed_scenarios}/${data.total_scenarios} scenarios passed (${data.pass_rate_pct}%).`, "success");
      fetchMetrics();
    } else {
      if (resultsBox) {
        resultsBox.innerHTML = `<div class="empty-state" style="color: #f85149;">Failed to run validation suite (${res.status}).</div>`;
      }
      showActionStatus("Failed to run validation test suite.", "error");
    }
  } catch (err) {
    console.error("[Validation Error]", err);
    if (resultsBox) {
      resultsBox.innerHTML = `<div class="empty-state" style="color: #f85149;">Validation error: ${err.message}</div>`;
    }
    showActionStatus(`Validation error: ${err.message}`, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `⚡ Run Deterministic Test Suite`;
    }
  }
}

function renderValidationResults(data) {
  const resultsBox = document.getElementById("validation-results-box");
  if (!resultsBox) return;

  const m = data.metrics || {};
  const cm = data.confusion_matrix || {};
  const prec = m.precision_pct !== null && m.precision_pct !== undefined ? `${m.precision_pct.toFixed(1)}%` : 'N/A';
  const rec = m.recall_pct !== null && m.recall_pct !== undefined ? `${m.recall_pct.toFixed(1)}%` : 'N/A';
  const fpr = m.false_positive_rate_pct !== null && m.false_positive_rate_pct !== undefined ? `${m.false_positive_rate_pct.toFixed(2)}%` : 'N/A';
  const mttd = m.mttd_ms !== null && m.mttd_ms !== undefined ? `${m.mttd_ms.toFixed(1)} ms` : 'N/A';

  resultsBox.innerHTML = `
    <div class="val-summary-row">
      <div class="val-stat">
        <span class="val-stat-label">Pass Rate</span>
        <span class="val-stat-val" style="color: #3fb950;">${data.passed_scenarios} / ${data.total_scenarios} (${data.pass_rate_pct}%)</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">Execution Time</span>
        <span class="val-stat-val">${data.execution_time_ms} ms</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">True Positives (TP)</span>
        <span class="val-stat-val text-green">${cm.true_positives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">False Positives (FP)</span>
        <span class="val-stat-val" style="color: ${cm.false_positives > 0 ? '#f85149' : 'var(--text-muted)'};">${cm.false_positives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">False Negatives (FN)</span>
        <span class="val-stat-val" style="color: ${cm.false_negatives > 0 ? '#f85149' : 'var(--text-muted)'};">${cm.false_negatives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">True Negatives (TN)</span>
        <span class="val-stat-val">${cm.true_negatives || 0}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">Suite Precision</span>
        <span class="val-stat-val">${prec}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">Suite Recall</span>
        <span class="val-stat-val">${rec}</span>
      </div>
      <div class="val-stat">
        <span class="val-stat-label">Avg Latency</span>
        <span class="val-stat-val">${mttd}</span>
      </div>
    </div>

    <div class="val-table-container">
      <table class="val-table">
        <thead>
          <tr>
            <th>Scenario ID</th>
            <th>Name & Objective</th>
            <th>Events</th>
            <th>Expected Rule</th>
            <th>Actual Result</th>
            <th>Latency</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${data.scenarios.map(sc => `
            <tr>
              <td><code>${sc.test_id}</code></td>
              <td><strong>${escapeHtml(sc.name)}</strong><br/><span style="color: var(--text-muted); font-size: 10px;">${escapeHtml(sc.description)}</span></td>
              <td>${sc.events_count}</td>
              <td><code>${sc.expected_rule_id}</code></td>
              <td><code>${sc.actual_rules_triggered.join(", ")}</code></td>
              <td>${sc.latency_ms !== null ? sc.latency_ms + ' ms' : 'N/A'}</td>
              <td>
                <span class="${sc.passed ? 'val-badge-pass' : 'val-badge-fail'}">
                  ${sc.passed ? 'PASSED' : (sc.missed_detection ? 'MISSED' : 'UNEXPECTED')}
                </span>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="val-disclaimer">
      ℹ️ <strong>Measurement Scope Note:</strong> ${escapeHtml(data.disclaimer)}
    </div>
  `;
}

async function clearAlerts() {
  try {
    await fetch("/api/alerts/clear", { method: "POST" });
    activeAlerts = [];
    renderAlerts();
    fetchMetrics();
    clearTelemetry();
    const resultsBox = document.getElementById("validation-results-box");
    if (resultsBox) resultsBox.style.display = "none";
    showActionStatus("Alerts, telemetry stream, and metrics successfully reset.", "success");
  } catch (err) {
    console.error("[Clear Alerts Error]", err);
    showActionStatus("Failed to reset alerts and metrics.", "error");
  }
}

/* ==========================================================================
   Rules & Portability
   ========================================================================== */
function renderRules() {
  const container = document.getElementById("rules-container");
  if (!container) return;

  const countBadge = document.getElementById("rules-count-badge");
  if (countBadge) countBadge.innerText = `${activeRules.length} Loaded`;

  const subBadge = document.getElementById("explore-rules-badge");
  if (subBadge) subBadge.innerText = `${activeRules.length} Rules`;

  container.innerHTML = activeRules.map(rule => `
    <div class="rule-card">
      <div class="rule-card-header">
        <span class="rule-id">${rule.id}</span>
        <span class="sev-badge ${rule.severity || 'MEDIUM'}">${rule.severity || 'MEDIUM'}</span>
      </div>
      <div class="rule-card-title">${escapeHtml(rule.title)}</div>
      <div class="rule-card-meta">${rule.tags ? (rule.tags.mitre_technique_id || '') : ''} &bull; ${rule.log_source ? rule.log_source.log_type : ''}</div>
      <p style="font-size: 11px; color: var(--text-muted); margin-top: 4px; line-height: 1.3;">${escapeHtml(rule.description || '')}</p>
    </div>
  `).join("");
}

async function reloadRules(btn) {
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Reloading...`;
  }
  showActionStatus("Hot-reloading SIGMA rules from disk...", "loading");

  try {
    const res = await fetch("/api/rules/reload", { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      activeRules = data.rules || [];
      renderRules();
      showActionStatus(`Successfully reloaded ${data.rules_count} SIGMA YAML rules from disk.`, "success");
    } else {
      showActionStatus("Failed to reload rules from disk.", "error");
    }
  } catch (e) {
    showActionStatus(`Reload error: ${e.message}`, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `🔄 Hot-Reload Rules from Disk`;
    }
  }
}

/* ==========================================================================
   Incident Investigation & Modal Triage
   ========================================================================== */
async function openRemediationModal(alertId) {
  selectedAlertId = alertId;
  const alert = activeAlerts.find(a => a.alert_id === alertId);
  if (!alert) return;

  document.getElementById("modal-rule-title").innerText = alert.rule_name || alert.rule_id;
  document.getElementById("modal-alert-id").innerText = alert.alert_id;
  document.getElementById("modal-rule-id").innerText = alert.rule_id;
  document.getElementById("modal-mitre-tag").innerText = `${alert.mitre_technique_id || ''} ${alert.mitre_technique_name ? '- ' + alert.mitre_technique_name : ''}`;
  
  const sevBadge = document.getElementById("modal-severity-badge");
  sevBadge.innerText = alert.severity || 'MEDIUM';
  sevBadge.className = `cell-val sev-badge ${alert.severity || 'MEDIUM'}`;

  const sourceBadge = document.getElementById("modal-source-badge");
  if (sourceBadge) {
    const src = alert.telemetry_source || "simulated";
    sourceBadge.className = `source-badge ${src}`;
    sourceBadge.innerText = src === "live" ? "LIVE TELEMETRY" : src === "replayed" ? "REPLAYED LOG" : "SIMULATED TEST";
  }

  // Ground truth badge
  const gtBadge = document.getElementById("modal-ground-truth-badge");
  if (gtBadge) {
    const gt = alert.ground_truth_label || (alert.details && alert.details.ground_truth);
    if (gt === "malicious" || gt === "attack") {
      gtBadge.innerHTML = `<span class="tag tag-tp">MALICIOUS</span>`;
    } else if (gt === "benign") {
      gtBadge.innerHTML = `<span class="tag tag-tn">BENIGN</span>`;
    } else {
      gtBadge.innerHTML = `<span class="tag" style="background:#21262d; color:#8b949e;">UNLABELED</span>`;
    }
  }

  // Classification badge
  const clsBadge = document.getElementById("modal-classification-badge");
  if (clsBadge) {
    const cls = alert.classification || (alert.ground_truth_label === "malicious" ? "TP" : alert.ground_truth_label === "benign" ? "FP" : null);
    if (cls === "TP") {
      clsBadge.innerHTML = `<span class="tag tag-tp">TRUE POSITIVE</span>`;
    } else if (cls === "FP") {
      clsBadge.innerHTML = `<span class="tag tag-fp">FALSE POSITIVE</span>`;
    } else {
      clsBadge.innerHTML = `<span class="tag" style="background:#21262d; color:#8b949e;">LIVE STREAM</span>`;
    }
  }

  // Latency badge
  const latBadge = document.getElementById("modal-latency-badge");
  if (latBadge) {
    latBadge.innerText = alert.detection_latency_ms !== null && alert.detection_latency_ms !== undefined ? `${alert.detection_latency_ms} ms` : 'N/A';
  }

  // Trigger rationale
  const ratElem = document.getElementById("modal-trigger-rationale");
  if (ratElem) {
    ratElem.innerText = (alert.details && alert.details.trigger_reason) ? alert.details.trigger_reason : alert.description;
  }

  // Confidence assessment
  const confElem = document.getElementById("modal-confidence-assessment");
  if (confElem) {
    confElem.innerText = (alert.details && alert.details.confidence_assessment) ? alert.details.confidence_assessment : "Detection rule pattern match. Verify with correlated endpoint telemetry.";
  }

  // Windows Sysmon Endpoint Telemetry Forensics
  const sysmonBox = document.getElementById("modal-sysmon-forensics");
  const pDetails = (alert.details && (alert.details.primary_event_details || alert.details)) || {};
  const isSysmonAlert = (alert.rule_id && alert.rule_id.startsWith("RULE-WIN-")) || pDetails.sysmon_event_id || (pDetails.Channel && String(pDetails.Channel).includes("Sysmon"));
  if (sysmonBox) {
    if (isSysmonAlert) {
      sysmonBox.style.display = "block";
      const qname = pDetails.QueryName ? `<div class="sysmon-field-item"><span class="sysmon-field-key">DNS Query</span><span class="sysmon-field-val">${escapeHtml(pDetails.QueryName)}</span></div>` : '';
      const qstat = pDetails.QueryStatus !== undefined && pDetails.QueryStatus !== null && pDetails.QueryStatus !== "" ? `<div class="sysmon-field-item"><span class="sysmon-field-key">DNS Query Status</span><span class="sysmon-field-val">${escapeHtml(String(pDetails.QueryStatus))}</span></div>` : '';
      const srcSock = pDetails.SourceIp ? `<div class="sysmon-field-item"><span class="sysmon-field-key">Source Socket</span><span class="sysmon-field-val">${escapeHtml(pDetails.SourceIp)}:${pDetails.SourcePort || ''}</span></div>` : '';
      const dstSock = pDetails.DestinationIp ? `<div class="sysmon-field-item"><span class="sysmon-field-key">Destination Socket</span><span class="sysmon-field-val">${escapeHtml(pDetails.DestinationIp)}:${pDetails.DestinationPort || ''}</span></div>` : '';

      sysmonBox.innerHTML = `
        <div style="font-weight: 600; color: #38bdf8; margin-bottom: 4px;">🪟 Windows Sysmon Endpoint Telemetry Forensics:</div>
        <div class="sysmon-field-grid">
          <div class="sysmon-field-item"><span class="sysmon-field-key">Event Source</span><span class="sysmon-field-val">Microsoft-Windows-Sysmon/Operational</span></div>
          <div class="sysmon-field-item"><span class="sysmon-field-key">Sysmon Event ID</span><span class="sysmon-field-val">${pDetails.sysmon_event_id || alert.details.event_id || 'N/A'}</span></div>
          <div class="sysmon-field-item"><span class="sysmon-field-key">Process Name</span><span class="sysmon-field-val">${escapeHtml(pDetails.process_name || pDetails.Image || alert.details.process_name || 'N/A')}</span></div>
          <div class="sysmon-field-item"><span class="sysmon-field-key">Process ID (PID)</span><span class="sysmon-field-val">${pDetails.ProcessId || pDetails.process_id || 'N/A'}</span></div>
          <div class="sysmon-field-item"><span class="sysmon-field-key">User</span><span class="sysmon-field-val">${escapeHtml(pDetails.User || pDetails.user || alert.details.user || 'N/A')}</span></div>
          <div class="sysmon-field-item"><span class="sysmon-field-key">Parent Process</span><span class="sysmon-field-val">${escapeHtml(pDetails.ParentImage || pDetails.parent_process_name || 'N/A')}</span></div>
          <div class="sysmon-field-item"><span class="sysmon-field-key">Command Line</span><span class="sysmon-field-val">${escapeHtml(pDetails.CommandLine || pDetails.command_line || 'N/A')}</span></div>
          ${srcSock}
          ${dstSock}
          ${qname}
          ${qstat}
          ${pDetails.EventRecordID ? `<div class="sysmon-field-item"><span class="sysmon-field-key">EventRecordID</span><span class="sysmon-field-val">${pDetails.EventRecordID}</span></div>` : ''}
        </div>
      `;
    } else {
      sysmonBox.style.display = "none";
      sysmonBox.innerHTML = "";
    }
  }

  document.getElementById("modal-raw-logs").innerText = alert.sample_raw_logs ? alert.sample_raw_logs.join("\n") : "No raw logs recorded.";
  document.getElementById("modal-remediation-steps").innerText = alert.remediation_suggestion || "• Isolate host and audit user privileges.";

  renderNotesLog(alert);

  document.getElementById("remediation-modal").classList.add("active");

  // Fetch SIGMA SIEM translations
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

  // Fetch Wireshark filter
  try {
    const wsRes = await fetch(`/api/v1/wireshark/filter/${alert.rule_id}`);
    if (wsRes.ok) {
      const data = await wsRes.json();
      document.getElementById("modal-wireshark-filter").innerText = data.wireshark_filter || "ip";
    }
  } catch (e) {
    document.getElementById("modal-wireshark-filter").innerText = "ip";
  }

  // Fetch Burp export
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
  if (!notesBox) return;
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
      showActionStatus(`Alert ${selectedAlertId} status updated to [${status}].`, "success");
    }
  } catch (err) {
    console.error("[Triage Error]", err);
    showActionStatus("Failed to update alert triage status.", "error");
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
      showActionStatus("Analyst note recorded on alert.", "success");
    }
  } catch (err) {
    console.error("[Note Error]", err);
    showActionStatus("Failed to add analyst note.", "error");
  }
}

async function tuneCurrentAlert() {
  if (!selectedAlertId) return;
  try {
    const res = await fetch(`/api/alerts/${selectedAlertId}/tune`, { method: "POST" });
    if (res.ok) {
      const updated = await res.json();
      updateLocalAlert(updated);
      showActionStatus(`Rule threshold tuned for alert ${selectedAlertId}.`, "success");
    }
  } catch (err) {
    console.error("[Tune Error]", err);
    showActionStatus("Failed to tune alert rule.", "error");
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

function copySnippet(elementId, feedbackId) {
  const elem = document.getElementById(elementId);
  if (!elem) return;
  const text = elem.innerText;
  navigator.clipboard.writeText(text).then(() => {
    const fb = document.getElementById(feedbackId);
    if (fb) {
      fb.style.display = "inline";
      setTimeout(() => { fb.style.display = "none"; }, 2000);
    }
  }).catch(() => {
    alert("Could not copy to clipboard.");
  });
}

function downloadPcapCapture() {
  if (!selectedAlertId) return;
  window.open(`/api/v1/pcap/export/${selectedAlertId}`, "_blank");
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
      showActionStatus("Incident report JSON downloaded.", "success");
    }
  } catch (err) {
    console.error("[Report Export Error]", err);
    showActionStatus("Failed to export incident report.", "error");
  }
}

async function exportBurpRepeater() {
  if (!selectedAlertId) return;
  try {
    const res = await fetch(`/api/v1/burp/export/${selectedAlertId}`);
    if (res.ok) {
      const data = await res.json();
      navigator.clipboard.writeText(data.raw_http_request);
      showActionStatus("✅ Burp Suite Repeater Request copied to clipboard!", "success");
    }
  } catch (e) {
    showActionStatus("Failed to export Burp Repeater request.", "error");
  }
}

/* ==========================================================================
   Tool Integrations: Burp Suite & Wireshark
   ========================================================================== */
async function importBurpXmlLogs() {
  const xml = document.getElementById("burp-xml-input").value.trim();
  const statusElem = document.getElementById("burp-import-status");
  if (!xml) {
    alert("Please paste Burp Suite XML proxy items first.");
    return;
  }
  if (statusElem) {
    statusElem.style.color = "#38bdf8";
    statusElem.innerText = "Parsing and ingesting Burp proxy XML...";
  }

  try {
    const res = await fetch("/api/v1/burp/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ xml_content: xml })
    });
    if (res.ok) {
      const data = await res.json();
      if (statusElem) {
        statusElem.style.color = "#3fb950";
        statusElem.innerText = `✅ Successfully ingested ${data.ingested_count} Burp proxy HTTP requests into SOC engine!`;
      }
      fetchInitialData();
      showActionStatus(`Burp Proxy ingest: ${data.ingested_count} requests ingested.`, "success");
    } else {
      const errData = await res.json().catch(() => ({}));
      if (statusElem) {
        statusElem.style.color = "#f85149";
        statusElem.innerText = `❌ ${errData.detail || 'Failed to parse Burp XML payload.'}`;
      }
    }
  } catch (e) {
    if (statusElem) {
      statusElem.style.color = "#f85149";
      statusElem.innerText = "❌ Network error connecting to ingestion endpoint.";
    }
  }
}

/* ==========================================================================
   Monitored Devices Inventory
   ========================================================================== */
async function fetchDevices() {
  try {
    const res = await fetch("/api/v1/devices");
    if (res.ok) {
      const data = await res.json();
      activeDevicesList = data.devices || [];
      const count = data.active_devices_count || activeDevicesList.length;

      const badgeCount = document.getElementById("devices-count-badge");
      if (badgeCount) badgeCount.innerText = `${count} Live`;

      const subBadge = document.getElementById("explore-devices-badge");
      if (subBadge) subBadge.innerText = `${count} Active`;

      renderDevices(activeDevicesList);
    }
  } catch (e) {
    console.error("[Fetch Devices Error]", e);
  }
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
            <span class="spec-k">Display / Res</span>
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

/* ==========================================================================
   Modals & Helpers
   ========================================================================== */
function closeModal(event) {
  const modal = document.getElementById("remediation-modal");
  if (modal) modal.classList.remove("active");
  selectedAlertId = null;
}

function openManualModal() {
  localStorage.setItem("soc_manual_visited", "true");
  const modal = document.getElementById("manual-modal");
  if (modal) modal.classList.add("active");
}

function closeManualModal() {
  localStorage.setItem("soc_manual_visited", "true");
  const modal = document.getElementById("manual-modal");
  if (modal) modal.classList.remove("active");
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

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
