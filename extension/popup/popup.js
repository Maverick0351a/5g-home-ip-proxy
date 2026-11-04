const daemonBadge = document.getElementById("daemonBadge");
const wanIpDisplay = document.getElementById("wanIpDisplay");
const sourceIpDisplay = document.getElementById("sourceIpDisplay");
const webrtcBadge = document.getElementById("webrtcBadge");
const modeHint = document.getElementById("modeHint");
const adapterSelect = document.getElementById("adapterSelect");
const gatewayType = document.getElementById("gatewayType");
const gatewayHost = document.getElementById("gatewayHost");
const gatewayPassword = document.getElementById("gatewayPassword");
const controlTokenInput = document.getElementById("controlTokenInput");
const rotateBtn = document.getElementById("rotateBtn");
const freshIdentityBtn = document.getElementById("freshIdentityBtn");
const autoRotateSelect = document.getElementById("autoRotateSelect");
const controlUrlInput = document.getElementById("controlUrlInput");
const exportAuditBtn = document.getElementById("exportAuditBtn");
const outputLog = document.getElementById("outputLog");
const modeButtons = Array.from(document.querySelectorAll(".mode-btn"));

const MODE_DESCRIPTIONS = {
  direct: "Direct browser connection (proxy disabled).",
  "5g_proxy": "5G Proxy (:8888) active + WebRTC Non-Proxied UDP Leak Lock enforced.",
  burp_chain: "Red-Team Chain: Browser -> Burp/ZAP (:8080) -> 5G Proxy (:8888) + WebRTC Locked."
};

function logMessage(msg) {
  outputLog.textContent = typeof msg === "string" ? msg : JSON.stringify(msg, null, 2);
}

function buildHeaders() {
  const headers = { "Content-Type": "application/json" };
  const token = (controlTokenInput && controlTokenInput.value) ? controlTokenInput.value.trim() : "";
  if (token) {
    headers["X-Control-Token"] = token;
  }
  return headers;
}

function renderModeButtons(activeMode) {
  modeButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.mode === activeMode);
  });
  modeHint.textContent = MODE_DESCRIPTIONS[activeMode] || MODE_DESCRIPTIONS.direct;
  if (webrtcBadge) {
    webrtcBadge.textContent =
      activeMode === "5g_proxy" || activeMode === "burp_chain"
        ? "WebRTC Leak Lock: ON"
        : "WebRTC: Standard";
  }
}

async function fetchDaemonStatus(controlUrl) {
  const baseUrl = (controlUrl || "http://127.0.0.1:8889").replace(/\/+$/, "");
  try {
    const res = await fetch(`${baseUrl}/api/status`, { headers: buildHeaders() });
    if (res.status === 401) {
      daemonBadge.textContent = "Token Required";
      daemonBadge.className = "status-pill offline";
      return;
    }
    const data = await res.json();
    daemonBadge.textContent = "Daemon Online";
    daemonBadge.className = "status-pill online";
    wanIpDisplay.textContent = data.wan_ip || "Unknown";
    sourceIpDisplay.textContent = data.active_source_ip || "All (Default)";

    const currentVal = data.active_source_ip || "";
    adapterSelect.innerHTML = '<option value="">Default OS Route (All Interfaces)</option>';
    (data.adapters || []).forEach((nic) => {
      const ip = nic.ipv4_address || nic.ipv4 || "";
      const name = nic.interface_name || nic.name || "Interface";
      const ssidLabel = nic.ssid ? ` [${nic.ssid}]` : "";
      if (ip && !ip.startsWith("169.254.")) {
        const opt = document.createElement("option");
        opt.value = ip;
        opt.textContent = `${name}${ssidLabel} — ${ip} (${nic.inferred_provider || nic.description || "NIC"})`;
        if (ip === currentVal) {
          opt.selected = true;
        }
        adapterSelect.appendChild(opt);
      }
    });
  } catch (err) {
    daemonBadge.textContent = "Daemon Offline";
    daemonBadge.className = "status-pill offline";
    wanIpDisplay.textContent = "Offline";
  }
}

async function saveConfigUpdates(updates) {
  return await chrome.runtime.sendMessage({
    action: "update_config",
    updates
  });
}

modeButtons.forEach((btn) => {
  btn.addEventListener("click", async () => {
    const mode = btn.dataset.mode;
    renderModeButtons(mode);
    const resp = await saveConfigUpdates({ proxyMode: mode });
    if (resp && resp.ok) {
      logMessage(`Switched browser proxy mode to: ${mode}`);
    }
  });
});

adapterSelect.addEventListener("change", async () => {
  const baseUrl = (controlUrlInput.value || "http://127.0.0.1:8889").replace(/\/+$/, "");
  const sourceIp = adapterSelect.value;
  try {
    const res = await fetch(`${baseUrl}/api/select-adapter`, {
      method: "POST",
      headers: buildHeaders(),
      body: JSON.stringify({ source_ip: sourceIp })
    });
    const data = await res.json();
    if (!res.ok || data.status === "error") {
      logMessage(data.message || `HTTP ${res.status} error switching adapter`);
      return;
    }
    sourceIpDisplay.textContent = data.active_source_ip || "All (Default)";
    logMessage(data);
  } catch (err) {
    logMessage(`Adapter switch error: ${err}`);
  }
});

gatewayType.addEventListener("change", async () => {
  if (gatewayType.value === "verizon_askey") gatewayHost.value = "192.168.1.1";
  if (gatewayType.value === "xfinity") gatewayHost.value = "10.0.0.1";
  if (gatewayType.value === "tmobile_tmi") gatewayHost.value = "192.168.12.1";
  await saveConfigUpdates({
    gatewayType: gatewayType.value,
    gatewayHost: gatewayHost.value
  });
});

gatewayHost.addEventListener("change", async () => {
  await saveConfigUpdates({ gatewayHost: gatewayHost.value.trim() });
});

gatewayPassword.addEventListener("change", async () => {
  await saveConfigUpdates({ gatewayPassword: gatewayPassword.value });
});

controlTokenInput.addEventListener("change", async () => {
  await saveConfigUpdates({ controlToken: controlTokenInput.value.trim() });
  await fetchDaemonStatus(controlUrlInput.value.trim());
});

autoRotateSelect.addEventListener("change", async () => {
  const mins = Number(autoRotateSelect.value) || 0;
  await saveConfigUpdates({ autoRotateMinutes: mins });
  logMessage(mins > 0 ? `Auto-rotation scheduled every ${mins} minutes.` : "Auto-rotation disabled.");
});

controlUrlInput.addEventListener("change", async () => {
  const url = controlUrlInput.value.trim() || "http://127.0.0.1:8889";
  await saveConfigUpdates({ controlUrl: url });
  await fetchDaemonStatus(url);
});

rotateBtn.addEventListener("click", async () => {
  rotateBtn.disabled = true;
  freshIdentityBtn.disabled = true;
  try {
    await saveConfigUpdates({
      gatewayType: gatewayType.value,
      gatewayHost: gatewayHost.value.trim(),
      gatewayPassword: gatewayPassword.value,
      controlToken: controlTokenInput.value.trim(),
      controlUrl: controlUrlInput.value.trim()
    });
    logMessage("Triggering 5G Home WAN IP rotation...");
    const resp = await chrome.runtime.sendMessage({ action: "rotate_ip" });
    logMessage(resp);
    await fetchDaemonStatus(controlUrlInput.value.trim());
  } finally {
    rotateBtn.disabled = false;
    freshIdentityBtn.disabled = false;
  }
});

freshIdentityBtn.addEventListener("click", async () => {
  rotateBtn.disabled = true;
  freshIdentityBtn.disabled = true;
  try {
    await saveConfigUpdates({
      gatewayType: gatewayType.value,
      gatewayHost: gatewayHost.value.trim(),
      gatewayPassword: gatewayPassword.value,
      controlToken: controlTokenInput.value.trim(),
      controlUrl: controlUrlInput.value.trim()
    });
    logMessage("Clearing active tab cookies/storage & rotating 5G WAN IP...");
    const resp = await chrome.runtime.sendMessage({ action: "fresh_identity" });
    logMessage(resp);
    await fetchDaemonStatus(controlUrlInput.value.trim());
  } finally {
    rotateBtn.disabled = false;
    freshIdentityBtn.disabled = false;
  }
});

exportAuditBtn.addEventListener("click", async () => {
  const baseUrl = (controlUrlInput.value || "http://127.0.0.1:8889").replace(/\/+$/, "");
  try {
    const res = await fetch(`${baseUrl}/api/audit-log`, { headers: buildHeaders() });
    const data = await res.json();
    if (!res.ok || data.status === "error") {
      logMessage(data.message || `HTTP ${res.status} error exporting audit log`);
      return;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `5g-signed-roe-audit-log-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
    logMessage(`Exported ${data.count || 0} SHA-256 hash-chained ROE audit records (chain_valid=${data.chain_valid}).`);
  } catch (err) {
    logMessage(`Failed to export audit log: ${err}`);
  }
});

(async function initPopup() {
  const state = await chrome.runtime.sendMessage({ action: "get_state" });
  const cfg = (state && state.config) || {};
  renderModeButtons(cfg.proxyMode || "direct");
  gatewayType.value = cfg.gatewayType || "verizon_askey";
  gatewayHost.value = cfg.gatewayHost || "192.168.1.1";
  gatewayPassword.value = cfg.gatewayPassword || "";
  controlTokenInput.value = cfg.controlToken || "";
  autoRotateSelect.value = String(cfg.autoRotateMinutes || 0);
  controlUrlInput.value = cfg.controlUrl || "http://127.0.0.1:8889";
  await fetchDaemonStatus(controlUrlInput.value);
})();
