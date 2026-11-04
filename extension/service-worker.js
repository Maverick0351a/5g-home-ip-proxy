// Hardened Manifest V3 Background Service Worker for 5G Home IP Proxy & Red-Team Switcher (v1.3.0)
// - Non-sensitive preferences stored in chrome.storage.local
// - Sensitive secrets (gatewayPassword, controlToken) stored strictly in RAM-only chrome.storage.session
// - Enforces WebRTC non-proxied UDP leak lock when 5G Proxy or Burp/ZAP Chain mode is active

const LOCAL_DEFAULTS = {
  proxyMode: "direct",          // "direct" | "5g_proxy" | "burp_chain"
  controlUrl: "http://127.0.0.1:8889",
  socksHost: "127.0.0.1",
  socksPort: 8888,
  burpHost: "127.0.0.1",
  burpPort: 8080,
  autoRotateMinutes: 0,         // 0 = disabled, 5, 15, 30
  gatewayType: "verizon_askey",
  gatewayHost: "192.168.1.1"
};

const SESSION_DEFAULTS = {
  gatewayPassword: "",
  controlToken: ""
};

const ALARM_NAME = "autoRotate5gWanIp";

async function getConfig() {
  const localData = await chrome.storage.local.get(Object.keys(LOCAL_DEFAULTS));
  let sessionData = {};
  if (chrome.storage.session) {
    sessionData = await chrome.storage.session.get(Object.keys(SESSION_DEFAULTS));
  }
  return { ...LOCAL_DEFAULTS, ...SESSION_DEFAULTS, ...localData, ...sessionData };
}

async function saveConfig(updates) {
  const localUpdates = {};
  const sessionUpdates = {};
  for (const [k, v] of Object.entries(updates || {})) {
    if (k in SESSION_DEFAULTS) {
      sessionUpdates[k] = v;
    } else if (k in LOCAL_DEFAULTS) {
      localUpdates[k] = v;
    }
  }
  if (Object.keys(localUpdates).length > 0) {
    await chrome.storage.local.set(localUpdates);
  }
  if (Object.keys(sessionUpdates).length > 0 && chrome.storage.session) {
    await chrome.storage.session.set(sessionUpdates);
  }
  return await getConfig();
}

async function updateBadge(mode) {
  if (mode === "5g_proxy") {
    await chrome.action.setBadgeText({ text: "5G" });
    await chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
  } else if (mode === "burp_chain") {
    await chrome.action.setBadgeText({ text: "BURP" });
    await chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
  } else {
    await chrome.action.setBadgeText({ text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ color: "#475569" });
  }
}

async function applyWebRTCLeakPolicy(mode) {
  if (!chrome.privacy || !chrome.privacy.network || !chrome.privacy.network.webRTCIPHandlingPolicy) {
    return;
  }
  if (mode === "5g_proxy" || mode === "burp_chain") {
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({
      value: "disable_non_proxied_udp"
    });
  } else {
    await chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
  }
}

async function applyProxySettings(config) {
  const mode = config.proxyMode || "direct";
  if (mode === "direct") {
    await chrome.proxy.settings.clear({ scope: "regular" });
  } else if (mode === "5g_proxy") {
    await chrome.proxy.settings.set({
      value: {
        mode: "fixed_servers",
        rules: {
          singleProxy: {
            scheme: "socks5",
            host: config.socksHost || "127.0.0.1",
            port: Number(config.socksPort) || 8888
          },
          bypassList: ["127.0.0.1", "localhost", "192.168.1.1", "192.168.12.1", "10.0.0.1"]
        }
      },
      scope: "regular"
    });
  } else if (mode === "burp_chain") {
    await chrome.proxy.settings.set({
      value: {
        mode: "fixed_servers",
        rules: {
          singleProxy: {
            scheme: "http",
            host: config.burpHost || "127.0.0.1",
            port: Number(config.burpPort) || 8080
          },
          bypassList: ["127.0.0.1:8889", "localhost:8889"]
        }
      },
      scope: "regular"
    });
  }
  await applyWebRTCLeakPolicy(mode);
  await updateBadge(mode);
}

async function syncAutoRotateAlarm(minutes) {
  await chrome.alarms.clear(ALARM_NAME);
  const mins = Number(minutes) || 0;
  if (mins > 0) {
    await chrome.alarms.create(ALARM_NAME, { periodInMinutes: mins });
  }
}

function buildAuthHeaders(config) {
  const headers = { "Content-Type": "application/json" };
  if (config.controlToken) {
    headers["X-Control-Token"] = config.controlToken;
  }
  return headers;
}

async function triggerWanRotation(config) {
  const baseUrl = (config.controlUrl || "http://127.0.0.1:8889").replace(/\/+$/, "");
  const response = await fetch(`${baseUrl}/api/rotate-ip`, {
    method: "POST",
    headers: buildAuthHeaders(config),
    body: JSON.stringify({
      gateway_type: config.gatewayType || "verizon_askey",
      host: config.gatewayHost || "192.168.1.1",
      password: config.gatewayPassword || ""
    })
  });
  return await response.json();
}

async function clearActiveTabIdentity() {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tabs || tabs.length === 0 || !tabs[0].url) {
    return { cleared: false, reason: "no_active_tab" };
  }
  try {
    const url = new URL(tabs[0].url);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { cleared: false, reason: "non_http_origin", origin: url.origin };
    }
    await chrome.browsingData.remove(
      { origins: [url.origin] },
      {
        cookies: true,
        localStorage: true,
        cache: true,
        indexedDB: true,
        serviceWorkers: true
      }
    );
    return { cleared: true, origin: url.origin };
  } catch (err) {
    return { cleared: false, reason: String(err) };
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  const config = await getConfig();
  await saveConfig(config);
  await applyProxySettings(config);
  await syncAutoRotateAlarm(config.autoRotateMinutes);
});

chrome.runtime.onStartup.addListener(async () => {
  const config = await getConfig();
  await applyProxySettings(config);
  await syncAutoRotateAlarm(config.autoRotateMinutes);
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM_NAME) {
    try {
      const config = await getConfig();
      await triggerWanRotation(config);
    } catch (err) {
      console.warn("Scheduled 5G WAN IP rotation failed:", err);
    }
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      const config = await getConfig();
      if (message.action === "get_state") {
        sendResponse({ ok: true, config });
      } else if (message.action === "update_config") {
        const updated = await saveConfig(message.updates || {});
        await applyProxySettings(updated);
        if ("autoRotateMinutes" in (message.updates || {})) {
          await syncAutoRotateAlarm(updated.autoRotateMinutes);
        }
        sendResponse({ ok: true, config: updated });
      } else if (message.action === "rotate_ip") {
        const result = await triggerWanRotation(config);
        sendResponse({ ok: true, result });
      } else if (message.action === "fresh_identity") {
        const siteClear = await clearActiveTabIdentity();
        const rotation = await triggerWanRotation(config);
        sendResponse({ ok: true, siteClear, rotation });
      } else {
        sendResponse({ ok: false, error: "Unknown action" });
      }
    } catch (err) {
      sendResponse({ ok: false, error: String(err) });
    }
  })();
  return true;
});
