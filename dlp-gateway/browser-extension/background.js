/**
 * Barclays DLP Guardian — Background Service Worker (Manifest V3)
 *
 * NOTE: webRequest blocking is NOT available in MV3. All prompt interception
 * is handled by content.js (DOM-level). This worker only manages the badge.
 */

const GATEWAY_HEALTH = 'http://localhost:8001/health';

function setBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

async function checkGateway() {
  try {
    const r = await fetch(GATEWAY_HEALTH);
    if (r.ok) setBadge('ON', '#4CAF50');
    else       setBadge('OFF', '#F44336');
  } catch {
    setBadge('OFF', '#F44336');
  }
}

// On install
chrome.runtime.onInstalled.addListener(() => {
  console.log('[DLP Guardian] Installed — MV3 service worker active');
  setBadge('ON', '#2196F3');
  checkGateway();
});

// Periodic health check every 30s
chrome.alarms.create('healthCheck', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'healthCheck') checkGateway();
});

// Badge updates from content.js
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'DLP_RESULT') {
    if (msg.decision === 'BLOCK')       setBadge('BLK', '#F44336');
    else if (msg.decision === 'WARN')   setBadge('WRN', '#FF9800');
    else                                setBadge('OK',  '#4CAF50');
    setTimeout(checkGateway, 3000);
  }
});
