// ============================================
// ADCTIN Browser Extension - Background Service
// ============================================

const API_URL = 'https://adctin-backend.onrender.com';
const CACHE_DURATION = 5 * 60 * 1000;
const NAVIGATION_THROTTLE_MS = 1500;

const TRUSTED_DOMAINS = [
  'google.com', 'youtube.com', 'youtu.be',
  'microsoft.com', 'apple.com', 'cloudflare.com',
  'mozilla.org', 'localhost'
];

const threatCache = new Map();
let lastNavigationCheck = 0;

function isTrusted(url) {
  try {
    const hostname = new URL(url).hostname.replace('www.', '');
    return TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  } catch {
    return false;
  }
}

// ============================================
// URL Checking (with intent signals)
// ============================================

async function checkUrlWithSignals(url, signals = {}) {
  const cacheKey = url;
  if (threatCache.has(cacheKey)) {
    const cached = threatCache.get(cacheKey);
    if (Date.now() - cached.timestamp < CACHE_DURATION) {
      return cached.data;
    }
  }

  if (isTrusted(url)) {
    const safeResult = {
      prediction: 'benign',
      malicious: false,
      confidence: 0.99,
      trusted: true,
      url
    };
    threatCache.set(cacheKey, { data: safeResult, timestamp: Date.now() });
    return safeResult;
  }

  try {
    console.log('🔒 ADCTIN: Fetching backend for:', url.substring(0, 60));

    const response = await fetch(`${API_URL}/threat/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ url, signals })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    console.log('🔒 ADCTIN: Backend response received:', data.prediction);

    threatCache.set(cacheKey, {
      data: data,
      timestamp: Date.now()
    });

    if (data.malicious || data.prediction === 'malicious') {
      showNotification(url, data);
    }

    return data;
  } catch (error) {
    console.error('❌ ADCTIN: Backend fetch failed:', error.message);
    return {
      error: error.message,
      prediction: 'unknown',
      malicious: false,
      url
    };
  }
}

// ============================================
// Notifications
// ============================================

function showNotification(url, data) {
  const confidence = ((data.confidence || 0) * 100).toFixed(0);
  const threatType = data.threat_type || 'Threat Detected';
  
  if (chrome.notifications) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon-128.png',
      title: `⚠️ ADCTIN: ${threatType}`,
      message: `${confidence}% confidence\n${url.substring(0, 80)}`,
      priority: 2
    });
  }

  saveAlert({
    url: url,
    prediction: data.prediction,
    confidence: data.confidence,
    threat_type: threatType,
    time: new Date().toISOString()
  });
}

function saveAlert(alert) {
  chrome.storage.local.get(['alerts'], (result) => {
    const alerts = result.alerts || [];
    alerts.unshift(alert);
    chrome.storage.local.set({ alerts: alerts.slice(0, 100) });
  });
}

// ============================================
// Initialize Listeners
// ============================================

function initializeListeners() {
  // Navigation listener (with throttle)
  if (chrome.webNavigation && chrome.webNavigation.onCompleted) {
    chrome.webNavigation.onCompleted.addListener(async (details) => {
      if (details.frameId !== 0) return;
      
      const url = details.url;
      if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;
      if (isTrusted(url)) return;
      
      const now = Date.now();
      if ((now - lastNavigationCheck) < NAVIGATION_THROTTLE_MS) return;
      lastNavigationCheck = now;
      
      const result = await checkUrlWithSignals(url, {});
      
      try {
        await chrome.tabs.sendMessage(details.tabId, {
          type: 'threatResult',
          data: result,
          url: url
        });
      } catch (e) {}
    });
  }

  // Message handlers
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'checkUrl') {
      checkUrlWithSignals(request.url, {}).then(sendResponse);
      return true;
    }
    
    if (request.type === 'checkUrlWithSignals') {
      checkUrlWithSignals(request.url, request.signals || {}).then(sendResponse);
      return true;
    }
    
    if (request.type === 'reportUrl') {
      fetch(`${API_URL}/threat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: request.url })
      }).then(() => sendResponse({ success: true }))
        .catch(() => sendResponse({ success: false }));
      return true;
    }
    
    if (request.type === 'getAlerts') {
      chrome.storage.local.get(['alerts'], (result) => {
        sendResponse(result.alerts || []);
      });
      return true;
    }
    
    if (request.type === 'getApiUrl') {
      sendResponse({ apiUrl: API_URL });
      return true;
    }
  });

  if (chrome.notifications && chrome.notifications.onClicked) {
    chrome.notifications.onClicked.addListener(() => {
      chrome.tabs.create({ url: 'http://localhost:3000/dashboard' });
    });
  }
}

// ============================================
// Initialize
// ============================================

chrome.runtime.onInstalled.addListener(() => {
  console.log('🔒 ADCTIN installed');
  initializeListeners();
});

chrome.runtime.onStartup.addListener(() => {
  console.log('🔒 ADCTIN started');
  initializeListeners();
});

initializeListeners();

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of threatCache) {
    if (now - value.timestamp > CACHE_DURATION) {
      threatCache.delete(key);
    }
  }
}, 60000);

console.log('🔒 ADCTIN Protection Background Service Started');