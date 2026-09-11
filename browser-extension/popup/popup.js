// ============================================
// ADCTIN Popup Controller
// ============================================

document.addEventListener('DOMContentLoaded', async () => {
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Check current page
  const result = await checkCurrentPage(tab.url);
  updateUI(result);
  
  // Load alerts
  loadAlerts();
  
  // Setup event listeners
  setupEventListeners();
});

// ============================================
// Check Current Page
// ============================================

async function checkCurrentPage(url) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'checkUrl',
      url: url
    });
    return response || {};
  } catch (error) {
    console.error('Error checking page:', error);
    return { prediction: 'unknown' };
  }
}

// ============================================
// Update UI
// ============================================

function updateUI(result) {
  const scoreEl = document.getElementById('page-score');
  const labelEl = document.getElementById('page-label');
  
  if (result.prediction === 'malicious' || result.malicious) {
    scoreEl.textContent = (result.confidence * 100).toFixed(0);
    scoreEl.className = 'score suspicious';
    labelEl.textContent = '⚠️ Suspicious';
    labelEl.style.color = '#d45c4c';
  } else if (result.prediction === 'benign' || result.prediction === 'safe') {
    scoreEl.textContent = ((1 - (result.confidence || 0)) * 100).toFixed(0);
    scoreEl.className = 'score';
    labelEl.textContent = '✅ Safe';
    labelEl.style.color = '#3a7d5a';
  } else {
    scoreEl.textContent = '—';
    scoreEl.className = 'score';
    labelEl.textContent = 'Checking...';
    labelEl.style.color = '#6b6560';
  }
  
  // Update threat count
  chrome.storage.local.get(['alerts'], (data) => {
    const alerts = data.alerts || [];
    document.getElementById('threat-count').textContent = `${alerts.length} blocked`;
  });
}

// ============================================
// Load Alerts
// ============================================

function loadAlerts() {
  chrome.runtime.sendMessage({ type: 'getAlerts' }, (alerts) => {
    const container = document.getElementById('alert-list');
    
    if (!alerts || alerts.length === 0) {
      container.innerHTML = '<p class="no-alerts">No recent alerts</p>';
      return;
    }
    
    container.innerHTML = '';
    alerts.slice(0, 8).forEach(alert => {
      const div = document.createElement('div');
      div.className = 'alert-item';
      div.innerHTML = `
        <span class="alert-type ${alert.prediction}">${alert.prediction}</span>
        <span class="alert-url" title="${alert.url}">${alert.url}</span>
        <span class="alert-time">${new Date(alert.time).toLocaleTimeString()}</span>
      `;
      container.appendChild(div);
    });
  });
}

// ============================================
// Event Listeners
// ============================================

function setupEventListeners() {
  // Report button
  document.getElementById('report-btn').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.runtime.sendMessage({
      type: 'reportUrl',
      url: tab.url
    }, () => {
      alert('URL submitted for analysis!');
    });
  });
  
  // Dashboard button
  document.getElementById('dashboard-btn').addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:3000/dashboard' });
  });
}

// ============================================
// Auto-refresh alerts
// ============================================

setInterval(loadAlerts, 10000);