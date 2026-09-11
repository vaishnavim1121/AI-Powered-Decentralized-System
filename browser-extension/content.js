// ============================================
// ADCTIN Browser Extension - Content Script
// ============================================

console.log('🔒 ADCTIN: Protection active');

const scannedUrls = new Map();
const processedLinks = new WeakSet();

// ============================================
// Collect page signals
// ============================================

function collectPageSignals() {
  const signals = {
    has_login_form: false,
    has_password_field: false,
    has_credit_card_field: false,
    has_crypto_wallet_prompt: false,
    has_auto_download: false,
    has_hidden_iframe: false,
    page_title: document.title || '',
    visible_brand_names: [],
  };
  
  try {
    if (document.querySelector('input[type="password"]')) {
      signals.has_password_field = true;
    }
    
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      if (form.querySelector('input[type="password"]') || 
          form.querySelector('input[type="email"]') ||
          form.querySelector('input[name*="user"]') ||
          form.querySelector('input[name*="login"]')) {
        signals.has_login_form = true;
      }
    });
    
    const ccInputs = document.querySelectorAll(
      'input[name*="card"], input[name*="credit"], input[name*="cvv"], input[name*="cvc"], input[autocomplete="cc-number"]'
    );
    if (ccInputs.length > 0) signals.has_credit_card_field = true;
    
    const pageText = (document.body?.innerText || '').toLowerCase();
    if (pageText.includes('connect wallet') || 
        pageText.includes('connect your wallet') ||
        pageText.includes('metamask') ||
        pageText.includes('seed phrase') ||
        pageText.includes('phantom wallet')) {
      signals.has_crypto_wallet_prompt = true;
    }
    
    const downloadLinks = document.querySelectorAll(
      'a[download], a[href$=".exe"], a[href$=".dmg"], a[href$=".zip"], a[href$=".apk"]'
    );
    if (downloadLinks.length > 0) signals.has_auto_download = true;
    
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      const style = window.computedStyle ? window.getComputedStyle(iframe) : null;
      if (style && (style.display === 'none' || style.visibility === 'hidden')) {
        signals.has_hidden_iframe = true;
      }
    });
    
    const brands = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 
                    'facebook', 'instagram', 'coinbase', 'binance', 'metamask'];
    brands.forEach(brand => {
      if (pageText.includes(brand)) signals.visible_brand_names.push(brand);
    });
  } catch (e) {
    console.warn('ADCTIN: Signal collection error', e);
  }
  
  return signals;
}

// ============================================
// Local pre-check (only scan suspicious-looking links)
// ============================================

function isLocallySuspicious(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const path = urlObj.pathname;
    
    let signals = 0;
    if (/login|verify|secure|update|account|confirm|signin|password|banking/i.test(path)) signals += 1;
    if (/\.(tk|ml|ga|cf|gq|xyz|top)$/i.test(hostname)) signals += 1;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) signals += 2;
    if ((hostname.match(/\./g) || []).length >= 4) signals += 1;
    if (hostname.length > 30) signals += 1;
    if ((hostname.match(/-/g) || []).length >= 3) signals += 1;
    
    return signals >= 1;
  } catch {
    return false;
  }
}

// ============================================
// Check URL with backend (with signals)
// ============================================

async function checkUrl(url, signals = null) {
  const cacheKey = url;
  if (scannedUrls.has(cacheKey)) return scannedUrls.get(cacheKey);
  
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { type: 'checkUrlWithSignals', url: url, signals: signals || {} },
      (response) => {
        if (chrome.runtime.lastError) {
          resolve({ prediction: 'unknown', malicious: false });
          return;
        }
        scannedUrls.set(cacheKey, response);
        resolve(response || { prediction: 'unknown', malicious: false });
      }
    );
  });
}

// ============================================
// Check current page (triggers popup)
// ============================================

async function checkCurrentPage() {
  const url = window.location.href;
  console.log('🔒 ADCTIN: Checking page:', url.substring(0, 80));
  
  const signals = collectPageSignals();
  console.log('🔒 ADCTIN: Page signals:', signals);
  
  const result = await checkUrl(url, signals);
  console.log('🔒 ADCTIN: Result:', result);
  
  if (result.malicious || result.prediction === 'malicious') {
    showBlockingWarning(result);
  } else if (result.verdict === 'suspicious') {
    showSuspiciousBanner(result);
  } else {
    console.log('✅ ADCTIN: Page safe');
  }
}

// ============================================
// FULL-SCREEN BLOCKING WARNING (with VT data)
// ============================================

function showBlockingWarning(result) {
  if (document.getElementById('adctin-blocker')) return;
  
  const confidence = ((result.confidence || 0) * 100).toFixed(1);
  const threatType = result.threat_type || 'Malicious Content';
  const riskLevel = (result.intent?.risk_level || 'high').toUpperCase();
  const whatItDoes = result.explanation?.what_it_does || threatType;
  const whySuspicious = result.explanation?.why_suspicious || [];
  const domainAge = result.domain_analysis?.age_days;
  const vt = result.virustotal;
  
  const riskColor = riskLevel === 'CRITICAL' ? '#d45c4c' : '#e8853a';
  
  const whyHtml = whySuspicious.length > 0
    ? whySuspicious.map(w => `<li style="padding: 4px 0; color: rgba(245,240,235,0.75); font-size: 13px;">• ${w}</li>`).join('')
    : '<li style="color: rgba(245,240,235,0.5); font-size: 13px;">Detected by pattern analysis</li>';
  
  const domainAgeHtml = domainAge !== null && domainAge !== undefined
    ? `<div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06);">
         <span style="color: rgba(245, 240, 235, 0.5); font-size: 13px;">Domain Age</span>
         <span style="color: ${domainAge < 30 ? '#d45c4c' : 'rgba(245,240,235,0.8)'}; font-size: 13px; font-weight: 600;">
           ${domainAge} days
         </span>
       </div>`
    : '';
  
  // VirusTotal section
  let vtHtml = '';
  if (vt && vt.verdict && vt.verdict !== 'queued') {
    const vtColor = vt.verdict === 'malicious' ? '#d45c4c' 
      : vt.verdict === 'suspicious' ? '#e8853a'
      : '#3a7d5a';
    
    const flaggedHtml = vt.flagged_by && vt.flagged_by.length > 0
      ? `<div style="margin-top: 8px;">
           <span style="color: rgba(245,240,235,0.5); font-size: 11px;">Flagged by:</span>
           <span style="color: rgba(245,240,235,0.75); font-size: 11px;">${vt.flagged_by.slice(0, 5).join(', ')}</span>
         </div>`
      : '';
    
    const catHtml = vt.categories && Object.keys(vt.categories).length > 0
      ? `<div style="margin-top: 8px;">
           <span style="color: rgba(245,240,235,0.5); font-size: 11px;">Categories:</span>
           <span style="color: rgba(245,240,235,0.75); font-size: 11px;">${Object.values(vt.categories).slice(0, 3).join(', ')}</span>
         </div>`
      : '';
    
    vtHtml = `
      <div style="background: rgba(255,255,255,0.03); border-radius: 8px; padding: 16px; margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="color: rgba(245,240,235,0.5); font-size: 11px; text-transform: uppercase; letter-spacing: 1px;">VirusTotal Report</span>
          <span style="color: ${vtColor}; font-size: 11px; font-weight: 700;">${vt.verdict.toUpperCase()}</span>
        </div>
        <div style="display: flex; gap: 16px; font-size: 13px; margin-bottom: 4px;">
          <span style="color: ${vt.malicious > 0 ? '#d45c4c' : 'rgba(245,240,235,0.6)'};">
            <strong>${vt.malicious}</strong> malicious
          </span>
          <span style="color: rgba(245,240,235,0.6);">
            <strong>${vt.suspicious || 0}</strong> suspicious
          </span>
          <span style="color: rgba(245,240,235,0.6);">
            <strong>${vt.harmless || 0}</strong> harmless
          </span>
          <span style="color: rgba(245,240,235,0.4);">
            / ${vt.total_engines} engines
          </span>
        </div>
        ${flaggedHtml}
        ${catHtml}
        ${vt.vt_link ? `<a href="${vt.vt_link}" target="_blank" style="color: #c17f59; font-size: 11px; margin-top: 8px; display: inline-block;">View full report →</a>` : ''}
      </div>
    `;
  }
  
  const blocker = document.createElement('div');
  blocker.id = 'adctin-blocker';
  blocker.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    z-index: 2147483647;
    background: linear-gradient(135deg, #1a1a2e 0%, #2d2a40 100%);
    color: #f5f0eb;
    display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    padding: 40px; overflow-y: auto;
  `;
  
  blocker.innerHTML = `
    <div style="max-width: 680px; width: 100%;">
      <div style="text-align: center; margin-bottom: 24px;">
        <div style="font-size: 72px; margin-bottom: 8px;">🛡️</div>
        <h1 style="font-size: 32px; font-weight: 700; margin: 0 0 8px; color: ${riskColor};">
          Dangerous Site Detected
        </h1>
        <p style="font-size: 15px; color: rgba(245, 240, 235, 0.7); margin: 0; line-height: 1.6;">
          ADCTIN has blocked this page because it may harm your device or steal your personal information.
        </p>
      </div>
      
      <div style="background: rgba(255, 255, 255, 0.05); border: 1px solid ${riskColor}44; border-radius: 12px; padding: 24px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06);">
          <span style="color: rgba(245, 240, 235, 0.5); font-size: 13px;">Risk Level</span>
          <span style="color: ${riskColor}; font-size: 13px; font-weight: 700;">${riskLevel}</span>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06);">
          <span style="color: rgba(245, 240, 235, 0.5); font-size: 13px;">Threat Type</span>
          <span style="color: ${riskColor}; font-size: 13px; font-weight: 600;">${threatType}</span>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06);">
          <span style="color: rgba(245, 240, 235, 0.5); font-size: 13px;">Confidence</span>
          <span style="color: ${riskColor}; font-size: 13px; font-weight: 600;">${confidence}%</span>
        </div>
        ${domainAgeHtml}
      </div>
      
      <div style="background: rgba(255, 255, 255, 0.03); border-left: 3px solid ${riskColor}; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px;">
        <div style="color: rgba(245, 240, 235, 0.5); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">
          What this page does
        </div>
        <div style="color: #f5f0eb; font-size: 15px; font-weight: 600; margin-bottom: 12px;">
          ${whatItDoes}
        </div>
        <div style="color: rgba(245, 240, 235, 0.5); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">
          Why it's suspicious
        </div>
        <ul style="margin: 0; padding: 0; list-style: none;">
          ${whyHtml}
        </ul>
      </div>
      
      ${vtHtml}
      
      <div style="background: rgba(0,0,0,0.2); border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; overflow: hidden;">
        <div style="color: rgba(245, 240, 235, 0.4); font-size: 11px; margin-bottom: 4px;">URL</div>
        <div style="color: rgba(245, 240, 235, 0.7); font-size: 11px; font-family: monospace; word-break: break-all;">
          ${window.location.href}
        </div>
      </div>
      
      <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
        <button id="adctin-back" style="padding: 14px 32px; background: ${riskColor}; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; font-family: inherit;">
          ← Go Back to Safety
        </button>
        <button id="adctin-proceed" style="padding: 14px 32px; background: rgba(255, 255, 255, 0.08); color: #f5f0eb; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; font-size: 15px; cursor: pointer; font-family: inherit;">
          Proceed Anyway
        </button>
      </div>
      
      <p style="margin-top: 20px; text-align: center; font-size: 11px; color: rgba(245, 240, 235, 0.35);">
        Protected by ADCTIN — AI + VirusTotal Threat Intelligence
      </p>
    </div>
  `;
  
  document.body.appendChild(blocker);
  document.body.style.overflow = 'hidden';
  
  blocker.querySelector('#adctin-back').addEventListener('click', () => {
    if (window.history.length > 1) window.history.back();
    else window.location.href = 'about:blank';
  });
  
  blocker.querySelector('#adctin-proceed').addEventListener('click', () => {
    blocker.remove();
    document.body.style.overflow = '';
  });
}

// ============================================
// Suspicious banner
// ============================================

function showSuspiciousBanner(result) {
  if (document.getElementById('adctin-banner')) return;
  
  const banner = document.createElement('div');
  banner.id = 'adctin-banner';
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
    background: linear-gradient(90deg, #c49a5c 0%, #e8853a 100%);
    color: #1a1a2e; padding: 12px 20px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    font-family: -apple-system, sans-serif; font-size: 14px;
    display: flex; justify-content: space-between; align-items: center;
  `;
  banner.innerHTML = `
    <span>⚠️ <strong>ADCTIN:</strong> ${result.explanation?.what_it_does || 'Suspicious page detected'}. Proceed with caution.</span>
    <button id="adctin-dismiss-banner" style="padding: 6px 14px; background: rgba(0,0,0,0.15); border: none; border-radius: 4px; cursor: pointer; color: #1a1a2e; font-weight: 600;">
      Dismiss
    </button>
  `;
  document.body.prepend(banner);
  banner.querySelector('#adctin-dismiss-banner').addEventListener('click', () => banner.remove());
}

// ============================================
// Batch Link Scanner
// ============================================

class LinkScanner {
  constructor() {
    this.queue = [];
    this.isProcessing = false;
    this.batchSize = 5;
  }
  
  enqueue(link) {
    if (processedLinks.has(link)) return;
    processedLinks.add(link);
    
    const url = link.href;
    if (!url || !url.startsWith('http')) return;
    if (!isLocallySuspicious(url)) return;
    
    this.queue.push({ link, url });
    if (!this.isProcessing) this.scheduleBatch();
  }
  
  scheduleBatch() {
    if (this.queue.length === 0) {
      this.isProcessing = false;
      return;
    }
    this.isProcessing = true;
    const schedule = window.requestIdleCallback || ((cb) => setTimeout(cb, 100));
    schedule(() => this.processBatch(), { timeout: 2000 });
  }
  
  async processBatch() {
    const batch = this.queue.splice(0, this.batchSize);
    if (batch.length === 0) {
      this.isProcessing = false;
      return;
    }
    
    await Promise.all(batch.map(async ({ link, url }) => {
      try {
        const result = await checkUrl(url, {});
        if (result.malicious || result.prediction === 'malicious') {
          this.markSuspicious(link, result);
        }
      } catch (e) {}
    }));
    
    this.scheduleBatch();
  }
  
  markSuspicious(link, result) {
    link.setAttribute('data-adctin', 'suspicious');
    link.style.borderBottom = '2px dashed #d45c4c';
    link.style.paddingBottom = '1px';
    link.title = `⚠️ ADCTIN: ${result.threat_type || 'Malicious'}`;
    
    if (!link.querySelector('.adctin-badge')) {
      const badge = document.createElement('sup');
      badge.className = 'adctin-badge';
      badge.textContent = '⚠️';
      badge.style.cssText = 'color: #d45c4c; font-size: 10px; margin-left: 2px;';
      link.appendChild(badge);
    }
  }
}

const scanner = new LinkScanner();

function scanAllLinks() {
  const links = document.querySelectorAll('a[href]');
  links.forEach(link => {
    if (!processedLinks.has(link)) scanner.enqueue(link);
  });
}

let mutationTimer = null;
function onMutations() {
  if (mutationTimer) return;
  mutationTimer = setTimeout(() => {
    mutationTimer = null;
    scanAllLinks();
  }, 1500);
}

const observer = new MutationObserver(onMutations);

// ============================================
// Initialize
// ============================================

function start() {
  checkCurrentPage();
  scanAllLinks();
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
  console.log('🔒 ADCTIN: Protection initialized');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}

// ============================================
// Debug helpers (call from console)
// ============================================

window.__adctin_debug = {
  signals: collectPageSignals,
  check: checkCurrentPage,
  testPopup: () => showBlockingWarning({
    prediction: 'malicious',
    confidence: 0.95,
    threat_type: 'Phishing — Impersonating PayPal',
    risk_score: 12,
    intent: { type: 'Phishing', risk_level: 'critical', reasons: ['Test'] },
    explanation: {
      what_it_does: 'Stealing PayPal login credentials',
      why_suspicious: ['Domain impersonates PayPal', 'Page asks for password', 'Domain is 3 days old'],
      risk_level: 'critical'
    },
    domain_analysis: { age_days: 3, flags: [] },
    virustotal: {
      verdict: 'malicious',
      malicious: 15,
      suspicious: 3,
      harmless: 55,
      total_engines: 90,
      flagged_by: ['Sophos', 'BitDefender', 'Kaspersky', 'Webroot', 'McAfee'],
      categories: { 'Webroot': 'Phishing and Other Frauds', 'Sophos': 'Malware' },
      vt_link: 'https://www.virustotal.com/gui/url/test'
    }
  })
};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'threatResult') {
    if (request.data && request.data.malicious) {
      showBlockingWarning(request.data);
    }
    sendResponse({ success: true });
  }
});

console.log('🔒 ADCTIN: Content script loaded');