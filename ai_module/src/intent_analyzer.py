"""
Intent Analyzer — Detects WHAT a page is trying to do, not just what it looks like.

Uses:
  1. Domain intelligence (age, TLD, WHOIS)
  2. URL structure analysis
  3. Page signals from the browser extension (forms, iframes, downloads)
  4. Brand impersonation detection
"""

import re
import urllib.parse
from datetime import datetime

# Try to import whois (optional)
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois not installed. Run: pip install python-whois")
    print("   Domain age detection will be limited.")


# ============================================
# Brands commonly impersonated in phishing
# ============================================

IMPERSONATED_BRANDS = {
    'paypal': 'PayPal',
    'apple': 'Apple ID',
    'google': 'Google Account',
    'microsoft': 'Microsoft Account',
    'amazon': 'Amazon',
    'netflix': 'Netflix',
    'facebook': 'Facebook',
    'instagram': 'Instagram',
    'whatsapp': 'WhatsApp',
    'chase': 'Chase Bank',
    'wellsfargo': 'Wells Fargo',
    'bankofamerica': 'Bank of America',
    'coinbase': 'Coinbase',
    'binance': 'Binance',
    'metamask': 'MetaMask',
    'trustwallet': 'Trust Wallet',
    'steam': 'Steam',
    'roblox': 'Roblox',
    'discord': 'Discord',
    'linkedin': 'LinkedIn',
}

# Official domains for each brand
OFFICIAL_DOMAINS = {
    'paypal': ['paypal.com'],
    'apple': ['apple.com', 'icloud.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
    'amazon': ['amazon.com', 'amazon.in', 'aws.amazon.com'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com', 'wa.me'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com'],
    'metamask': ['metamask.io'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'roblox': ['roblox.com'],
    'discord': ['discord.com', 'discord.gg'],
    'linkedin': ['linkedin.com'],
}

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.click', '.link', '.download', '.review', '.country', '.kim',
    '.cricket', '.science', '.party', '.gdn', '.stream'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'cutt.ly', 'rb.gy', 'rebrand.ly', 'shorturl.at',
    'tiny.cc', 'bit.do', 'short.link', 'shorte.st', 'adf.ly'
]


# ============================================
# Domain Intelligence
# ============================================

def get_domain_age_days(hostname):
    """How old is the domain? New domains = high risk"""
    if not WHOIS_AVAILABLE:
        return None
    try:
        parts = hostname.split('.')
        if len(parts) >= 2:
            root = '.'.join(parts[-2:])
        else:
            root = hostname
        
        info = whois.whois(root)
        creation_date = info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date[:10], '%Y-%m-%d')
            age = (datetime.now() - creation_date).days
            return age
        return None
    except Exception:
        return None


def analyze_domain(hostname):
    """Analyze domain for red flags"""
    flags = []
    score = 0
    
    age_days = get_domain_age_days(hostname)
    if age_days is not None:
        if age_days < 7:
            flags.append(f"Domain registered only {age_days} days ago")
            score += 4
        elif age_days < 30:
            flags.append(f"Domain is very new ({age_days} days old)")
            score += 3
        elif age_days < 90:
            flags.append(f"Domain is new ({age_days} days old)")
            score += 1
    
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append(f"Suspicious top-level domain ({tld})")
            score += 2
            break
    
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        flags.append("Uses raw IP address instead of domain")
        score += 3
    
    if hostname.count('.') >= 4:
        flags.append("Excessive subdomains (common in phishing)")
        score += 2
    
    if len(hostname) > 40:
        flags.append("Unusually long domain name")
        score += 1
    
    if hostname.count('-') >= 3:
        flags.append("Multiple hyphens in domain")
        score += 1
    
    if re.search(r'\d', hostname.split('.')[0]):
        flags.append("Numbers in domain name (potential typosquatting)")
        score += 1
    
    return {
        'score': score,
        'flags': flags,
        'age_days': age_days,
        'hostname': hostname,
    }


# ============================================
# Brand Impersonation Detection
# ============================================

def detect_impersonation(hostname, path=''):
    """Check if domain is impersonating a known brand"""
    hostname_lower = hostname.lower()
    
    for brand_key, brand_name in IMPERSONATED_BRANDS.items():
        if brand_key in hostname_lower:
            official = OFFICIAL_DOMAINS.get(brand_key, [])
            
            is_official = any(
                hostname_lower == off or hostname_lower.endswith('.' + off)
                for off in official
            )
            
            if not is_official:
                suspicious_suffixes = [
                    '-secure', '-verify', '-login', '-update', '-account',
                    '-support', '-help', '-signin', 'secure-', 'verify-',
                    'login-', 'update-', 'account-'
                ]
                
                has_suspicious_suffix = any(s in hostname_lower for s in suspicious_suffixes)
                
                if has_suspicious_suffix:
                    return {
                        'is_impersonation': True,
                        'brand': brand_name,
                        'reason': f"Domain contains '{brand_key}' with suspicious prefix/suffix — impersonating {brand_name}",
                        'confidence': 0.92,
                    }
                else:
                    return {
                        'is_impersonation': True,
                        'brand': brand_name,
                        'reason': f"Domain contains '{brand_key}' but is not the official domain for {brand_name}",
                        'confidence': 0.75,
                    }
    
    return {'is_impersonation': False}


# ============================================
# Intent Classification
# ============================================

def classify_intent(url, page_signals=None):
    """Determine the INTENT of the page using URL + page signals"""
    url_lower = url.lower()
    parsed = urllib.parse.urlparse(url_lower)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    page_signals = page_signals or {}
    
    intent = {
        'type': 'unknown',
        'confidence': 0.5,
        'reasons': [],
        'risk_level': 'low',
    }
    
    # ============================================
    # 1. Brand Impersonation (strongest signal)
    # ============================================
    impersonation = detect_impersonation(hostname, path)
    if impersonation['is_impersonation']:
        intent['type'] = f'Phishing — Impersonating {impersonation["brand"]}'
        intent['confidence'] = impersonation['confidence']
        intent['reasons'].append(impersonation['reason'])
        intent['risk_level'] = 'critical'
        return intent
    
    # ============================================
    # 2. Page Content Signals (highest priority)
    # ============================================
    if page_signals.get('has_crypto_wallet_prompt'):
        intent['type'] = 'Crypto Scam — Wallet Drainer'
        intent['confidence'] = 0.92
        intent['reasons'].append("Page prompts users to connect crypto wallet")
        intent['risk_level'] = 'critical'
        return intent
    
    if page_signals.get('has_credit_card_field'):
        intent['type'] = 'Financial Fraud — Card Data Collection'
        intent['confidence'] = 0.88
        intent['reasons'].append("Page requests credit card information")
        intent['risk_level'] = 'critical'
        return intent
    
    if page_signals.get('has_auto_download'):
        intent['type'] = 'Malware Distribution — Auto Download'
        intent['confidence'] = 0.90
        intent['reasons'].append("Page triggers automatic file download")
        intent['risk_level'] = 'critical'
        return intent
    
    if page_signals.get('has_hidden_iframe'):
        intent['type'] = 'Hidden Content / Clickjacking'
        intent['confidence'] = 0.82
        intent['reasons'].append("Page contains hidden iframes")
        intent['risk_level'] = 'high'
    
    if page_signals.get('has_password_field') and page_signals.get('has_login_form'):
        intent['type'] = 'Phishing — Credential Harvesting'
        intent['confidence'] = 0.80
        intent['reasons'].append("Page asks for login credentials on an untrusted domain")
        intent['risk_level'] = 'high'
        return intent
    
    # ============================================
    # 3. URL Pattern Fallbacks (REORDERED — crypto before piracy!)
    # ============================================
    if intent['type'] == 'unknown':
        
        # Crypto FIRST (highest priority — most common scam type)
        if any(kw in url_lower for kw in ['bitcoin', 'btc', 'ethereum', 'eth', 'crypto',
                                          'airdrop', 'wallet', 'doubler', 'generator',
                                          'metamask', 'binance', 'coinbase']):
            intent['type'] = 'Crypto Scam'
            intent['confidence'] = 0.82
            intent['reasons'].append("URL relates to cryptocurrency — common scam target")
            intent['risk_level'] = 'high'
        
        # Prize/lottery scams
        elif any(kw in url_lower for kw in ['prize', 'winner', 'won', 'reward', 'claim',
                                            'lottery', 'giveaway', 'gift-card', 'free-iphone']):
            intent['type'] = 'Fake Prize / Lottery Scam'
            intent['confidence'] = 0.80
            intent['reasons'].append("URL matches fake prize/reward scam patterns")
            intent['risk_level'] = 'high'
        
        # Credential collection
        elif any(kw in path for kw in ['login', 'verify', 'signin', 'secure', 'account']):
            intent['type'] = 'Phishing — Credential Collection'
            intent['confidence'] = 0.75
            intent['reasons'].append("URL path suggests credential collection")
            intent['risk_level'] = 'high'
        
        # Piracy/malware
        elif any(kw in url_lower for kw in ['torrent', 'pirate', 'warez', 'nulled',
                                            'free-movies', 'putlocker', '123movie']):
            intent['type'] = 'Piracy / Malware Distribution'
            intent['confidence'] = 0.82
            intent['reasons'].append("URL matches piracy/malware distribution patterns")
            intent['risk_level'] = 'high'
        
        # Adult content
        elif any(kw in url_lower for kw in ['xxx', 'porn', 'adult', 'nude']):
            intent['type'] = 'Adult / Malicious Content'
            intent['confidence'] = 0.75
            intent['reasons'].append("URL matches adult content patterns (common malware vector)")
            intent['risk_level'] = 'high'
        
        # Suspicious download
        elif any(kw in url_lower for kw in ['free-download', 'crack', 'keygen', 'free-software']):
            intent['type'] = 'Suspicious Download'
            intent['confidence'] = 0.78
            intent['reasons'].append("URL offers free downloads (common malware vector)")
            intent['risk_level'] = 'high'
        
        # URL Shorteners (hide destination — always suspicious)
        elif any(hostname == s or hostname.endswith('.' + s) for s in URL_SHORTENERS):
            intent['type'] = 'URL Shortener — Hidden Destination'
            intent['confidence'] = 0.72
            intent['reasons'].append("URL shortener hides the real destination")
            intent['risk_level'] = 'medium'
        
        # Generic free stuff
        elif any(kw in url_lower for kw in ['free', 'win', 'gift']):
            intent['type'] = 'Suspicious Content'
            intent['confidence'] = 0.65
            intent['reasons'].append("URL contains suspicious keywords")
            intent['risk_level'] = 'medium'
    
    return intent


# ============================================
# Full Analysis
# ============================================

def analyze_url(url, page_signals=None):
    """Complete analysis: domain + intent + risk"""
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ''
    
    domain_analysis = analyze_domain(hostname)
    intent = classify_intent(url, page_signals)
    
    total_risk = domain_analysis['score']
    
    if intent['risk_level'] == 'critical':
        total_risk += 6
    elif intent['risk_level'] == 'high':
        total_risk += 4
    elif intent['risk_level'] == 'medium':
        total_risk += 2
    
    if total_risk >= 6:
        verdict = 'malicious'
    elif total_risk >= 3:
        verdict = 'suspicious'
    else:
        verdict = 'benign'
    
    return {
        'url': url,
        'verdict': verdict,
        'risk_score': total_risk,
        'domain_analysis': domain_analysis,
        'intent': intent,
        'explanation': {
            'what_it_does': intent['type'],
            'why_suspicious': domain_analysis['flags'] + intent['reasons'],
            'risk_level': intent['risk_level'],
        }
    }


# ============================================
# Test
# ============================================

if __name__ == '__main__':
    test_urls = [
        ("https://www.google.com", {}),
        ("http://paypal-secure-verify.com/login", {'has_password_field': True, 'has_login_form': True}),
        ("https://apple-id-verify.xyz", {'has_password_field': True}),
        ("http://free-bitcoin-generator.tk", {}),
        ("https://crypto-airdrop.gq", {'has_crypto_wallet_prompt': True}),
        ("https://metamask-wallet-connect.xyz", {'has_crypto_wallet_prompt': True}),
        ("https://bit.ly/xyz", {}),
        ("https://123moviesapp.net", {}),
        ("http://free-movies-hd.xyz", {}),
    ]
    
    print("\n" + "="*80)
    print("🧠 INTENT ANALYSIS TEST")
    print("="*80 + "\n")
    
    for url, signals in test_urls:
        result = analyze_url(url, signals)
        emoji = "🚨" if result['verdict'] == 'malicious' else "⚠️" if result['verdict'] == 'suspicious' else "✅"
        print(f"{emoji} {url}")
        print(f"   Verdict: {result['verdict'].upper()} (risk score: {result['risk_score']})")
        print(f"   Intent: {result['intent']['type']}")
        if result['explanation']['why_suspicious']:
            for reason in result['explanation']['why_suspicious']:
                print(f"   • {reason}")
        print()