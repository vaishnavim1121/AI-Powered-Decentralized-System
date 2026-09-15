import joblib
import numpy as np
import urllib.parse
import re
from collections import Counter
import os


def detect_threat_category(url):
    """Detect the category of threat based on URL patterns"""
    url_lower = url.lower()
    
    categories = {
        'Phishing': ['login', 'verify', 'update', 'secure', 'account', 'confirm', 'signin', 'password'],
        'Malware Distribution': ['.exe', 'download-installer', 'update-flash', 'codec', 'crack'],
        'Adult/Malicious Content': ['xxx', 'porn', 'adult', 'sex', 'hot-girls', 'nude'],
        'Piracy/Malware': ['free-movies', 'torrent', 'crack', 'putlocker', '123movies', 'watch-free', 'watch-free-movies'],
        'Crypto Scam': ['bitcoin', 'btc', 'eth', 'crypto', 'airdrop', 'doubler', 'giveaway', 'crypto-giveaway'],
        'Fake Prize/Lottery': ['prize', 'winner', 'won', 'gift-card', 'reward', 'voucher', 'lottery', 'free-iphone', 'free-amazon'],
        'Suspicious Domain': ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.work', '.click', '.link'],
        'IP Address': [r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'],
        'Typosquatting': ['gooogle', 'arnazon', 'paypa1', 'faceb00k', 'micros0ft', 'g00gle'],
        'Free Hosting': ['000webhostapp', 'weebly', 'wixsite', 'godaddysites', 'blogspot'],
    }
    
    matches = []
    for category, patterns in categories.items():
        for pattern in patterns:
            if pattern.startswith('^'):
                if re.search(pattern, url_lower):
                    matches.append(category)
                    break
            elif pattern in url_lower:
                matches.append(category)
                break
    
    return matches[0] if matches else None


def is_known_malicious_pattern(url):
    """Rule-based check for clearly malicious patterns"""
    url_lower = url.lower()
    
    malicious_indicators = [
        'free-movies', 'free-video-xxx', 'cracked-software', 'torrent-download',
        'watch-free', 'putlocker', '123movies', 'download-cracked',
        'free-bitcoin', 'crypto-airdrop', 'btc-doubler',
        'you-won', 'claim-your-prize', 'winner-lottery',
        'hot-girls-stream', 'xxx-video-free', 'porn-mega',
        'paypa1', 'gooogle', 'arnazon', 'faceb00k', 'g00gle',
    ]
    
    for indicator in malicious_indicators:
        if indicator in url_lower:
            return True
    
    if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
        if any(kw in url_lower for kw in ['login', 'admin', 'payload', 'malware', 'steal']):
            return True
    
    return False


def is_real_world_suspicious(url):
    """Detect patterns commonly seen in real malicious URLs"""
    url_lower = url.lower()
    
    try:
        parsed = urllib.parse.urlparse(url_lower)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
    except:
        return False
    
    suspicious_score = 0
    
    # 1. Suspicious keywords in path
    high_risk_paths = ['login', 'verify', 'secure', 'update', 'confirm', 
                       'signin', 'account', 'banking', 'wallet', 'password']
    if any(kw in path for kw in high_risk_paths):
        suspicious_score += 2
    
    # 2. Suspicious TLDs
    bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    if any(hostname.endswith(tld) for tld in bad_tlds):
        suspicious_score += 2
    
    # 3. IP address as host
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        suspicious_score += 3
    
    # 4. Typosquatting (brand + suspicious suffix)
    impersonated = ['google', 'facebook', 'paypal', 'amazon', 'apple',
                    'microsoft', 'netflix', 'instagram', 'whatsapp', 'twitter']
    for brand in impersonated:
        if brand in hostname:
            for suffix in ['-secure', '-verify', '-update', '-login', '-account', '-support', '-help']:
                if suffix in hostname:
                    suspicious_score += 3
                    break
    
    # 5. Multiple subdomains
    if hostname.count('.') >= 4:
        suspicious_score += 2
    
    # 6. Suspicious free hosting
    bad_hosting = ['000webhostapp', 'weebly', 'wixsite', 'godaddysites',
                   'blogspot', 'herokuapp', 'web.app', 'ngrok']
    if any(h in hostname for h in bad_hosting):
        suspicious_score += 1
    
    # 7. @ symbol in URL
    if '@' in url:
        suspicious_score += 3
    
    # 8. Excessive hyphens in hostname
    if hostname.count('-') >= 3:
        suspicious_score += 1
    
    # 9. Long hostname
    if len(hostname) > 30:
        suspicious_score += 1
    
    # 10. Suspicious query params
    bad_params = ['redirect=', 'url=', 'next=', 'return=']
    if any(p in query for p in bad_params):
        suspicious_score += 1
    
    # 11. URL Shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
                  'is.gd', 'buff.ly', 'short.link', 'cutt.ly', 'rb.gy',
                  'rebrand.ly', 'bl.ink', 'shorturl.at', 'tiny.cc']
    if any(hostname == s or hostname.endswith('.' + s) for s in shorteners):
        suspicious_score += 4
    
    return suspicious_score >= 4


def extract_url_features(url):
    """Extract features from a URL (must match training)"""
    features = {}
    
    features['url_length'] = len(url)
    features['digit_count'] = sum(c.isdigit() for c in url)
    features['special_count'] = sum(not c.isalnum() for c in url)
    
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        features['subdomain_count'] = domain.count('.')
    except:
        features['subdomain_count'] = 0
    
    features['has_https'] = 1 if url.startswith('https') else 0
    
    suspicious = ['login', 'verify', 'update', 'bank', 'secure', 'account', 
                  'confirm', 'signin', 'paypal', 'amazon', 'chase', 'wellsfargo',
                  'bankofamerica', 'appleid', 'microsoft', 'netflix', 'spotify']
    features['suspicious_keywords'] = sum(1 for word in suspicious if word in url.lower())
    
    if url:
        freq = Counter(url)
        entropy = 0
        for c in freq.values():
            p = c / len(url)
            entropy -= p * np.log2(p) if p > 0 else 0
        features['entropy'] = entropy
    else:
        features['entropy'] = 0
    
    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd', 'buff.ly', 'short.link']
    features['is_shortened'] = 1 if any(s in url for s in shorteners) else 0
    
    features['slash_count'] = url.count('/')
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_hyphen'] = 1 if '-' in url else 0
    features['equals_count'] = url.count('=')
    features['ampersand_count'] = url.count('&')
    
    media_domains = ['youtube.com', 'youtu.be', 'vimeo.com', 'dailymotion.com', 
                     'twitch.tv', 'spotify.com', 'netflix.com', 'hulu.com']
    features['is_media'] = 1 if any(d in url for d in media_domains) else 0
    
    tech_domains = ['github.com', 'stackoverflow.com', 'python.org', 'pypi.org',
                    'npmjs.com', 'react.dev', 'vitejs.dev', 'docs.python.org']
    features['is_tech'] = 1 if any(d in url for d in tech_domains) else 0
    
    search_indicators = ['search?', 'query=', 'q=', '&q=', '?q=', 'search?q=']
    features['is_search'] = 1 if any(i in url for i in search_indicators) else 0
    
    return features


def load_model():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(base_dir, 'models', 'random_forest_real.joblib')
    scaler_path = os.path.join(base_dir, 'models', 'scaler.joblib')
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}. Please run train_real_model.py first.")
    
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    return model, scaler


model, scaler = load_model()


def predict(input_data):
    """
    Predict if a URL is malicious or benign.
    
    Uses a hybrid approach:
    1. Rule-based detection for known malicious patterns
    2. Real-world suspicious pattern detection
    3. AI model as final layer
    """
    is_url = isinstance(input_data, str) and (
        input_data.startswith('http') or 
        input_data.startswith('www') or 
        input_data.startswith('youtu')
    )
    
    feature_names = ['URL Length', 'Digit Count', 'Special Chars', 'Subdomains', 
                     'Has HTTPS', 'Suspicious Keywords', 'Entropy', 'Has IP', 
                     'Is Shortened', 'Slash Count', 'Has @', 'Has -', 
                     'Equals Count', 'Ampersand Count', 'Is Media', 'Is Tech', 'Is Search']
    
    # LAYER 1: Known malicious pattern
    if is_url and is_known_malicious_pattern(input_data):
        features = extract_url_features(input_data)
        explanation = {}
        for i, name in enumerate(feature_names):
            v = list(features.values())[i] if i < len(features) else 0
            if name in ['Has HTTPS', 'Has IP', 'Is Shortened', 'Has @', 'Has -', 'Is Media', 'Is Tech', 'Is Search']:
                explanation[name] = "Yes" if v == 1 else "No"
            else:
                explanation[name] = round(v, 2)
        
        return {
            "prediction": "malicious",
            "confidence": 0.98,
            "threat_type": detect_threat_category(input_data) or "Known Threat Pattern",
            "explanation": explanation,
            "detection_method": "rule-based"
        }
    
    # LAYER 2: Real-world suspicious patterns
    if is_url and is_real_world_suspicious(input_data):
        features = extract_url_features(input_data)
        explanation = {}
        for i, name in enumerate(feature_names):
            v = list(features.values())[i] if i < len(features) else 0
            if name in ['Has HTTPS', 'Has IP', 'Is Shortened', 'Has @', 'Has -', 'Is Media', 'Is Tech', 'Is Search']:
                explanation[name] = "Yes" if v == 1 else "No"
            else:
                explanation[name] = round(v, 2)
        
        return {
            "prediction": "malicious",
            "confidence": 0.82,
            "threat_type": detect_threat_category(input_data) or "Suspicious URL Pattern",
            "explanation": explanation,
            "detection_method": "pattern-match"
        }
    
    # LAYER 3: AI Model Prediction
    if is_url:
        features_dict = extract_url_features(input_data)
        features_list = list(features_dict.values())
    elif isinstance(input_data, list):
        features_list = input_data
    else:
        features_dict = extract_url_features(str(input_data))
        features_list = list(features_dict.values())
    
    # Ensure exactly 17 features
    if len(features_list) != 17:
        while len(features_list) < 17:
            features_list.append(0)
        features_list = features_list[:17]
    
    features_list = [float(x) if not isinstance(x, (int, float)) else x for x in features_list]
    features_array = np.array(features_list).reshape(1, -1)
    
    features_scaled = scaler.transform(features_array)
    
    pred_class = model.predict(features_scaled)[0]
    proba = model.predict_proba(features_scaled)[0]
    confidence = float(proba[pred_class])
    
    explanation = {}
    for i, name in enumerate(feature_names):
        if i < len(features_list):
            value = features_list[i]
            if name in ['Has HTTPS', 'Has IP', 'Is Shortened', 'Has @', 'Has -', 'Is Media', 'Is Tech', 'Is Search']:
                explanation[name] = "Yes" if value == 1 else "No"
            else:
                explanation[name] = round(value, 2)
    
    threat_type = None
    if is_url and pred_class == 1:
        threat_type = detect_threat_category(input_data) or "Suspicious Content"
    
    return {
        "prediction": "malicious" if pred_class == 1 else "benign",
        "confidence": confidence,
        "threat_type": threat_type,
        "explanation": explanation,
        "detection_method": "ai-model"
    }


def predict_with_details(input_data):
    """Detailed prediction with risk factors"""
    result = predict(input_data)
    
    risk_factors = []
    if result['explanation'].get('Suspicious Keywords', 0) > 0:
        risk_factors.append("Contains suspicious keywords")
    if result['explanation'].get('Has IP', "No") == "Yes":
        risk_factors.append("Uses IP address instead of domain")
    if result['explanation'].get('Is Shortened', "No") == "Yes":
        risk_factors.append("Uses URL shortener")
    if result['explanation'].get('Has @', "No") == "Yes":
        risk_factors.append("Contains @ symbol")
    if result['explanation'].get('Entropy', 0) > 3:
        risk_factors.append("High randomness")
    if result['explanation'].get('Has HTTPS', "Yes") == "No":
        risk_factors.append("No HTTPS")
    
    result['risk_factors'] = risk_factors
    result['is_risky'] = len(risk_factors) > 0
    
    return result


if __name__ == '__main__':
    test_urls = [
        "https://www.google.com",
        "https://www.youtube.com/watch?v=jmpUP1MaQ9Q",
        "https://github.com",
        "http://paypa1-secure-verify.com/login",
        "https://amazon-account-verify.xyz",
        "http://free-movies-hd.xyz",
        "https://123movies-hd.cf",
        "http://free-bitcoin-generator.xyz",
        "https://crypto-airdrop.gq",
        "http://you-won-iphone.xyz",
    ]
    
    print("\n" + "="*80)
    print("🧪 TESTING URL PREDICTIONS")
    print("="*80 + "\n")
    
    for url in test_urls:
        result = predict(url)
        emoji = "⚠️" if result['prediction'] == 'malicious' else "✅"
        threat_info = f" | {result.get('threat_type', '')}" if result.get('threat_type') else ""
        method = f" [{result.get('detection_method', 'ai')}]"
        print(f"{emoji} {url[:55]:<55} → {result['prediction']:>9} ({result['confidence']:.2%}){threat_info}{method}")