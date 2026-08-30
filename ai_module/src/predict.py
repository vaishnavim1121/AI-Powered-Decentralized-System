import joblib
import numpy as np
import urllib.parse
import re
from collections import Counter
import os

# ---------- Feature Extraction (must match training) ----------
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

# ---------- Load Model ----------
def load_model():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(base_dir, 'models', 'random_forest_real.joblib')
    scaler_path = os.path.join(base_dir, 'models', 'scaler.joblib')
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}. Please run train_real_model.py first.")
    
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    return model, scaler

# Load once
model, scaler = load_model()

def predict(input_data):
    """
    Predict if a URL is malicious or benign
    
    Args:
        input_data: Can be either:
            - A URL string
            - A list of features
        
    Returns:
        dict: {prediction, confidence, explanation}
    """
    # Check if input is a URL
    if isinstance(input_data, str) and (input_data.startswith('http') or input_data.startswith('www') or input_data.startswith('youtu')):
        # It's a URL - extract features
        features_dict = extract_url_features(input_data)
        features_list = list(features_dict.values())
    elif isinstance(input_data, list):
        features_list = input_data
    else:
        features_dict = extract_url_features(str(input_data))
        features_list = list(features_dict.values())
    
    # Ensure we have exactly 17 features
    if len(features_list) != 17:
        # Pad with zeros if too short
        while len(features_list) < 17:
            features_list.append(0)
        # Truncate if too long
        features_list = features_list[:17]
    
    # Ensure all values are numbers
    features_list = [float(x) if not isinstance(x, (int, float)) else x for x in features_list]
    features_array = np.array(features_list).reshape(1, -1)
    
    # Scale
    features_scaled = scaler.transform(features_array)
    
    # Predict
    pred_class = model.predict(features_scaled)[0]
    proba = model.predict_proba(features_scaled)[0]
    confidence = float(proba[pred_class])
    
    # Explanation
    feature_names = ['URL Length', 'Digit Count', 'Special Chars', 'Subdomains', 
                     'Has HTTPS', 'Suspicious Keywords', 'Entropy', 'Has IP', 
                     'Is Shortened', 'Slash Count', 'Has @', 'Has -', 
                     'Equals Count', 'Ampersand Count', 'Is Media', 'Is Tech', 'Is Search']
    
    explanation = {}
    for i, name in enumerate(feature_names):
        if i < len(features_list):
            value = features_list[i]
            if name in ['Has HTTPS', 'Has IP', 'Is Shortened', 'Has @', 'Has -', 'Is Media', 'Is Tech', 'Is Search']:
                explanation[name] = "Yes" if value == 1 else "No"
            else:
                explanation[name] = round(value, 2)
    
    return {
        "prediction": "malicious" if pred_class == 1 else "benign",
        "confidence": confidence,
        "explanation": explanation
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
        risk_factors.append("Contains @ symbol (often used in phishing)")
    if result['explanation'].get('Entropy', 0) > 3:
        risk_factors.append("High randomness (unusual URL pattern)")
    if result['explanation'].get('Has HTTPS', "Yes") == "No":
        risk_factors.append("No HTTPS (insecure connection)")
    
    result['risk_factors'] = risk_factors
    result['is_risky'] = len(risk_factors) > 0
    
    return result

if __name__ == '__main__':
    test_urls = [
        "https://www.youtube.com/watch?v=jmpUP1MaQ9Q&list=RD8_KBlCKK-0k&index=21",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.google.com/search?q=cybersecurity",
        "https://github.com/search?q=neural+network",
        "http://paypa1-secure-verify.com/login",
        "https://amazon-account-verify.xyz",
    ]
    
    print("\n" + "="*50)
    print("🧪 TESTING URL PREDICTIONS")
    print("="*50 + "\n")
    
    for url in test_urls:
        result = predict(url)
        print(f"URL: {url[:60]}...")
        print(f"  → Prediction: {result['prediction']} (confidence: {result['confidence']:.4f})")
        print()