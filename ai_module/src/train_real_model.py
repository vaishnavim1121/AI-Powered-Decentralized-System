<<<<<<< HEAD
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
import urllib.parse
import re
from collections import Counter
import os

# ---------- Feature Extraction (17 features) ----------
def extract_url_features(url):
    """Extract ALL 17 features from a URL"""
    features = {}
    
    # 1. URL length
    features['url_length'] = len(url)
    
    # 2. Number of digits
    features['digit_count'] = sum(c.isdigit() for c in url)
    
    # 3. Number of special characters
    features['special_count'] = sum(not c.isalnum() for c in url)
    
    # 4. Number of subdomains
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        features['subdomain_count'] = domain.count('.')
    except:
        features['subdomain_count'] = 0
    
    # 5. Has HTTPS
    features['has_https'] = 1 if url.startswith('https') else 0
    
    # 6. Suspicious keywords
    suspicious = ['login', 'verify', 'update', 'bank', 'secure', 'account', 
                  'confirm', 'signin', 'paypal', 'amazon', 'chase', 'wellsfargo',
                  'bankofamerica', 'appleid', 'microsoft', 'netflix', 'spotify']
    features['suspicious_keywords'] = sum(1 for word in suspicious if word in url.lower())
    
    # 7. Entropy
    if url:
        freq = Counter(url)
        entropy = 0
        for c in freq.values():
            p = c / len(url)
            entropy -= p * np.log2(p) if p > 0 else 0
        features['entropy'] = entropy
    else:
        features['entropy'] = 0
    
    # 8. Has IP address
    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    
    # 9. URL shorteners
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd', 'buff.ly', 'short.link']
    features['is_shortened'] = 1 if any(s in url for s in shorteners) else 0
    
    # 10. Number of slashes
    features['slash_count'] = url.count('/')
    
    # 11. Has @ symbol
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # 12. Has hyphen
    features['has_hyphen'] = 1 if '-' in url else 0
    
    # 13. Count of equals signs
    features['equals_count'] = url.count('=')
    
    # 14. Count of ampersands
    features['ampersand_count'] = url.count('&')
    
    # 15. Is from trusted media domain
    media_domains = ['youtube.com', 'youtu.be', 'vimeo.com', 'dailymotion.com', 
                     'twitch.tv', 'spotify.com', 'netflix.com', 'hulu.com']
    features['is_media'] = 1 if any(d in url for d in media_domains) else 0
    
    # 16. Is from trusted tech domain
    tech_domains = ['github.com', 'stackoverflow.com', 'python.org', 'pypi.org',
                    'npmjs.com', 'react.dev', 'vitejs.dev', 'docs.python.org']
    features['is_tech'] = 1 if any(d in url for d in tech_domains) else 0
    
    # 17. Is a search URL
    search_indicators = ['search?', 'query=', 'q=', '&q=', '?q=', 'search?q=']
    features['is_search'] = 1 if any(i in url for i in search_indicators) else 0
    
    return features

# ---------- Create Dataset ----------
def create_dataset():
    print("📊 Creating dataset with real URLs...")
    
    # LEGITIMATE URLs
    legitimate_urls = [
        # YouTube
        "https://www.youtube.com/watch?v=jmpUP1MaQ9Q",
        "https://www.youtube.com/watch?v=jmpUP1MaQ9Q&list=RD8_KBlCKK-0k&index=21",
        "https://www.youtube.com/playlist?list=RD8_KBlCKK-0k",
        "https://www.youtube.com/results?search_query=machine+learning",
        "https://youtu.be/jmpUP1MaQ9Q",
        
        # Google
        "https://www.google.com",
        "https://www.google.com/search?q=cybersecurity",
        "https://www.google.com/search?q=phishing+detection",
        "https://docs.google.com/document/d/abc123/edit",
        "https://drive.google.com/file/d/xyz456/view",
        
        # Social Media
        "https://twitter.com/search?q=cybersecurity",
        "https://www.instagram.com/p/ABC123XYZ/",
        "https://www.facebook.com/groups/cybersecurity/",
        "https://www.linkedin.com/in/johndoe/",
        "https://www.reddit.com/r/cybersecurity/comments/abc123/",
        "https://www.tiktok.com/search?q=phishing",
        
        # Tech
        "https://github.com",
        "https://github.com/search?q=neural+network",
        "https://stackoverflow.com/questions/1234567/python",
        "https://stackoverflow.com/search?q=flask+api",
        "https://www.python.org/downloads/",
        "https://docs.python.org/3/library/urllib.html",
        "https://pypi.org/project/requests/",
        "https://react.dev/learn/start-a-new-react-project",
        
        # Shopping
        "https://www.amazon.com",
        "https://www.amazon.com/s?k=cybersecurity+books",
        "https://www.amazon.com/dp/B08N5WRWNW/",
        "https://www.ebay.com/itm/1234567890",
        "https://www.walmart.com/ip/1234567890",
        
        # News
        "https://www.bbc.com/news/technology-12345678",
        "https://www.cnn.com/2024/cybersecurity/index.html",
        "https://www.nytimes.com/2024/ai-security.html",
        "https://www.wsj.com/articles/cyber-attack-12345678",
        
        # Education
        "https://www.coursera.org/learn/cybersecurity",
        "https://www.edx.org/course/artificial-intelligence",
        "https://www.udemy.com/course/ethical-hacking/",
        "https://www.khanacademy.org/computing/computer-science",
        
        # Wikipedia
        "https://www.wikipedia.org/wiki/Cybersecurity",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://en.wikipedia.org/wiki/Phishing",
        
        # Entertainment
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.spotify.com/playlist/37i9dQZF1DX4sW",
        "https://open.spotify.com/track/1234567890",
        "https://www.twitch.tv/security_expert",
        
        # Finance
        "https://www.paypal.com",
        "https://www.chase.com",
        "https://www.wellsfargo.com",
        "https://www.bankofamerica.com",
        
        # Government
        "https://www.whitehouse.gov",
        "https://www.state.gov",
        "https://www.usps.com",
        
        # Hosting/CDN
        "https://www.cloudflare.com",
        "https://www.mongodb.com",
        "https://www.mysql.com",
        "https://www.postgresql.org",
    ]
    
    # PHISHING URLs
    phishing_urls = [
=======
def create_dataset():
    print("📊 Creating dataset with real URLs...")
    
    # ============================================
    # LEGITIMATE URLs (safe)
    # ============================================
    legitimate_urls = [
        # ... keep your existing legitimate URLs ...
        "https://www.youtube.com/watch?v=jmpUP1MaQ9Q",
        "https://www.google.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://www.wikipedia.org",
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.linkedin.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.cloudflare.com",
        "https://www.python.org",
        "https://react.dev",
        "https://www.bbc.com",
        "https://www.cnn.com",
        "https://www.nytimes.com",
        "https://www.coursera.org",
        "https://www.khanacademy.org",
        "https://www.paypal.com",
        "https://www.chase.com",
        "https://www.wellsfargo.com",
        "https://www.whitehouse.gov",
        "https://www.usps.com",
        # Add legitimate sites from varied categories
        "https://www.reddit.com/r/cybersecurity",
        "https://www.pinterest.com",
        "https://www.walmart.com",
        "https://www.target.com",
        "https://www.ebay.com",
        "https://www.etsy.com",
        "https://www.airbnb.com",
        "https://www.uber.com",
        "https://www.doordash.com",
        "https://www.zoom.us",
        "https://www.dropbox.com",
        "https://www.slack.com",
        "https://www.notion.so",
        "https://www.figma.com",
        "https://www.medium.com",
        "https://www.quora.com",
    ]
    
    # ============================================
    # REAL-WORLD MALICIOUS URLs (expanded)
    # ============================================
    phishing_urls = [
        # Classic phishing
>>>>>>> bc64e94 (Add VirusTotal integration, fix categorization, upgrade popup UI)
        "http://paypa1-secure-verify.com/login",
        "https://amazon-account-verify.xyz",
        "http://bankofamerica-verify.net",
        "https://secure-update-login.ru",
        "http://google-account-verify.com",
        "https://paypal-security-check.com",
        "http://apple-id-verify.xyz",
        "https://microsoft-update-login.net",
        "http://chase-bank-verify.com",
        "https://wells-fargo-login.xyz",
<<<<<<< HEAD
        "http://bank-login-verify.com",
        "https://amazon-prime-update.net",
        "http://netflix-account-verify.com",
        "https://spotify-premium-update.xyz",
        "http://facebook-security-check.com",
        "https://instagram-verify-account.net",
        "http://twitter-account-update.com",
        "https://linkedin-verify.xyz",
        "http://dropbox-update-login.com",
        "https://google-drive-verify.net",
        "http://paypal-login-secure.xyz",
        "https://amazon-account-update.com",
        "http://bank-login-verify.net",
        "https://apple-id-security-check.xyz",
        "http://microsoft-update-now.com",
        "https://chase-verify-account.net",
        "http://wellsfargo-login.xyz",
        "https://netflix-verify.com",
        "http://spotify-update.xyz",
        "https://facebook-login.net",
        "http://instagram-verify.com",
        "https://twitter-login.xyz",
        "http://linkedin-update.com",
        "https://dropbox-login.net",
        "http://google-account-update.xyz",
        "https://paypal-verify.com",
        "http://amazon-security-check.net",
        "https://bankofamerica-login.xyz",
        "http://apple-id-update.com",
        "https://microsoft-verify.net",
        "http://secure-account-verify.ml/login",
        "https://amazon-security-check.gq",
=======
        
        # Free-host phishing (common real pattern)
        "http://login-verify.000webhostapp.com",
        "https://secure-update.weebly.com/login",
        "http://apple-verify.blogspot.com/p/login.html",
        "https://paypal-confirm.wixsite.com/secure",
        "http://banking-alert.godaddysites.com",
        
        # Suspicious TLDs used in real attacks
        "http://download-free-software.top",
        "https://prize-winner.tk",
        "http://win-iphone.ml",
        "https://claim-reward.ga",
        "http://free-gift-card.cf",
        "https://crypto-airdrop.gq",
        
        # Adult/malware distribution (common real threat)
        "http://free-video-xxx.xyz",
        "https://hot-girls-stream.tk",
        "http://adult-content-mega.ml",
        "https://xxx-video-free.ga",
        "http://porn-mega-free.top",
        
        # Piracy/malware sites
        "http://free-movies-hd.xyz",
        "https://torrent-download.tk",
        "http://cracked-software.ml",
        "https://watch-free-movies.ga",
        "http://download-cracked.cf",
        "https://full-version-free.top",
        "http://crack-games.gq",
        
        # Fake streaming sites (very common malware source)
        "http://watch-netflix-free.xyz",
        "https://free-streaming-hd.tk",
        "http://watch-movies-online.ml",
        "https://putlocker-free.ga",
        "http://123movies-hd.cf",
        "https://watch-series-free.top",
        
        # Crypto scams
        "http://free-bitcoin-generator.xyz",
        "https://crypto-giveaway.tk",
        "http://eth-airdrop.ml",
        "https://claim-free-btc.ga",
        "http://btc-doubler.cf",
        "https://free-crypto-now.top",
        
        # Fake lottery/prize
        "http://you-won-iphone.xyz",
        "https://claim-your-prize.tk",
        "http://winner-lottery.ml",
        "https://free-iphone-15.ga",
        "http://amazon-gift-card.cf",
        "https://free-amazon-voucher.top",
        
        # Fake bank/e-commerce login
        "http://secure-bank-login.xyz",
        "https://account-verify-bank.tk",
        "http://update-payment-info.ml",
        "https://confirm-transaction.ga",
        "http://verify-account-now.cf",
        "https://login-secure-banking.top",
        
        # Malware hosting patterns
        "http://download-installer.exe.xyz",
        "https://update-flash-player.tk",
        "http://install-codec.ml",
        "https://adobe-update-now.ga",
        "http://java-update-required.cf",
        "https://chrome-update-free.top",
        
        # Common suspicious paths
        "http://1.2.3.4/login.php",
        "https://192.168.1.1/admin",
        "http://attacker-site.com/malware.exe",
        "https://evil-server.xyz/payload",
        "http://bad-actor.tk/steal",
        
        # URL shorteners to bad sites
        "http://bit.ly/free-prize-scam",
        "https://tinyurl.com/verify-account",
        "http://ow.ly/claim-reward",
        "https://is.gd/free-download",
        
        # Typosquatting
        "http://gooogle.com",
        "https://arnazon.com",
        "http://paypa1.com",
        "https://faceb00k.com",
        "http://micros0ft.com",
        "https://apple-id.com.fake.tk",
        "http://g00gle-drive.xyz",
        
        # Suspicious subdomain chains
        "http://secure.login.verify.account.bank.xyz",
        "https://www.paypal.com.verify-now.tk",
        "http://amazon.com.order-status.ml",
        "https://apple.com.id-verify.ga",
        "http://google.com.account-alert.cf",
        
        # More real-world phishing
>>>>>>> bc64e94 (Add VirusTotal integration, fix categorization, upgrade popup UI)
        "http://paypal-verify-account.tk",
        "https://apple-id-confirm.ga",
        "http://microsoft-update-now.cf",
        "https://chase-bank-verify.ml",
        "http://wellsfargo-login.gq",
        "https://netflix-account-update.tk",
        "http://spotify-premium-verify.ga",
        "https://facebook-security-alert.cf",
        "http://instagram-verify.ml",
        "https://twitter-account-confirm.gq",
<<<<<<< HEAD
        "http://linkedin-login-verify.tk",
        "https://dropbox-security-check.ga",
        "http://google-drive-update.cf",
        "https://paypal-confirm-account.ml",
        "http://amazon-order-verify.gq",
        "https://bank-of-america-login.tk",
        "http://apple-id-security.ga",
        "https://microsoft-account-verify.cf",
=======
>>>>>>> bc64e94 (Add VirusTotal integration, fix categorization, upgrade popup UI)
    ]
    
    data = []
    
    print(f"  → Processing {len(legitimate_urls)} legitimate URLs...")
    for url in legitimate_urls:
        features = extract_url_features(url)
        features['label'] = 0
        data.append(features)
    
<<<<<<< HEAD
    print(f"  → Processing {len(phishing_urls)} phishing URLs...")
=======
    print(f"  → Processing {len(phishing_urls)} malicious URLs...")
>>>>>>> bc64e94 (Add VirusTotal integration, fix categorization, upgrade popup UI)
    for url in phishing_urls:
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
    
<<<<<<< HEAD
    return pd.DataFrame(data)

# ---------- Train ----------
def train_model():
    print("\n" + "="*50)
    print("🎯 TRAINING REAL URL PHISHING DETECTION MODEL")
    print("="*50 + "\n")
    
    df = create_dataset()
    
    os.makedirs('data', exist_ok=True)
    df.to_csv('data/real_url_dataset.csv', index=False)
    print(f"📁 Dataset saved to data/real_url_dataset.csv ({len(df)} samples)")
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    print(f"\n📊 Dataset stats:")
    print(f"  → Total samples: {len(df)}")
    print(f"  → Legitimate: {sum(y == 0)}")
    print(f"  → Phishing: {sum(y == 1)}")
    print(f"  → Features: {len(X.columns)}")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("\n🧠 Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_split=5,
        random_state=42
    )
    model.fit(X_train_scaled, y_train)
    
    train_score = model.score(X_train_scaled, y_train)
    test_score = model.score(X_test_scaled, y_test)
    
    print(f"\n✅ Training accuracy: {train_score:.4f}")
    print(f"✅ Test accuracy: {test_score:.4f}")
    
    feature_names = X.columns.tolist()
    importance = model.feature_importances_
    print("\n📈 Feature importance:")
    for name, imp in sorted(zip(feature_names, importance), key=lambda x: x[1], reverse=True):
        print(f"  → {name}: {imp:.4f}")
    
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/random_forest_real.joblib')
    joblib.dump(scaler, 'models/scaler.joblib')
    
    print("\n💾 Model saved to models/random_forest_real.joblib")
    print("💾 Scaler saved to models/scaler.joblib")
    
    # Test
    print("\n🧪 Testing on YouTube URLs:")
    from predict import predict
    test_urls = [
        "https://www.youtube.com/watch?v=jmpUP1MaQ9Q&list=RD8_KBlCKK-0k&index=21",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.google.com/search?q=cybersecurity",
        "http://paypa1-secure-verify.com/login",
    ]
    for url in test_urls:
        result = predict(url)
        print(f"  → {url[:50]}... => {result['prediction']} ({result['confidence']:.4f})")
    
    return model, scaler

if __name__ == '__main__':
    train_model()
=======
    return pd.DataFrame(data)
>>>>>>> bc64e94 (Add VirusTotal integration, fix categorization, upgrade popup UI)
