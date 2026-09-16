from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, Threat, Alert
from config import Config
from datetime import datetime
from time import time
import bcrypt
import os
import sys
import urllib.parse

# ── Add parent directory to path ──
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# ── Import sibling modules ──
from ai_module.src.predict import predict
from ai_module.src.intent_analyzer import analyze_url
from ai_module.src.virustotal import lookup_url as vt_lookup, is_available as vt_available
from blockchain.src.web3_interface import BlockchainInterface

app = Flask(__name__)
app.config.from_object(Config)

# ── CORS ──
CORS(app, resources={r"/*": {"origins": "*"}})

db.init_app(app)
jwt = JWTManager(app)

# ── PRE-LOAD AI MODEL ──
print("🔄 Pre-loading AI model...")
try:
    _ = predict('https://www.google.com')
    print("✅ AI model pre-loaded successfully")
except Exception as e:
    print(f"⚠️ Failed to pre-load AI model: {e}")

# ── VirusTotal status ──
print(f"🦠 VirusTotal API: {'✅ Available' if vt_available() else '⚠️ Not configured'}")

# ── Caches ──
THREAT_CACHE = {}
CACHE_TTL = 300

REQUEST_LOG = {}
RATE_LIMIT = 200
RATE_WINDOW = 60

def is_rate_limited(client_ip):
    now = time()
    if client_ip not in REQUEST_LOG:
        REQUEST_LOG[client_ip] = []
    REQUEST_LOG[client_ip] = [t for t in REQUEST_LOG[client_ip] if now - t < RATE_WINDOW]
    if len(REQUEST_LOG[client_ip]) >= RATE_LIMIT:
        return True
    REQUEST_LOG[client_ip].append(now)
    return False

# ── JWT error handlers ──
@jwt.unauthorized_loader
def unauthorized_callback(reason):
    return jsonify({"msg": "Missing or invalid token"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({"msg": "Invalid token"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_data):
    return jsonify({"msg": "Token expired"}), 401

with app.app_context():
    db.create_all()

# ── Helpers ──
def run_ai_prediction(features):
    return predict(features)

def store_on_blockchain(threat_hash):
    bi = BlockchainInterface()
    return bi.store_threat(threat_hash, severity=5)

# ═══════════════════════════════════════════
# CATEGORY DETECTION
# ═══════════════════════════════════════════

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'cutt.ly', 'rb.gy', 'rebrand.ly', 'shorturl.at',
    'tiny.cc', 'bit.do', 'short.link', 'shorte.st', 'adf.ly'
]

def categorize_threat(url):
    """If intent analysis says 'unknown', build a category from URL patterns"""
    url_lower = url.lower()
    
    try:
        parsed = urllib.parse.urlparse(url_lower)
        hostname = parsed.hostname or ''
    except:
        hostname = ''
    
    # URL Shorteners
    if any(hostname == s or hostname.endswith('.' + s) for s in URL_SHORTENERS):
        return {
            'type': 'URL Shortener — Hidden Destination',
            'risk': 'medium',
            'reason': 'URL shortener hides the real destination',
            'what_it_does': 'This shortened URL hides where it really leads — common in phishing and malware distribution'
        }
    
    # Crypto Scam
    if any(kw in url_lower for kw in ['bitcoin', 'btc', 'ethereum', 'eth', 'crypto',
                                       'airdrop', 'wallet', 'doubler', 'generator',
                                       'metamask', 'binance', 'coinbase']):
        return {
            'type': 'Crypto Scam',
            'risk': 'high',
            'reason': 'Domain relates to cryptocurrency — common scam target',
            'what_it_does': 'May attempt to steal crypto wallet credentials or funds'
        }
    
    # Piracy
    if any(kw in url_lower for kw in ['123movie', 'putlocker', 'watch-free', 'free-movies', 
                                       'torrent', 'pirate', 'piratebay', 'yts', 'rarbg',
                                       'movierulz', '5movie', 'tamilmv', 'filmyzilla',
                                       'filmywap', 'tamilrockers', '9xmovies']):
        return {
            'type': 'Piracy / Malware Distribution',
            'risk': 'high',
            'reason': 'Domain matches known piracy/malware distribution patterns',
            'what_it_does': 'Offers pirated content — common malware distribution vector'
        }
    
    # Fake Prize
    if any(kw in url_lower for kw in ['prize', 'winner', 'reward', 'claim-free', 'lottery', 'giveaway']):
        return {
            'type': 'Fake Prize / Lottery Scam',
            'risk': 'high',
            'reason': 'Domain matches fake prize/reward scam patterns',
            'what_it_does': 'Attempts to trick you into clicking fake prize offers'
        }
    
    # Adult
    if any(kw in url_lower for kw in ['adult', 'xxx', 'porn', 'nude']):
        return {
            'type': 'Adult / Malicious Content',
            'risk': 'high',
            'reason': 'Domain matches adult content patterns (common malware vector)',
            'what_it_does': 'May host malware disguised as adult content'
        }
    
    # Suspicious Download
    if any(kw in url_lower for kw in ['free-download', 'free-software', 'crack', 'keygen']):
        return {
            'type': 'Suspicious Download',
            'risk': 'high',
            'reason': 'Domain offers free software/cracks (common malware vector)',
            'what_it_does': 'May distribute malware disguised as free software'
        }
    
    # Phishing
    if any(kw in url_lower for kw in ['login', 'verify', 'secure', 'account', 'signin']):
        return {
            'type': 'Phishing — Credential Collection',
            'risk': 'high',
            'reason': 'URL suggests credential collection',
            'what_it_does': 'Attempts to steal your login credentials'
        }
    
    # Generic Suspicious
    if any(kw in url_lower for kw in ['free', 'win', 'gift']):
        return {
            'type': 'Suspicious Content',
            'risk': 'medium',
            'reason': 'URL contains suspicious keywords',
            'what_it_does': 'Contains characteristics commonly seen in scam sites'
        }
    
    return {
        'type': 'AI-Detected Threat',
        'risk': 'high',
        'reason': 'AI model identified malicious patterns in URL structure',
        'what_it_does': 'This URL exhibits characteristics of known malicious sites'
    }

# ═══════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════

@app.route('/')
def health():
    return jsonify({
        "status": "ADCTIN backend is running",
        "virustotal": vt_available()
    }), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 409

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user = User(username=username, password_hash=hashed.decode('utf-8'))
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User created"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or not bcrypt.checkpw(data.get('password').encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({"msg": "Invalid credentials"}), 401
    access_token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": access_token})

@app.route('/threat', methods=['POST'])
@jwt_required()
def submit_threat():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    if data is None:
        return jsonify({"msg": "Missing JSON body"}), 400

    features = data.get('features')
    url = data.get('url')
    file_hash = data.get('file_hash')
    
    ai_input = None
    if url:
        ai_input = url
    elif features and len(features) > 0:
        ai_input = features
    elif file_hash:
        ai_input = file_hash
    else:
        return jsonify({"msg": "Missing URL, features, or file hash"}), 400
    
    try:
        ai_result = run_ai_prediction(ai_input)
    except Exception as e:
        return jsonify({"msg": f"AI prediction failed: {str(e)}"}), 500

    threat_identifier = file_hash if file_hash else (url if url else "unknown")
    try:
        tx_hash = store_on_blockchain(threat_identifier)
    except Exception as e:
        return jsonify({"msg": f"Blockchain storage failed: {str(e)}"}), 500
    
    threat = Threat(
        user_id=user_id,
        file_hash=file_hash,
        url=url,
        prediction=ai_result['prediction'],
        confidence=ai_result['confidence'],
        explanation=ai_result['explanation'],
        blockchain_tx=tx_hash
    )
    db.session.add(threat)
    db.session.commit()
    
    alert = Alert(
        threat_id=threat.id,
        message=f"New {ai_result['prediction']} threat detected!"
    )
    db.session.add(alert)
    db.session.commit()
    
    return jsonify({
        "threat_id": threat.id,
        "prediction": ai_result['prediction'],
        "confidence": ai_result['confidence'],
        "tx_hash": tx_hash
    }), 201

@app.route('/threats', methods=['GET'])
@jwt_required()
def get_threats():
    threats = Threat.query.order_by(Threat.created_at.desc()).limit(20).all()
    return jsonify([{
        "id": t.id,
        "prediction": t.prediction,
        "confidence": t.confidence,
        "created_at": t.created_at.isoformat()
    } for t in threats])

# ── Fetch single threat detail ──
@app.route('/threats/<int:threat_id>', methods=['GET'])
@jwt_required()
def get_threat_detail(threat_id):
    threat = Threat.query.get(threat_id)
    if not threat:
        return jsonify({"msg": "Threat not found"}), 404
    return jsonify({
        "id": threat.id,
        "prediction": threat.prediction,
        "confidence": threat.confidence,
        "explanation": threat.explanation,
        "file_hash": threat.file_hash,
        "url": threat.url,
        "blockchain_tx": threat.blockchain_tx,
        "created_at": threat.created_at.isoformat()
    })

@app.route('/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    alerts = Alert.query.filter_by(is_read=False).order_by(Alert.created_at.desc()).all()
    return jsonify([{
        "id": a.id,
        "message": a.message,
        "created_at": a.created_at.isoformat()
    } for a in alerts])

# ═══════════════════════════════════════════
# THREAT CHECK (AI + Intent + VirusTotal)
# ═══════════════════════════════════════════

@app.route('/threat/check', methods=['POST', 'OPTIONS'])
def threat_check():
    """Full threat analysis: AI + intent + domain intelligence + VirusTotal"""
    if request.method == 'OPTIONS':
        return '', 204
    
    client_ip = request.remote_addr or 'unknown'
    if is_rate_limited(client_ip):
        return jsonify({
            "msg": "Rate limit exceeded",
            "prediction": "unknown",
            "malicious": False,
            "rate_limited": True
        }), 429
    
    data = request.get_json()
    if not data:
        return jsonify({"msg": "Missing JSON body"}), 400
    
    url = data.get('url')
    signals = data.get('signals', {}) or {}
    
    if not url:
        return jsonify({"msg": "Missing URL"}), 400
    
    now = time()
    cache_key = url
    if cache_key in THREAT_CACHE:
        cached = THREAT_CACHE[cache_key]
        if now - cached['timestamp'] < CACHE_TTL:
            return jsonify(cached['data']), 200
    
    try:
        # ═══ LAYER 1: AI Model ═══
        ai_result = predict(url)
        
        # ═══ LAYER 2: Intent Analysis ═══
        intent_result = analyze_url(url, signals)
        
        # ═══ LAYER 3: VirusTotal ═══
        vt_result = vt_lookup(url)
        
        # ═══ MERGE ═══
        intent_verdict = intent_result['verdict']
        intent_risk = intent_result['intent']['risk_level']
        intent_type = intent_result['intent']['type']
        
        # Start with AI
        if ai_result['prediction'] == 'malicious':
            final_prediction = 'malicious'
            final_confidence = ai_result['confidence']
            malicious = True
        else:
            final_prediction = 'benign'
            final_confidence = ai_result['confidence']
            malicious = False
        
        # Override with Intent
        if intent_verdict == 'malicious' or intent_risk == 'critical':
            final_prediction = 'malicious'
            final_confidence = max(final_confidence, 0.85)
            malicious = True
        elif intent_verdict == 'suspicious' or intent_risk in ('high', 'medium'):
            final_prediction = 'malicious'
            final_confidence = max(final_confidence, 0.70)
            malicious = True
        
        # Override with VirusTotal
        if vt_result.get('available'):
            vt_verdict = vt_result.get('verdict', 'unknown')
            
            if vt_verdict == 'malicious':
                final_prediction = 'malicious'
                final_confidence = max(final_confidence, 0.95)
                malicious = True
            elif vt_verdict == 'suspicious':
                final_prediction = 'malicious'
                final_confidence = max(final_confidence, 0.80)
                malicious = True
                # If intent type is still generic, use VT categories
                if intent_type in ('unknown', 'AI-Detected Threat') and vt_result.get('categories'):
                    ignore_cats = ('computersandsoftware', 'information technology')
                    vt_cats = [c for c in vt_result['categories'].values() 
                               if c.lower() not in ignore_cats]
                    if vt_cats:
                        intent_result['intent']['type'] = f"VirusTotal Flagged: {vt_cats[0]}"
                        intent_result['intent']['risk_level'] = 'high'
                        intent_result['explanation']['what_it_does'] = f"VirusTotal detected: {vt_cats[0]}"
        
        # Build category if still unknown
        if malicious and (intent_result['intent']['type'] == 'unknown' or intent_result['intent']['risk_level'] == 'low'):
            category = categorize_threat(url)
            
            intent_result['intent']['type'] = category['type']
            intent_result['intent']['risk_level'] = category['risk']
            intent_result['intent']['reasons'] = (
                list(intent_result['intent'].get('reasons', [])) + [category['reason']]
            )
            intent_result['explanation']['what_it_does'] = category['what_it_does']
            intent_result['explanation']['why_suspicious'] = (
                list(intent_result['explanation'].get('why_suspicious', [])) + [category['reason']]
            )
            intent_result['explanation']['risk_level'] = category['risk']
        
        # FINAL CONSISTENCY
        if malicious:
            intent_result['verdict'] = 'malicious'
            if intent_result.get('risk_score', 0) < 6:
                intent_result['risk_score'] = 6
        
        # Build VT summary for response
        vt_summary = None
        if vt_result.get('available'):
            vt_summary = {
                'verdict': vt_result.get('verdict', 'unknown'),
                'malicious': vt_result.get('malicious', 0),
                'suspicious': vt_result.get('suspicious', 0),
                'harmless': vt_result.get('harmless', 0),
                'undetected': vt_result.get('undetected', 0),
                'total_engines': vt_result.get('total_engines', 0),
                'reputation': vt_result.get('reputation', 0),
                'flagged_by': vt_result.get('flagged_by', []),
                'categories': vt_result.get('categories', {}),
                'vt_link': vt_result.get('vt_link', ''),
            }
        
        combined = {
            "url": url,
            "prediction": final_prediction,
            "confidence": final_confidence,
            "malicious": malicious,
            
            "ai_prediction": ai_result['prediction'],
            "ai_confidence": ai_result['confidence'],
            "detection_method": ai_result.get('detection_method'),
            
            "threat_type": intent_result['intent']['type'] if malicious else None,
            "verdict": intent_result['verdict'],
            "risk_score": intent_result['risk_score'],
            "intent": intent_result['intent'],
            "domain_analysis": intent_result['domain_analysis'],
            "explanation": intent_result['explanation'],
            
            "virustotal": vt_summary,
        }
        
        THREAT_CACHE[cache_key] = {
            'data': combined,
            'timestamp': now
        }
        
        return jsonify(combined), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "msg": str(e),
            "prediction": "unknown",
            "malicious": False
        }), 500

# ── Cache cleanup ──
@app.before_request
def cleanup_caches():
    if len(THREAT_CACHE) > 1000:
        now = time()
        to_delete = [k for k, v in THREAT_CACHE.items() if now - v['timestamp'] > 600]
        for k in to_delete:
            del THREAT_CACHE[k]

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, port=port, host='0.0.0.0')