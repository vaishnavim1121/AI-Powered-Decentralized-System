from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, Threat, Alert
from config import Config
from datetime import datetime
import bcrypt

import sys
sys.path.append(r'C:\Users\ASUS\OneDrive\Desktop\adctin-project\blockchain\src')
from web3_interface import BlockchainInterface

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
jwt = JWTManager(app)

from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.exceptions import Unauthorized

@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return jsonify({"msg": "Missing or invalid token"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(callback):   # this param is actually the error *reason string*
    return jsonify({"msg": "Invalid token"}), 401

@jwt.expired_token_loader
def expired_token_callback(callback):
    return jsonify({"msg": "Token expired"}), 401
# Create tables if not exist
with app.app_context():
    db.create_all()

# ---------- Helper functions (PLACEHOLDERS for AI & Blockchain) ----------
def run_ai_prediction(features):
    # TODO: MEMBER 2 will replace this
    return {"prediction": "malicious", "confidence": 0.95, "explanation": {"feature1": 0.3}}

def store_on_blockchain(threat_hash):
    bi = BlockchainInterface()
    return bi.store_threat(threat_hash, severity=5)

# ---------- Routes ----------
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
    
    # For now, assume features are passed directly (MEMBER 2 will decide format)
    features = data.get('features')  # list of numbers
    file_hash = data.get('file_hash')
    url = data.get('url')
    
    # Call AI (placeholder)
    ai_result = run_ai_prediction(features)
    
    # Call Blockchain (placeholder)
    threat_identifier = file_hash if file_hash else url
    tx_hash = store_on_blockchain(threat_identifier)
    
    # Save to DB
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
    
    # Create alert
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

@app.route('/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    alerts = Alert.query.filter_by(is_read=False).order_by(Alert.created_at.desc()).all()
    return jsonify([{
        "id": a.id,
        "message": a.message,
        "created_at": a.created_at.isoformat()
    } for a in alerts])

if __name__ == '__main__':
    app.run(debug=True, port=5000)