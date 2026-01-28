import os
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///defi_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Blockchain Configuration ---
INFURA_URL = os.environ.get('INFURA_URL', 'http://127.0.0.1:8545')
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    wallets = db.relationship('Wallet', backref='user', lazy=True)

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String(42), unique=True, nullable=False)
    private_key = db.Column(db.String(255), nullable=False) # In production, use KMS/Vault
    balance = db.Column(db.Float, default=0.0)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    tx_hash = db.Column(db.String(66), unique=True)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20)) # 'send', 'receive', 'lend', 'borrow'
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# --- Authentication Middleware ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[\"HS256\"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Routes: User Auth ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = User.query.filter_by(username=auth['username']).first()
    if user and check_password_hash(user.password_hash, auth['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return jsonify({'message': 'Login failed'}), 401

# --- Routes: Phase 3 - Blockchain Operations ---
@app.route('/wallet/create', methods=['POST'])
@token_required
def create_wallet(current_user):
    account = w3.eth.account.create()
    new_wallet = Wallet(user_id=current_user.id, address=account.address, private_key=account.key.hex())
    db.session.add(new_wallet)
    db.session.commit()
    return jsonify({'address': account.address, 'message': 'New DeFi wallet created'})

@app.route('/wallet/balance/<address>', methods=['GET'])
@token_required
def get_balance(current_user, address):
    balance_wei = w3.eth.get_balance(address)
    balance_eth = w3.from_wei(balance_wei, 'ether')
    return jsonify({'address': address, 'balance_eth': str(balance_eth)})

# --- Routes: Phase 4 - DeFi Operations (Lending/Swapping) ---
@app.route('/defi/send', methods=['POST'])
@token_required
def send_transaction(current_user):
    data = request.get_json()
    wallet = Wallet.query.filter_by(address=data['from_address'], user_id=current_user.id).first()
    
    if not wallet:
        return jsonify({'message': 'Wallet not found or unauthorized'}), 404

    # Build transaction
    tx = {
        'nonce': w3.eth.get_transaction_count(wallet.address),
        'to': data['to_address'],
        'value': w3.to_wei(data['amount'], 'ether'),
        'gas': 21000,
        'gasPrice': w3.eth.gas_price,
        'chainId': 1 # Mainnet, change for testnets
    }

    # Sign and send
    signed_tx = w3.eth.account.sign_transaction(tx, wallet.private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    
    # Record in DB
    new_tx = Transaction(wallet_id=wallet.id, tx_hash=tx_hash.hex(), amount=data['amount'], type='send')
    db.session.add(new_tx)
    db.session.commit()

    return jsonify({'tx_hash': tx_hash.hex(), 'status': 'submitted'})

@app.route('/defi/lend', methods=['POST'])
@token_required
def lend_assets(current_user):
    # Mock lending logic for DeFi dashboard
    data = request.get_json()
    return jsonify({
        'message': f\"Successfully lent {data['amount']} {data['asset']} to the pool\",
        'apy': '5.4%',
        'estimated_rewards': '0.002 ETH/month'
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

