import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///defi_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Models ---
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
    private_key_encrypted = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Float, default=0.0)

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    contract_address = db.Column(db.String(42))

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    tx_hash = db.Column(db.String(66), unique=True)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20)) # lending, borrowing, swap
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# --- Blockchain Integration ---
w3 = Web3(Web3.HTTPProvider(os.environ.get('INFURA_URL', 'http://127.0.0.1:8545')))

# --- Auth Middleware ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[\"HS256\"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Routes ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = User.query.filter_by(username=auth['username']).first()
    if user and check_password_hash(user.password_hash, auth['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/create_wallet', methods=['POST'])
@token_required
def create_wallet(current_user):
    account = w3.eth.account.create()
    new_wallet = Wallet(user_id=current_user.id, address=account.address, private_key_encrypted=account.key.hex()) # In production, encrypt this!
    db.session.add(new_wallet)
    db.session.commit()
    return jsonify({'address': account.address, 'message': 'Wallet created'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
