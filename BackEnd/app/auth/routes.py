from flask import request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, current_user, logout_user
from app import db, login_manager, oauth
from app.models import User
from . import auth
import requests

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth.route('/manual_register', methods=['POST'])
def manual_register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return jsonify({'message': 'Missing parameters'}), 400
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = generate_password_hash(password)
    user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    return jsonify({'message': 'User registered successfully'}), 201

@auth.route('/manual_login', methods=['POST'])
def manual_login():
    data = request.get_json()
    username_or_email = data.get('username_or_email')
    password = data.get('password')
    if not username_or_email or not password:
        return jsonify({'message': 'Missing parameters'}), 400
    user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@auth.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@auth.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({'message': 'Missing token'}), 400
    try:
        response = requests.get('https://oauth2.googleapis.com/tokeninfo', params={'id_token': token})
        user_info = response.json()
        if 'error_description' in user_info:
            return jsonify({'message': 'Invalid token', 'error': user_info['error_description']}), 400
        email = user_info.get('email')
        google_id = user_info.get('sub')
        name = user_info.get('name')
        if not email:
            return jsonify({'message': 'Failed to retrieve user info'}), 400
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'User not registered'}), 403
        else:
            login_user(user)
            return jsonify({'message': 'Logged in successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Authentication failed', 'error': str(e)}), 400

@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({'message': 'Missing token'}), 400
    try:
        response = requests.get('https://oauth2.googleapis.com/tokeninfo', params={'id_token': token})
        user_info = response.json()
        if 'error_description' in user_info:
            return jsonify({'message': 'Invalid token', 'error': user_info['error_description']}), 400
        email = user_info.get('email')
        name = user_info.get('name')
        google_id = user_info.get('sub')
        if not email:
            return jsonify({'message': 'Failed to retrieve user info'}), 400
        user = User.query.filter_by(email=email).first()
        if user:
            return jsonify({'message': 'User already exists'}), 400
        user = User(username=name, email=email, google_id=google_id)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return jsonify({'message': 'User registered and logged in successfully'}), 201
    except Exception as e:
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 400
