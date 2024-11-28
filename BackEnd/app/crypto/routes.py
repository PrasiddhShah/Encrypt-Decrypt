from flask import request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models import EncryptedData
from app.crypto_utils import encrypt_aes, decrypt_aes, encrypt_des, decrypt_des, encrypt_rsa, decrypt_rsa
from . import crypto

@crypto.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    data = request.get_json()
    text = data.get('text')
    algorithm = data.get('algorithm')
    key = data.get('key')
    if not text or not algorithm or not key:
        return jsonify({'message': 'Missing parameters'}), 400
    try:
        if algorithm == 'AES':
            encrypted_text = encrypt_aes(text, key)
        elif algorithm == 'DES':
            encrypted_text = encrypt_des(text, key)
        elif algorithm == 'RSA':
            encrypted_text = encrypt_rsa(text, key)
        else:
            return jsonify({'message': 'Unsupported algorithm'}), 400
        encrypted_data = EncryptedData(
            user_id=current_user.id,
            algorithm=algorithm,
            input_text=text,
            output_text=encrypted_text,
            key=key
        )
        db.session.add(encrypted_data)
        db.session.commit()
        return jsonify({'encrypted_text': encrypted_text}), 200
    except Exception as e:
        return jsonify({'message': 'Encryption failed', 'error': str(e)}), 500

@crypto.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    data = request.get_json()
    encrypted_text = data.get('encrypted_text')
    algorithm = data.get('algorithm')
    key = data.get('key')  # For RSA, this will be the private key in base64
    if not encrypted_text or not algorithm or not key:
        return jsonify({'message': 'Missing parameters'}), 400
    try:
        if algorithm == 'AES':
            decrypted_text = decrypt_aes(encrypted_text, key)
        elif algorithm == 'DES':
            decrypted_text = decrypt_des(encrypted_text, key)
        elif algorithm == 'RSA':
            decrypted_text = decrypt_rsa(encrypted_text, key)
        else:
            return jsonify({'message': 'Unsupported algorithm'}), 400
        decrypted_data = EncryptedData(
            user_id=current_user.id,
            algorithm=algorithm,
            input_text=decrypted_text,
            output_text=encrypted_text,
            key=key
        )
        db.session.add(decrypted_data)
        db.session.commit()
        return jsonify({'decrypted_text': decrypted_text}), 200
    except Exception as e:
        return jsonify({'message': 'Decryption failed', 'error': str(e)}), 500
@crypto.route('/history', methods=['GET'])
@login_required
def get_history():
    try:
        # Fetch the history for the current user, ordered by timestamp descending
        history = EncryptedData.query.filter_by(user_id=current_user.id).order_by(EncryptedData.timestamp.desc()).all()
        
        # Serialize the data
        history_data = []
        for record in history:
            history_data.append({
                'id': record.id,
                'algorithm': record.algorithm,
                'input_text': record.input_text,
                'output_text': record.output_text,
                'key': record.key,
                'timestamp': record.timestamp.isoformat()
            })
        
        return jsonify({'history': history_data}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to fetch history', 'error': str(e)}), 500
