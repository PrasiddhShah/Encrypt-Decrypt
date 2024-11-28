import base64
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

# Padding for block cipher algorithms
def pad(s, block_size):
    pad_len = block_size - (len(s) % block_size)
    return s + (chr(pad_len) * pad_len)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

# AES Encryption/Decryption
def encrypt_aes(plaintext, key):
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    plaintext_padded = pad(plaintext, AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(plaintext_padded.encode('utf-8'))
    encrypted_with_iv = iv + encrypted_bytes
    encrypted_base64 = base64.b64encode(encrypted_with_iv).decode('utf-8')
    return encrypted_base64

def decrypt_aes(encrypted_base64, key):
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    encrypted_with_iv = base64.b64decode(encrypted_base64)
    iv = encrypted_with_iv[:AES.block_size]
    encrypted_bytes = encrypted_with_iv[AES.block_size:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted = unpad(decrypted_padded.decode('utf-8'))
    return decrypted

# DES Encryption/Decryption
def encrypt_des(plaintext, key):
    key_bytes = hashlib.md5(key.encode('utf-8')).digest()[:8]
    plaintext_padded = pad(plaintext, DES.block_size)
    iv = Random.new().read(DES.block_size)
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(plaintext_padded.encode('utf-8'))
    encrypted_with_iv = iv + encrypted_bytes
    encrypted_base64 = base64.b64encode(encrypted_with_iv).decode('utf-8')
    return encrypted_base64

def decrypt_des(encrypted_base64, key):
    key_bytes = hashlib.md5(key.encode('utf-8')).digest()[:8]
    encrypted_with_iv = base64.b64decode(encrypted_base64)
    iv = encrypted_with_iv[:DES.block_size]
    encrypted_bytes = encrypted_with_iv[DES.block_size:]
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted = unpad(decrypted_padded.decode('utf-8'))
    return decrypted

# RSA Encryption
def encrypt_rsa(plaintext, public_key_pem_base64):
    public_key_pem = base64.b64decode(public_key_pem_base64)
    public_key = RSA.importKey(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_base64
# RSA Decryption
def decrypt_rsa(encrypted_base64, private_key_pem_base64):
    try:
        encrypted_bytes = base64.b64decode(encrypted_base64)
        private_key_pem = base64.b64decode(private_key_pem_base64)
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        decrypted_text = decrypted_bytes.decode('utf-8')
        return decrypted_text
    except Exception as e:
        raise Exception(f'RSA decryption failed: {str(e)}')
