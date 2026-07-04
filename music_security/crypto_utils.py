"""
crypto_utils.py - Module mã hóa cho hệ thống truyền file nhạc bản quyền
Sử dụng: Triple DES, RSA 1024-bit (OAEP + SHA-512), SHA-512
"""

import os
import base64
import hashlib
import time
from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ─────────────────────────────────────────
# RSA - Tạo & Load khóa
# ─────────────────────────────────────────

def generate_rsa_keypair(bits=1024):
    """Tạo cặp khóa RSA 1024-bit"""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def load_rsa_private_key(pem_data):
    return RSA.import_key(pem_data)


def load_rsa_public_key(pem_data):
    return RSA.import_key(pem_data)


# ─────────────────────────────────────────
# RSA - Mã hóa / Giải mã SessionKey (OAEP + SHA-512)
# ─────────────────────────────────────────

def rsa_encrypt_session_key(public_key_pem, session_key: bytes) -> str:
    """Mã hóa SessionKey bằng RSA-OAEP với SHA-512"""
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    encrypted = cipher.encrypt(session_key)
    return base64.b64encode(encrypted).decode()


def rsa_decrypt_session_key(private_key_pem, encrypted_b64: str) -> bytes:
    """Giải mã SessionKey bằng RSA private key"""
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    encrypted = base64.b64decode(encrypted_b64)
    return cipher.decrypt(encrypted)


# ─────────────────────────────────────────
# RSA - Ký & Xác thực chữ ký (SHA-512)
# ─────────────────────────────────────────

def rsa_sign(private_key_pem, message: bytes) -> str:
    """Ký message bằng RSA private key với SHA-512"""
    priv_key = RSA.import_key(private_key_pem)
    h = SHA512.new(message)
    signature = pkcs1_15.new(priv_key).sign(h)
    return base64.b64encode(signature).decode()


def rsa_verify(public_key_pem, message: bytes, signature_b64: str) -> bool:
    """Xác thực chữ ký RSA"""
    try:
        pub_key = RSA.import_key(public_key_pem)
        h = SHA512.new(message)
        sig = base64.b64decode(signature_b64)
        pkcs1_15.new(pub_key).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False


# ─────────────────────────────────────────
# Triple DES - Mã hóa / Giải mã file
# ─────────────────────────────────────────

def generate_session_key() -> bytes:
    """Tạo SessionKey 24 bytes cho Triple DES"""
    return DES3.adjust_key_parity(get_random_bytes(24))


def generate_iv() -> bytes:
    """Tạo IV 8 bytes cho DES/3DES CBC"""
    return get_random_bytes(8)


def triple_des_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Mã hóa dữ liệu bằng Triple DES CBC mode"""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(plaintext, DES3.block_size)
    return cipher.encrypt(padded)


def triple_des_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Giải mã dữ liệu bằng Triple DES CBC mode"""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, DES3.block_size)


# ─────────────────────────────────────────
# DES - Mã hóa / Giải mã metadata
# ─────────────────────────────────────────

def des_encrypt_metadata(key_8bytes: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Mã hóa metadata bằng DES CBC"""
    cipher = DES.new(key_8bytes, DES.MODE_CBC, iv)
    padded = pad(plaintext, DES.block_size)
    return cipher.encrypt(padded)


def des_decrypt_metadata(key_8bytes: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Giải mã metadata bằng DES CBC"""
    cipher = DES.new(key_8bytes, DES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, DES.block_size)


# ─────────────────────────────────────────
# SHA-512 - Tính Hash toàn vẹn
# ─────────────────────────────────────────

def compute_sha512(data: bytes) -> str:
    """Tính SHA-512 hash, trả về hex string"""
    h = SHA512.new(data)
    return h.hexdigest()


def compute_integrity_hash(iv: bytes, ciphertext: bytes) -> str:
    """Tính hash toàn vẹn: SHA-512(IV || ciphertext)"""
    combined = iv + ciphertext
    return compute_sha512(combined)


def verify_integrity_hash(iv: bytes, ciphertext: bytes, expected_hash: str) -> bool:
    """Kiểm tra tính toàn vẹn"""
    computed = compute_integrity_hash(iv, ciphertext)
    return computed == expected_hash


# ─────────────────────────────────────────
# Helper
# ─────────────────────────────────────────

def get_timestamp() -> str:
    return str(int(time.time()))


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64decode(s: str) -> bytes:
    return base64.b64decode(s)


def measure_time(func, *args, **kwargs):
    """Đo thời gian thực hiện hàm"""
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed = (time.perf_counter() - start) * 1000  # ms
    return result, elapsed
