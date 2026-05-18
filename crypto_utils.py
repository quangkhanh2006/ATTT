"""
Module 1: crypto_utils.py
=========================
Chứa toàn bộ hàm mật mã thuần túy (không phụ thuộc network).

Mô tả các thuật toán mật mã sử dụng:
- RSA-2048: Thuật toán mã hóa bất đối xứng, dùng để trao đổi khóa và ký số
- AES-256-CBC: Thuật toán mã hóa đối xứng, dùng để mã hóa dữ liệu lớn
- SHA-256: Hàm băm, dùng để tạo digest và đảm bảo toàn vẹn dữ liệu
- OAEP: Optimal Asymmetric Encryption Padding, làm cho RSA an toàn hơn
- PSS: Probabilistic Signature Scheme, dùng cho ký số RSA
- PKCS7: Padding scheme cho block ciphers như AES

Các hàm được định nghĩa:
- generate_rsa_keypair()         → (private_key, public_key)
- serialize_public_key(pub_key)  → bytes (PEM)
- load_public_key(pem_bytes)     → public_key object
- rsa_encrypt(pub_key, data)    → bytes  [OAEP+SHA256]
- rsa_decrypt(priv_key, data)   → bytes  [OAEP+SHA256]
- rsa_sign(priv_key, message)  → bytes  [PSS+SHA256]
- rsa_verify(pub_key, message, signature) → bool
- aes_encrypt(key, iv, plaintext) → bytes  [AES-256-CBC+PKCS7]
- aes_decrypt(key, iv, ciphertext) → bytes
- compute_hash(iv, ciphertext)  → str (hex digest SHA-256)
- verify_hash(iv, ciphertext, expected_hash) → bool
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import json


def generate_rsa_keypair():
    """
    Sinh cặp khóa RSA-2048.
    
    RSA (Rivest-Shamir-Adleman) là thuật toán mã hóa bất đối xứng:
    - Khóa công khai (public key): dùng để mã hóa và xác thực chữ ký
    - Khóa riêng (private key): dùng để giải mã và ký số
    - 2048-bit: độ dài khóa tiêu chuẩn hiện đại, an toàn trước các tấn công brute-force
    
    Returns:
        tuple: (private_key, public_key) - Cặp khóa RSA
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # e = 65537 là giá trị tiêu chuẩn cho public exponent
        key_size=2048,          # 2048 bits cho độ an toàn cao
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(pub_key):
    """
    Serialize public key thành bytes (PEM format).
    
    Args:
        pub_key: Public key object từ cryptography library
        
    Returns:
        bytes: Public key dạng PEM bytes
    """
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(pem_bytes):
    """
    Load public key từ PEM bytes.
    
    Args:
        pem_bytes: Public key dạng PEM bytes
        
    Returns:
        public_key: Public key object
    """
    return serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )


def rsa_encrypt(pub_key, data):
    """
    Mã hóa dữ liệu bằng RSA-OAEP với SHA-256 hash.
    
    OAEP (Optimal Asymmetric Encryption Padding) làm cho RSA an toàn hơn:
    - Ngăn chặn các tấn công dựa trên padding
    - Sử dụng hash function (SHA-256) để tạo randomness
    - MGF1: Mask Generation Function dựa trên hash
    
    Args:
        pub_key: Public key object
        data: Dữ liệu cần mã hóa (bytes), tối đa ~190 bytes cho RSA-2048
        
    Returns:
        bytes: Dữ liệu đã mã hóa RSA (256 bytes cho RSA-2048)
    """
    return pub_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(priv_key, data):
    """
    Giải mã dữ liệu bằng RSA-OAEP với SHA-256 hash.
    
    Args:
        priv_key: Private key object
        data: Dữ liệu đã mã hóa RSA (bytes)
        
    Returns:
        bytes: Dữ liệu đã giải mã
    """
    return priv_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_sign(priv_key, message):
    """
    Ký dữ liệu bằng RSA-PSS với SHA-256 hash.
    
    PSS (Probabilistic Signature Scheme) là chuẩn ký số hiện đại:
    - Sử dụng salt ngẫu nhiên để ngăn chặn tấn công
    - SHA-256 làm hash function cho message
    - MGF1 tạo mask từ hash
    
    Args:
        priv_key: Private key object
        message: Tin nhắn cần ký (bytes)
        
    Returns:
        bytes: Chữ ký số RSA-PSS (256 bytes)
    """
    return priv_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size
        ),
        hashes.SHA256()
    )


def rsa_verify(pub_key, message, signature):
    """
    Xác thực chữ ký số RSA-PSS.
    
    Args:
        pub_key: Public key object
        message: Tin nhắn gốc (bytes)
        signature: Chữ ký số cần xác thực (bytes)
        
    Returns:
        bool: True nếu chữ ký hợp lệ, False nếu không
    """
    try:
        pub_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Padding dữ liệu theo chuẩn PKCS7.
    
    Args:
        data: Dữ liệu cần padding
        block_size: Kích thước block (mặc định 16 bytes cho AES)
        
    Returns:
        bytes: Dữ liệu đã được padding
    """
    padding_length = block_size - (len(data) % block_size)
    padding_bytes = bytes([padding_length] * padding_length)
    return data + padding_bytes


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Bỏ padding PKCS7.
    
    Args:
        data: Dữ liệu đã padding
        
    Returns:
        bytes: Dữ liệu gốc sau khi bỏ padding
    """
    padding_length = data[-1]
    return data[:-padding_length]


def aes_encrypt(key, iv, plaintext):
    """
    Mã hóa dữ liệu bằng AES-256-CBC với padding PKCS7.
    
    AES (Advanced Encryption Standard):
    - Thuật toán mã hóa đối xứng chuẩn
    - 256-bit key: an toàn cao, được khuyến nghị bởi NIST
    - CBC mode: Cipher Block Chaining, mỗi block phụ thuộc vào block trước
    
    IV (Initialization Vector): 16 bytes ngẫu nhiên
    PKCS7 padding: thêm bytes để đủ block size (16 bytes cho AES)
    
    Args:
        key: Khóa AES (32 bytes cho AES-256)
        iv: Initialization Vector (16 bytes)
        plaintext: Dữ liệu plaintext cần mã hóa (bytes)
        
    Returns:
        bytes: Dữ liệu đã mã hóa AES
    """
    # Pad dữ liệu theo PKCS7
    padded_data = pkcs7_pad(plaintext)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def aes_decrypt(key, iv, ciphertext):
    """
    Giải mã dữ liệu bằng AES-256-CBC.
    
    Args:
        key: Khóa AES (32 bytes cho AES-256)
        iv: Initialization Vector (16 bytes)
        ciphertext: Dữ liệu đã mã hóa (bytes)
        
    Returns:
        bytes: Dữ liệu đã giải mã
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Bỏ padding PKCS7
    return pkcs7_unpad(padded_plaintext)


def compute_hash(iv, ciphertext):
    """
    Tính hash SHA-256 của IV + ciphertext để kiểm tra toàn vẹn.
    
    SHA-256 (Secure Hash Algorithm 256):
    - Hàm băm mật mã, tạo 256-bit digest
    - Một chiều: không thể tính ngược
    - Collision-resistant: khó tìm 2 input khác nhau có cùng hash
    - Dùng để đảm bảo dữ liệu không bị thay đổi
    
    Tại sao hash IV + ciphertext?
    - IV là public, ciphertext là encrypted
    - Hash đảm bảo cả IV và dữ liệu encrypted không bị sửa đổi
    
    Args:
        iv: Initialization Vector (bytes)
        ciphertext: Dữ liệu đã mã hóa (bytes)
        
    Returns:
        str: Hex digest của SHA-256 (64 ký tự hex)
    """
    hasher = hashlib.sha256()
    hasher.update(iv)
    hasher.update(ciphertext)
    return hasher.hexdigest()


def verify_hash(iv, ciphertext, expected_hash):
    """
    Xác thực hash SHA-256 của IV + ciphertext.
    
    Args:
        iv: Initialization Vector (bytes)
        ciphertext: Dữ liệu đã mã hóa (bytes)
        expected_hash: Hash mong đợi (hex string)
        
    Returns:
        bool: True nếu hash khớp, False nếu không
    """
    actual_hash = compute_hash(iv, ciphertext)
    return actual_hash == expected_hash


def generate_aes_key():
    """
    Sinh khóa AES-256 ngẫu nhiên (32 bytes).
    
    Returns:
        bytes: Khóa AES-256 ngẫu nhiên
    """
    return os.urandom(32)


def generate_iv():
    """
    Sinh IV ngẫu nhiên (16 bytes) cho AES-CBC.
    
    Returns:
        bytes: IV ngẫu nhiên 16 bytes
    """
    return os.urandom(16)


# ============ HELPER FUNCTIONS FOR BASE64 ============

def bytes_to_base64(data: bytes) -> str:
    """
    Chuyển đổi bytes sang base64 string.
    
    Args:
        data: Dữ liệu bytes
        
    Returns:
        str: Chuỗi base64
    """
    return base64.b64encode(data).decode('utf-8')


def base64_to_bytes(data: str) -> bytes:
    """
    Chuyển đổi base64 string sang bytes.
    
    Args:
        data: Chuỗi base64
        
    Returns:
        bytes: Dữ liệu bytes
    """
    return base64.b64decode(data)


# ============ TEST FUNCTIONS ============

def test_crypto():
    """
    Hàm test đơn giản để kiểm tra các hàm mật mã.
    """
    print("[TEST] Testing cryptographic functions...")
    
    # Test RSA keypair
    priv_key, pub_key = generate_rsa_keypair()
    print("[TEST] RSA keypair generated successfully")
    
    # Test serialize/load public key
    pem_data = serialize_public_key(pub_key)
    loaded_pub_key = load_public_key(pem_data)
    print("[TEST] Public key serialization/deserialization OK")
    
    # Test RSA encrypt/decrypt
    test_data = b"Hello, SecureVoiceChat!"
    encrypted = rsa_encrypt(loaded_pub_key, test_data)
    decrypted = rsa_decrypt(priv_key, encrypted)
    assert decrypted == test_data
    print("[TEST] RSA-OAEP encrypt/decrypt OK")
    
    # Test RSA sign/verify
    signature = rsa_sign(priv_key, test_data)
    assert rsa_verify(loaded_pub_key, test_data, signature)
    print("[TEST] RSA-PSS sign/verify OK")
    
    # Test AES encrypt/decrypt
    aes_key = generate_aes_key()
    iv = generate_iv()
    cipher = aes_encrypt(aes_key, iv, test_data)
    plain = aes_decrypt(aes_key, iv, cipher)
    assert plain == test_data
    print("[TEST] AES-256-CBC encrypt/decrypt OK")
    
    # Test hash
    hash1 = compute_hash(iv, cipher)
    assert verify_hash(iv, cipher, hash1)
    print("[TEST] SHA-256 hash compute/verify OK")
    
    print("[TEST] All cryptographic tests passed!")


if __name__ == "__main__":
    test_crypto()