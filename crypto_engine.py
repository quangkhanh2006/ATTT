"""
Module: crypto_engine.py
========================
Chứa class CryptoEngine - engine xử lý tất cả các thao tác mật mã trong ứng dụng.

Sử dụng hybrid cryptography:
- RSA-2048: cho key exchange và digital signatures
- AES-256-CBC: cho encryption của dữ liệu lớn (âm thanh)
- SHA-256: cho integrity checking
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


class CryptoEngine:
    """
    Engine xử lý tất cả các thao tác mật mã trong ứng dụng.

    Sử dụng hybrid cryptography:
    - RSA-2048: cho key exchange và digital signatures
    - AES-256-CBC: cho encryption của dữ liệu lớn (âm thanh)
    - SHA-256: cho integrity checking

    Tại sao hybrid?
    - RSA chậm với dữ liệu lớn → chỉ dùng để mã hóa AES key
    - AES nhanh với dữ liệu lớn → dùng để mã hóa âm thanh
    """
    def __init__(self):
        self.rsa_key      = RSA.generate(2048)  # Khóa RSA cho asymmetric crypto
        self.public_key   = self.rsa_key.publickey()
        self.peer_pub_key = None  # Public key của peer (nhận từ network)
        self.aes_key      = None  # Session key cho symmetric crypto (tạo sau)

    def get_public_key_bytes(self):
        """Trả về public key dưới dạng bytes để gửi qua network"""
        return self.public_key.export_key()

    def set_peer_public_key(self, key_bytes):
        """Thiết lập public key của peer từ bytes nhận được"""
        self.peer_pub_key = RSA.import_key(key_bytes)

    # ── Bước 2: Sender tạo & mã hóa AES key bằng RSA ──────────────────────
    def generate_and_encrypt_aes_key(self):
        """
        Tạo AES session key ngẫu nhiên và mã hóa bằng public key của peer.

        Đây là bước quan trọng trong key exchange:
        - AES key là symmetric key, dùng để mã hóa dữ liệu lớn
        - Được mã hóa bằng RSA để gửi an toàn qua network
        - Peer sẽ dùng private key để giải mã và lấy AES key
        """
        self.aes_key = get_random_bytes(32)          # AES-256: 32 bytes key
        cipher_rsa   = PKCS1_OAEP.new(
            self.peer_pub_key, hashAlgo=SHA256
        )
        encrypted = cipher_rsa.encrypt(self.aes_key)
        return encrypted

    def decrypt_aes_key(self, encrypted_key):
        """Giải mã AES key đã được mã hóa bằng RSA"""
        cipher_rsa   = PKCS1_OAEP.new(self.rsa_key, hashAlgo=SHA256)
        self.aes_key = cipher_rsa.decrypt(encrypted_key)

    # ── Ký số ──────────────────────────────────────────────────────────────
    def sign(self, data: bytes) -> bytes:
        """Ký số dữ liệu bằng RSA-PSS + SHA-256"""
        h   = SHA256.new(data)
        sig = pss.new(self.rsa_key).sign(h)
        return sig

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Xác thực chữ ký số RSA-PSS"""
        h = SHA256.new(data)
        try:
            pss.new(self.peer_pub_key).verify(h, signature)
            return True
        except Exception:
            return False

    # ── Bước 3: Mã hóa âm thanh AES-256-CBC ───────────────────────────────
    def encrypt_audio(self, plaintext: bytes):
        """
        Mã hóa dữ liệu âm thanh bằng AES-256-CBC.

        Quy trình:
        1. Tạo IV ngẫu nhiên (16 bytes)
        2. Padding dữ liệu âm thanh theo PKCS7 (để đủ block size)
        3. Mã hóa với AES-CBC
        4. Tính hash SHA-256 của IV + ciphertext để đảm bảo integrity

        Returns:
            tuple: (iv, ciphertext, digest)
        """
        iv         = get_random_bytes(16)  # IV cho CBC mode
        pad_len    = 16 - (len(plaintext) % 16)  # Tính padding length
        padded     = plaintext + bytes([pad_len] * pad_len)  # PKCS7 padding
        cipher     = AES.new(self.aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded)
        digest     = SHA256.new(iv + ciphertext).digest()  # Hash để check integrity
        return iv, ciphertext, digest

    def decrypt_audio(self, iv: bytes, ciphertext: bytes, digest: bytes):
        """
        Giải mã dữ liệu âm thanh đã mã hóa AES-256-CBC.

        Quy trình:
        1. Kiểm tra hash để đảm bảo dữ liệu không bị thay đổi
        2. Giải mã AES-CBC
        3. Bỏ padding PKCS7 để lấy dữ liệu gốc

        Args:
            iv: Initialization Vector (16 bytes)
            ciphertext: Dữ liệu đã mã hóa
            digest: SHA-256 hash của iv + ciphertext

        Returns:
            bytes: Dữ liệu âm thanh gốc

        Raises:
            ValueError: Nếu hash không khớp (dữ liệu bị giả mạo)
        """
        # Kiểm tra hash
        expected = SHA256.new(iv + ciphertext).digest()
        if expected != digest:
            raise ValueError("Hash không hợp lệ — dữ liệu có thể bị giả mạo!")
        cipher    = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded    = cipher.decrypt(ciphertext)
        pad_len   = padded[-1]  # PKCS7: last byte = padding length
        plaintext = padded[:-pad_len]  # Remove padding
        return plaintext