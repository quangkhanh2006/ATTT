"""
Module 3: protocol.py
=====================
Định nghĩa tất cả cấu trúc JSON message cho giao thức SecureVoiceChat.

Flow cơ bản:
1. Sender gửi HELLO + public key
2. Receiver trả HELLO_ACK + public key
3. Sender gửi KEY_EXCHANGE gồm signed_info + encrypted_aes_key
4. Receiver trả KEY_EXCHANGE_ACK
5. Sender gửi VOICE_MSG gồm iv, cipher, hash
6. Receiver trả ACK hoặc NACK

Các message types:
- HELLO: Khởi tạo kết nối, gửi public key
- HELLO_ACK: Xác nhận kết nối từ phía receiver
- KEY_EXCHANGE: Trao đổi khóa AES đã mã hóa
- KEY_EXCHANGE_ACK: Xác nhận trao đổi khóa
- VOICE_MSG: Tin nhắn âm thanh đã mã hóa
- ACK: Xác nhận nhận tin nhắn thành công
- NACK: Thông báo lỗi khi nhận tin nhắn
"""

import json
import uuid
from typing import Optional, Dict, Any
from crypto_utils import bytes_to_base64, base64_to_bytes


# ============ MESSAGE TYPE CONSTANTS ============
# Các giá trị này được sử dụng trong trường "type" của JSON message.
# Nó giúp receiver xác định được loại thao tác đang xảy ra.
MSG_HELLO = "HELLO"
MSG_HELLO_ACK = "HELLO_ACK"
MSG_KEY_EXCHANGE = "KEY_EXCHANGE"
MSG_KEY_EXCHANGE_ACK = "KEY_EXCHANGE_ACK"
MSG_VOICE_MSG = "VOICE_MSG"
MSG_ACK = "ACK"
MSG_NACK = "NACK"


# ============ HANDSHAKE MESSAGES ============

def create_hello(sender_id: str, public_key_pem: bytes) -> Dict[str, Any]:
    """
    Tạo message HELLO để khởi tạo kết nối.
    
    Args:
        sender_id: UUID của sender
        public_key_pem: Public key dạng PEM bytes
        
    Returns:
        Dict: Message HELLO JSON
    """
    return {
        "type": MSG_HELLO,
        "sender_id": sender_id,
        # Chuyển public key sang base64 để đúc thành JSON an toàn
        "public_key": bytes_to_base64(public_key_pem)
    }


def create_hello_ack(receiver_id: str, public_key_pem: bytes) -> Dict[str, Any]:
    """
    Tạo message HELLO_ACK để xác nhận kết nối.
    
    Args:
        receiver_id: UUID của receiver
        public_key_pem: Public key dạng PEM bytes
        
    Returns:
        Dict: Message HELLO_ACK JSON
    """
    return {
        "type": MSG_HELLO_ACK,
        "receiver_id": receiver_id,
        # Trả về public key của receiver để sender có thể mã hóa AES key
        "public_key": bytes_to_base64(public_key_pem)
    }


def parse_hello(message: Dict[str, Any]) -> tuple:
    """
    Parse message HELLO.
    
    Args:
        message: Dictionary từ JSON parse
        
    Returns:
        tuple: (sender_id, public_key_pem)
        
    Raises:
        ValueError: Nếu message không hợp lệ
    """
    if message.get("type") != MSG_HELLO:
        raise ValueError(f"Expected HELLO, got {message.get('type')}")
    
    sender_id = message.get("sender_id")
    public_key_b64 = message.get("public_key")
    
    if not sender_id or not public_key_b64:
        raise ValueError("Missing sender_id or public_key in HELLO")
    
    # Giải mã public key từ base64 về bytes PEM
    return sender_id, base64_to_bytes(public_key_b64)


def parse_hello_ack(message: Dict[str, Any]) -> tuple:
    """
    Parse message HELLO_ACK.
    
    Args:
        message: Dictionary từ JSON parse
        
    Returns:
        tuple: (receiver_id, public_key_pem)
        
    Raises:
        ValueError: Nếu message không hợp lệ
    """
    if message.get("type") != MSG_HELLO_ACK:
        raise ValueError(f"Expected HELLO_ACK, got {message.get('type')}")
    
    receiver_id = message.get("receiver_id")
    public_key_b64 = message.get("public_key")
    
    if not receiver_id or not public_key_b64:
        raise ValueError("Missing receiver_id or public_key in HELLO_ACK")
    
    # Giải mã public key của receiver để sender lưu làm peer key
    return receiver_id, base64_to_bytes(public_key_b64)


# ============ KEY EXCHANGE MESSAGES ============

def create_key_exchange(signed_info: bytes, encrypted_aes_key: bytes) -> Dict[str, Any]:
    """
    Tạo message KEY_EXCHANGE để trao đổi khóa AES.
    
    Args:
        signed_info: Chữ ký số của (sender_id || receiver_id || aes_key)
        encrypted_aes_key: Khóa AES đã mã hóa bằng RSA-OAEP
        
    Returns:
        Dict: Message KEY_EXCHANGE JSON
    """
    return {
        "type": MSG_KEY_EXCHANGE,
        # Chữ ký của (sender_id || receiver_id || aes_key) giúp receiver xác thực nguồn gốc
        "signed_info": bytes_to_base64(signed_info),
        # Khóa AES đã mã hóa bằng RSA-OAEP
        "encrypted_aes_key": bytes_to_base64(encrypted_aes_key)
    }


def create_key_exchange_ack(status: str, reason: str = "") -> Dict[str, Any]:
    """
    Tạo message KEY_EXCHANGE_ACK để xác nhận trao đổi khóa.
    
    Args:
        status: "OK" hoặc "FAILED"
        reason: Lý do失败 nếu status là "FAILED"
        
    Returns:
        Dict: Message KEY_EXCHANGE_ACK JSON
    """
    return {
        "type": MSG_KEY_EXCHANGE_ACK,
        "status": status,
        "reason": reason
    }


def parse_key_exchange(message: Dict[str, Any]) -> tuple:
    """
    Parse message KEY_EXCHANGE.
    
    Args:
        message: Dictionary từ JSON parse
        
    Returns:
        tuple: (signed_info_bytes, encrypted_aes_key_bytes)
        
    Raises:
        ValueError: Nếu message không hợp lệ
    """
    if message.get("type") != MSG_KEY_EXCHANGE:
        raise ValueError(f"Expected KEY_EXCHANGE, got {message.get('type')}")
    
    signed_info_b64 = message.get("signed_info")
    encrypted_aes_key_b64 = message.get("encrypted_aes_key")
    
    if not signed_info_b64 or not encrypted_aes_key_b64:
        raise ValueError("Missing signed_info or encrypted_aes_key in KEY_EXCHANGE")
    
    # Convert signed_info và encrypted_aes_key về bytes để xử lý tiếp
    return base64_to_bytes(signed_info_b64), base64_to_bytes(encrypted_aes_key_b64)


def parse_key_exchange_ack(message: Dict[str, Any]) -> tuple:
    """
    Parse message KEY_EXCHANGE_ACK.
    
    Args:
        message: Dictionary từ JSON parse
        
    Returns:
        tuple: (status, reason)
        
    Raises:
        ValueError: Nếu message không hợp lệ
    """
    if message.get("type") != MSG_KEY_EXCHANGE_ACK:
        raise ValueError(f"Expected KEY_EXCHANGE_ACK, got {message.get('type')}")
    
    status = message.get("status")
    reason = message.get("reason", "")
    
    if not status:
        raise ValueError("Missing status in KEY_EXCHANGE_ACK")
    
    return status, reason


# ============ VOICE MESSAGE ============

def create_voice_message(msg_id: str, iv: bytes, cipher: bytes, hash_value: str) -> Dict[str, Any]:
    """
    Tạo message VOICE_MSG để gửi tin nhắn âm thanh đã mã hóa.
    
    Args:
        msg_id: UUID của tin nhắn
        iv: Initialization Vector (bytes)
        cipher: Dữ liệu đã mã hóa AES (bytes)
        hash_value: SHA-256 hash của IV + cipher (hex string)
        
    Returns:
        Dict: Message VOICE_MSG JSON
    """
    return {
        "type": MSG_VOICE_MSG,
        "msg_id": msg_id,
        "iv": bytes_to_base64(iv),
        "cipher": bytes_to_base64(cipher),
        # Hash SHA-256 của iv || ciphertext để kiểm tra integrity
        "hash": hash_value
    }


def create_ack(msg_id: str) -> Dict[str, Any]:
    """
    Tạo message ACK để xác nhận nhận tin nhắn thành công.
    
    Args:
        msg_id: UUID của tin nhắn được xác nhận
        
    Returns:
        Dict: Message ACK JSON
    """
    return {
        "type": MSG_ACK,
        "msg_id": msg_id,
        "status": "OK"
    }


def create_nack(msg_id: str, reason: str) -> Dict[str, Any]:
    """
    Tạo message NACK để báo lỗi khi nhận tin nhắn.
    
    Args:
        msg_id: UUID của tin nhắn bị lỗi
        reason: Lý do lỗi (INTEGRITY_ERROR, SIGNATURE_ERROR, DECRYPT_ERROR)
        
    Returns:
        Dict: Message NACK JSON
    """
    return {
        "type": MSG_NACK,
        "msg_id": msg_id,
        "status": "FAILED",
        "reason": reason
    }


def parse_voice_message(message: Dict[str, Any]) -> tuple:
    """
    Parse message VOICE_MSG.
    
    Args:
        message: Dictionary từ JSON parse
        
    Returns:
        tuple: (msg_id, iv_bytes, cipher_bytes, hash_value)
        
    Raises:
        ValueError: Nếu message không hợp lệ
    """
    if message.get("type") != MSG_VOICE_MSG:
        raise ValueError(f"Expected VOICE_MSG, got {message.get('type')}")
    
    msg_id = message.get("msg_id")
    iv_b64 = message.get("iv")
    cipher_b64 = message.get("cipher")
    hash_value = message.get("hash")
    
    if not msg_id or not iv_b64 or not cipher_b64 or not hash_value:
        raise ValueError("Missing required fields in VOICE_MSG")
    
    # Chuyển iv và cipher về bytes để giải mã AES trên receiver
    return msg_id, base64_to_bytes(iv_b64), base64_to_bytes(cipher_b64), hash_value


def parse_ack(message: Dict[str, Any]) -> str:
    """
    Parse message ACK.
    
    Args:
        message: Dictionary từ JSON parse
        
    Returns:
        str: msg_id được xác nhận
        
    Raises:
        ValueError: Nếu message không hợp lệ
    """
    if message.get("type") != MSG_ACK:
        raise ValueError(f"Expected ACK, got {message.get('type')}")
    
    msg_id = message.get("msg_id")
    if not msg_id:
        raise ValueError("Missing msg_id in ACK")
    
    return msg_id


def parse_nack(message: Dict[str, Any]) -> tuple:
    """
    Parse message NACK.
    
    Args:
        message: Dictionary từ JSON parse
        
    Returns:
        tuple: (msg_id, reason)
        
    Raises:
        ValueError: Nếu message không hợp lệ
    """
    if message.get("type") != MSG_NACK:
        raise ValueError(f"Expected NACK, got {message.get('type')}")
    
    msg_id = message.get("msg_id")
    reason = message.get("reason")
    
    if not msg_id or not reason:
        raise ValueError("Missing msg_id or reason in NACK")
    
    return msg_id, reason


# ============ SERIALIZATION HELPERS ============

def encode_message(message: Dict[str, Any]) -> bytes:
    """
    Encode message thành JSON bytes để gửi qua network.
    
    Args:
        message: Dictionary message
        
    Returns:
        bytes: JSON encoded message
    """
    return json.dumps(message).encode('utf-8')


def decode_message(data: bytes) -> Dict[str, Any]:
    """
    Decode message từ JSON bytes nhận được từ network.
    
    Args:
        data: JSON encoded message
        
    Returns:
        Dict: Dictionary message
        
    Raises:
        ValueError: Nếu JSON không hợp lệ
    """
    try:
        return json.loads(data.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


def generate_msg_id() -> str:
    """
    Sinh UUID unique cho mỗi tin nhắn.
    
    Returns:
        str: UUID string
    """
    return str(uuid.uuid4())


# ============ TEST FUNCTIONS ============

def test_protocol():
    """
    Hàm test đơn giản để kiểm tra các hàm protocol.
    """
    print("[TEST] Testing protocol functions...")
    
    # Test HELLO
    from crypto_utils import generate_rsa_keypair, serialize_public_key
    priv_key, pub_key = generate_rsa_keypair()
    pem = serialize_public_key(pub_key)
    
    hello = create_hello("test-sender-id", pem)
    print(f"[TEST] HELLO created: {hello['type']}")
    
    sender_id, received_pem = parse_hello(hello)
    assert sender_id == "test-sender-id"
    print("[TEST] HELLO parse OK")
    
    # Test HELLO_ACK
    hello_ack = create_hello_ack("test-receiver-id", pem)
    print(f"[TEST] HELLO_ACK created: {hello_ack['type']}")
    
    receiver_id, _ = parse_hello_ack(hello_ack)
    assert receiver_id == "test-receiver-id"
    print("[TEST] HELLO_ACK parse OK")
    
    # Test KEY_EXCHANGE
    key_exchange = create_key_exchange(b"signed_info", b"encrypted_key")
    print(f"[TEST] KEY_EXCHANGE created: {key_exchange['type']}")
    
    # Test VOICE_MSG
    voice_msg = create_voice_message("msg-123", b"iv_data", b"cipher_data", "abc123hash")
    print(f"[TEST] VOICE_MSG created: {voice_msg['type']}")
    
    # Test ACK/NACK
    ack = create_ack("msg-123")
    print(f"[TEST] ACK created: {ack['type']}")
    
    nack = create_nack("msg-456", "INTEGRITY_ERROR")
    print(f"[TEST] NACK created: {nack['type']}, reason: {nack['reason']}")
    
    # Test encode/decode
    encoded = encode_message(hello)
    decoded = decode_message(encoded)
    assert decoded['type'] == MSG_HELLO
    print("[TEST] Encode/decode OK")
    
    print("[TEST] All protocol tests passed!")


if __name__ == "__main__":
    test_protocol()