"""
Module 4: sender.py
===================
Class VoiceSender: Gửi tin nhắn âm thanh mã hóa đến receiver.

Các phương thức:
- __init__(host, port, sender_id)
- connect()               → thực hiện TCP connect
- handshake()             → bước 1–2, lưu receiver_pub_key
- exchange_key()          → bước 3–4, gửi KEY_EXCHANGE
- send_voice(duration)    → ghi âm → mã hóa → gửi VOICE_MSG → chờ ACK/NACK
- close()
"""

import socket
import threading
import time
from typing import Optional

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    load_public_key,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    aes_encrypt,
    aes_decrypt,
    compute_hash,
    verify_hash,
    generate_aes_key,
    generate_iv
)
from audio_handler import record_audio, play_audio
from protocol import (
    create_hello,
    create_hello_ack,
    create_key_exchange,
    create_key_exchange_ack,
    create_voice_message,
    create_ack,
    create_nack,
    parse_hello,
    parse_hello_ack,
    parse_key_exchange,
    parse_key_exchange_ack,
    parse_voice_message,
    parse_ack,
    parse_nack,
    encode_message,
    decode_message,
    generate_msg_id
)


class VoiceSender:
    """
    Class VoiceSender: Gửi tin nhắn âm thanh mã hóa đến receiver.
    
    Attributes:
        host: Địa chỉ IP của receiver
        port: Cổng kết nối
        sender_id: UUID của sender
        socket: Socket kết nối TCP
        private_key: Private key RSA của sender
        public_key: Public key RSA của sender
        receiver_public_key: Public key RSA của receiver (nhận được từ handshake)
        receiver_id: UUID của receiver (nhận được từ handshake)
        aes_key: Khóa AES phiên (32 bytes)
        session_active: Trạng thái phiên làm việc
        last_activity: Thời điểm hoạt động cuối cùng
    """
    
    def __init__(self, host: str, port: int, sender_id: str):
        """
        Khởi tạo VoiceSender.
        
        Args:
            host: Địa chỉ IP của receiver
            port: Cổng kết nối
            sender_id: UUID của sender
        """
        self.host = host
        self.port = port
        self.sender_id = sender_id
        self.socket: Optional[socket.socket] = None
        self.private_key = None
        self.public_key = None
        self.receiver_public_key = None
        self.receiver_id = None
        self.aes_key = None
        self.session_active = False
        self.last_activity = time.time()
        self.lock = threading.Lock()
        
        print(f"[SENDER] Initialized with sender_id: {self.sender_id}")
    
    def connect(self) -> bool:
        """
        Kết nối TCP đến receiver.
        
        Returns:
            bool: True nếu kết nối thành công
            
        Raises:
            Exception: Nếu không thể kết nối
        """
        print(f"[SENDER] Connecting to {self.host}:{self.port}...")
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(30)  # 30 seconds timeout
        
        try:
            self.socket.connect((self.host, self.port))
            print(f"[SENDER] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[SENDER] Connection failed: {e}")
            raise
    
    def handshake(self) -> bool:
        """
        Thực hiện bước handshake (Bước 1-2):
        - Bước 1: Gửi HELLO + public_key
        - Bước 2: Nhận HELLO_ACK + receiver_public_key
        
        Returns:
            bool: True nếu handshake thành công
            
        Raises:
            Exception: Nếu handshake thất bại
        """
        print("[SENDER] Starting handshake...")
        
        # Sinh RSA keypair cho sender
        self.private_key, self.public_key = generate_rsa_keypair()
        pub_key_pem = serialize_public_key(self.public_key)
        
        # Bước 1: Gửi HELLO
        hello_msg = create_hello(self.sender_id, pub_key_pem)
        self._send_message(hello_msg)
        print(f"[SENDER] HELLO sent with sender_id: {self.sender_id}")
        
        # Bước 2: Nhận HELLO_ACK
        response = self._receive_message()
        self.receiver_id, receiver_pub_key_pem = parse_hello_ack(response)
        self.receiver_public_key = load_public_key(receiver_pub_key_pem)
        
        print(f"[SENDER] HELLO_ACK received, receiver_id: {self.receiver_id}")
        print("[SENDER] Handshake completed successfully")
        
        return True
    
    def exchange_key(self) -> bool:
        """
        Thực hiện bước trao đổi khóa (Bước 3-4):
        - Bước 3: Gửi KEY_EXCHANGE (signed_info + encrypted_aes_key)
        - Bước 4: Nhận KEY_EXCHANGE_ACK
        
        Returns:
            bool: True nếu trao đổi khóa thành công
            
        Raises:
            Exception: Nếu trao đổi khóa thất bại
        """
        print("[SENDER] Starting key exchange...")
        
        # Bước 4: Sinh AES session key
        self.aes_key = generate_aes_key()
        print(f"[SENDER] AES session key generated: {self.aes_key.hex()[:16]}...")
        
        # Bước 5: Tạo signed_info = (sender_id || receiver_id || aes_key)
        # Encode các thành phần thành bytes
        payload = f"{self.sender_id}{self.receiver_id}".encode('utf-8') + self.aes_key
        
        # Ký payload bằng RSA-PSS
        signature = rsa_sign(self.private_key, payload)
        print("[SENDER] Payload signed with RSA-PSS")
        
        # Bước 6: Mã hóa AES key bằng RSA-OAEP
        encrypted_aes_key = rsa_encrypt(self.receiver_public_key, self.aes_key)
        print("[SENDER] AES key encrypted with RSA-OAEP")
        
        # Bước 7: Gửi KEY_EXCHANGE
        key_exchange_msg = create_key_exchange(signature, encrypted_aes_key)
        self._send_message(key_exchange_msg)
        print("[SENDER] KEY_EXCHANGE sent")
        
        # Bước 8: Nhận KEY_EXCHANGE_ACK
        response = self._receive_message()
        status, reason = parse_key_exchange_ack(response)
        
        if status != "OK":
            print(f"[SENDER] KEY_EXCHANGE_ACK FAILED: {reason}")
            raise Exception(f"Key exchange failed: {reason}")
        
        print("[SENDER] KEY_EXCHANGE_ACK received: OK")
        print("[SENDER] Key exchange completed successfully")
        
        self.last_activity = time.time()
        self.session_active = True
        
        return True
    
    def send_voice(self, duration: float = 5.0) -> bool:
        """
        Ghi âm, mã hóa và gửi tin nhắn âm thanh (Bước 11-19).
        
        Args:
            duration: Thời gian ghi âm (giây), mặc định 5 giây
            
        Returns:
            bool: True nếu gửi thành công
            
        Raises:
            Exception: Nếu gửi thất bại
        """
        if not self.session_active or not self.aes_key:
            raise Exception("Session not active. Please run handshake() and exchange_key() first.")
        
        print(f"[SENDER] Recording voice for {duration} seconds...")
        
        # Bước 11: Ghi âm PCM
        pcm_data = record_audio(duration)
        print(f"[SENDER] Audio recorded: {len(pcm_data)} bytes")
        
        # Bước 12: Sinh IV
        iv = generate_iv()
        print(f"[SENDER] IV generated: {iv.hex()[:16]}...")
        
        # Bước 13: Mã hóa AES-256-CBC
        cipher = aes_encrypt(self.aes_key, iv, pcm_data)
        print(f"[SENDER] Audio encrypted with AES-256-CBC: {len(cipher)} bytes")
        
        # Bước 14: Tính hash SHA-256(iv || cipher)
        hash_value = compute_hash(iv, cipher)
        print(f"[SENDER] Hash computed: {hash_value[:16]}...")
        
        # Bước 15: Gửi VOICE_MSG
        msg_id = generate_msg_id()
        voice_msg = create_voice_message(msg_id, iv, cipher, hash_value)
        self._send_message(voice_msg)
        print(f"[SENDER] VOICE_MSG sent, msg_id: {msg_id}")
        
        # Chờ ACK/NACK
        print("[SENDER] Waiting for ACK/NACK...")
        response = self._receive_message()
        
        if response.get("type") == "ACK":
            ack_msg_id = parse_ack(response)
            print(f"[SENDER] ACK received for msg_id: {ack_msg_id}")
            self.last_activity = time.time()
            return True
            
        elif response.get("type") == "NACK":
            nack_msg_id, reason = parse_nack(response)
            print(f"[SENDER] NACK received: {reason} for msg_id: {nack_msg_id}")
            raise Exception(f"Message failed: {reason}")
        
        else:
            raise Exception(f"Unexpected response type: {response.get('type')}")
    
    def _send_message(self, message: dict) -> None:
        """
        Gửi message qua socket.
        
        Args:
            message: Dictionary message
            
        Raises:
            Exception: Nếu gửi thất bại
        """
        if not self.socket:
            raise Exception("Not connected")
        
        data = encode_message(message)
        # Prepend length as 4-byte header
        length = len(data)
        header = length.to_bytes(4, byteorder='big')
        
        self.socket.sendall(header + data)
    
    def _receive_message(self) -> dict:
        """
        Nhận message từ socket.
        
        Returns:
            dict: Dictionary message
            
        Raises:
            Exception: Nếu nhận thất bại
        """
        if not self.socket:
            raise Exception("Not connected")
        
        # Read 4-byte length header
        header = self._recv_exact(4)
        length = int.from_bytes(header, byteorder='big')
        
        # Read message data
        data = self._recv_exact(length)
        return decode_message(data)
    
    def _recv_exact(self, num_bytes: int) -> bytes:
        """
        Nhận chính xác N bytes từ socket.
        
        Args:
            num_bytes: Số bytes cần nhận
            
        Returns:
            bytes: Dữ liệu nhận được
        """
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                raise Exception("Connection closed")
            data += chunk
        return data
    
    def close(self) -> None:
        """
        Đóng kết nối và dọn dẹp tài nguyên.
        """
        print("[SENDER] Closing connection...")
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.session_active = False
        print("[SENDER] Connection closed")
    
    def is_session_active(self) -> bool:
        """
        Kiểm tra phiên làm việc còn hoạt động không.
        
        Returns:
            bool: True nếu còn hoạt động
        """
        return self.session_active
    
    def check_session_timeout(self, timeout_seconds: int = 300) -> bool:
        """
        Kiểm tra phiên có timeout không (mặc định 5 phút).
        
        Args:
            timeout_seconds: Số giây timeout, mặc định 300 (5 phút)
            
        Returns:
            bool: True nếu phiên đã timeout
        """
        elapsed = time.time() - self.last_activity
        if elapsed > timeout_seconds:
            print(f"[SENDER] Session timeout after {elapsed:.0f} seconds")
            return True
        return False


def run_sender(host: str, port: int, sender_id: str, voice_duration: float = 5.0):
    """
    Hàm chạy sender chính.
    
    Args:
        host: Địa chỉ IP của receiver
        port: Cổng kết nối
        sender_id: UUID của sender
        voice_duration: Thời gian ghi âm (giây)
    """
    sender = None
    try:
        # Khởi tạo và kết nối
        sender = VoiceSender(host, port, sender_id)
        sender.connect()
        
        # Handshake
        sender.handshake()
        
        # Trao đổi khóa
        sender.exchange_key()
        
        # Gửi tin nhắn âm thanh
        sender.send_voice(voice_duration)
        
        print("[SENDER] Voice message sent successfully!")
        
    except Exception as e:
        print(f"[SENDER] Error: {e}")
        raise
        
    finally:
        if sender:
            sender.close()


if __name__ == "__main__":
    import sys
    import uuid
    
    if len(sys.argv) < 3:
        print("Usage: python sender.py <host> <port> [duration]")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    duration = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
    
    sender_id = str(uuid.uuid4())
    print(f"[SENDER] Starting sender with ID: {sender_id}")
    
    run_sender(host, port, sender_id, duration)