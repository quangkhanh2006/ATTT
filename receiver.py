"""
Module 5: receiver.py
=====================
Class VoiceReceiver: Nhận và giải mã tin nhắn âm thanh từ sender.

Các phương thức:
- __init__(host, port, receiver_id)
- listen()                → bind & accept TCP
- handshake()             → bước 1–2, gửi HELLO_ACK
- receive_key()           → bước 3–4, giải mã & xác thực AES key
- receive_voice()         → nhận VOICE_MSG → kiểm tra hash + chữ ký
                            → giải mã → phát âm → gửi ACK/NACK
- close()
"""

import socket
import threading
import time
from typing import Optional, Tuple

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


class VoiceReceiver:
    """
    Class VoiceReceiver: Nhận và giải mã tin nhắn âm thanh từ sender.
    
    Attributes:
        host: Địa chỉ IP để bind
        port: Cổng kết nối
        receiver_id: UUID của receiver
        server_socket: Server socket để lắng nghe
        client_socket: Client socket kết nối với sender
        private_key: Private key RSA của receiver
        public_key: Public key RSA của receiver
        sender_public_key: Public key RSA của sender (nhận được từ handshake)
        sender_id: UUID của sender (nhận được từ handshake)
        aes_key: Khóa AES phiên (32 bytes)
        session_active: Trạng thái phiên làm việc
        last_activity: Thời điểm hoạt động cuối cùng
    """
    
    def __init__(self, host: str, port: int, receiver_id: str):
        """
        Khởi tạo VoiceReceiver.
        
        Args:
            host: Địa chỉ IP để bind (để trống cho tất cả interface)
            port: Cổng kết nối
            receiver_id: UUID của receiver
        """
        self.host = host
        self.port = port
        self.receiver_id = receiver_id
        self.server_socket: Optional[socket.socket] = None
        self.client_socket: Optional[socket.socket] = None
        self.private_key = None
        self.public_key = None
        self.sender_public_key = None
        self.sender_id = None
        self.aes_key = None
        self.session_active = False
        self.last_activity = time.time()
        self.lock = threading.Lock()
        
        print(f"[RECEIVER] Initialized with receiver_id: {self.receiver_id}")
    
    def listen(self) -> bool:
        """
        Bind và lắng nghe kết nối TCP.
        
        Returns:
            bool: True nếu bind thành công
            
        Raises:
            Exception: Nếu bind thất bại
        """
        print(f"[RECEIVER] Listening on {self.host}:{self.port}...")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        
        print(f"[RECEIVER] Server listening on port {self.port}")
        
        # Chấp nhận kết nối
        print("[RECEIVER] Waiting for connection...")
        self.client_socket, address = self.server_socket.accept()
        print(f"[RECEIVER] Accepted connection from {address}")
        
        return True
    
    def handshake(self) -> bool:
        """
        Thực hiện bước handshake (Bước 1-2):
        - Bước 1: Nhận HELLO + sender_public_key
        - Bước 2: Gửi HELLO_ACK + public_key
        
        Returns:
            bool: True nếu handshake thành công
            
        Raises:
            Exception: Nếu handshake thất bại
        """
        print("[RECEIVER] Starting handshake...")
        
        # Bước 1: Nhận HELLO
        hello_msg = self._receive_message()
        self.sender_id, sender_pub_key_pem = parse_hello(hello_msg)
        self.sender_public_key = load_public_key(sender_pub_key_pem)
        
        print(f"[RECEIVER] HELLO received, sender_id: {self.sender_id}")
        
        # Sinh RSA keypair cho receiver
        self.private_key, self.public_key = generate_rsa_keypair()
        pub_key_pem = serialize_public_key(self.public_key)
        
        # Bước 2: Gửi HELLO_ACK
        hello_ack_msg = create_hello_ack(self.receiver_id, pub_key_pem)
        self._send_message(hello_ack_msg)
        print(f"[RECEIVER] HELLO_ACK sent with receiver_id: {self.receiver_id}")
        
        print("[RECEIVER] Handshake completed successfully")
        
        return True
    
    def receive_key(self) -> bool:
        """
        Thực hiện bước nhận và xác thực khóa (Bước 8-10):
        - Bước 8: Nhận KEY_EXCHANGE
        - Bước 9: Giải mã AES key + xác thực signature
        - Bước 10: Gửi KEY_EXCHANGE_ACK
        
        Returns:
            bool: True nếu nhận khóa thành công
            
        Raises:
            Exception: Nếu nhận khóa thất bại
        """
        print("[RECEIVER] Waiting for key exchange...")
        
        # Bước 8: Nhận KEY_EXCHANGE
        key_exchange_msg = self._receive_message()
        signature, encrypted_aes_key = parse_key_exchange(key_exchange_msg)
        
        print("[RECEIVER] KEY_EXCHANGE received")
        
        # Bước 9a: Giải mã AES key bằng RSA-OAEP
        try:
            self.aes_key = rsa_decrypt(self.private_key, encrypted_aes_key)
            print(f"[RECEIVER] AES key decrypted: {self.aes_key.hex()[:16]}...")
        except Exception as e:
            print(f"[RECEIVER] AES key decryption failed: {e}")
            self._send_message(create_key_exchange_ack("FAILED", "DECRYPT_ERROR"))
            raise
        
        # Bước 9b: Xác thực signature = RSA-PSS-Verify(sender_pub_key, payload, sig)
        # Tạo payload tương tự như sender: (sender_id || receiver_id || aes_key)
        payload = f"{self.sender_id}{self.receiver_id}".encode('utf-8') + self.aes_key
        
        if not rsa_verify(self.sender_public_key, payload, signature):
            print("[RECEIVER] Signature verification FAILED")
            self._send_message(create_key_exchange_ack("FAILED", "SIGNATURE_ERROR"))
            raise Exception("Signature verification failed")
        
        print("[RECEIVER] Signature verified OK")
        
        # Bước 10: Gửi KEY_EXCHANGE_ACK
        ack_msg = create_key_exchange_ack("OK")
        self._send_message(ack_msg)
        print("[RECEIVER] KEY_EXCHANGE_ACK sent: OK")
        
        print("[RECEIVER] Key exchange completed successfully")
        
        self.last_activity = time.time()
        self.session_active = True
        
        return True
    
    def receive_voice(self) -> bool:
        """
        Nhận và xử lý tin nhắn âm thanh (Bước 16-19).
        
        Returns:
            bool: True nếu nhận thành công
            
        Raises:
            Exception: Nếu nhận thất bại
        """
        if not self.session_active or not self.aes_key:
            raise Exception("Session not active. Please run listen(), handshake(), and receive_key() first.")
        
        print("[RECEIVER] Waiting for voice message...")
        
        # Bước 16: Nhận VOICE_MSG
        voice_msg = self._receive_message()
        msg_id, iv, cipher, received_hash = parse_voice_message(voice_msg)
        
        print(f"[RECEIVER] VOICE_MSG received, msg_id: {msg_id}")
        
        # Bước 16: Kiểm tra hash = SHA-256(iv || cipher)
        if not verify_hash(iv, cipher, received_hash):
            print(f"[RECEIVER] Hash verification FAILED")
            print(f"[RECEIVER] NACK sent: INTEGRITY_ERROR")
            self._send_message(create_nack(msg_id, "INTEGRITY_ERROR"))
            raise Exception("Hash verification failed")
        
        print("[RECEIVER] Hash verified OK")
        
        # Bước 17: Giải mã AES-256-CBC
        try:
            pcm_data = aes_decrypt(self.aes_key, iv, cipher)
            print(f"[RECEIVER] Audio decrypted: {len(pcm_data)} bytes")
        except Exception as e:
            print(f"[RECEIVER] Decryption FAILED: {e}")
            print(f"[RECEIVER] NACK sent: DECRYPT_ERROR")
            self._send_message(create_nack(msg_id, "DECRYPT_ERROR"))
            raise
        
        # Bước 18: Phát âm thanh
        print("[RECEIVER] Playing audio...")
        try:
            play_audio(pcm_data)
            print("[RECEIVER] Audio played successfully")
        except Exception as e:
            print(f"[RECEIVER] Audio playback warning: {e}")
        
        # Bước 19: Gửi ACK
        ack_msg = create_ack(msg_id)
        self._send_message(ack_msg)
        print(f"[RECEIVER] ACK sent for msg_id: {msg_id}")
        
        self.last_activity = time.time()
        
        return True
    
    def _send_message(self, message: dict) -> None:
        """
        Gửi message qua socket.
        
        Args:
            message: Dictionary message
            
        Raises:
            Exception: Nếu gửi thất bại
        """
        if not self.client_socket:
            raise Exception("Not connected")
        
        data = encode_message(message)
        # Prepend length as 4-byte header
        length = len(data)
        header = length.to_bytes(4, byteorder='big')
        
        self.client_socket.sendall(header + data)
    
    def _receive_message(self) -> dict:
        """
        Nhận message từ socket.
        
        Returns:
            dict: Dictionary message
            
        Raises:
            Exception: Nếu nhận thất bại
        """
        if not self.client_socket:
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
            chunk = self.client_socket.recv(num_bytes - len(data))
            if not chunk:
                raise Exception("Connection closed")
            data += chunk
        return data
    
    def close(self) -> None:
        """
        Đóng kết nối và dọn dẹp tài nguyên.
        """
        print("[RECEIVER] Closing connection...")
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        self.session_active = False
        print("[RECEIVER] Connection closed")
    
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
            print(f"[RECEIVER] Session timeout after {elapsed:.0f} seconds")
            return True
        return False


def run_receiver(host: str, port: int, receiver_id: str):
    """
    Hàm chạy receiver chính.
    
    Args:
        host: Địa chỉ IP để bind
        port: Cổng kết nối
        receiver_id: UUID của receiver
    """
    receiver = None
    try:
        # Khởi tạo và lắng nghe
        receiver = VoiceReceiver(host, port, receiver_id)
        receiver.listen()
        
        # Handshake
        receiver.handshake()
        
        # Nhận khóa
        receiver.receive_key()
        
        # Nhận tin nhắn âm thanh
        receiver.receive_voice()
        
        print("[RECEIVER] Voice message received successfully!")
        
    except Exception as e:
        print(f"[RECEIVER] Error: {e}")
        raise
        
    finally:
        if receiver:
            receiver.close()


if __name__ == "__main__":
    import sys
    import uuid
    
    if len(sys.argv) < 3:
        print("Usage: python receiver.py <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]  # Thường là '' để bind tất cả interface
    port = int(sys.argv[2])
    
    receiver_id = str(uuid.uuid4())
    print(f"[RECEIVER] Starting receiver with ID: {receiver_id}")
    
    run_receiver(host, port, receiver_id)