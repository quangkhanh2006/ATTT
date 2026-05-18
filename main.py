"""
Đề tài 17: Ứng dụng bảo mật tin nhắn âm thanh
Mã hóa AES-256-CBC + Xác thực RSA-2048 + Hash SHA-256
Yêu cầu: pip install pycryptodome pyaudio
"""

import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import time
import os
import struct
import hashlib
import json
import base64
import uuid

import pyaudio
from crypto_engine import CryptoEngine

# ── Cấu hình âm thanh ──────────────────────────────────────────────────────
CHUNK      = 1024
FORMAT     = pyaudio.paInt16
CHANNELS   = 1
RATE       = 44100
HOST       = "127.0.0.1"
PORT       = 9000
AUDIO_DIR  = "recordings"

# ── Màu sắc & font ─────────────────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
GREEN    = "#3fb950"
BLUE     = "#58a6ff"
RED      = "#f85149"
YELLOW   = "#d29922"
TEXT     = "#e6edf3"
SUBTEXT  = "#8b949e"
FONT     = ("Consolas", 10)
FONT_B   = ("Consolas", 10, "bold")
TITLE_F  = ("Consolas", 13, "bold")

# ═══════════════════════════════════════════════════════════════════════════
#  HÀM TIỆN ÍCH LƯU FILE ÂM THANH
# ═══════════════════════════════════════════════════════════════════════════
def ensure_audio_dir():
    """Tạo thư mục lưu file nếu chưa tồn tại"""
    if not os.path.exists(AUDIO_DIR):
        os.makedirs(AUDIO_DIR)

def save_wav_file(filename: str, audio_data: bytes) -> str:
    """
    Lưu dữ liệu âm thanh thành file WAV
    
    Args:
        filename: Tên file (không cần .wav)
        audio_data: Dữ liệu âm thanh raw
    
    Returns:
        Đường dẫn file đã lưu
    """
    ensure_audio_dir()
    filepath = os.path.join(AUDIO_DIR, f"{filename}.wav")
    
    # Tính số mẫu
    bytes_per_sample = 2  # 16-bit = 2 bytes
    num_samples = len(audio_data) // bytes_per_sample
    
    # Tạo header WAV
    import wave
    with wave.open(filepath, 'wb') as wav_file:
        wav_file.setnchannels(CHANNELS)
        wav_file.setsampwidth(bytes_per_sample)
        wav_file.setframerate(RATE)
        wav_file.writeframes(audio_data)
    
    return filepath

def load_wav_file(filepath: str) -> bytes:
    """
    Đọc dữ liệu âm thanh từ file WAV
    
    Args:
        filepath: Đường dẫn file WAV
    
    Returns:
        Dữ liệu âm thanh raw
    """
    import wave
    with wave.open(filepath, 'rb') as wav_file:
        frames = wav_file.readframes(wav_file.getnframes())
    return frames


def to_b64(data: bytes) -> str:
    """Chuyển bytes sang base64 string."""
    return base64.b64encode(data).decode('utf-8')


def from_b64(text: str) -> bytes:
    """Chuyển base64 string sang bytes."""
    return base64.b64decode(text.encode('utf-8'))


def generate_msg_id() -> str:
    """Tạo message id duy nhất."""
    return uuid.uuid4().hex


def list_audio_files() -> list:
    """Liệt kê các file âm thanh đã lưu"""
    ensure_audio_dir()
    files = []
    for f in os.listdir(AUDIO_DIR):
        if f.endswith('.wav'):
            filepath = os.path.join(AUDIO_DIR, f)
            size = os.path.getsize(filepath)
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(filepath)))
            files.append({
                'name': f[:-4],  # Bỏ .wav
                'path': filepath,
                'size': size,
                'time': mtime
            })
    # Sắp xếp theo thời gian mới nhất
    files.sort(key=lambda x: x['time'], reverse=True)
    return files

def delete_audio_file(filename: str) -> bool:
    """
    Xóa file âm thanh
    
    Args:
        filename: Tên file (không cần .wav)
    
    Returns:
        True nếu xóa thành công
    """
    filepath = os.path.join(AUDIO_DIR, f"{filename}.wav")
    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  CỬA SỔ CHUNG (base class)
# ═══════════════════════════════════════════════════════════════════════════
class BaseWindow:
    def __init__(self, root, title, role_color):
        self.root       = root
        self.crypto     = CryptoEngine()
        self.pa         = pyaudio.PyAudio()
        self.recording  = False
        self.audio_buf  = bytearray()
        self.connected  = False

        root.title(title)
        root.configure(bg=BG)
        root.resizable(False, False)
        self._build_ui(title, role_color)

    # ── Giao diện ─────────────────────────────────────────────────────────
    def _build_ui(self, title, role_color):
        # Header
        hdr = tk.Frame(self.root, bg=role_color, pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text=title, font=TITLE_F,
                 bg=role_color, fg=BG).pack()

        # Body
        body = tk.Frame(self.root, bg=BG, padx=12, pady=8)
        body.pack(fill="both", expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="⬤  Chưa kết nối")
        tk.Label(body, textvariable=self.status_var,
                 font=FONT_B, bg=BG, fg=RED).pack(anchor="w")

        sep = tk.Frame(body, height=1, bg=BORDER)
        sep.pack(fill="x", pady=6)

        # Log
        tk.Label(body, text="📋 LOG HỆ THỐNG",
                 font=FONT_B, bg=BG, fg=SUBTEXT).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(
            body, width=52, height=18,
            bg=PANEL, fg=TEXT, font=FONT,
            insertbackground=TEXT, relief="flat",
            borderwidth=1, highlightthickness=1,
            highlightbackground=BORDER
        )
        self.log.pack(pady=(4, 8))
        # tag màu
        self.log.tag_config("ok",      foreground=GREEN)
        self.log.tag_config("info",    foreground=BLUE)
        self.log.tag_config("warn",    foreground=YELLOW)
        self.log.tag_config("error",   foreground=RED)
        self.log.tag_config("section", foreground=SUBTEXT)

        # Nút điều khiển
        btn_frame = tk.Frame(body, bg=BG)
        btn_frame.pack(fill="x")
        self._build_buttons(btn_frame)

    def _btn(self, parent, text, cmd, color=BLUE, state="normal"):
        b = tk.Button(
            parent, text=text, command=cmd,
            bg=color, fg=BG, font=FONT_B,
            relief="flat", padx=10, pady=5,
            activebackground=TEXT, activeforeground=BG,
            cursor="hand2", state=state
        )
        b.pack(side="left", padx=4)
        return b

    def _build_buttons(self, frame):
        pass  # override

    # ── Log helper ────────────────────────────────────────────────────────
    def log_msg(self, msg, tag="info"):
        ts = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n", tag)
        self.log.see("end")

    def set_status(self, text, color=GREEN):
        self.status_var.set(f"⬤  {text}")
        for w in self.root.pack_slaves():
            for c in w.pack_slaves():
                if isinstance(c, tk.Label) and c.cget("textvariable") \
                        == str(self.status_var):
                    c.configure(fg=color)
                    break

    # ── Âm thanh ──────────────────────────────────────────────────────────
    def start_recording(self):
        self.recording  = True
        self.audio_buf  = bytearray()
        self.log_msg("🎙️  Đang ghi âm...", "warn")
        threading.Thread(target=self._record_loop, daemon=True).start()

    def _record_loop(self):
        stream = self.pa.open(
            format=FORMAT, channels=CHANNELS,
            rate=RATE, input=True, frames_per_buffer=CHUNK
        )
        while self.recording:
            self.audio_buf.extend(stream.read(CHUNK, exception_on_overflow=False))
        stream.stop_stream(); stream.close()

    def stop_recording(self):
        self.recording = False
        time.sleep(0.1)
        self.log_msg(f"✅ Ghi âm xong — {len(self.audio_buf):,} bytes", "ok")
        return bytes(self.audio_buf)

    def play_audio(self, raw: bytes):
        def _play():
            stream = self.pa.open(
                format=FORMAT, channels=CHANNELS,
                rate=RATE, output=True
            )
            stream.write(raw)
            stream.stop_stream(); stream.close()
            self.log_msg("🔊 Phát lại hoàn tất", "ok")
        threading.Thread(target=_play, daemon=True).start()

    # ── Gửi dữ liệu có length-prefix ──────────────────────────────────────
    @staticmethod
    def send_data(sock, data: bytes):
        sock.sendall(struct.pack(">I", len(data)) + data)

    @staticmethod
    def recv_data(sock) -> bytes:
        raw = BaseWindow._recv_exact(sock, 4)
        length = struct.unpack(">I", raw)[0]
        return BaseWindow._recv_exact(sock, length)

    def send_json(self, sock, message: dict):
        data = json.dumps(message).encode('utf-8')
        BaseWindow.send_data(sock, data)

    def recv_json(self, sock) -> dict:
        raw = BaseWindow.recv_data(sock)
        return json.loads(raw.decode('utf-8'))

    @staticmethod
    def _recv_exact(sock, n) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Kết nối bị ngắt")
            buf += chunk
        return buf


# ═══════════════════════════════════════════════════════════════════════════
#  CỬA SỔ SENDER
# ═══════════════════════════════════════════════════════════════════════════
class SenderWindow(BaseWindow):
    def __init__(self, root):
        super().__init__(root, "📤  SENDER — Người Gửi", GREEN)
        self.sock       = None
        self.audio_data = None
        self.sender_id  = uuid.uuid4().hex
        self.receiver_id = None

    def _build_buttons(self, frame):
        self.btn_connect = self._btn(frame, "🔗 Kết nối", self.connect, BLUE)
        self.btn_record  = self._btn(frame, "🎙️ Ghi âm",  self.toggle_record,
                                     YELLOW, "disabled")
        self.btn_send    = self._btn(frame, "📨 Gửi",     self.send_voice,
                                     GREEN,  "disabled")
        self.btn_reset   = self._btn(frame, "🔄 Reset",  self.reset_sender, BLUE, "disabled")

    # ── Reset sender ─────────────────────────────────────────────────────
    def reset_sender(self):
        """Reset trạng thái để kết nối lại"""
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        
        self.sock = None
        self.audio_data = None
        self.connected = False
        self.crypto = CryptoEngine()  # Tạo crypto mới
        
        self.btn_connect.config(state="normal")
        self.btn_record.config(state="disabled")
        self.btn_send.config(state="disabled")
        self.btn_reset.config(state="disabled")
        self.set_status("Chưa kết nối", RED)
        self.log_msg("🔄 Đã reset — sẵn sàng kết nối lại", "info")

    # ── Bước 1: Handshake ─────────────────────────────────────────────────
    def connect(self):
        def _conn():
            try:
                self.log_msg("━━━ BƯỚC 1: HANDSHAKE ━━━", "section")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((HOST, PORT))
                self.log_msg(f"Kết nối tới {HOST}:{PORT}", "info")

                self.send_json(self.sock, {
                    "type": "START",
                    "message": "Start Voice Chat"
                })

                resp = self.recv_json(self.sock)
                if resp.get("type") != "ACCEPT" or resp.get("message") != "Connection Accepted":
                    raise ConnectionError("Receiver từ chối kết nối")
                self.log_msg("✅ Handshake thành công", "ok")

                # ── Bước 2: Trao đổi khóa RSA ──────────────────────────
                self.log_msg("━━━ BƯỚC 2: XÁC THỰC & TRAO KHÓA ━━━", "section")
                self.send_json(self.sock, {
                    "type": "PUBLIC_KEY",
                    "sender_id": self.sender_id,
                    "public_key": to_b64(self.crypto.get_public_key_bytes())
                })

                resp = self.recv_json(self.sock)
                if resp.get("type") != "PUBLIC_KEY":
                    raise ConnectionError("Invalid public key response")

                self.receiver_id = resp.get("receiver_id")
                self.crypto.set_peer_public_key(from_b64(resp.get("public_key")))
                self.log_msg("✅ Trao đổi Public Key RSA-2048 xong", "ok")

                # Ký payload và trao khóa AES
                enc_aes = self.crypto.generate_and_encrypt_aes_key()
                payload = self.sender_id.encode("utf-8") + self.receiver_id.encode("utf-8") + self.crypto.aes_key
                signature = self.crypto.sign(payload)

                self.send_json(self.sock, {
                    "type": "KEY_EXCHANGE",
                    "signed_info": to_b64(signature),
                    "encrypted_aes_key": to_b64(enc_aes)
                })
                self.log_msg("✅ Đã gửi KEY_EXCHANGE với signed_info và encrypted_aes_key", "ok")

                ack = self.recv_json(self.sock)
                if ack.get("type") != "KEY_EXCHANGE_ACK" or ack.get("status") != "OK":
                    raise Exception(f"Key exchange failed: {ack.get('reason', 'unknown')}")
                self.log_msg("✅ Key exchange hoàn tất", "ok")

                self.connected = True
                self.root.after(0, lambda: [
                    self.btn_record.config(state="normal"),
                    self.btn_connect.config(state="disabled"),
                    self.btn_reset.config(state="normal"),
                    self.set_status("Đã kết nối", GREEN)
                ])
            except Exception as e:
                self.log_msg(f"❌ Lỗi: {e}", "error")
        threading.Thread(target=_conn, daemon=True).start()

    # ── Ghi âm toggle ─────────────────────────────────────────────────────
    def toggle_record(self):
        if not self.recording:
            self.btn_record.config(text="⏹ Dừng", bg=RED)
            self.start_recording()
        else:
            self.btn_record.config(text="🎙️ Ghi âm", bg=YELLOW)
            self.audio_data = self.stop_recording()
            self.btn_send.config(state="normal")

    # ── Bước 3: Mã hóa & Gửi ─────────────────────────────────────────────
    def send_voice(self):
        if not self.audio_data:
            return
        def _send():
            try:
                self.log_msg("━━━ BƯỚC 3: MÃ HÓA & GỬI ━━━", "section")
                iv, cipher, digest = self.crypto.encrypt_audio(self.audio_data)
                self.log_msg(f"✅ Mã hóa AES-256-CBC xong — {len(cipher):,} bytes", "ok")
                self.log_msg(f"✅ SHA-256(IV||Cipher): {digest.hex()[:32]}...", "ok")

                msg_id = generate_msg_id()
                self.send_json(self.sock, {
                    "type": "VOICE_MSG",
                    "msg_id": msg_id,
                    "iv": to_b64(iv),
                    "cipher": to_b64(cipher),
                    "hash": digest.hex()
                })
                self.log_msg(f"📨 Đã gửi VOICE_MSG msg_id={msg_id}", "info")

                result = self.recv_json(self.sock)
                if result.get("type") == "ACK" and result.get("msg_id") == msg_id:
                    self.log_msg("✅ ACK nhận được — gửi thành công!", "ok")
                    self.root.after(0, lambda: self.btn_record.config(state="normal"))
                    self.btn_send.config(state="disabled")
                elif result.get("type") == "NACK":
                    self.log_msg(f"❌ NACK: {result.get('reason', 'unknown')}", "error")
                else:
                    self.log_msg(f"❌ Phản hồi không hợp lệ: {result}", "error")
            except Exception as e:
                self.log_msg(f"❌ Lỗi: {e}", "error")
        threading.Thread(target=_send, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════
#  CỬA SỔ RECEIVER
# ═══════════════════════════════════════════════════════════════════════════
class ReceiverWindow(BaseWindow):
    def __init__(self, root):
        super().__init__(root, "📥  RECEIVER — Người Nhận", BLUE)
        self.server_sock = None
        self.conn        = None
        self.listening  = False
        self.receiver_id = uuid.uuid4().hex
        self.sender_id = None

    def _build_buttons(self, frame):
        self.btn_listen = self._btn(frame, "👂 Lắng nghe", self.start_listen, BLUE)
        self.btn_reset  = self._btn(frame, "🔄 Reset", self.reset_receiver, BLUE, "disabled")

    # ── Reset receiver ───────────────────────────────────────────────────
    def reset_receiver(self):
        """Reset trạng thái để lắng nghe lại"""
        try:
            if self.conn:
                self.conn.close()
            if self.server_sock:
                self.server_sock.close()
        except:
            pass
        
        self.conn = None
        self.server_sock = None
        self.connected = False
        self.crypto = CryptoEngine()  # Tạo crypto mới
        self.listening = False
        
        self.btn_listen.config(state="normal")
        self.btn_reset.config(state="disabled")
        self.set_status("Chưa kết nối", RED)
        self.log_msg("🔄 Đã reset — sẵn sàng lắng nghe lại", "info")

    # ── Lắng nghe kết nối ─────────────────────────────────────────────────
    def start_listen(self):
        if self.listening:
            return
        self.listening = True
        self.btn_listen.config(state="disabled")
        self.btn_reset.config(state="normal")
        self.log_msg(f"🔌 Đang lắng nghe tại {HOST}:{PORT}...", "info")
        threading.Thread(target=self._listen_loop, daemon=True).start()

    def _listen_loop(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((HOST, PORT))
            self.server_sock.listen(1)
            self.server_sock.settimeout(1.0)  # Timeout để kiểm tra listening flag
            
            while self.listening:
                try:
                    self.conn, addr = self.server_sock.accept()
                    self.log_msg(f"📡 Có kết nối từ {addr}", "info")
                    self._handle_connection()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.listening:
                        self.log_msg(f"❌ Lỗi: {e}", "error")
                    break
            
            # Đóng socket khi không còn lắng nghe
            if self.server_sock:
                try:
                    self.server_sock.close()
                except:
                    pass
                self.server_sock = None
                    
        except Exception as e:
            self.log_msg(f"❌ Lỗi: {e}", "error")
        finally:
            self.listening = False
            self.root.after(0, lambda: self.btn_listen.config(state="normal"))

    def _handle_connection(self):
        try:
            # ── Bước 1: Handshake ────────────────────────────────────────
            self.log_msg("━━━ BƯỚC 1: HANDSHAKE ━━━", "section")
            msg = self.recv_json(self.conn)
            self.log_msg(f"← {msg}", "info")
            if msg.get("type") != "START" or msg.get("message") != "Start Voice Chat":
                raise ConnectionError("Yêu cầu handshake không hợp lệ")

            self.send_json(self.conn, {
                "type": "ACCEPT",
                "message": "Connection Accepted"
            })
            self.log_msg("✅ Handshake hoàn tất", "ok")

            # ── Bước 2: Trao đổi khóa RSA ────────────────────────────────
            self.log_msg("━━━ BƯỚC 2: XÁC THỰC & TRAO KHÓA ━━━", "section")
            peer_pub_msg = self.recv_json(self.conn)
            if peer_pub_msg.get("type") != "PUBLIC_KEY":
                raise ConnectionError("Yêu cầu public key không hợp lệ")

            self.sender_id = peer_pub_msg.get("sender_id")
            self.crypto.set_peer_public_key(from_b64(peer_pub_msg.get("public_key")))
            self.send_json(self.conn, {
                "type": "PUBLIC_KEY",
                "receiver_id": self.receiver_id,
                "public_key": to_b64(self.crypto.get_public_key_bytes())
            })
            self.log_msg("✅ Trao đổi Public Key RSA-2048 xong", "ok")

            # ── Bước 3: Nhận KEY_EXCHANGE và xác thực AES key ──────────
            key_msg = self.recv_json(self.conn)
            if key_msg.get("type") != "KEY_EXCHANGE":
                raise ConnectionError("KEY_EXCHANGE không hợp lệ")

            signature = from_b64(key_msg.get("signed_info"))
            encrypted_aes_key = from_b64(key_msg.get("encrypted_aes_key"))
            self.crypto.decrypt_aes_key(encrypted_aes_key)

            payload = self.sender_id.encode("utf-8") + self.receiver_id.encode("utf-8") + self.crypto.aes_key
            if not self.crypto.verify(payload, signature):
                self.log_msg("❌ Chữ ký không hợp lệ!", "error")
                self.send_json(self.conn, {
                    "type": "KEY_EXCHANGE_ACK",
                    "status": "FAILED",
                    "reason": "SIGNATURE_ERROR"
                })
                return

            self.send_json(self.conn, {
                "type": "KEY_EXCHANGE_ACK",
                "status": "OK"
            })
            self.log_msg("✅ Giải mã AES Session Key và xác thực chữ ký thành công", "ok")
            self.connected = True
            self.root.after(0, lambda: self.set_status("Đã kết nối", GREEN))

            # ── Vòng lặp nhận nhiều tin nhắn ──────────────────────────────
            self.log_msg("━━━ SẴN SÀNG NHẬN TIN NHẮN ━━━", "section")
            
            while self.connected and self.listening:
                try:
                    self.conn.settimeout(5.0)
                    msg = self.recv_json(self.conn)
                    if msg.get("type") != "VOICE_MSG":
                        self.log_msg(f"⚠️  Bỏ qua message không hợp lệ: {msg}", "warn")
                        continue

                    iv = from_b64(msg.get("iv"))
                    cipher = from_b64(msg.get("cipher"))
                    digest = bytes.fromhex(msg.get("hash"))
                    msg_id = msg.get("msg_id")
                    self.log_msg(f"📩 Nhận VOICE_MSG msg_id={msg_id}", "info")

                    try:
                        audio = self.crypto.decrypt_audio(iv, cipher, digest)
                        self.log_msg("✅ Hash hợp lệ — toàn vẹn dữ liệu OK", "ok")
                        self.log_msg(f"✅ Giải mã AES-256-CBC xong — {len(audio):,} bytes", "ok")
                        self.send_json(self.conn, {
                            "type": "ACK",
                            "msg_id": msg_id,
                            "status": "OK"
                        })
                        self.play_audio(audio)
                        self.log_msg("🎉 Đã phát xong — sẵn sàng tin tiếp theo", "ok")
                    except ValueError as e:
                        self.log_msg(f"❌ {e}", "error")
                        self.send_json(self.conn, {
                            "type": "NACK",
                            "msg_id": msg_id,
                            "reason": "INTEGRITY_ERROR"
                        })
                        
                except socket.timeout:
                    continue
                except ConnectionError:
                    self.log_msg("⚠️  Kết nối bị ngắt", "warn")
                    break
                except Exception as e:
                    self.log_msg(f"❌ Lỗi khi nhận: {e}", "error")
                    break

            self.connected = False
            self.root.after(0, lambda: self.set_status("Chờ kết nối mới", YELLOW))
            self.log_msg("📌 Kết thúc phiên — nhấn Reset để lắng nghe lại", "info")
            
        except Exception as e:
            self.log_msg(f"❌ {e}", "error")
            self.connected = False


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN — Mở 2 cửa sổ
# ═══════════════════════════════════════════════════════════════════════════
def main():
    # Cửa sổ Receiver
    root_r = tk.Tk()
    ReceiverWindow(root_r)
    root_r.geometry("480x520+100+100")

    # Cửa sổ Sender
    root_s = tk.Toplevel(root_r)
    SenderWindow(root_s)
    root_s.geometry("480x520+620+100")

    root_r.mainloop()

if __name__ == "__main__":
    main()