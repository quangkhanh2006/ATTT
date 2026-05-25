"""
Kiểm tra tích hợp cho SecureVoiceChat
====================================
Script này kiểm tra toàn bộ quá trình giao tiếp end-to-end, handshake bảo mật,
trao đổi khóa, và giao thức mã hóa/giải mã tin nhắn âm thanh mà không
yêu cầu giao diện người dùng đồ họa (GUI) hay quyền truy cập phần cứng âm thanh thực.
"""

import threading
import time
import sys

# Thay thế (Monkey-patch) audio_handler để bỏ qua phần cứng microphone và loa thực
import audio_handler
audio_handler.record_audio = lambda duration, sample_rate=44100: b'\x00\x01\x02\x03' * 10000
audio_handler.play_audio = lambda pcm_bytes, sample_rate=44100: print(f"[MOCK AUDIO] Đã phát thành công {len(pcm_bytes)} bytes dữ liệu PCM được giải mã!")

from receiver import VoiceReceiver
from sender import VoiceSender

def run_receiver_thread():
    print("\n[TEST-SYSTEM] --- BẮT ĐẦU RECEIVER ---")
    receiver = None
    try:
        receiver = VoiceReceiver('127.0.0.1', 9001, "receiver-uuid-demo-123456")
        receiver.listen()
        
        # 1. Handshake
        receiver.handshake()
        
        # 2. Trao đổi khóa
        receiver.receive_key()
        
        # 3. Truyền tin nhắn âm thanh
        receiver.receive_voice()
        
        print("[TEST-SYSTEM] --- RECEIVER HOÀN THÀNH THÀNH CÔNG ---")
    except Exception as e:
        print(f"[TEST-SYSTEM] Lỗi luồng Receiver: {e}")
    finally:
        if receiver:
            receiver.close()

def run_sender_thread():
    # Đợi receiver bắt đầu lắng nghe
    time.sleep(1)
    print("\n[TEST-SYSTEM] --- BẮT ĐẦU SENDER ---")
    sender = None
    try:
        sender = VoiceSender('127.0.0.1', 9001, "sender-uuid-demo-654321")
        sender.connect()
        
        # 1. Handshake
        sender.handshake()
        
        # 2. Trao đổi khóa
        sender.exchange_key()
        
        # 3. Truyền tin nhắn âm thanh
        sender.send_voice(duration=1.0)
        
        print("[TEST-SYSTEM] --- SENDER HOÀN THÀNH THÀNH CÔNG ---")
    except Exception as e:
        print(f"[TEST-SYSTEM] Lỗi luồng Sender: {e}")
    finally:
        if sender:
            sender.close()

if __name__ == "__main__":
    print("======================================================================")
    print("SecureVoiceChat - Đang chạy bài kiểm tra giao thức bảo mật tự động End-to-End")
    print("======================================================================")
    
    r_thread = threading.Thread(target=run_receiver_thread)
    s_thread = threading.Thread(target=run_sender_thread)
    
    r_thread.start()
    s_thread.start()
    
    r_thread.join(timeout=10)
    s_thread.join(timeout=10)
    
    print("\n======================================================================")
    print("Bài kiểm tra đã hoàn tất thực thi.")
    print("======================================================================")
