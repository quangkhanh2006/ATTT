"""
Module 2: audio_handler.py
===========================
Xử lý âm thanh: ghi âm, phát âm, và chuyển đổi định dạng.

Các hàm được định nghĩa:
- record_audio(duration_sec, sample_rate=44100) → bytes (PCM raw)
- play_audio(pcm_bytes, sample_rate=44100)
- bytes_to_base64(b) / base64_to_bytes(s)  [helper]
"""

import pyaudio
import wave
import numpy as np
import base64
import os
import tempfile
from typing import Optional

# Cấu hình audio
CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1


def record_audio(duration_sec: float, sample_rate: int = 44100) -> bytes:
    """
    Ghi âm thanh từ microphone trong một khoảng thời gian xác định.
    
    Args:
        duration_sec: Thời gian ghi âm (giây)
        sample_rate: Tần số mẫu (Hz), mặc định 44100 Hz
        
    Returns:
        bytes: Dữ liệu PCM raw
        
    Raises:
        Exception: Nếu không thể truy cập microphone
    """
    print(f"[AUDIO] Starting recording for {duration_sec} seconds...")
    
    p = pyaudio.PyAudio()
    
    # Mở stream để ghi âm
    stream = p.open(
        format=FORMAT,
        channels=CHANNELS,
        rate=sample_rate,
        input=True,
        frames_per_buffer=CHUNK
    )
    
    frames = []
    num_chunks = int(sample_rate / CHUNK * duration_sec)
    
    for i in range(num_chunks):
        try:
            data = stream.read(CHUNK)
            frames.append(data)
        except Exception as e:
            print(f"[AUDIO] Warning: Buffer underrun at chunk {i}: {e}")
    
    # Dừng và đóng stream
    stream.stop_stream()
    stream.close()
    p.terminate()
    
    # Kết hợp tất cả các chunk
    audio_data = b''.join(frames)
    
    print(f"[AUDIO] Recording completed. Total bytes: {len(audio_data)}")
    return audio_data


def play_audio(pcm_bytes: bytes, sample_rate: int = 44100) -> None:
    """
    Phát âm thanh từ dữ liệu PCM.
    
    Args:
        pcm_bytes: Dữ liệu PCM raw
        sample_rate: Tần số mẫu (Hz), mặc định 44100 Hz
        
    Raises:
        Exception: Nếu không thể phát âm thanh
    """
    print(f"[AUDIO] Starting playback of {len(pcm_bytes)} bytes...")
    
    p = pyaudio.PyAudio()
    
    # Mở stream để phát âm
    stream = p.open(
        format=FORMAT,
        channels=CHANNELS,
        rate=sample_rate,
        output=True
    )
    
    # Phát theo từng chunk để tránh buffer overflow
    chunk_size = CHUNK * 2  # 2 bytes per sample for 16-bit audio
    
    for i in range(0, len(pcm_bytes), chunk_size):
        chunk = pcm_bytes[i:i + chunk_size]
        if len(chunk) > 0:
            stream.write(chunk)
    
    # Đợi cho âm thanh phát hết
    stream.stop_stream()
    stream.close()
    p.terminate()
    
    print("[AUDIO] Playback completed")


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


def get_audio_devices() -> list:
    """
    Lấy danh sách các thiết bị audio khả dụng.
    
    Returns:
        list: Danh sách thông tin thiết bị audio
    """
    devices = []
    p = pyaudio.PyAudio()
    
    for i in range(p.get_device_count()):
        info = p.get_device_info_by_index(i)
        devices.append({
            'index': i,
            'name': info['name'],
            'max_input_channels': info['maxInputChannels'],
            'max_output_channels': info['maxOutputChannels']
        })
    
    p.terminate()
    return devices


def test_audio():
    """
    Hàm test đơn giản để kiểm tra các hàm xử lý âm thanh.
    """
    print("[TEST] Testing audio functions...")
    
    # Liệt kê các thiết bị audio
    devices = get_audio_devices()
    print(f"[TEST] Found {len(devices)} audio devices:")
    for dev in devices:
        print(f"  - {dev['name']} (input: {dev['max_input_channels']}, output: {dev['max_output_channels']})")
    
    print("[TEST] Audio device enumeration OK")
    print("[TEST] Note: Recording/Playback test requires microphone and speaker")


if __name__ == "__main__":
    test_audio()