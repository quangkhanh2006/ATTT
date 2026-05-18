# Hướng dẫn chạy SecureVoiceChat (Giao diện GUI)

## Yêu cầu hệ thống
- Python 3.10 hoặc mới hơn
- Môi trường ảo Python (virtual environment)
- Các thư viện cần thiết được liệt kê trong `requirements.txt`

## Cài đặt

1. **Tạo môi trường ảo**:
   ```bash
   python -m venv .venv
   ```

2. **Kích hoạt môi trường ảo**:
   - Trên Windows:
     ```bash
     .venv\Scripts\Activate.ps1
     ```
   - Trên macOS/Linux:
     ```bash
     source .venv/bin/activate
     ```

3. **Cài đặt các thư viện**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Cài đặt thêm thư viện cần thiết** (nếu chưa có):
   ```bash
   pip install pycryptodome pyaudio
   ```

## Chạy chương trình

### Chạy ứng dụng GUI
Mở terminal và chạy lệnh sau:
```bash
python main.py
```

**Lưu ý:** Không cần truyền tham số dòng lệnh. Ứng dụng sẽ tự động mở 2 cửa sổ:
- **Cửa sổ Receiver** (bên trái): Người nhận tin nhắn âm thanh
- **Cửa sổ Sender** (bên phải): Người gửi tin nhắn âm thanh

### Các bước sử dụng

#### Trên cửa sổ Receiver (Người nhận):
1. Nhấn nút **"👂 Lắng nghe"** để bắt đầu chờ kết nối
2. Chờ Sender kết nối và gửi tin nhắn
3. Khi nhận được âm thanh, hệ thống sẽ tự động giải mã và phát lại
4. Sau khi phát xong, có thể tiếp tục chờ tin nhắn tiếp theo
5. Nhấn **"🔄 Reset"** để reset và lắng nghe lại từ đầu

#### Trên cửa sổ Sender (Người gửi):
1. Nhấn nút **"🔗 Kết nối"** để kết nối tới Receiver
2. Sau khi kết nối thành công, nhấn **"🎙️ Ghi âm"** để bắt đầu ghi
3. Nhấn **"⏹ Dừng"** để dừng ghi âm
4. Nhấn **"📨 Gửi"** để mã hóa và gửi tin nhắn âm thanh
5. Có thể ghi âm và gửi nhiều lần liên tiếp
6. Nhấn **"🔄 Reset"** để ngắt kết nối và kết nối lại

## Quy trình bảo mật

1. **Handshake**: Xác lập kết nối P2P
2. **Trao đổi khóa RSA-2048**: Trao đổi khóa công khai RSA
3. **Xác thực chữ ký**: Ký số bằng RSA/PSS + SHA-256
4. **Mã hóa AES-256-CBC**: Mã hóa dữ liệu âm thanh
5. **Hash SHA-256**: Đảm bảo toàn vẹn dữ liệu

## Giải thích các bước trong quy trình bảo mật

### Bước 1: Handshake
- Sender gửi tin nhắn "Start Voice Chat" tới Receiver
- Receiver xác nhận bằng "Connection Accepted"
- Thiết lập kết nối P2P ban đầu

### Bước 2: Xác thực & Trao đổi khóa
- **Trao đổi khóa RSA-2048**: Cả hai bên trao đổi khóa công khai
- **Ký số**: Sender ký ID bằng RSA/PSS + SHA-256
- **Mã hóa AES key**: Sender tạo khóa AES-256 ngẫu nhiên và mã hóa bằng khóa công khai của Receiver (RSA-OAEP)
- Receiver giải mã khóa AES bằng khóa riêng

### Bước 3: Mã hóa & Gửi âm thanh
- **Mã hóa AES-256-CBC**: Mã hóa dữ liệu âm thanh với chế độ CBC
- **Hash SHA-256**: Tạo hash từ IV + Ciphertext để đảm bảo toàn vẹn
- Gửi: IV | Ciphertext | Digest
- Receiver xác minh hash và giải mã

## Cấu hình mặc định
| Tham số | Giá trị mặc định |
|---------|------------------|
| Cổng | 9000 |
| Địa chỉ IP | 127.0.0.1 |
| Tần số mẫu | 44100 Hz |
| Kênh | 1 (Mono) |
| Chunk size | 1024 bytes |

## Xử lý sự cố

### Lỗi thường gặp
1. **Import Error**: Thiếu thư viện
   - Giải pháp: `pip install -r requirements.txt`

2. **Port already in use**: Cổng đang được sử dụng
   - Giải pháp: Đổi cổng khác hoặc đóng ứng dụng đang dùng cổng đó

3. **Microphone not found**: Không tìm thấy microphone
   - Giải pháp: Kiểm tra thiết bị âm thanh của máy

4. **Connection refused**: Receiver chưa được khởi động
   - Giải pháp: Chạy Receiver trước khi chạy Sender

### Kiểm tra thư viện đã cài đặt
```bash
pip list
```

## Ghi chú
- Cổng mặc định: `9000`
- Địa chỉ IP mặc định: `127.0.0.1` (localhost)
- Nếu gặp lỗi, kiểm tra lại các thư viện đã được cài đặt đầy đủ chưa bằng lệnh:
  ```bash
  pip list
  ```

Chúc bạn thành công!