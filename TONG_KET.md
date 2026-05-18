# Tổng kết dự án SecureVoiceChat

## 1. Mục tiêu dự án
- Xây dựng hệ thống giao tiếp âm thanh P2P bảo mật.
- Đảm bảo các yếu tố: **bí mật**, **toàn vẹn**, **xác thực**.
- Sử dụng mã hóa kết hợp hybrid cryptography: RSA cho trao đổi khóa và chữ ký, AES cho mã hóa dữ liệu âm thanh.

## 2. Các thành phần chính
- `main.py`: giao diện chính, khởi tạo hai cửa sổ Sender và Receiver bằng `tkinter`.
- `crypto_engine.py`: lớp `CryptoEngine` xử lý tất cả thao tác mật mã.
- `crypto_utils.py`: các hàm tiện ích chuyển đổi base64/bytes và hỗ trợ mã hóa/giải mã.
- `protocol.py`: định nghĩa giao thức JSON và các hàm tạo/parse message.
- `sender.py`: class `VoiceSender` thực hiện connect, handshake, key exchange, gửi voice message.
- `receiver.py`: class `VoiceReceiver` lắng nghe, nhận handshake, nhận khóa, giải mã và phát âm thanh.
- `audio_handler.py`: xử lý ghi âm, phát âm thanh và lưu/đọc file WAV.

## 3. Kiến trúc luồng dữ liệu
1. Sender kết nối TCP tới Receiver.
2. Handshake:
   - Sender gửi `HELLO` chứa `sender_id` và public key RSA.
   - Receiver trả `HELLO_ACK` chứa `receiver_id` và public key RSA.
3. Trao đổi khóa:
   - Sender tạo AES-256 session key.
   - Ký payload bằng `RSA-PSS(SHA-256)`.
   - Mã hóa AES key bằng `RSA-OAEP(SHA-256)` với public key của Receiver.
   - Gửi `KEY_EXCHANGE` chứa signature và AES key mã hóa.
   - Receiver giải mã AES key, kiểm tra chữ ký, trả `KEY_EXCHANGE_ACK`.
4. Gửi audio:
   - Sender ghi âm PCM.
   - Mã hóa bằng `AES-256-CBC` với IV ngẫu nhiên.
   - Tính hash `SHA-256(IV || ciphertext)`.
   - Gửi `VOICE_MSG` gồm `msg_id`, `iv`, `cipher`, `hash`.
   - Receiver kiểm tra hash, giải mã audio, phát âm thanh, trả `ACK` hoặc `NACK`.

## 4. Chi tiết bảo mật
- AES-256-CBC: mã hóa audio dữ liệu lớn.
- RSA-2048: trao đổi khóa và xác thực nguồn gốc.
- RSA-OAEP + SHA-256: bảo vệ AES key khi truyền.
- RSA-PSS + SHA-256: ký và verify payload nhằm đảm bảo authenticity.
- SHA-256 của `IV || ciphertext`: đảm bảo integrity của gói dữ liệu âm thanh.

## 5. Các message chính trong protocol
- `HELLO`: bắt đầu kết nối, gửi public key.
- `HELLO_ACK`: xác nhận và trả public key của receiver.
- `KEY_EXCHANGE`: trao đổi AES session key đã mã hóa cùng chữ ký.
- `KEY_EXCHANGE_ACK`: xác nhận thành công hoặc lỗi.
- `VOICE_MSG`: gửi tin nhắn âm thanh mã hóa.
- `ACK` / `NACK`: phản hồi kết quả nhận âm thanh.

## 6. Hướng dẫn chạy thử
1. Cài dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Chạy ứng dụng:
   ```bash
   python main.py
   ```
3. Ứng dụng sẽ mở hai cửa sổ:
   - Sender: gửi âm thanh.
   - Receiver: nhận và phát âm thanh.

## 7. Điểm đáng chú ý
- Dự án hoạt động theo mô hình P2P đơn giản, phù hợp demo trên cùng máy.
- Đã sử dụng `tkinter` cho giao diện trực quan.
- Mã nguồn tách rõ phần giao thức, phần mã hóa và phần audio.
- Các module có thể mở rộng để hỗ trợ nhiều lần gửi nhận và đa kết nối.

---

*File này là tổng kết toàn bộ dự án để dùng làm báo cáo hoặc tham khảo nhanh.*
