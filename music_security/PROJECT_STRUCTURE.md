# Cấu trúc thư mục dự án music_security

## Tổng quan
Dự án mô phỏng hệ thống truyền file nhạc bản quyền an toàn với các tấn công bảo mật và cơ chế phát hiện.

## Cấu trúc thư mục

```
music_security/
├── README.md                           # (nếu có) Giới thiệu dự án
├── requirements.txt                    # Dependencies của dự án
├── TODO.md                            # Danh sách công việc cần làm
├── FILE_EXPLANATION.md                 # Giải thích chi tiết các file
├── HACKER_GUIDE.md                     # Hướng dẫn tấn công/hack
├── CACH_BI_HACK.md                     # Cách phòng chống tấn công
│
├── Core Application Files
│   ├── sender_app.py                   # Ứng dụng gửi file (Sender) - Port 5001
│   ├── receiver_app.py                 # Ứng dụng nhận file (Receiver) - Port 5000
│   └── receiver_app_logic.py           # Logic xử lý cho Receiver
│
├── Security & Cryptography
│   ├── crypto_utils.py                 # Tiện ích mã hóa: RSA, Triple DES, SHA-512
│   ├── admin_notifier.py               # Hệ thống giám sát và thông báo bảo mật
│   └── test_integration.py             # Test tích hợp hệ thống
│
├── Attack Demos
│   ├── mitm_demo.py                    # Demo MITM attack thực tế (đang sửa)
│   ├── mitm_attack_demo.py             # Demo MITM attack mô phỏng
│   └── attacker_demo.py                # Demo các tấn công khác
│
├── Static Files
│   ├── static/                         # Thư mục chứa file audio/demo
│   │   ├── *.mp3                       # Các file nhạc mẫu
│   │   └── ...
│   │
│   ├── templates/                      # Templates HTML (nếu có)
│   │
│   ├── uploads/                        # Thư mục upload file từ Sender
│   │
│   └── received/                       # Thư mục lưu file nhận được ở Receiver
│       ├── nguoimiennuichat.mp3
│       └── tuyenbangai.mp3
│
└── Documentation
    └── PROJECT_STRUCTURE.md            # File này - Mô tả cấu trúc dự án
```

## Mô tả chi tiết các file quan trọng

### 1. sender_app.py
- **Mô tả**: Ứng dụng Flask đóng vai trò là Sender (người gửi file)
- **Chức năng**:
  - Handshake với Receiver
  - Tạo RSA keypair và session key
  - Mã hóa file bằng Triple DES + RSA
  - Gửi file đến Receiver qua HTTP API
- **Port**: 5001
- **Dependencies**: Flask, requests, crypto_utils

### 2. receiver_app.py
- **Mô tả**: Ứng dụng Flask đóng vai trò là Receiver (người nhận file)
- **Chức năng**:
  - Nhận handshake từ Sender
  - Tạo RSA keypair
  - Giải mã session key bằng RSA private key
  - Xác thực chữ ký RSA/SHA-512
  - Giải mã file bằng Triple DES
  - Lưu file vào thư mục `received/`
  - Phát hiện tấn công bảo mật (MITM, SQL injection, spam, etc.)
- **Port**: 5000
- **Dependencies**: Flask, crypto_utils, admin_notifier

### 3. crypto_utils.py
- **Mô tả**: Module chứa các hàm mã hóa/giải mã
- **Chức năng**:
  - RSA 1024-bit: Tạo khóa, mã hóa/giải mã session key, ký/xác thực chữ ký
  - Triple DES (3DES): Mã hóa/giải mã file
  - DES: Mã hóa/giải mã metadata
  - SHA-512: Tính hash toàn vẹn
  - Helper functions: encode/decode base64, tạo IV, timestamp
- **Libraries**: pycryptodome

### 4. admin_notifier.py
- **Mô tả**: Hệ thống giám sát bảo mật và thông báo cho admin
- **Chức năng**:
  - `SecurityEvent`: Đại diện cho sự kiện bảo mật
  - `SecurityMonitor`: Phát hiện tấn công (spam, brute force, SQL injection, MITM, etc.)
  - `EmailNotifier`: Mô phỏng gửi email cảnh báo
  - `SMSNotifier`: Mô phỏng gửi SMS cảnh báo
  - Flask integration: `init_security_monitor()` để tự động bảo vệ routes

### 5. mitm_demo.py / mitm_attack_demo.py
- **Mô tả**: Demo tấn công Man-in-the-Middle
- **Chức năng**:
  - Mô phỏng kịch bản tấn công MITM
  - Thay thế session key bằng evil key
  - Gửi file độc hại đến Receiver
  - Phát hiện tấn công và cảnh báo admin
- **Lưu ý**: File mitm_demo.py hiện tại được sửa để thực hiện tấn công thực tế vào receiver_app đang chạy

### 6. attacker_demo.py
- **Mô tả**: Demo các loại tấn công khác nhau vào hệ thống

### 7. test_integration.py
- **Mô tả**: Test suite cho các integration test
- **Chức năng**: Kiểm tra toàn bộ luồng handshake, key exchange, gửi/nhận file

## Luồng hoạt động chính

### Luồng hợp lệ (Legitimate Flow)
```
Sender (5001)                          Receiver (5000)
     |                                      |
     |--- 1. Handshake -------------------->|
     |<-- 2. Ready! ------------------------|
     |                                      |
     |--- 3. Get Public Key --------------->|
     |<-- 4. RSA Public Key ----------------|
     |                                      |
     |--- 5. Send Session Key (encrypted) -->|
     |    + Signature                       |
     |<-- 6. Key Exchange OK ---------------|
     |                                      |
     |--- 7. Send Encrypted File ---------->|
     |    + Metadata + Hash + Signature     |
     |<-- 8. ACK + File Info ---------------|
     |                                      |
```

### Luồng tấn công MITM (Attack Flow)
```
Attacker (mitm_demo.py)
     |
     |--- 1. Scan Receiver ----------------->|
     |<-- 2. Status OK ---------------------|
     |                                      |
     |--- 3. Handshake --------------------->|
     |<-- 4. Ready! ------------------------|
     |                                      |
     |--- 5. Get Public Key --------------->|
     |<-- 6. RSA Public Key ----------------|
     |                                      |
     |=== GÌ TIẾP THEO? ===================|
     |                                      |
     |--- (Giả mạo Sender)                  |
     |--- 7. Send Evil Session Key --------->|
     |    (Mã hóa bằng Receiver Public Key)  |
     |    (Ký bằng Evil Private Key)         |
     |<-- 8. Key Exchange OK ---------------|
     |    (Receiver chấp nhận Evil Key!)    |
     |                                      |
     |--- 9. Send Malicious File ---------->|
     |    (Mã hóa bằng Evil Session Key)     |
     |<-- 10. ACK --------------------------|
     |    (Receiver lưu file độc hại!)       |
     |                                      |
     |--- 11. Monitor detects MITM --------->|
     |    (SecurityMonitor phát hiện)        |
     |--> 12. Alert Admin ----------------->|
     |    (Email/SMS notification)           |
```

## Cài đặt & Sử dụng

### Cài đặt dependencies
```bash
pip install -r requirements.txt
```

### Chạy các thành phần

1. **Chạy Receiver** (Port 5000):
   ```bash
   python receiver_app.py
   ```

2. **Chạy Sender** (Port 5001):
   ```bash
   python sender_app.py
   ```

3. **Chạy MITM Demo** (Attacker):
   ```bash
   python mitm_demo.py
   ```

## Công nghệ sử dụng

- **Web Framework**: Flask
- **Cryptography**:
  - RSA 1024-bit (OAEP + SHA-256/SHA-512)
  - Triple DES (3DES) CBC mode
  - DES CBC mode
  - SHA-512 Integrity Hash
- **Networking**: HTTP/REST API, requests
- **Security Monitoring**: Custom security monitor với rule-based detection

## Bảo mật & Hacking

### Các lỗ hổng được mô phỏng
1. **MITM (Man-in-the-Middle)**: Thay thế session key
2. **SQL Injection**: Chèn SQL code vào parameters
3. **Spam/DoS**: Gửi hàng loạt requests
4. **Brute Force**: Tấn công đăng nhập
5. **Path Traversal**: Đọc file nhạy cảm
6. **Fake Sender**: Giả mạo người gửi

### Cách phòng chống
Xem file `CACH_BI_HACK.md` và phần remediation trong `admin_notifier.py`

## Lưu ý quan trọng

⚠️ **Đây là dự án giáo dục/đào tạo bảo mật**

- Các tấn công chỉ mô phỏng trong môi trường local
- File nhạc trong `static/` và `received/` là file mẫu cho demo
- Không sử dụng cho mục đích xấu
- Chỉ chạy trên localhost hoặc mạng nội bộ kiểm soát

## Maintainer

Dự án được phát triển cho mục đích học tập và nghiên cứu về an ninh mạng.

---
*Last updated: 2024*