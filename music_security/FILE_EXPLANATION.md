# 📚 GIẢI THÍCH CÁC FILE TRONG HỆ THỐNG MUSIC SECURITY

## Tổng quan Hệ thống

Hệ thống Music Security gồm 2 thành phần chính:
- **Sender (Người gửi)**: Mã hóa và gửi file nhạc có bản quyền
- **Receiver (Người nhận)**: Nhận và giải mã file nhạc

---

## 1. 📤 sender_app.py

**Mô tả:** Ứng dụng Flask cho phía người GỬI file nhạc. Chạy trên cổng 5001.

### Chức năng chính:
1. **Giao diện Web**: UI Cyberpunk cho người dùng tương tác
2. **Handshake**: Xác thực kết nối với Receiver
3. **Key Exchange**: Trao đổi khóa phiên an toàn
4. **Mã hóa file**: Triple DES + DES metadata
5. **Ký số**: RSA/SHA-512
6. **Tính toàn vẹn**: SHA-512 hash

### Cấu trúc State (Bộ nhớ):
```python
STATE = {
    "private_key_pem": None,          # RSA private key của Sender
    "public_key_pem": None,           # RSA public key của Sender
    "session_key": None,              # Session key 24-byte cho Triple DES
    "receiver_public_key_pem": None,  # Public key của Receiver
    "receiver_url": None,             # Địa chỉ URL của Receiver
    "handshake_done": False,          # Đã handshake chưa?
    "key_exchange_done": False,       # Đã trao khóa chưa?
    "log": []                         # Log các sự kiện
}
```

### Các API Endpoints:

#### `/api/set_receiver` (POST)
- **Mục đích**: Thiết lập địa chỉ Receiver
- **Input**: `{"url": "http://192.168.1.100:5000"}`
- **Output**: `{"status": "ok", "url": "..."}`

#### `/api/handshake` (POST)
- **Mục đích**: Thực hiện bắt tay ban đầu với Receiver
- **Flow**:
  1. Gửi `{"msg": "Hello!"}` đến Receiver
  2. Nhận `{"msg": "Ready!"}` từ Receiver
  3. Đánh dấu `handshake_done = True`
- **Timing**: Đo thời gian phản hồi (ms)

#### `/api/key_exchange` (POST)
- **Mục đích**: Trao đổi khóa phiên an toàn
- **Flow**:
  1. Tạo RSA keypair 1024-bit (nếu chưa có)
  2. Lấy public key từ Receiver (`/api/get_public_key`)
  3. Tạo session key 24-byte (Triple DES)
  4. Ký metadata với RSA/SHA-512
  5. Mã hóa session key bằng RSA-OAEP
  6. Gửi đến Receiver (`/api/receive_session_key`)
  7. Nhận ACK/NACK
- **Tạo log timing**: `rsa_keygen`, `get_pubkey`, `session_keygen`, `sign`, `rsa_encrypt`, `send`

#### `/api/send_file` (POST)
- **Mục đích**: Mã hóa và gửi file nhạc
- **Input**: Form data với file, artist, copyright
- **Flow**:
  1. Đọc file nhạc
  2. Tạo IV 8-byte
  3. Mã hóa metadata (filename, copyright, artist, size, timestamp) bằng DES
  4. Mã hóa file bằng Triple DES CBC
  5. Tính SHA-512(IV || ciphertext)
  6. Ký gói tin (iv + cipher + hash) bằng RSA/SHA-512
  7. Gửi packet đến Receiver (`/api/receive_file`)
  8. Nhận ACK/NACK
- **Output**: JSON với timing, filesize, packet_size

#### `/api/status` (GET)
- **Mục đích**: Lấy trạng thái hiện tại
- **Output**: JSON với handshake, key_exchange, session_key_ready, receiver_url, log

#### `/api/reset` (POST)
- **Mục đích**: Reset toàn bộ trạng thái
- **Output**: `{"status": "ok"}`

#### `/api/ping_receiver` (GET)
- **Mục đích**: Kiểm tra Receiver có online không
- **Output**: `{"status": "online", "receiver": {...}}`

#### `/api/scan_receivers` (GET)
- **Mục đích**: Quét mạng LAN tìm Receiver đang chạy
- **Output**: `{"status": "ok", "receivers": [{"ip": "...", "port": "...", "url": "..."}]}`

### Các hàm phụ trợ:

#### `auto_discover_receiver_ip()`
- **Mục đích**: Tự động tìm IP Receiver qua UDP broadcast
- **Cách hoạt động**: 
  - Lắng nghe trên cổng 5555
  - Chờ message "I_AM_RECEIVER:5000"
  - Timeout 10 giây
- **Return**: URL của Receiver hoặc None

#### `get_receiver()`
- **Mục đích**: Lấy địa chỉ Receiver (từ cache hoặc auto-discover)
- **Logic**: 
  - Nếu đã có `receiver_url` → return
  - Nếu chưa → gọi `auto_discover_receiver_ip()`
  - Nếu không tìm thấy → default `http://127.0.0.1:5000`

#### `scan_receivers_lan(timeout=4.0)`
- **Mục đích**: Quét tất cả Receiver trong LAN
- **Cách hoạt động**:
  - Bind UDP socket trên cổng 5555
  - Lắng nghe broadcast messages trong 4 giây
  - Thu thập tất cả IP phát hiện được
- **Return**: List của `{"ip": ..., "port": ..., "url": ...}`

---

## 2. 📥 receiver_app.py và receiver_app_logic.py

**Mô tả:** Ứng dụng Flask cho phía NGƯỜI NHẬN file. Chạy trên cổng 5000.

### Sự khác biệt:
- `receiver_app.py`: Đầy đủ UI + admin dashboard
- `receiver_app_logic.py`: Chỉ có logic nhận file (không có UI)

### Chức năng chính:
1. **Nhận file đã mã hóa**: Giải mã Triple DES + DES
2. **Xác thực chữ ký**: RSA/SHA-512
3. **Kiểm tra toàn vẹn**: SHA-512 hash
4. **Lưu file**: Lưu vào thư mục `received/`
5. **Security Monitor**: Phát hiện tấn công (spam, SQL injection, brute force)
6. **Admin Dashboard**: Trang quản lý bảo mật

### Cấu trúc State:
```python
STATE = {
    "private_key_pem": None,
    "public_key_pem": None,
    "session_key": None,
    "sender_public_key_pem": None,
    "handshake_done": False,
    "key_exchange_done": False,
    "log": [],
    "received_files": []
}
```

### Các API Endpoints:

#### `/api/handshake` (POST)
- **Input**: `{"msg": "Hello!"}`
- **Output**: `{"msg": "Ready!", "status": "ok"}`
- **Logic**: Nếu msg == "Hello!" → đánh dấu handshake_done = True

#### `/api/get_public_key` (GET)
- **Điều kiện**: Phải handshake trước
- **Logic**: Tạo RSA keypair nếu chưa có, return public key
- **Output**: `{"public_key": "-----BEGIN PUBLIC KEY-----...", "status": "ok"}`

#### `/api/receive_session_key` (POST)
- **Input**:
  - `encrypted_session_key`: Session key đã mã hóa RSA
  - `signature`: Chữ ký số của Sender
  - `metadata_signed`: "music_transfer|timestamp"
  - `sender_public_key`: Public key của Sender
- **Logic**:
  1. Giải mã session key bằng RSA private key
  2. Xác thực chữ ký RSA/SHA-512
  3. Nếu hợp lệ → lưu session_key và sender_public_key
- **Output**: `{"status": "ok"}` hoặc `{"error": "..."}`

#### `/api/receive_file` (POST)
- **Input**:
  - `iv`: Initialization vector (base64)
  - `cipher`: File đã mã hóa Triple DES (base64)
  - `meta`: Metadata đã mã hóa DES (base64)
  - `hash`: SHA-512 hash (hex string)
  - `sig`: Chữ ký số (base64)
- **Logic**:
  1. Giải mã IV, ciphertext, metadata
  2. Verify SHA-512 hash
  3. Verify RSA signature
  4. Giải mã metadata (DES) → lấy filename, copyright, artist
  5. Giải mã file (Triple DES)
  6. Lưu file vào thư mục `received/`
- **Output**: `{"status": "ACK", "file_info": {...}}`

#### `/api/status` (GET)
- **Output**: JSON với handshake, key_exchange, log, received_files

#### `/api/reset` (POST)
- **Logic**: Reset toàn bộ STATE về None/False

#### `/download/<filename>` (GET)
- **Mục đích**: Download file đã nhận
- **Return**: File từ thư mục `received/`

#### `/stream/<filename>` (GET)
- **Mục đích**: Phát trực tiếp file nhạc trong browser
- **Return**: File stream

### Security Monitor (`admin_notifier.py`):

#### Phát hiện tấn công:
1. **Spam Detection**: >100 requests/60s từ cùng IP
2. **Brute Force**: >=5 lần đăng nhập thất bại
3. **SQL Injection**: Phát hiện SQL keywords trong query
4. **DoS**: Request >10MB

#### Phản ứng:
- Gửi email cho admin
- Gửi SMS cho critical events
- Tự động block IP

#### Admin Dashboard (`/admin`):
- Xem security events
- Chặn IP thủ công
- Thống kê tấn công

### Broadcast Presence:
```python
def broadcast_presence():
    # Phát broadcast UDP đến cổng 5555
    # Message: "I_AM_RECEIVER:5000"
    # Chu kỳ: 3 giây
```

---

## 3. 🔐 crypto_utils.py

**Mô tả:** Module chứa các hàm mã hóa/giải mã

### Các hàm chính:

#### RSA Operations:
```python
generate_rsa_keypair(bits=1024)  # Tạo cặp khóa RSA
rsa_encrypt_session_key(public_key_pem, session_key)  # Mã hóa session key
rsa_decrypt_session_key(private_key_pem, encrypted_b64)  # Giải mã
rsa_sign(private_key_pem, message)  # Ký số
rsa_verify(public_key_pem, message, signature_b64)  # Xác thực chữ ký
```

#### Triple DES Operations:
```python
generate_session_key()  # Tạo key 24-byte
generate_iv()  # Tạo IV 8-byte
triple_des_encrypt(key, iv, plaintext)  # Mã hóa CBC
triple_des_decrypt(key, iv, ciphertext)  # Giải mã CBC
```

#### DES Operations (Metadata):
```python
des_encrypt_metadata(key_8bytes, iv, plaintext)  # Mã hóa metadata
des_decrypt_metadata(key_8bytes, iv, ciphertext)  # Giải mã metadata
```

#### Hash Operations:
```python
compute_sha512(data)  # Tính SHA-512 hash
compute_integrity_hash(iv, ciphertext)  # SHA-512(IV || ciphertext)
verify_integrity_hash(iv, ciphertext, expected_hash)  # Verify hash
```

#### Helper Functions:
```python
get_timestamp()  # Lấy Unix timestamp
b64encode(data)  # Base64 encode
b64decode(s)  # Base64 decode
measure_time(func, *args)  # Đo thời gian thực thi hàm
```

---

## 4. 🛡️ admin_notifier.py

**Mô tả:** Hệ thống giám sát bảo mật và thông báo cho admin

### Các lớp (Classes):

#### SecurityEvent
- Đại diện cho một sự kiện bảo mật
- Attributes: event_type, source_ip, details, severity, timestamp, id

#### EmailNotifier
- Gửi email cảnh báo cho admin
- Mock implementation (chỉ print, không gửi thật)

#### SMSNotifier
- Gửi SMS cảnh báo cho admin
- Mock implementation (chỉ print, không gửi thật)

#### SecurityMonitor
- Theo dõi và phát hiện tấn công
- Methods:
  - `detect_spam(ip_address, user_agent)` - Phát hiện spam
  - `detect_brute_force(ip_address, failed_attempts)` - Phát hiện brute force
  - `detect_sql_injection(ip_address, query)` - Phát hiện SQL injection
  - `detect_dos(ip_address, request_size)` - Phát hiện DoS
  - `notify_admin(event)` - Gửi thông báo
  - `block_ip(ip_address)` - Chặn IP
  - `is_blocked(ip_address)` - Kiểm tra IP bị chặn

---

## 5. 🔴 attacker_demo.py

**Mô tả:** Script tấn công giáo dục vào receiver_app.py

### Các lớp và hàm:

#### MusicSecurityAttacker
- **Khởi tạo**: `target_url="http://localhost:5000"`
- **Attack Log**: Ghi lại tất cả các cuộc tấn công

#### Các phương thức tấn công:

1. **spam_attack(duration, requests_per_second)**
   - Gửi requests liên tục đến `/api/handshake` và `/api/status`
   - Mục đích: Làm quá tải server

2. **mitm_attack_simulation()**
   - Lấy public key của Receiver
   - Tạo evil session key
   - Gửi forged key exchange request
   - Mục đích: Thay thế session key

3. **fake_sender_attack()**
   - Tạo fake RSA keypair
   - Tạo malicious payload
   - Gửi file độc hại đến Receiver
   - Mục đích: Gửi file chứa malware

4. **sql_injection_attack()**
   - Test SQL payloads vào `/api/search`
   - Mục đích: Khai thác lỗi SQL injection

5. **oversized_request_attack(size_mb)**
   - Tạo file lớn (mặc định 50MB)
   - Gửi đến `/api/send_file`
   - Mục đích: Test giới hạn file size

6. **path_traversal_attack()**
   - Test path traversal payloads vào `/download/`
   - Mục đích: Đọc file nhạy cảm

#### Menu Interface:
```python
while True:
    print("1. Spam/DoS Attack")
    print("2. MITM Attack")
    print("3. Fake Sender Attack")
    print("4. SQL Injection")
    print("5. Oversized Request")
    print("6. Path Traversal")
    print("7. Run ALL Attacks")
    print("0. Exit")
    choice = input("Enter choice: ")
```

---

## 6. 📄 CACH_BI_HACK.md

**Mô tả:** Tài liệu gốc (bằng tiếng Anh) mô tả các lỗ hổng bảo mật

### Nội dung:
- Tổng quan hệ thống
- Các loại tấn công phổ biến
- Chi tiết từng phương thức tấn công
- Cách phòng chống
- Quy trình xử lý khi bị tấn công
- Dashboard admin
- Best practices

---

## 7. 📘 HACKER_GUIDE.md

**Mô tả:** Hướng dẫn tấn công chi tiết bằng tiếng Việt

### Nội dung:
- Hướng dẫn cài đặt attacker_demo.py
- 6 phương thức tấn công với code examples
- Cách sử dụng nâng cao (attack chains, custom payloads)
- Kỹ thuật tránh phát hiện (proxy, slow attack, user-agent spoofing)
- Troubleshooting thường gặp
- 3 kịch bản tấn công thực tế
- Tuyên bố pháp lý

---

## Luồng hoạt động hệ thống

### 1. Khởi động:
```bash
# Terminal 1: Receiver
python receiver_app_logic.py  # Port 5000
# → Tạo RSA keypair
# → Bắt đầu broadcast UDP "I_AM_RECEIVER:5000"
# → Mở UI tại http://localhost:5000

# Terminal 2: Sender
python sender_app.py  # Port 5001
# → Mở UI tại http://localhost:5001
```

### 2. Quy trình gửi file (Legitimate):
```
Sender UI → Handshake → Key Exchange → Select File → Encrypt → Sign → Send → ACK
```

#### Chi tiết mã hóa:
```
1. Session Key: 24 bytes (Triple DES)
2. IV: 8 bytes (random)
3. Metadata (JSON):
   - filename, copyright, artist, size, timestamp
   → Mã hóa bằng DES (session_key[:8])
4. FileContent (bytes):
   → Mã hóa bằng Triple DES CBC
5. Hash: SHA-512(IV || ciphertext)
6. Signature: RSA/SHA-512(iv_b64 + cipher_b64 + hash)
```

### 3. Quy trình nhận file:
```
Receiver UI → Handshake → Key Exchange → Receive Packet → Verify Hash → Verify Sig → Decrypt → Save File
```

### 4. Security Monitoring:
```
Mỗi request → before_request hook
→ Lấy IP
→ Kiểm tra blocked IPs
→ Detect spam (đếm requests trong 60s)
→ Detect SQL injection (keyword matching)
→ Detect oversized requests (>10MB)
→ Nếu phát hiện → notify_admin() → block_ip()
```

---

## Phụ thuộc giữa các file

```
sender_app.py
    ↓ imports
crypto_utils.py  (mã hóa/giải mã)

receiver_app.py
    ↓ imports
crypto_utils.py  (mã hóa/giải mã)
admin_notifier.py  (security monitoring)

attacker_demo.py
    ↓ imports
crypto_utils.py  (mã hóa/giải mã giả mạo)
    ↓ attacks
receiver_app.py  (target)
```

---

## Xử lý lỗi trong sender_app.py

**Lỗi "ModuleNotFoundError: No module named 'crypto_utils'":**

```python
# Đã fix bằng cách thêm:
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import ...
```

**Lý do**: Khi chạy từ thư mục `music_security`, Python không tìm thấy module `crypto_utils` vì nó không nằm trong `sys.path` mặc định. Thêm path của script vào `sys.path[0]` giải quyết vấn đề.

---

## Bảo mật Hệ thống

### Lớp bảo mật hiện có:
1. **Handshake**: Xác thực kết nối ban đầu
2. **Key Exchange**: RSA-OAEP + SHA-512
3. **Encryption**: Triple DES (24-byte key) + DES (8-byte key)
4. **Integrity**: SHA-512 hash
5. **Authentication**: RSA/SHA-512 signature
6. **Monitoring**: Rate limiting, IP blocking, SQL injection detection

### Lỗ hổng đã biết (theo CACH_BI_HACK.md):
- RSA 1024-bit (nên nâng lên 2048+)
- Triple DES đã lỗi thời (nên dùng AES-256)
- Chưa có authentication cho admin dashboard
- Chưa có HTTPS (dùng HTTP)
- Path traversal vulnerability trong `/download/`

---

## Cách chạy Demo

```bash
# 1. Khởi động Receiver
cd music_security
python receiver_app_logic.py
# Mở browser: http://localhost:5000

# 2. Khởi động Sender
python sender_app.py
# Mở browser: http://localhost:5001

# 3. Thực hiện Handshake và Key Exchange trên UI Sender
# 4. Chọn file và gửi

# 5. Xem file nhận được trên Receiver UI
```

---

## Cách chạy Attacker Demo

```bash
# Đảm bảo Receiver đang chạy
python receiver_app_logic.py

# Chạy attacker
python attacker_demo.py

# Nhập 'y' và chọn tấn công
```

---

## Tài liệu tham khảo

- `CACH_BI_HACK.md` - Tài liệu gốc bằng tiếng Anh
- `HACKER_GUIDE.md` - Hướng dẫn tấn công chi tiết bằng tiếng Việt
- `attacker_demo.py` - Script tấn công executable
- `crypto_utils.py` - Module mã hóa

---

**Tác giả:** Security Team  
**Ngày tạo:** 2026-07-06  
**Phiên bản:** 1.0.0