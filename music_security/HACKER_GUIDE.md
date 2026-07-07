# 🔴 HƯỚNG DẪN TẤN CÔNG - Music Security Attack Toolkit

## ⚠️ CẢNH BÁO - MỤC ĐÍCH GIÁO DỤC

**Hướng dẫn này chỉ dùng cho ethical hacking, penetration testing và nghiên cứu bảo mật.**

- Chỉ test hệ thống bạn sở hữu hoặc có sự cho phép
- Truy cập trái phép vào hệ thống máy tính là hành vi bất hợp pháp
- Người vi phạm có thể bị truy cứu trách nhiệm hình sự theo luật an ninh mạng

---

## 📋 Mục Lục

1. [Tổng quan](#tổng-quan)
2. [Yêu cầu](#yêu-cầu)
3. [Cài đặt](#cài-đặt)
4. [Chuẩn bị Target](#chuẩn-bị-target)
5. [Các Phương thức Tấn công](#các-phương-thức-tấn-công)
6. [Sử dụng Nâng cao](#sử-dụng-nâng-cao)
7. [Tránh Phát hiện](#tránh-phát-hiện)
8. [Xử lý Lỗi](#xử-lý-lỗi)

---

## Tổng quan

Toolkit này cung cấp 6 vector tấn công khác nhau vào hệ thống Music Security:

| Tấn công | Độ khó | Mức độ ảnh hưởng | Rủi ro phát hiện |
|----------|--------|------------------|------------------|
| Spam/DoS | Dễ | Cao | Cao |
| MITM | Trung bình | Nghiêm trọng | Thấp |
| Fake Sender | Trung bình | Nghiêm trọng | Trung bình |
| SQL Injection | Dễ | Cao | Trung bình |
| Oversized Request | Dễ | Cao | Trung bình |
| Path Traversal | Trung bình | Cao | Thấp |

---

## Yêu cầu

### Phần mềm cần thiết
```bash
# Python 3.7+
python --version

# Thư viện cần thiết
pip install requests pycryptodome
```

### Yêu cầu hệ thống
- Windows/Linux/macOS
- Quyền truy cập mạng đến target (cổng 5000)
- Tối thiểu 100MB RAM

---

## Cài đặt

### Bước 1: Tải Toolkit
```bash
# Nếu có git
git clone <đường-dẫn-repository>
cd music_security

# Hoặc tải attacker_demo.py trực tiếp
```

### Bước 2: Cài đặt Dependencies
```bash
cd music_security
pip install -r requirements.txt
```

### Bước 3: Kiểm tra
```bash
python attacker_demo.py
# Sẽ hiện giao diện menu
```

---

## Chuẩn bị Target

### Cách A: Tấn công Localhost (Testing)
```bash
# Terminal 1: Khởi động receiver
cd music_security
python receiver_app_logic.py

# Terminal 2: Khởi động attacker
python attacker_demo.py
```

### Cách B: Tấn công Target Xa
```bash
# Nếu target ở 192.168.1.100:5000
python attacker_demo.py
# Nhập URL target khi được hỏi: http://192.168.1.100:5000
```

---

## Các Phương thức Tấn công

### 1. 🚨 Tấn công Spam/DoS

**Mục đích:** Làm tràn server với requests để gây từ chối dịch vụ

**Lệnh:**
```
Nhập lựa chọn: 1
Thời gian (giây, mặc định 10): 30
```

**Tác động:**
- Gửi 50+ requests/giây đến `/api/handshake`
- Đồng thời query `/api/status`
- Làm quá tải tài nguyên server

**Kết quả mong đợi:**
- Server chậm/không phản hồi
- Người dùng hợp lệ không kết nối được
- Security monitor có thể block IP của bạn

**Phòng thủ:**
- Rate limiting (100 req/60s per IP)
- Block IP sau khi phát hiện spam

---

### 2. 🔓 Tấn công MITM (Man-in-the-Middle)

**Mục đích:** Thay thế session key để giải mã file

**Lệnh:**
```
Nhập lựa chọn: 2
```

**Cách hoạt động:**
1. Chặn public key của receiver
2. Tạo session key độc hại
3. Ký với private key của attacker
4. Gửi forged key exchange request

**Luồng Code:**
```python
# Attacker tạo evil key
evil_session_key = b"EVIL_SESSION_KEY_123456"

# Mã hóa với public key của receiver
encrypted_sk = rsa_encrypt_session_key(receiver_pub, evil_session_key)

# Gửi đến receiver
POST /api/receive_session_key
{
    "encrypted_session_key": encrypted_sk,
    "signature": signature,
    "metadata_signed": "music_transfer|1234567890",
    "sender_public_key": attacker_public_key
}
```

**Điều kiện thành công:**
- Receiver chấp nhận evil session key
- Tất cả file sau này mã hóa với key này có thể giải mã bằng attacker

**Phòng thủ:**
- Verify sender public key against whitelist
- Sử dụng certificate pinning
- Theo dõi thay đổi key

---

### 3. 🎭 Tấn công Fake Sender

**Mục đích:** Gửi file độc hại đến receiver

**Lệnh:**
```
Nhập lựa chọn: 3
```

**Cách hoạt động:**
1. Tạo fake RSA keypair
2. Thực hiện handshake
3. Tạo malicious payload
4. Ký với fake private key
5. Gửi đến receiver

**Ví dụ Payload:**
```python
# Thay vì nhạc, gửi malicious data
plaintext = b"MALICIOUS_PAYLOAD_SIMULATION_" * 100

# Bọc trong encryption
ciphertext = triple_des_encrypt(session_key, iv, plaintext)

# Tạo fake metadata
metadata = {
    "filename": "malicious_track.mp3",
    "artist": "Fake Artist",
    "copyright": "INFECTED"
}
```

**Điều kiện thành công:**
- Receiver chấp nhận và lưu file
- File có vẻ hợp lệ nhưng chứa malicious data

**Phòng thủ:**
- Verify sender public key against known senders
- Kiểm tra file type (magic bytes)
- Quét virus trên file nhận được

---

### 4. 💉 SQL Injection

**Mục đích:** Khai thác lỗi database

**Lệnh:**
```
Nhập lựa chọn: 4
```

**Payloads sử dụng:**
```
' OR '1'='1
'; DROP TABLE files; --
1' UNION SELECT * FROM users--
admin'--
' OR 1=1--
```

**Target:** `/api/search?query=PAYLOAD`

**Dấu hiệu thành công:**
- HTTP 200 với data bất thường
- HTTP 500 với SQL error messages
- Lỗi database trong response

**Phòng thủ:**
- Parameterized queries
- Input sanitization
- Sử dụng ORM

---

### 5. 📦 Tấn công Oversized Request

**Mục đích:** Lấp đầy ổ đĩa / test giới hạn size

**Lệnh:**
```
Nhập lựa chọn: 5
Kích thước file MB (mặc định 50): 100
```

**Cách hoạt động:**
- Tạo large binary data (100MB chữ 'A')
- Gửi dưới dạng file upload đến `/api/send_file`
- Test xem server có giới hạn size phù hợp không

**Điều kiện thành công:**
- Server chấp nhận file > 100MB
- Disk space bị chiếm
- Server crash

**Phòng thủ:**
- `MAX_CONTENT_LENGTH = 100MB` trong Flask config
- Trả về HTTP 413 (Payload Too Large)

---

### 6. 🔍 Path Traversal

**Mục đích:** Đọc file nhạy cảm trên server

**Lệnh:**
```
Nhập lựa chọn: 6
```

**Payloads sử dụng:**
```
../../../etc/passwd
..\..\..\windows\system32\config\sam
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**Target:** `/download/{PAYLOAD}`

**Dấu hiệu thành công:**
- HTTP 200 với nội dung file
- Nội dung `/etc/passwd` trong response
- Windows SAM file data

**Phòng thủ:**
- Input validation (whitelist filenames)
- Sử dụng `secure_filename()` từ Werkzeug
- Chroot/jail environment

---

## Sử dụng Nâng cao

### Tự động Tấn công Liên hoàn

Chỉnh sửa `attacker_demo.py` để tạo custom attack chains:

```python
# Ví dụ: MITM + Fake Sender combo
attacker.mitm_attack_simulation()
time.sleep(2)
attacker.fake_sender_attack()
```

### Custom Payloads

Chỉnh sửa các attack methods để dùng payload của bạn:

```python
# Trong fake_sender_attack()
plaintext = b"YOUR_CUSTOM_PAYLOAD_HERE"
```

### Quét Target

Đầu tiên, xác định targets:
```bash
# Quét receivers trên LAN
python receiver_app.py  # Chạy trên terminal khác
# Dùng tính năng scan trong sender_app.py
```

---

## Tránh Phát hiện

### Tránh bị phát hiện

1. **Giảm Tốc độ Tấn công**
```python
# Trong spam_attack()
time.sleep(0.1)  # Chậm = khó phát hiện hơn
```

2. **Xoay IP**
```python
# Sử dụng proxy chains
proxies = {
    'http': 'http://proxy1:8080',
    'https': 'http://proxy2:8080'
}
session.proxies = proxies
```

3. **Giả mạo User-Agent**
```python
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}
session.headers.update(headers)
```

4. **Tấn công Phân tán**
```python
# Dùng nhiều máy
threads = []
for ip in botnet_ips:
    t = threading.Thread(target=attack, args=(ip,))
    threads.append(t)
    t.start()
```

---

## Xử lý Lỗi

### "Connection Refused"
```bash
# Kiểm tra receiver đang chạy không
netstat -an | findstr :5000

# Khởi động receiver
python receiver_app_logic.py
```

### "ModuleNotFoundError: No module named 'crypto_utils'"
```bash
# Đảm bảo đang ở đúng thư mục
cd music_security

# Chạy từ đúng path
python attacker_demo.py
```

### "Handshake Failed"
```bash
# Reset receiver state
# Trong browser: http://localhost:5000/api/reset (POST)
# Hoặc restart receiver_app.py
```

### "Key Exchange Failed"
```bash
# Kiểm tra logs receiver
# Đảm bảo handshake đã hoàn thành
# Verify crypto_utils đang hoạt động
```

---

## Hệ thống Thông báo Admin

### Giám sát Bảo mật Tự động

Khi bạn thực hiện tấn công, hệ thống `admin_notifier.py` sẽ tự động:

1. **Phát hiện tấn công** theo thời gian thực
2. **Gửi thông báo chi tiết** về lỗ hổng, nguyên nhân, và cách khắc phục
3. **Chặn IP** tự động (nếu vượt ngưỡng)
4. **Gửi Email & SMS** cho admin (mô phỏng)

### Ví dụ Output khi Admin được thông báo:

```
🚨 PHÁT HIỆN TẤN CÔNG: MITM_ATTACK
   IP: 192.168.1.100
   Mức độ: critical
   Mã sự kiện: SEC-1234567890-1234
   Thời gian: 2026-07-06 22:30:45

📊 THÔNG TIN LỖ HỔNG:
   Loại: Man-in-the-Middle Attack
   Mô tả: Chặn và thay thế session key trong quá trình key exchange...
   Nguyên nhân: Không có certificate pinning, sử dụng HTTP...
   Tác động: Hacker đọc được tất cả file nhạc đã mã hóa...

🛠️ CÁCH KHẮC PHỤC:
   1. Implement TLS/SSL certificates cho tất cả endpoints
   2. Sử dụng certificate pinning để prevent MITM
   3. Thêm fingerprint verification cho public keys
   4. Monitor session key changes và alert admin
   5. Implement perfect forward secrecy (PFS)
   6. Sử dụng HMAC để verify key exchange integrity
   7. Implement mutual TLS (mTLS) cho authentication

[EMAIL] 📧 Đã gửi cảnh báo tới ['admin@company.com']
  Subject: [CRITICAL] Cảnh báo bảo mật: mitm_attack
  Vulnerability: Man-in-the-Middle Attack

[SMS] 📱 Đã gửi SMS tới ['+84912345678']
  Message: 🚨 [CRITICAL] Man-in-the-Middle Attack từ 192.168.1.100. Root cause: Không có certificate pinning... Action: Block IP and investigate.
```

### Các Loại Tấn công Được Phát hiện:

| Tấn công | Độ nghiêm trọng | Thông bao | Hành động |
|----------|----------------|-----------|-----------|
| Spam/DoS | HIGH | Email + Block IP | Chặn IP sau 100 req/60s |
| MITM | CRITICAL | Email + SMS | Alert admin ngay |
| Fake Sender | CRITICAL | Email + SMS | Alert admin ngay |
| SQL Injection | CRITICAL | Email + SMS | Chặn IP + Alert |
| Oversized Request | HIGH | Email | Trả về 413 |
| Path Traversal | HIGH | Email + Block IP | Chặn IP + Alert |

---

## Kịch bản Tấn công

### Kịch bản 1: Chiếm toàn bộ
```bash
# Bước 1: DoS để distraction admin
python attacker_demo.py
# Chọn 1, duration 30

# Bước 2: Trong khi admin bận, thực hiện MITM
# Chọn 2

# Bước 3: Gửi file độc hại
# Chọn 3
```

### Kịch bản 2: Đánh cắp Dữ liệu
```bash
# Bước 1: MITM để lấy session key
# Chọn 2

# Bước 2: Chờ legitimate sender gửi file
# Bước 3: Giải mã file bị intercept
```

### Kịch bản 3: Triển khai Ransomware
```bash
# Bước 1: Fake sender attack
# Chọn 3

# Bước 2: Upload encrypted ransomware
# Bước 3: Chờ victim tải và execute
```

---

## Tuyên bố Pháp lý

```text
PHẦN MỀM NÀY CHỈ DÀNH CHO MỤC ĐÍCH GIÁO DỤC.

Tác giả không chịu trách nhiệm về việc lạm dụng hoặc thiệt hại do chương trình này gây ra.

Bằng cách sử dụng phần mềm này, bạn đồng ý:
1. Chỉ test hệ thống bạn sở hữu hoặc có giấy phép
2. Tuân thủ tất cả luật pháp và quy định hiện hành
3. Chấp nhận toàn bộ trách nhiệm cho hành động của bạn

Người vi phạm sẽ bị truy cứu đến mức độ tối đa theo luật pháp.
```

---

## Liên hệ

Để hợp tác nghiên cứu bảo mật:
- Email: security@research.local
- Chủ đề: "Music Security Research"

---

## Tài liệu Tham khảo

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CWE Top 25: https://cwe.mitre.org/top25/
- NIST Cybersecurity: https://www.nist.gov/cybersecurity

---

**Cập nhật lần cuối:** 2026-07-06  
**Phiên bản:** 1.0.0  
**Phân loại:** Educational / Red Team Tools