# 🔐 CÁC CÁCH BỊ HACK TRONG HỆ THỐNG BẢO MẬT MUSIC SECURITY

## 📋 Mục lục
1. [Tổng quan hệ thống](#tổng-quan-hệ-thống)
2. [Các loại tấn công phổ biến](#các-loại-tấn-công-phổ-biến)
3. [Chi tiết từng phương thức tấn công](#chi-tiết-từng-phương-thức-tấn-công)
4. [Cách phòng chống](#cách-phòng-chống)
5. [Quy trình xử lý khi bị tấn công](#quy-trình-xử-lý-khi-bị-tấn-công)

---

## Tổng quan hệ thống

Hệ thống Music Security sử dụng kiến trúc Client-Server với 2 thành phần chính:
- **Sender**: Gửi file nhạc đã mã hóa
- **Receiver**: Nhận và giải mã file nhạc

### Các lớp bảo mật hiện có:
1. **Handshake**: Xác thực kết nối ban đầu
2. **Key Exchange**: Trao đổi khóa phiên (Session Key) bằng RSA-OAEP
3. **Mã hóa Triple DES**: Mã hóa file nhạc
4. **Chữ ký số RSA/SHA-512**: Xác thực nguồn gốc
5. **Hash SHA-512**: Kiểm tra toàn vẹn dữ liệu

---

## Các loại tấn công phổ biến

### 1. 🚨 Spam Attack / DoS Attack

**Mô tả**: Hacker gửi hàng loạt requests liên tục làm quá tải server

**Cách thực hiện**:
```python
# Hacker script đơn giản
import requests
import time

while True:
    try:
        requests.post("http://receiver-server/api/handshake", 
                     json={"msg": "Hello!"})
        requests.get("http://receiver-server/api/status")
        # Gửi hàng trăm requests/giây
    except:
        pass
```

**Hậu quả**:
- Server quá tải, không phục vụ được người dùng hợp lệ
- Tài nguyên hệ thống bị chiếm dụng
- Giảm hiệu suất hoạt động

**Cách phát hiện**:
- Hệ thống giám sát đếm số requests từ mỗi IP
- Nếu > 100 requests trong 60s → đánh dấu spam

---

### 2. 🔓 Man-in-the-Middle Attack (MITM)

**Mô tả**: Hacker chặn và đọc traffic giữa Sender và Receiver

**Cách thực hiện**:
```
Attacker
    ↓
[Bắt được gói tin RSA key exchange]
    ↓
[Giải mã hoặc sửa đổi Session Key]
    ↓
[Chuyển tiếp gói tin đã bị sửa]
```

**Hậu quả**:
- Hacker có thể đọc được file nhạc đã giải mã
- Hacker có thể thay thế file nhạc bằng file malicious
- Chữ ký số bị bỏ qua nếu không được kiểm tra kỹ

**Cách phòng chống**:
- Luôn kiểm tra chữ ký RSA trước khi giải mã
- Sử dụng HTTPS thay vì HTTP (trong môi trường production)
- Certificate pinning

---

### 3. 🎭 Fake Sender Attack

**Mô tả**: Hacker giả mạo Sender gửi file độc hại

**Cách thực hiện**:
```python
# Hacker tạo request giả mạo
fake_packet = {
    "iv": "base64_iv",
    "cipher": "base64_ma_hoa",
    "meta": "base64_metadata",
    "hash": "fake_hash",
    "sig": "fake_signature"
}

# Gửi đến Receiver
requests.post("http://receiver/api/receive_file", json=fake_packet)
```

**Hậu quả**:
- Nhận được file không mong muốn/hack
- Hacker có thể gửi file chứa mã độc
- Xâm phạm tính toàn vẹn hệ thống

**Cách phòng chống**:
- Luôn xác minh chữ ký RSA trước khi giải mã
- Kiểm tra hash SHA-512 của file
- Chỉ chấp nhận Sender đã đăng ký (whitelist)

---

### 4. 💣 SQL Injection

**Mô tả**: Hacker chèn SQL code vào các tham số

**Cách thực hiện**:
```
GET /api/search?query='; DROP TABLE files; -- 
POST /api/login {"username": "admin' OR '1'='1", "password": "xxx"}
```

**Hậu quả**:
- Xóa cơ sở dữ liệu
- Đánh cắp thông tin nhạy cảm
- Chiếm quyền điều khiển server

**Cách phòng chống**:
- Sử dụng parameterized queries
- Input validation và sanitization
- Hệ thống đã có detect_sql_injection() trong SecurityMonitor

---

### 5. 🔑 Brute Force Attack

**Mô tả**: Hacker thử mật khẩu liên tục để đăng nhập

**Cách thực hiện**:
```python
# Đoán mật khẩu admin
passwords = ["admin123", "password", "123456", ...]
for pwd in passwords:
    login("admin", pwd)
```

**Hậu quả**:
- Chiếm được tài khoản admin
- Truy cập vào hệ thống quản trị
- Đánh cắp dữ liệu

**Cách phòng chống**:
- Giới hạn số lần đăng nhập thất bại (5 lần)
- Lock account sau nhiều lần thất bại
- Sử dụng CAPTCHA
- Hệ thống đã có detect_brute_force() trong SecurityMonitor

---

### 6. 📦 Oversized Request Attack

**Mô tả**: Hacker gửi file cực lớn làm đầy ổ đĩa server

**Cách thực hiện**:
```python
# Tạo file 100MB chứa random data
with open("huge_file.bin", "wb") as f:
    f.write(os.urandom(100 * 1024 * 1024))

# Gửi đến server
requests.post("http://receiver/api/receive_file", 
             files={"file": open("huge_file.bin", "rb")})
```

**Hậu quả**:
- Ổ đĩa server bị đầy
- Server crash
- Mất dữ liệu quan trọng

**Cách phòng chống**:
- Giới hạn kích thước file upload (MAX_CONTENT_LENGTH)
- Kiểm tra kích thước trước khi lưu
- Hệ thống đã có detect_dos() trong SecurityMonitor

---

## Chi tiết từng phương thức tấn công

### A. Tấn công vào Handshake Phase

**Mục tiêu**: Phá vỡ giai đoạn xác thực ban đầu

**Kỹ thuật**:
1. **Replay Attack**: Ghi lại gói tin "Hello!" hợp lệ và gửi lại nhiều lần
2. **Fake Response**: Giả mạo phản hồi "Ready!" từ Receiver

**Biện pháp phòng chống**:
```python
# Thêm timestamp vào handshake
timestamp = get_timestamp()
handshake_data = {
    "msg": "Hello!",
    "timestamp": timestamp,
    "nonce": generate_random_nonce()
}

# Receiver kiểm tra timestamp < 5s
if current_time - timestamp > 5:
    return {"error": "Handshake timeout"}
```

---

### B. Tấn công vào Key Exchange Phase

**Mục tiêu**: Đánh cắp hoặc sửa đổi Session Key

**Kỹ thuật**:
1. **Key Substitution**: Thay thế Session Key bằng key do hacker tạo
2. **Public Key Spoofing**: Gửi public key giả mạo

**Dấu hiệu nhận biết**:
- RSA signature verification fails
- Decryption produces gibberish

**Biện pháp phòng chống**:
- Xác thực chữ ký RSA của Sender
- Sử dụng certificate authority
- Verify fingerprint của public key

---

### C. Tấn công vào File Transfer Phase

**Mục tiêu**: Gửi file độc hại hoặc corrupted file

**Kỹ thuật**:
1. **Integrity Hash Forgery**: Giả mạo hash SHA-512
2. **Ciphertext Manipulation**: Sửa đổi nội dung đã mã hóa
3. **Metadata Injection**: Chèn malicious code vào metadata

**Hậu quả nghiêm trọng**:
```python
# File nhạc đã bị sửa đổi
# Chứa embedded malware
# Khi nghe sẽ execute payload
```

**Cấp độ nghiêm trọng**: 🔴 CRITICAL

---

### D. Social Engineering Attack

**Mô tả**: Lừa người dùng cài đặt malicious software

**Kỹ thuật**:
- Phishing email giả mạo từ "Admin"
- Fake update cho phần mềm
- USB drop với infected files

**Phòng chống**:
- Education & awareness
- Email filtering
- Antivirus scanning

---

## Cách phòng chống

### 1. Rate Limiting & Throttling
```python
# Giới hạn 100 requests/60s per IP
if len(requests_in_last_60s) > 100:
    block_ip(ip_address)
    notify_admin("Spam detected")
```

### 2. IP Blacklisting
- Tự động chặn IP tấn công
- Maintain blacklist database
- Regular cleanup của old entries

### 3. Input Validation
```python
# Kiểm tra tất cả inputs
if not validate_filename(filename):
    return {"error": "Invalid filename"}
    
if request.content_length > MAX_SIZE:
    return {"error": "File too large"}
```

### 4. Encryption Best Practices
- Sử dụng RSA 2048+ bit (hiện tại đang dùng 1024)
- Triple DES đã cũ, nâng cấp lên AES-256
- Session key rotation sau mỗi N files

### 5. Monitoring & Alerting
- Real-time log monitoring
- Email/SMS alerts cho admin
- Dashboard theo dõi security events

---

## Quy trình xử lý khi bị tấn công

### Bước 1: Phát hiện ✅
- Hệ thống giám sát phát hiện spam/DDoS
- Alert được gửi đến admin qua Email và SMS

### Bước 2: Đánh giá mức độ 🔍
```python
if event.severity == "critical":
    # SMS ngay lập tức
    send_sms(admin_phone, "CRITICAL: Brute force attack detected")
    # Email chi tiết
    send_email(admin_email, event.full_details())
elif event.severity == "high":
    # Email thông báo
    send_email(admin_email, event.summary())
```

### Bước 3: Chặn nguồn tấn công 🔒
```python
# Từ Admin Dashboard
POST /api/admin/block_ip
{
    "ip": "192.168.1.100"
}

# Hoặc tự động
if detect_spam(ip):
    block_ip(ip)
    notify_admin(f"Auto-blocked: {ip}")
```

### Bước 4: Phân tích logs 📊
```bash
# Xem security events
GET /api/admin/security_events

# Phân tích pattern
- Source IP distribution
- Attack types frequency
- Time patterns
```

### Bước 5: Khắc phục và cải thiện 🔧
1. **Ngắn hạn**:
   - Chặn IP tấn công
   - Reset các session key bị ảnh hưởng
   - Restore file backup nếu bị xóa

2. **Trung hạn**:
   - Cập nhật rules phát hiện
   - Tăng cường monitoring
   - Patch security holes

3. **Dài hạn**:
   - Nâng cấp cryptographic algorithms
   - Implement WAF (Web Application Firewall)
   - Regular security audits

---

## 📊 Dashboard Admin

Hệ thống cung cấp dashboard quản trị tại `/admin`:

### Tính năng:
1. **Xem security events**: Danh sách các sự kiện bảo mật
2. **Chặn IP thủ công**: Form nhập IP để chặn
3. **Thống kê**: Số events, IP bị chặn, severity breakdown
4. **Real-time alerts**: Email và SMS notifications

### Các API endpoints:
```
GET  /api/admin/security_events    # Lấy danh sách events
POST /api/admin/block_ip           # Chặn IP
```

---

## 🛡️ Best Practices

1. **Không bao giờ** hardcode credentials trong code
2. **Luôn** validate và sanitize inputs
3. **Sử dụng** HTTPS trong production
4. **Rotate** keys và passwords định kỳ
5. **Monitor** logs 24/7
6. **Backup** data thường xuyên
7. **Update** dependencies để fix known vulnerabilities
8. **Test** security với penetration testing

---

## 📞 Liên hệ Admin

**Email**: admin@company.com  
**SMS**: +84912345678  
**Dashboard**: http://receiver-server/admin

---

## 📚 Tài liệu tham khảo

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- Triple DES vs AES: https://security.stackoverflow.com
- RSA Key Size Recommendations: https://www.keylength.com

---

**⚠️ LƯU Ý QUAN TRỌNG**:
- Hệ thống hiện tại vẫn dùng RSA 1024-bit (cần nâng lên 2048+)
- Triple DES đã lỗi thời (nên chuyển sang AES-256)
- Cần implement proper authentication cho admin dashboard
- Cần thêm rate limiting chi tiết hơn

**📅 Cập nhật**: 2026-06-06  
**👨‍💻 Tác giả**: Security Team  
**🔖 Phiên bản**: 1.0.0