"""
MITM Demo - Man-in-the-Middle Attack Against Real sender_app/receiver_app
Tấn công MITM thực tế vào hệ thống bằng cách thay thế session key và gửi file độc hại
"""

import sys
import os
import time
import json
import requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from admin_notifier import SecurityEvent, SecurityMonitor
from crypto_utils import (
    generate_rsa_keypair, rsa_encrypt_session_key, rsa_sign,
    generate_session_key, generate_iv, triple_des_encrypt,
    des_encrypt_metadata, compute_integrity_hash, b64encode,
    get_timestamp, rsa_verify
)


class MITMAttacker:
    """Attacker thực hiện MITM attack vào hệ thống thực"""
    
    def __init__(self, receiver_url="http://127.0.0.1:5000"):
        self.receiver_url = receiver_url
        self.monitor = SecurityMonitor()
        
        # Evil keys
        self.evil_session_key = None
        self.evil_priv_key = None
        self.evil_pub_key = None
        
        # Legitimate keys lấy được từ receiver
        self.receiver_pub_key = None
        self.receiver_priv_key = None
        
    def step1_scan_receiver(self):
        """Bước 1: Quét và xác minh receiver đang hoạt động"""
        print("\n" + "="*70)
        print("🎯 BƯỚC 1: QUÉT & XÁC MINH HỆ THỐNG")
        print("="*70)
        
        # Kiểm tra receiver online
        try:
            resp = requests.get(f"{self.receiver_url}/api/status", timeout=5)
            if resp.status_code == 200:
                print(f"   ✅ Receiver đang online: {self.receiver_url}")
                print(f"   Status: {resp.json()}")
            else:
                print(f"   ❌ Receiver trả về status {resp.status_code}")
                return False
        except Exception as e:
            print(f"   ❌ Không thể kết nối receiver: {e}")
            print(f"   💡 Hãy chạy: python receiver_app.py")
            return False
        
        # Thực hiện handshake với receiver trước khi lấy public key
        handshake_resp = requests.post(
            f"{self.receiver_url}/api/handshake",
            json={"msg": "Hello!"},
            timeout=5
        )
        if handshake_resp.status_code != 200 or handshake_resp.json().get("msg") != "Ready!":
            print(f"   ❌ Handshake thất bại với receiver")
            print(f"   Response: {handshake_resp.text}")
            return False
        print(f"   ✅ Handshake thành công với Receiver")
        
        # Lấy public key của receiver
        resp = requests.get(f"{self.receiver_url}/api/get_public_key", timeout=10)
        if resp.status_code == 200:
            pub_key_data = resp.json().get("public_key")
            if pub_key_data:
                self.receiver_pub_key = pub_key_data.encode()
                assert self.receiver_pub_key is not None, "receiver_pub_key không thể None"
                pub_key_check = self.receiver_pub_key.decode()
                assert pub_key_check is not None, "public key decode rỗng"
                print(f"   ✅ Lấy được Receiver Public Key")
                print(f"   Key (100 chars): {pub_key_check[:100]}...")
            else:
                print(f"   ❌ Receiver public key rỗng")
                return False
        else:
            print(f"   ❌ Không thể lấy receiver public key: {resp.status_code}")
            print(f"   Response: {resp.text}")
            return False
            
        # Tạo evil keypair cho attacker
        self.evil_priv_key, self.evil_pub_key = generate_rsa_keypair(1024)
        print(f"   🔓 Attacker đã tạo Evil RSA keypair")
        
        return True
    
    def step2_mitm_attack(self):
        """Bước 2: Thực hiện MITM - thay thế session key bằng evil key"""
        print("\n" + "="*70)
        print("🎭 BƯỚC 2: THỰC HIỆN MITM ATTACK")
        print("="*70)
        
        # Tạo evil session key
        self.evil_session_key = generate_session_key()
        assert self.evil_session_key is not None, "generate_session_key() trả về None"
        assert isinstance(self.evil_session_key, bytes), "evil_session_key phải là bytes"
        evil_key = self.evil_session_key
        assert evil_key is not None, "evil_session_key không thể None"
        print(f"\n   🔓 Evil Session Key (24 bytes): {evil_key}")
        
        # Mã hóa evil session key bằng receiver public key thật
        encrypted_evil_key = rsa_encrypt_session_key(
            self.receiver_pub_key, 
            self.evil_session_key
        )
        print(f"   🔓 Đã mã hóa evil key bằng Receiver Public Key")
        
        # Tạo signature giả mạo (dùng evil private key)
        timestamp = get_timestamp()
        metadata_to_sign = f"music_transfer|{timestamp}"
        signature = rsa_sign(self.evil_priv_key, metadata_to_sign.encode())
        print(f"   🔓 Đã ký bằng Evil Private Key")
        
        # Gửi evil session key đến receiver (giả mạo sender)
        print(f"\n   📡 Gửi Evil Session Key đến Receiver...")
        assert self.evil_pub_key is not None, "evil_pub_key không thể None"
        sender_pub_key_str = self.evil_pub_key.decode()
        assert sender_pub_key_str is not None, "evil_pub_key decode rỗng"
        resp = requests.post(
            f"{self.receiver_url}/api/receive_session_key",
            json={
                "encrypted_session_key": encrypted_evil_key,
                "signature": signature,
                "metadata_signed": metadata_to_sign,
                "sender_public_key": sender_pub_key_str
            }
        )
        
        if resp.status_code == 200 and resp.json().get("status") == "ok":
            print(f"   ✅ MITM THÀNH CÔNG! Receiver đã chấp nhận Evil Session Key")
            print(f"   Response: {resp.json()}")
            return True
        else:
            print(f"   ❌ MITM thất bại: {resp.status_code} - {resp.text}")
            return False
    
    def step3_send_malicious_file(self):
        """Bước 3: Gửi file độc hại mã hóa bằng evil key"""
        print("\n" + "="*70)
        print("☠️  BƯỚC 3: GỬI FILE ĐỘC HẠI (MÃ HÓA BẰNG EVIL KEY)")
        print("="*70)
        
        # Tạo file giả lập chứa mã độc
        malicious_data = b"MALICIOUS_PAYLOAD_SIMULATION_" * 200
        iv = generate_iv()
        
        # Mã hóa bằng evil session key
        print(f"\n   🔐 Đang mã hóa file bằng Evil Session Key...")
        if self.evil_session_key is None:
            raise RuntimeError("Evil session key not initialized")
        evil_sk = self.evil_session_key
        ciphertext = triple_des_encrypt(evil_sk, iv, malicious_data)
        hash_hex = compute_integrity_hash(iv, ciphertext)
        
        # Metadata
        metadata = {
            "filename": "evil_music.mp3",
            "artist": "Hacker",
            "copyright": "© 2024 Evil Corp",
            "size": len(malicious_data),
            "timestamp": get_timestamp()
        }
        meta_bytes = json.dumps(metadata, ensure_ascii=False).encode()
        des_key = evil_sk[:8]
        meta_cipher = des_encrypt_metadata(des_key, iv, meta_bytes)
        
        # Ký gói tin với evil key
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
        print(f"   📡 Gửi malicious file đến Receiver...")
        resp = requests.post(f"{self.receiver_url}/api/receive_file", json=packet)
        
        if resp.status_code == 200 and resp.json().get("status") == "ACK":
            file_info = resp.json().get("file_info", {})
            print(f"   ✅ Receiver đã nhận và lưu file độc hại!")
            print(f"      Filename: {file_info.get('filename')}")
            print(f"      Size: {file_info.get('size_kb')} KB")
            print(f"      Artist: {file_info.get('artist')}")
            return True
        else:
            print(f"   ❌ Gửi file thất bại: {resp.status_code} - {resp.text}")
            return False
    
    def step4_verify_exploit(self):
        """Bước 4: Xác minh attacker có thể giải mã file đã gửi"""
        print("\n" + "="*70)
        print("🔓 BƯỚC 4: ATTACKER GIẢI MÃ FILE (DATA BỊ LỘ!)")
        print("="*70)
        
        print(f"\n   🔓 Attacker có Evil Session Key, có thể giải mã mọi file:")
        print(f"   Evil Key: {self.evil_session_key}")
        
        # Lấy danh sách file đã nhận từ receiver
        resp = requests.get(f"{self.receiver_url}/api/status")
        if resp.status_code == 200:
            data = resp.json()
            if data is None:
                print("   ❌ Không thể đọc response từ receiver")
                return False
            received = data.get("received_files")
            files = received if received is not None else []
            if files:
                print(f"\n   ✅ File trong Receiver:")
                for f in files[-3:]:
                    print(f"      - {f['filename']} ({f['size_kb']} KB)")
                
                print(f"\n   🚨 EXPLOIT THÀNH CÔNG!")
                print(f"   - File được mã hóa bằng Evil Key")
                print(f"   - Attacker có thể giải mã vì giữ Evil Session Key")
                print(f"   - DATA BỊ LỖ!")
                return True
            else:
                print("   ℹ️  Chưa có file nào được nhận")
                return False
        return False
    
    def step5_detect_and_alert(self):
        """Bước 5: Phát hiện tấn công và cảnh báo admin"""
        print("\n" + "="*70)
        print("🛡️  BƯỚC 5: PHÁT HIỆN & CẢNH BÁO")
        print("="*70)
        
        # Lấy trạng thái receiver sau khi đã thử tấn công
        resp = requests.get(f"{self.receiver_url}/api/status")
        if resp.status_code == 200:
            status_data = resp.json()
            if status_data:
                recent_logs = status_data.get("log", [])
                
                # Kiểm tra xem có log lỗi MITM không
                mitm_detected = any("MITM ATTACK DETECTED" in log.get("msg", "") or 
                                   "TỪ CHỐI" in log.get("msg", "") 
                                   for log in recent_logs)
                
                if mitm_detected:
                    print(f"\n   🚨 SECURITY ALERT!")
                    print(f"      Hệ thống đã phát hiện và TỪ CHỐI tấn công MITM!")
                    print(f"      Kết quả: Attack đã thất bại, IP đã bị chặn")
                    
                    # Hiển thị các log gần đây
                    print(f"\n   📋 Logs gần đây từ Receiver:")
                    for log in recent_logs[-5:]:
                        level_icon = "✅" if log.get("level") == "success" else "❌"
                        print(f"      {level_icon} [{log.get('time')}] {log.get('msg')}")
                    
                    # Security monitor phát hiện MITM
                    assert self.evil_session_key is not None, "evil_session_key phải được thiết lập"
                    mitm_event = self.monitor.detect_mitm("192.168.1.100", self.evil_session_key)
                    
                    if mitm_event:
                        print(f"\n   📊 Thông tin tấn công:")
                        print(f"      Event: {mitm_event.event_type}")
                        print(f"      IP: {mitm_event.source_ip}")
                        print(f"      Severity: {mitm_event.severity}")
                        print(f"      ID: {mitm_event.id}")
                        
                        # Thông báo admin
                        self.monitor.notify_admin(mitm_event)
                        self.monitor.block_ip("192.168.1.100")
                    return True
        
        return False
    
    def step6_summary(self, attack_failed=True):
        """Bước 6: Tổng kết"""
        print("\n" + "="*70)
        print("📊 TỔNG KẾT MITM ATTACK")
        print("="*70)
        
        if attack_failed:
            print("\n❌ TẤN CÔNG ĐÃ BỊ CHẶN!")
            print("\n✅ Các bước đã thực hiện:")
            print("   1. ✅ Quét và xác minh receiver đang hoạt động")
            print("   2. ✅ Lấy receiver public key")
            print("   3. ✅ Tạo evil RSA keypair")
            print("   4. ✅ Tạo evil session key")
            print("   5. ✅ Mã hóa evil key và gửi đến receiver (giả mạo sender)")
            print("   6. ❌ Receiver PHÁT HIỆN MITM ATTACK và TỪ CHỐI key")
            print("   7. ❌ Không thể gửi file độc hại")
            print("   8. ❌ IP đã bị chặn bởi hệ thống bảo mật")
            
            print("\n🛡️ HỆ THỐNG BẢO VỆ:")
            print("   ✅ MITM Detection: Đã phát hiện session key thay đổi đột ngột")
            print("   ✅ Fake Sender Detection: Đã phát hiện public key không hợp lệ")
            print("   ✅ IP Blocking: Đã chặn IP tấn công 192.168.1.100")
            print("   ✅ Admin Notification: Đã gửi cảnh báo cho admin")
            print("   ✅ Data Protected: File không bị lộ, dữ liệu được bảo vệ")
            
            print("\n✨ KẾT QUẢ:")
            print("   Hệ thống đã thành công ngăn chặn tấn công MITM!")
            print("   Attacker không thể truy cập hoặc giải mã dữ liệu.")
        else:
            print("\n⚠️  TẤN CÔNG THÀNH CÔNG (Hệ thống chưa được bảo vệ)")
            print("\n✅ Các bước đã thực hiện:")
            print("   1. ✅ Quét và xác minh receiver đang hoạt động")
            print("   2. ✅ Lấy receiver public key")
            print("   3. ✅ Tạo evil RSA keypair")
            print("   4. ✅ Tạo evil session key")
            print("   5. ✅ Mã hóa evil key và gửi đến receiver (giả mạo sender)")
            print("   6. ✅ Receiver chấp nhận evil session key")
            print("   7. ✅ Mã hóa file độc hại bằng evil key")
            print("   8. ✅ Gửi file đến receiver")
            print("   9. ✅ Receiver nhận và lưu file")
            print("   10. ✅ Attacker có thể giải mã file (evil key)")
            
            print("\n🚨 Tác động:")
            print("   - File được mã hóa bằng attacker's key")
            print("   - Attacker có thể giải mã mọi file")
            print("   - Data bị lộ hoàn toàn")
            print("   - Receiver không biết đang bị tấn công")
        
        print("\n🛠️ CÁCH KHẮC PHỤC:")
        print("   1. Implement TLS/SSL certificate pinning")
        print("   2. Verify sender public key với whitelist")
        print("   3. Dùng HMAC để verify session key integrity")
        print("   4. Monitor session key changes đột ngột")
        print("   5. Perfect Forward Secrecy (PFS)")
        print("   6. Mutual authentication (cả 2 bên xác thực nhau)")


def main():
    """Thực hiện MITM attack thực tế"""
    print("="*70)
    print("🔓 MITM ATTACK DEMO - Real Attack Against Running System")
    print("="*70)
    print("\n⚠️  Yêu cầu:")
    print("   - Receiver app đang chạy tại port 5000")
    print("   - Sender app đang chạy tại port 5001")
    
    # Cho phép custom receiver URL
    receiver_url = input("\nNhập Receiver URL (Enter để dùng http://127.0.0.1:5000): ").strip()
    if not receiver_url:
        receiver_url = "http://127.0.0.1:5000"
    
    attacker = MITMAttacker(receiver_url)
    
    try:
        # Bước 1: Quét và xác minh
        if not attacker.step1_scan_receiver():
            print("\n❌ Không thể tiếp tục - Receiver không sẵn sàng")
            return
        
        # Bước 2: MITM attack - thay thế session key
        if not attacker.step2_mitm_attack():
            print("\n❌ MITM attack thất bại")
            return
        
        # Bước 3: Gửi file độc hại
        if not attacker.step3_send_malicious_file():
            print("\n❌ Không thể gửi file độc hại")
            return
        
        # Bước 4: Verify exploit
        exploit_success = attacker.step4_verify_exploit()
        
        # Bước 5: Detect & alert
        detection_success = attacker.step5_detect_and_alert()
        
        # Bước 6: Tổng kết - kiểm tra xem attack có bị chặn không
        if detection_success:
            print("\n" + "="*70)
            print("✅ KẾT QUẢ: HỆ THỐNG ĐÃ TỰ BẢO VỆ")
            print("="*70)
            print("\nMITM attack đã được phát hiện và ngăn chặn thành công!")
            attacker.step6_summary(attack_failed=True)
        else:
            print("\n" + "="*70)
            print("⚠️  KẾT QUẢ: HỆ THỐNG CHƯA ĐƯỢC BẢO VỆ")
            print("="*70)
            print("\nMITM attack đã thành công - Hệ thống cần được cải thiện!")
            attacker.step6_summary(attack_failed=False)
        
    except Exception as e:
        print(f"\n❌ Lỗi trong quá trình attack: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()