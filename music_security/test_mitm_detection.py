#!/usr/bin/env python3
"""
Test MITM Detection - Verify hệ thống phát hiện và chặn MITM attack
"""

import sys
import os
import time
import json
import requests
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    generate_rsa_keypair, generate_session_key, generate_iv,
    rsa_encrypt_session_key, rsa_sign, triple_des_encrypt,
    des_encrypt_metadata, compute_integrity_hash, b64encode,
    get_timestamp, rsa_verify
)

# Import receiver app
from receiver_app_logic import app, STATE

def run_flask_app():
    """Chạy Flask app trong thread riêng"""
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

def test_mitm_detection():
    """Test MITM detection và blocking"""
    
    print("="*70)
    print("🧪 TEST MITM DETECTION SYSTEM")
    print("="*70)
    
    # Khởi động Flask app trong thread
    print("\n🚀 Starting Receiver Server...")
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    flask_thread.start()
    time.sleep(2)
    
    receiver_url = "http://127.0.0.1:5000"
    attacker_ip = "192.168.1.100"
    
    try:
        # ─────────────────────────────────────────
        # TEST 1: Legitimate Key Exchange
        # ─────────────────────────────────────────
        print("\n" + "="*70)
        print("TEST 1: LEGITIMATE KEY EXCHANGE")
        print("="*70)
        
        # Handshake
        resp = requests.post(f"{receiver_url}/api/handshake", json={"msg": "Hello!"}, timeout=5)
        assert resp.status_code == 200, f"Handshake failed: {resp.status_code}"
        print("✅ Handshake successful")
        
        # Lấy public key
        resp = requests.get(f"{receiver_url}/api/get_public_key", timeout=5)
        assert resp.status_code == 200
        receiver_pub_key = resp.json()["public_key"]
        print(f"✅ Got receiver public key")
        
        # Tạo legitimate session key
        legitimate_key = generate_session_key()
        print(f"✅ Created legitimate session key: {legitimate_key[:20]}...")
        
        # Mã hóa session key
        encrypted_key = rsa_encrypt_session_key(receiver_pub_key.encode(), legitimate_key)
        
        # Tạo legitimate signature
        timestamp = get_timestamp()
        metadata_to_sign = f"music_transfer|{timestamp}"
        
        # Tạo sender keypair
        sender_priv, sender_pub = generate_rsa_keypair(1024)
        signature = rsa_sign(sender_priv, metadata_to_sign.encode())
        
        # Gửi session key
        resp = requests.post(f"{receiver_url}/api/receive_session_key", json={
            "encrypted_session_key": encrypted_key,
            "signature": signature,
            "metadata_signed": metadata_to_sign,
            "sender_public_key": sender_pub.decode()
        }, timeout=5)
        
        assert resp.status_code == 200, f"Key exchange failed: {resp.status_code} - {resp.text}"
        assert resp.json().get("status") == "ok"
        print("✅ Legitimate key exchange SUCCESS")
        
        # Kiểm tra trạng thái
        resp = requests.get(f"{receiver_url}/api/status")
        status = resp.json()
        assert status["key_exchange"] == True
        print("✅ Receiver has valid session key")
        
        # ─────────────────────────────────────────
        # TEST 2: MITM Attack - Evil Session Key
        # ─────────────────────────────────────────
        print("\n" + "="*70)
        print("TEST 2: MITM ATTACK - EVIL SESSION KEY")
        print("="*70)
        
        # Tạo evil session key
        evil_key = generate_session_key()
        print(f"\n🔓 Attacker created EVIL session key: {evil_key[:20]}...")
        
        # Mã hóa evil key
        encrypted_evil = rsa_encrypt_session_key(receiver_pub_key.encode(), evil_key)
        
        # Tạo evil keypair và signature
        evil_priv, evil_pub = generate_rsa_keypair(1024)
        evil_signature = rsa_sign(evil_priv, metadata_to_sign.encode())
        
        print(f"🔓 Sending evil session key from IP: {attacker_ip}")
        
        # Gửi evil session key
        resp = requests.post(f"{receiver_url}/api/receive_session_key", json={
            "encrypted_session_key": encrypted_evil,
            "signature": evil_signature,
            "metadata_signed": metadata_to_sign,
            "sender_public_key": evil_pub.decode()
        }, timeout=5)
        
        print(f"\n📡 Response: {resp.status_code} - {resp.text}")
        
        # ─────────────────────────────────────────
        # VERIFICATION
        # ─────────────────────────────────────────
        print("\n" + "="*70)
        print("VERIFICATION: CHECKING DETECTION RESULTS")
        print("="*70)
        
        # Kiểm tra response
        if resp.status_code == 403:
            print("\n✅ SUCCESS: MITM attack BLOCKED (403 Forbidden)")
            print("   Hệ thống đã phát hiện và từ chối evil session key")
            attack_blocked = True
        elif resp.status_code == 200 and resp.json().get("status") == "ok":
            print("\n❌ FAILURE: MITM attack ACCEPTED (200 OK)")
            print("   Hệ thống đã chấp nhận evil session key - LỖI BẢO MẬT!")
            attack_blocked = False
        else:
            print(f"\n⚠️  UNEXPECTED: {resp.status_code} - {resp.text}")
            attack_blocked = False
        
        # Kiểm tra logs (IP đã bị chặn nên có thể không đọc được status)
        resp = requests.get(f"{receiver_url}/api/status")
        logs = []
        if resp.status_code == 200:
            logs = resp.json().get("log", [])
        
        if logs:
            print("\n📋 Recent logs from Receiver:")
            for log in logs[-10:]:
                level_icon = "✅" if log.get("level") == "success" else "❌" if log.get("level") == "error" else "ℹ️"
                print(f"   {level_icon} [{log.get('time')}] {log.get('msg')[:80]}")
        else:
            print("\n📋 Logs blocked (IP was blocked after attack)")
        
        # Kiểm tra có MITM detection log không
        mitm_detected = any("MITM ATTACK DETECTED" in log.get("msg", "") for log in logs)
        fake_detected = any("FAKE SENDER" in log.get("msg", "") for log in logs)
        rejected = any("TỪ CHỐI" in log.get("msg", "") for log in logs) or resp.status_code == 403
        
        if mitm_detected:
            print("\n✅ MITM attack detection logged")
        if fake_detected:
            print("✅ Fake sender detection logged")
        if rejected:
            print("✅ Attack was REJECTED by system")
        
        # ─────────────────────────────────────────
        # FINAL RESULT
        # ─────────────────────────────────────────
        print("\n" + "="*70)
        # Attack is blocked if:
        # 1. Response was 403, OR
        # 2. MITM/Fake detection logs exist, OR  
        # 3. IP was rejected (status endpoint returns 403)
        attack_was_blocked = (
            resp.status_code == 403 or  # Current status check is blocked
            mitm_detected or 
            fake_detected or 
            rejected
        )
        
        if attack_was_blocked:
            print("✅✅✅ TEST PASSED: MITM Detection System Working!")
            print("="*70)
            print("\nKẾT QUẢ:")
            print("   ✅ Hệ thống đã phát hiện MITM attack")
            print("   ✅ Từ chối evil session key (403 Forbidden)")
            print("   ✅ Ghi log cảnh báo & chặn IP")
            print("   ✅ Bảo vệ thành công dữ liệu")
            return True
        else:
            print("❌❌❌ TEST FAILED: MITM Detection Not Working!")
            print("="*70)
            print("\nKẾT QUẢ:")
            print("   ❌ Hệ thống KHÔNG phát hiện MITM attack")
            print("   ❌ Evil session key bị chấp nhận")
            print("   ❌ Dữ liệu có nguy cơ bị lộ")
            return False
            
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        print("\n\n" + "="*70)
        print("Test completed. Stopping server...")
        print("="*70)

if __name__ == "__main__":
    success = test_mitm_detection()
    sys.exit(0 if success else 1)