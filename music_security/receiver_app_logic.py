import socket
import threading
import os
import sys
import json
import time
import base64
import hashlib
from flask import Flask, request, jsonify, render_template_string, send_from_directory

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import (
    generate_rsa_keypair, load_rsa_private_key, load_rsa_public_key,
    rsa_decrypt_session_key, rsa_verify,
    triple_des_decrypt, des_decrypt_metadata,
    verify_integrity_hash, b64decode, b64encode,
    generate_iv
)
from admin_notifier import init_security_monitor, security_monitor

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)

# Initialize security monitor
security_monitor = init_security_monitor(app)

# ─── State bộ nhớ ───
STATE = {
    "private_key_pem": None,
    "public_key_pem": None,
    "session_key": None,
    "sender_public_key_pem": None,
    "handshake_done": False,
    "key_exchange_done": False,
    "log": [],
    "received_files": [],
    # Whitelist các sender public key đã được xác thực
    "authorized_sender_keys": [
        # Sender public key hợp lệ (có thể cập nhật từ database/file)
    ]
}

RECEIVED_DIR = "received"
os.makedirs(RECEIVED_DIR, exist_ok=True)


def add_log(msg, level="info"):
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "msg": msg,
        "level": level
    }
    STATE["log"].append(entry)
    print(f"[{entry['time']}] [{level.upper()}] {msg}")


# ─────────────────────────────────────────
# Các API Endpoint phục vụ kết nối
# ─────────────────────────────────────────

@app.route('/api/handshake', methods=['POST'])
def handshake():
    data = request.json
    if data.get("msg") == "Hello!":
        STATE["handshake_done"] = True
        add_log("✅ Nhận được Hello! từ Người Gửi → Gửi Ready!", "success")
        return jsonify({"msg": "Ready!", "status": "ok"})
    return jsonify({"error": "Invalid handshake"}), 400


@app.route('/api/get_public_key', methods=['GET'])
def get_public_key():
    if not STATE["handshake_done"]:
        return jsonify({"error": "Handshake chưa hoàn tất"}), 400
    if not STATE["private_key_pem"]:
        priv, pub = generate_rsa_keypair(1024)
        STATE["private_key_pem"] = priv
        STATE["public_key_pem"] = pub
        add_log("🔑 Tạo cặp khóa RSA 1024-bit", "success")
    return jsonify({"public_key": STATE["public_key_pem"].decode(), "status": "ok"})


@app.route('/api/receive_session_key', methods=['POST'])
def receive_session_key():
    data = request.json
    encrypted_session_key = data.get("encrypted_session_key")
    signature = data.get("signature")
    metadata_signed = data.get("metadata_signed")
    sender_public_key = data.get("sender_public_key")

    if not all([encrypted_session_key, signature, metadata_signed, sender_public_key]):
        return jsonify({"error": "Thiếu dữ liệu"}), 400

    try:
        session_key = rsa_decrypt_session_key(STATE["private_key_pem"], encrypted_session_key)
        
        # 🔒 KIỂM TRA MITM ATTACK TRƯỚC KHI CHẤP NHẬN KEY
        mitm_event = security_monitor.detect_mitm(request.remote_addr or "", session_key)
        if mitm_event:
            security_monitor.notify_admin(mitm_event)
            add_log(f"🚨 TỪ CHỐI MITM ATTACK từ {request.remote_addr}", "error")
            print(f"\n{'='*70}")
            print(f"🚨 PHÁT HIỆN TẤN CÔNG MITM!")
            print(f"   IP tấn công: {request.remote_addr}")
            print(f"   Session key bị thay đổi đột ngột")
            print(f"   Hành động: TỪ CHỐI key exchange & CHẶN IP")
            print(f"{'='*70}\n")
            security_monitor.block_ip(request.remote_addr or "")
            return jsonify({"error": "MITM ATTACK DETECTED! Session key thay đổi bất thường. Yêu cầu bị từ chối."}), 403
        
        # 🔒 KIỂM TRA FAKE SENDER
        fake_event = security_monitor.detect_fake_sender(request.remote_addr or "", sender_public_key)
        if fake_event:
            security_monitor.notify_admin(fake_event)
            add_log(f"🚨 TỪ CHỐI FAKE SENDER từ {request.remote_addr}", "error")
            print(f"\n{'='*70}")
            print(f"🚨 PHÁT HIỆN FAKE SENDER!")
            print(f"   IP tấn công: {request.remote_addr}")
            print(f"   Public key không hợp lệ (độ dài: {len(sender_public_key)} chars)")
            print(f"   Hành động: TỪ CHỐI key exchange & CHẶN IP")
            print(f"{'='*70}\n")
            security_monitor.block_ip(request.remote_addr or "")
            return jsonify({"error": "FAKE SENDER DETECTED! Public key không hợp lệ. Yêu cầu bị từ chối."}), 403
        
        # Chỉ lưu session key nếu đã vượt qua tất cả kiểm tra
        STATE["session_key"] = session_key
        STATE["sender_public_key_pem"] = sender_public_key.encode()
        
        # Xác thực chữ ký
        msg_bytes = metadata_signed.encode()
        valid = rsa_verify(sender_public_key.encode(), msg_bytes, signature)
        
        if valid:
            STATE["key_exchange_done"] = True
            add_log("✅ Xác thực chữ ký RSA/SHA-512 hợp lệ - Key exchange thành công", "success")
            return jsonify({"status": "ok", "msg": "Key exchange thành công"})
        else:
            add_log("❌ Chữ ký không hợp lệ", "error")
            return jsonify({"error": "Chữ ký không hợp lệ"}), 400
    except Exception as e:
        add_log(f"❌ Lỗi key exchange: {e}", "error")
        return jsonify({"error": f"Lỗi bảo mật: {str(e)}"}), 500


@app.route('/api/receive_file', methods=['POST'])
def receive_file():
    if not STATE["key_exchange_done"]:
        return jsonify({"error": "Key exchange chưa hoàn tất"}), 400

    data = request.json
    iv_b64 = data.get("iv")
    cipher_b64 = data.get("cipher")
    meta_b64 = data.get("meta")
    hash_hex = data.get("hash")
    signature = data.get("sig")

    try:
        iv = b64decode(iv_b64)
        ciphertext = b64decode(cipher_b64)
        meta_cipher = b64decode(meta_b64)

        if not verify_integrity_hash(iv, ciphertext, hash_hex):
            return jsonify({"status": "NACK", "error": "Hash không khớp"}), 400

        sig_data = (iv_b64 + cipher_b64 + hash_hex).encode()
        if not rsa_verify(STATE["sender_public_key_pem"], sig_data, signature):
            return jsonify({"status": "NACK", "error": "Chữ ký không hợp lệ"}), 400

        des_key = STATE["session_key"][:8]
        meta_bytes = des_decrypt_metadata(des_key, iv, meta_cipher)
        metadata = json.loads(meta_bytes.decode())

        plaintext = triple_des_decrypt(STATE["session_key"], iv, ciphertext)
        filename = metadata.get("filename", "song.mp3")
        safe_name = "".join(c for c in filename if c.isalnum() or c in "._-")
        
        with open(os.path.join(RECEIVED_DIR, safe_name), "wb") as f:
            f.write(plaintext)

        file_info = {
            "filename": safe_name,
            "size_kb": round(len(plaintext) / 1024, 2),
            "copyright": metadata.get("copyright", "N/A"),
            "artist": metadata.get("artist", "N/A"),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hash_sha256": hashlib.sha256(plaintext).hexdigest()
        }
        STATE["received_files"].append(file_info)
        add_log(f"💾 Đã giải mã & lưu file thành công: {safe_name}", "success")
        return jsonify({"status": "ACK", "file_info": file_info})
    except Exception as e:
        return jsonify({"status": "NACK", "error": str(e)}), 500


@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "handshake": STATE["handshake_done"],
        "key_exchange": STATE["key_exchange_done"],
        "log": STATE["log"][-30:],
        "received_files": STATE["received_files"]
    })


@app.route('/api/reset', methods=['POST'])
def reset():
    STATE.update({
        "private_key_pem": None, 
        "public_key_pem": None, 
        "session_key": None, 
        "sender_public_key_pem": None, 
        "handshake_done": False, 
        "key_exchange_done": False, 
        "log": [], 
        "received_files": []
    })
    add_log("🔄 Đã reset trạng thái hệ thống", "info")
    return jsonify({"status": "ok"})


@app.route('/download/<filename>')
def download_file(filename):
    # Detect path traversal
    path_event = security_monitor.detect_path_traversal(request.remote_addr or "", filename)
    if path_event:
        security_monitor.notify_admin(path_event)
        security_monitor.block_ip(request.remote_addr or "")
        return jsonify({"error": "Access denied - suspicious path"}), 403
    
    return send_from_directory(RECEIVED_DIR, filename, as_attachment=True)


# ─────────────────────────────────────────
# Luồng phát tin hiệu Broadcast UDP ngầm
# ─────────────────────────────────────────

def broadcast_presence():
    """Hàm chạy ngầm để liên tục phát thông điệp IP ra mạng nội bộ"""
    # Tạo một socket UDP để phát broadcast
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # Thiết lập cổng phát ngẫu nhiên cho socket phát tín hiệu công khai
    server.bind(("", 0)) 
    
    # Chuỗi thông điệp định dạng sẵn gửi kèm cổng chạy dịch vụ Web Receiver (5000)
    message = b"I_AM_RECEIVER:5000" 
    
    print("[BROADCAST] Đang tự động phát tín hiệu nhận diện IP ra mạng LAN...")
    while True:
        try:
            # Gửi gói tin đến địa chỉ broadcast mạng LAN nội bộ trên cổng nhận diện 5555
            server.sendto(message, ('<broadcast>', 5555))
            time.sleep(3) # Chu kỳ phát lại sau mỗi 3 giây
        except Exception as e:
            print(f"[BROADCAST ERROR] {e}")
            time.sleep(5)

# Kích hoạt luồng chạy ngầm phát thông tin trước khi Flask khởi chạy chính thức
broadcast_thread = threading.Thread(target=broadcast_presence, daemon=True)
broadcast_thread.start()
