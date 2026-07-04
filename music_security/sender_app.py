import sys
import os

# Thêm thư mục hiện tại vào Python path để import được crypto_utils
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import socket
import json
import time
import requests
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename
from crypto_utils import (
    generate_rsa_keypair,
    rsa_encrypt_session_key, rsa_sign,
    triple_des_encrypt, des_encrypt_metadata,
    compute_integrity_hash,
    generate_session_key, generate_iv,
    b64encode, b64decode, get_timestamp
)

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─── State ───
STATE = {
    "private_key_pem": None,
    "public_key_pem": None,
    "session_key": None,
    "receiver_public_key_pem": None,
    "receiver_url": None, 
    "handshake_done": False,
    "key_exchange_done": False,
    "log": []
}


def add_log(msg, level="info"):
    entry = {"time": time.strftime("%H:%M:%S"), "msg": msg, "level": level}
    STATE["log"].append(entry)
    print(f"[{entry['time']}] [{level.upper()}] {msg}")

# 🔴 ĐÃ XÓA: Hàm get_receiver() cũ ở đây đã được loại bỏ

   
# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────

@app.route('/api/set_receiver', methods=['POST'])
def set_receiver():
    data = request.json
    url = data.get("url", "").strip().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url
    STATE["receiver_url"] = url
    add_log(f"📡 Đặt địa chỉ Receiver: {url}", "info")
    return jsonify({"status": "ok", "url": url})


# ─────────────────────────────────────────
# BƯỚC 1: Handshake
# ─────────────────────────────────────────

@app.route('/api/handshake', methods=['POST'])
def handshake():
    try:
        t_start = time.perf_counter()
        resp = requests.post(f"{get_receiver()}/api/handshake",
                             json={"msg": "Hello!"},
                             timeout=10)
        t_elapsed = (time.perf_counter() - t_start) * 1000
        data = resp.json()
        if data.get("msg") == "Ready!":
            STATE["handshake_done"] = True
            add_log(f"✅ Handshake thành công: Nhận 'Ready!' ({t_elapsed:.0f}ms)", "success")
            return jsonify({"status": "ok", "response": data["msg"], "time_ms": round(t_elapsed, 1)})
        return jsonify({"error": "Handshake thất bại"}), 400
    except Exception as e:
        add_log(f"❌ Handshake lỗi: {e}", "error")
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────
# BƯỚC 2: Xác thực & Trao khóa
# ─────────────────────────────────────────

@app.route('/api/key_exchange', methods=['POST'])
def key_exchange():
    if not STATE["handshake_done"]:
        return jsonify({"error": "Handshake chưa hoàn tất"}), 400

    timing = {}

    try:
        # Tạo RSA keypair cho Sender (để ký)
        t_start = time.perf_counter()
        if not STATE["private_key_pem"]:
            priv, pub = generate_rsa_keypair(1024)
            STATE["private_key_pem"] = priv
            STATE["public_key_pem"] = pub
        timing["rsa_keygen"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"🔑 Tạo RSA keypair Sender ({timing['rsa_keygen']}ms)", "info")

        # Lấy Public Key của Receiver
        t_start = time.perf_counter()
        resp = requests.get(f"{get_receiver()}/api/get_public_key", timeout=10)
        receiver_pub = resp.json()["public_key"]
        STATE["receiver_public_key_pem"] = receiver_pub.encode()
        timing["get_pubkey"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"📥 Nhận Public Key từ Receiver ({timing['get_pubkey']}ms)", "success")

        # Tạo SessionKey
        t_start = time.perf_counter()
        session_key = generate_session_key()
        STATE["session_key"] = session_key
        timing["session_keygen"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"🗝️ Tạo SessionKey 24-byte Triple DES ({timing['session_keygen']}ms)", "info")

        # Ký metadata (tên file + timestamp) bằng RSA/SHA-512
        t_start = time.perf_counter()
        timestamp = get_timestamp()
        metadata_to_sign = f"music_transfer|{timestamp}"
        signature = rsa_sign(STATE["private_key_pem"], metadata_to_sign.encode())
        timing["sign"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"✍️ Ký metadata bằng RSA/SHA-512 ({timing['sign']}ms)", "info")

        # Mã hóa SessionKey bằng RSA-OAEP của Receiver
        t_start = time.perf_counter()
        encrypted_sk = rsa_encrypt_session_key(STATE["receiver_public_key_pem"], session_key)
        timing["rsa_encrypt"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"🔒 Mã hóa SessionKey bằng RSA-OAEP/SHA-512 ({timing['rsa_encrypt']}ms)", "info")

        # Gửi cho Receiver
        t_start = time.perf_counter()
        resp = requests.post(f"{get_receiver()}/api/receive_session_key", json={
            "encrypted_session_key": encrypted_sk,
            "signature": signature,
            "metadata_signed": metadata_to_sign,
            "sender_public_key": STATE["public_key_pem"].decode()
        }, timeout=10)
        timing["send"] = round((time.perf_counter() - t_start) * 1000, 2)

        result = resp.json()
        if result.get("status") == "ok":
            STATE["key_exchange_done"] = True
            add_log(f"✅ Key Exchange thành công ({timing['send']}ms)", "success")
            return jsonify({"status": "ok", "timing": timing})
        else:
            return jsonify({"error": result.get("error", "Thất bại")}), 400

    except Exception as e:
        add_log(f"❌ Key exchange lỗi: {e}", "error")
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────
# BƯỚC 3: Mã hóa & Gửi file
# ─────────────────────────────────────────

@app.route('/api/send_file', methods=['POST'])
def send_file_api():
    if not STATE["key_exchange_done"]:
        return jsonify({"error": "Key exchange chưa hoàn tất"}), 400

    if 'file' not in request.files:
        return jsonify({"error": "Không có file"}), 400

    file = request.files['file']
    copyright_info = request.form.get('copyright', 'Bản quyền thuộc về tác giả')
    artist = request.form.get('artist', 'Unknown Artist')

    if not file.filename:
        return jsonify({"error": "Tên file trống"}), 400

    timing = {}

    try:
        # Đọc file
        filename = secure_filename(file.filename)
        plaintext = file.read()
        filesize = len(plaintext)
        add_log(f"📂 File: {filename} ({round(filesize/1024, 2)} KB)", "info")

        # Tạo IV
        iv = generate_iv()

        # Mã hóa metadata bằng DES
        t_start = time.perf_counter()
        metadata = {
            "filename": filename,
            "copyright": copyright_info,
            "artist": artist,
            "size": filesize,
            "timestamp": get_timestamp()
        }
        meta_bytes = json.dumps(metadata, ensure_ascii=False).encode()
        des_key = STATE["session_key"][:8]
        meta_cipher = des_encrypt_metadata(des_key, iv, meta_bytes)
        timing["meta_encrypt"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"🔒 Mã hóa metadata bằng DES ({timing['meta_encrypt']}ms)", "info")

        # Mã hóa file bằng Triple DES
        t_start = time.perf_counter()
        ciphertext = triple_des_encrypt(STATE["session_key"], iv, plaintext)
        timing["file_encrypt"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"🔐 Mã hóa file Triple DES ({timing['file_encrypt']}ms)", "info")

        # Tính hash SHA-512(IV || ciphertext)
        t_start = time.perf_counter()
        hash_hex = compute_integrity_hash(iv, ciphertext)
        timing["hash"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"#️⃣ Hash SHA-512: {hash_hex[:32]}... ({timing['hash']}ms)", "info")

        # Ký gói tin
        t_start = time.perf_counter()
        iv_b64 = b64encode(iv)
        cipher_b64 = b64encode(ciphertext)
        meta_b64 = b64encode(meta_cipher)
        sig_data = (iv_b64 + cipher_b64 + hash_hex).encode()
        signature = rsa_sign(STATE["private_key_pem"], sig_data)
        timing["sign"] = round((time.perf_counter() - t_start) * 1000, 2)
        add_log(f"✍️ Ký gói tin bằng RSA/SHA-512 ({timing['sign']}ms)", "info")

        # Gửi gói tin
        packet = {
            "iv": iv_b64,
            "cipher": cipher_b64,
            "meta": meta_b64,
            "hash": hash_hex,
            "sig": signature
        }
        packet_size = len(json.dumps(packet).encode())

        t_start = time.perf_counter()
        resp = requests.post(
            f"{get_receiver()}/api/receive_file",
            json=packet,
            timeout=60
        )
        timing["send"] = round((time.perf_counter() - t_start) * 1000, 2)
        timing["total"] = round(sum(timing.values()), 2)

        result = resp.json()
        if result.get("status") == "ACK":
            add_log(f"✅ ACK nhận được! File gửi thành công ({timing['total']}ms)", "success")
            return jsonify({
                "status": "ACK",
                "filename": filename,
                "filesize_kb": round(filesize / 1024, 2),
                "packet_size_kb": round(packet_size / 1024, 2),
                "timing": timing,
                "receiver_info": result.get("file_info", {})
            })
        else:
            add_log(f"❌ NACK: {result.get('error', 'Lỗi không xác định')}", "error")
            return jsonify({"status": "NACK", "error": result.get("error")}), 400

    except Exception as e:
        add_log(f"❌ Lỗi gửi file: {e}", "error")
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────
# Status & Reset
# ─────────────────────────────────────────

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "handshake": STATE["handshake_done"],
        "key_exchange": STATE["key_exchange_done"],
        "session_key_ready": STATE["session_key"] is not None,
        "receiver_url": STATE["receiver_url"],
        "log": STATE["log"][-30:]
    })


@app.route('/api/reset', methods=['POST'])
def reset():
    STATE.update({
        "private_key_pem": None,
        "public_key_pem": None,
        "session_key": None,
        "receiver_public_key_pem": None,
        "receiver_url": None, # 🔴 ĐÃ SỬA: Reset về None luôn
        "handshake_done": False,
        "key_exchange_done": False,
        "log": []
    })
    add_log("🔄 Đã reset trạng thái", "info")
    return jsonify({"status": "ok"})


@app.route('/api/ping_receiver', methods=['GET'])
def ping_receiver():
    try:
        resp = requests.get(f"{get_receiver()}/api/status", timeout=5)
        data = resp.json()
        return jsonify({"status": "online", "receiver": data})
    except:
        return jsonify({"status": "offline"}), 503

# ─────────────────────────────────────────
# CƠ CHẾ ĐỒNG BỘ IP TỰ ĐỘNG (GIỮ NGUYÊN)
# ─────────────────────────────────────────

def auto_discover_receiver_ip():
    """Hàm lắng nghe 'loa phát' từ Receiver để tự động lấy IP"""
    print("[DISCOVERY] Đang tự động dò tìm IP của Receiver trong mạng, vui lòng chờ...")
    
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.bind(("", 5555))
    client.settimeout(10.0)
    
    try:
        while True:
            data, addr = client.recvfrom(1024)
            message = data.decode()
            
            if message.startswith("I_AM_RECEIVER:"):
                port = message.split(":")[1]
                receiver_ip = addr[0]
                receiver_url = f"http://{receiver_ip}:{port}"
                print(f"[DISCOVERY] Found! Đã tự động nhận diện Receiver tại địa chỉ: {receiver_url}")
                return receiver_url
    except socket.timeout:
        print("[DISCOVERY] Không tìm thấy Receiver nào đang mở trong mạng nội bộ.")
        return None
    finally:
        client.close()


def get_receiver():
    """Hàm lấy địa chỉ Receiver thông minh"""
    if not STATE.get("receiver_url"):
        discovered_url = auto_discover_receiver_ip()
        if discovered_url:
            STATE["receiver_url"] = discovered_url
        else:
            STATE["receiver_url"] = "http://127.0.0.1:5000" 
            
    return STATE["receiver_url"]


def scan_receivers_lan(timeout=4.0):
    """Quét toàn bộ mạng LAN trong khoảng thời gian `timeout` giây để tìm
    TẤT CẢ các Receiver đang phát tín hiệu broadcast (không dừng lại ở cái đầu tiên)."""
    found = {}
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        client.bind(("", 5555))
    except OSError as e:
        add_log(f"⚠️ Không thể mở cổng quét mạng (5555): {e}", "error")
        return []

    client.settimeout(0.5)
    end_time = time.time() + timeout

    while time.time() < end_time:
        try:
            data, addr = client.recvfrom(1024)
            message = data.decode(errors="ignore")
            if message.startswith("I_AM_RECEIVER:"):
                port = message.split(":")[1]
                ip = addr[0]
                found[ip] = port
        except socket.timeout:
            continue
        except Exception:
            continue

    client.close()

    results = [
        {"ip": ip, "port": port, "url": f"http://{ip}:{port}"}
        for ip, port in found.items()
    ]
    add_log(f"📡 Quét mạng LAN: tìm thấy {len(results)} Receiver đang hoạt động", "info")
    return results


@app.route('/api/scan_receivers', methods=['GET'])
def scan_receivers_api():
    """Trả về danh sách tất cả các Receiver đang chạy gần đó (cùng mạng LAN)."""
    results = scan_receivers_lan(timeout=4.0)
    return jsonify({"status": "ok", "receivers": results})

# Lưu ý: Biến CYBERPUNK_UI của bạn bị cắt cụt ở cuối, hãy giữ nguyên phần giao diện HTML cũ của bạn ở dưới này nhé!
CYBERPUNK_UI = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Serendipity Music - Secure Sender Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #0d0e22; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
        .sidebar { background-color: #151632; }
        .main-content { background-color: #0f1026; }
        .card-bg { background-color: #1b1c42; }
        .neon-text-purple { color: #cc66ff; text-shadow: 0 0 10px rgba(204,102,255,0.5); }
        .neon-btn-purple { background: linear-gradient(135deg, #8a2be2, #4a0e4e); }
        .glass-player { background: rgba(27, 28, 66, 0.85); backdrop-filter: blur(10px); border-top: 1px solid rgba(255,255,255,0.1); }
        
        .nct-footer { background-color: #1e1f1f !important; color: #a5a6a6 !important; font-family: Sans-Serif, Arial, sans-serif; }
        .nct-footer a { color: #a5a6a6; transition: color 0.2s; }
        .nct-footer a:hover { color: #ffffff; text-decoration: underline; }
        
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f1026; }
        ::-webkit-scrollbar-thumb { background: #3b3d7a; border-radius: 3px; }

        /* ── TOAST NOTIFICATION ── */
        #toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; pointer-events: none; }
        .toast { display: flex; align-items: flex-start; gap: 12px; min-width: 320px; max-width: 420px; padding: 14px 18px; border-radius: 14px; border: 1px solid; box-shadow: 0 8px 32px rgba(0,0,0,.4); backdrop-filter: blur(12px); animation: toastIn .35s cubic-bezier(.34,1.56,.64,1) forwards; pointer-events: all; }
        .toast.toast-success { background: rgba(16,185,129,.15); border-color: rgba(16,185,129,.4); }
        .toast.toast-error   { background: rgba(239,68,68,.15);  border-color: rgba(239,68,68,.4); }
        .toast.toast-info    { background: rgba(99,102,241,.15); border-color: rgba(99,102,241,.4); }
        .toast.toast-out     { animation: toastOut .3s ease forwards; }
        .toast-icon  { font-size: 1.4rem; flex-shrink: 0; margin-top: 1px; }
        .toast-body  { flex: 1; }
        .toast-title { font-weight: 700; font-size: .88rem; margin-bottom: 2px; }
        .toast-success .toast-title { color: #34d399; }
        .toast-error  .toast-title  { color: #f87171; }
        .toast-info   .toast-title  { color: #a5b4fc; }
        .toast-msg   { font-size: .78rem; color: rgba(255,255,255,.65); line-height: 1.5; }
        .toast-close { font-size: .8rem; color: rgba(255,255,255,.4); cursor: pointer; flex-shrink: 0; padding: 2px 4px; border-radius: 4px; }
        .toast-close:hover { color: #fff; background: rgba(255,255,255,.1); }
        @keyframes toastIn  { from { opacity:0; transform: translateX(40px) scale(.9); } to { opacity:1; transform: translateX(0) scale(1); } }
        @keyframes toastOut { from { opacity:1; transform: translateX(0);  }  to { opacity:0; transform: translateX(40px); } }

        /* ── SEND RESULT MODAL ── */
        #send-result-modal { display:none; position:fixed; inset:0; z-index:9998; background:rgba(0,0,0,.6); backdrop-filter:blur(6px); align-items:center; justify-content:center; }
        #send-result-modal.show { display:flex; }
        .modal-box { background:#1a1830; border:1px solid rgba(255,255,255,.1); border-radius:20px; padding:28px; width:480px; max-width:95vw; box-shadow:0 24px 80px rgba(0,0,0,.6); animation: modalIn .3s cubic-bezier(.34,1.56,.64,1); }
        @keyframes modalIn { from{opacity:0;transform:scale(.85)} to{opacity:1;transform:scale(1)} }
        .modal-header { display:flex; align-items:center; gap:12px; margin-bottom:18px; }
        .modal-icon   { font-size:2rem; }
        .modal-title  { font-size:1.1rem; font-weight:800; }
        .modal-title.success { color:#34d399; }
        .modal-title.error   { color:#f87171; }
        .modal-table  { width:100%; border-collapse:collapse; font-size:.82rem; margin-bottom:16px; }
        .modal-table td { padding:7px 10px; border-bottom:1px solid rgba(255,255,255,.06); }
        .modal-table td:first-child { color:rgba(255,255,255,.5); width:140px; }
        .modal-table td:last-child  { color:#fff; font-family:monospace; font-weight:600; }
        .timing-row   { margin-bottom:14px; }
        .timing-label { font-size:.72rem; color:rgba(255,255,255,.45); display:flex; justify-content:space-between; margin-bottom:4px; }
        .timing-track { height:5px; background:rgba(255,255,255,.07); border-radius:4px; overflow:hidden; }
        .timing-fill  { height:100%; background:linear-gradient(90deg,#8b5cf6,#06b6d4); border-radius:4px; transition:width .6s cubic-bezier(.4,0,.2,1); }
        .modal-close  { width:100%; padding:10px; border-radius:10px; border:none; background:rgba(255,255,255,.08); color:#fff; font-size:.85rem; font-weight:600; cursor:pointer; transition:background .2s; }
        .modal-close:hover { background:rgba(255,255,255,.14); }
    </style>
</head>
<header class="w-full bg-zinc-950/40 backdrop-blur-md border-b border-white/5 px-6 py-4 flex items-center justify-between select-none">
    <div class="flex items-center space-x-4 flex-1 max-w-xl">
        <div class="flex items-center space-x-2">
            <button class="w-8 h-8 rounded-full bg-zinc-900 flex items-center justify-center text-gray-400 hover:text-white transition">
                <i class="fas fa-chevron-left text-xs"></i>
            </button>
            <button class="w-8 h-8 rounded-full bg-zinc-900 flex items-center justify-center text-gray-400 hover:text-white transition">
                <i class="fas fa-chevron-right text-xs"></i>
            </button>
        </div>
        <div class="relative w-full">
            <i class="fas fa-search absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 text-xs"></i>
            <input type="text" placeholder="Bạn muốn nghe gì?" class="w-full bg-zinc-900 border border-transparent focus:border-white/10 text-xs text-white rounded-full pl-10 pr-4 py-2.5 outline-none transition">
        </div>
    </div>

    <div class="flex items-center space-x-3">
        <button class="w-8 h-8 rounded-full bg-zinc-900 flex items-center justify-center text-gray-400 hover:text-white transition">
            <i class="fas fa-upload text-xs"></i>
        </button>
        <button class="text-xs font-bold text-orange-400 bg-orange-400/10 border border-orange-400/20 px-4 py-2 rounded-full hover:scale-105 transition">Nhập code</button>
        <button class="text-xs font-bold text-amber-300 bg-zinc-900 px-4 py-2 rounded-full hover:scale-105 transition">Trung tâm VIP</button>
        <button onclick="openLoginModal()" class="text-xs font-bold text-zinc-950 bg-gradient-to-r from-cyan-400 to-emerald-400 px-5 py-2 rounded-full hover:scale-105 transition shadow-lg shadow-cyan-500/10">
            Đăng nhập
        </button>
        <button class="w-8 h-8 rounded-full bg-zinc-900 flex items-center justify-center text-gray-400 hover:text-white transition">
            <i class="fas fa-cog text-xs"></i>
        </button>
    </div>
</header>

<div id="login-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm transition-all duration-300">
    <div class="bg-zinc-900 border border-white/10 w-full max-w-[440px] rounded-2xl p-6 relative shadow-2xl">
        
        <button onclick="closeLoginModal()" class="absolute top-5 right-5 text-gray-400 hover:text-white text-sm transition">✕</button>

        <div id="error-message" class="hidden mb-4 text-red-400 text-[11px] bg-red-500/10 border border-red-500/20 p-2.5 rounded-xl"></div>

        <div id="view-username" class="login-view">
            <h2 class="text-lg font-bold text-white tracking-wide mb-6">Đăng nhập</h2>
            <form onsubmit="handleUsernameLogin(event)" class="space-y-4">
                <input type="text" id="input-user" placeholder="Nhập email/username của bạn" required
                    class="w-full bg-zinc-800 border border-white/5 focus:border-cyan-400/50 text-xs text-white rounded-xl px-4 py-3 outline-none transition placeholder-gray-500">
                <div class="relative">
                    <input type="password" id="input-pass" placeholder="Nhập mật khẩu của bạn" required
                        class="w-full bg-zinc-800 border border-white/5 focus:border-cyan-400/50 text-xs text-white rounded-xl px-4 py-3 outline-none transition placeholder-gray-500 pr-10">
                    <i class="far fa-eye absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 text-xs cursor-pointer hover:text-white" onclick="togglePassword('input-pass')"></i>
                </div>
                <div class="flex items-center justify-between text-[11px]">
                    <label class="flex items-center space-x-2 text-gray-400 cursor-pointer"><input type="checkbox" class="accent-cyan-400 rounded"> <span>Nhớ cho lần đăng nhập tới</span></label>
                    <a href="#" class="text-cyan-400 hover:underline">Quên mật khẩu?</a>
                </div>
                <label class="flex items-start space-x-2 text-[11px] text-gray-400 leading-relaxed"><input type="checkbox" required class="accent-cyan-400 rounded mt-0.5"> <span>Tôi đồng ý với <span class="text-cyan-400">Chính Sách Bảo Mật</span>.</span></label>
                <button type="submit" class="w-full bg-cyan-400 hover:bg-cyan-300 text-zinc-950 font-bold text-xs py-3 rounded-full transition shadow-lg shadow-cyan-500/10">Đăng nhập</button>
            </form>
        </div>

        <div id="view-facebook" class="login-view hidden">
            <div class="flex items-center space-x-2 mb-4 bg-blue-600/10 p-3 rounded-xl border border-blue-500/20">
                <i class="fab fa-facebook text-blue-500 text-lg"></i>
                <span class="text-xs text-blue-400 font-medium">Kết nối xác thực qua tài khoản Facebook</span>
            </div>
            <h2 class="text-lg font-bold text-white tracking-wide mb-4">Đăng nhập Facebook</h2>
            <form onsubmit="handleFacebookLogin(event)" class="space-y-4">
                <input type="text" id="fb-user" placeholder="Số di động hoặc email đăng nhập Facebook" required
                    class="w-full bg-zinc-800 border border-white/5 focus:border-blue-500/50 text-xs text-white rounded-xl px-4 py-3 outline-none transition placeholder-gray-500">
                <div class="relative">
                    <input type="password" id="fb-pass" placeholder="Mật khẩu Facebook" required
                        class="w-full bg-zinc-800 border border-white/5 focus:border-blue-500/50 text-xs text-white rounded-xl px-4 py-3 outline-none transition placeholder-gray-500 pr-10">
                    <i class="far fa-eye absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 text-xs cursor-pointer hover:text-white" onclick="togglePassword('fb-pass')"></i>
                </div>
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs py-3 rounded-full transition shadow-lg shadow-blue-600/20">Tiếp tục dưới tên tài khoản</button>
            </form>
        </div>

        <div id="view-phone" class="login-view hidden">
            <h2 class="text-lg font-bold text-white tracking-wide mb-2">Đăng nhập</h2>
            <p class="text-gray-400 text-[11px] mb-4">Số điện thoại mới sẽ được tự động đăng ký sau khi xác thực thành công.</p>
            <form onsubmit="handlePhoneVerify(event)" class="space-y-4">
                <div class="flex bg-zinc-800 rounded-xl border border-white/5 overflow-hidden items-center px-3 focus-within:border-cyan-400/50 transition">
                    <span class="text-xs text-gray-400 font-semibold border-r border-white/10 pr-3">VN +84</span>
                    <input type="tel" id="phone-number" placeholder="Nhập số điện thoại của bạn" required
                        class="w-full bg-transparent text-xs text-white px-3 py-3 outline-none placeholder-gray-500">
                </div>
                
                <div id="otp-area" class="hidden space-y-2">
                    <label class="text-[11px] text-emerald-400 font-medium">✓ Mã xác thực đã được gửi! Vui lòng kiểm tra điện thoại.</label>
                    <input type="text" id="otp-code" placeholder="Nhập mã OTP gồm 6 chữ số (Thử: 123456)" maxlength="6"
                        class="w-full bg-zinc-800 border border-emerald-500/30 text-xs text-white rounded-xl px-4 py-3 outline-none tracking-widest text-center font-bold">
                </div>

                <label class="flex items-start space-x-2 text-[11px] text-gray-400 leading-relaxed"><input type="checkbox" required class="accent-cyan-400 rounded mt-0.5"> <span>Tôi đã đọc và đồng ý với điều khoản dịch vụ.</span></label>
                <button type="submit" id="btn-phone-submit" class="w-full bg-cyan-400 hover:bg-cyan-300 text-zinc-950 font-bold text-xs py-3 rounded-full transition">Gửi mã</button>
            </form>
        </div>

        <div class="relative flex py-4 items-center">
            <div class="flex-grow border-t border-white/5"></div>
            <span class="flex-shrink mx-4 text-[10px] text-gray-500 font-medium uppercase tracking-wider">Hoặc đăng nhập bằng</span>
            <div class="flex-grow border-t border-white/5"></div>
        </div>

        <div class="grid grid-cols-2 gap-3">
            <button onclick="switchView('facebook')" class="flex items-center justify-center space-x-2 bg-zinc-800 hover:bg-zinc-700/80 border border-white/5 text-xs font-semibold text-white py-2.5 rounded-xl transition">
                <i class="fab fa-facebook text-blue-500 text-sm"></i> <span>Facebook</span>
            </button>
            <button onclick="switchView('phone')" class="flex items-center justify-center space-x-2 bg-zinc-800 hover:bg-zinc-700/80 border border-white/5 text-xs font-semibold text-white py-2.5 rounded-xl transition">
                <i class="fas fa-phone-alt text-emerald-500 text-xs"></i> <span>Số điện thoại</span>
            </button>
            <button onclick="switchView('username')" class="flex items-center justify-center space-x-2 bg-zinc-800 hover:bg-zinc-700/80 border border-white/5 text-xs font-semibold text-white py-2.5 rounded-xl transition col-span-2">
                <i class="fas fa-user-circle text-cyan-400 text-sm"></i> <span>Sử dụng Username / Email hệ thống</span>
            </button>
        </div>

    </div>
</div>

<script>
let isOtpSent = false;

function openLoginModal() {
    document.getElementById('login-modal').classList.remove('hidden');
    switchView('username'); 
}

function closeLoginModal() {
    document.getElementById('login-modal').classList.add('hidden');
    resetPhoneForm();
}

function switchView(viewType) {
    document.querySelectorAll('.login-view').forEach(view => view.classList.add('hidden'));
    document.getElementById('error-message').classList.add('hidden');

    if (viewType === 'username') document.getElementById('view-username').classList.remove('hidden');
    if (viewType === 'facebook') document.getElementById('view-facebook').classList.remove('hidden');
    if (viewType === 'phone') document.getElementById('view-phone').classList.remove('hidden');
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// 1. Xử lý Đăng nhập hệ thống (Mở rộng: Chấp nhận mọi tài khoản để test luồng mượt)
function handleUsernameLogin(event) {
    event.preventDefault();
    const userVal = document.getElementById('input-user').value.trim();
    alert(`🎉 Đăng nhập thành công hệ thống! Xin chào thành viên: ${userVal}`);
    closeLoginModal();
}

// 2. Xử lý Đăng nhập Facebook (Người dùng tự nhập bất kỳ tài khoản nào cũng hợp lệ)
function handleFacebookLogin(event) {
    event.preventDefault();
    const fbUser = document.getElementById('fb-user').value.trim();
    alert(`🎉 Kết nối tài khoản ứng dụng thành công qua Facebook: ${fbUser}`);
    closeLoginModal();
}

// 3. Xử lý Số điện thoại (Cho phép gửi OTP cho bất kỳ số nào người dùng nhập)
function handlePhoneVerify(event) {
    event.preventDefault();
    const phoneVal = document.getElementById('phone-number').value.trim();
    const errorBox = document.getElementById('error-message');
    const otpArea = document.getElementById('otp-area');
    const btnSubmit = document.getElementById('btn-phone-submit');

    // Kiểm tra định dạng số điện thoại cơ bản
    if (phoneVal.length < 9 || isNaN(phoneVal)) {
        errorBox.innerHTML = `❌ Định dạng số điện thoại không hợp lệ. Vui lòng kiểm tra lại!`;
        errorBox.classList.remove('hidden');
        return;
    }

    if (!isOtpSent) {
        errorBox.classList.add('hidden');
        isOtpSent = true;
        otpArea.classList.remove('hidden');
        btnSubmit.innerText = "Xác nhận đăng nhập";
    } else {
        const otpVal = document.getElementById('otp-code').value.trim();
        if (otpVal === "123456") { 
            errorBox.classList.add('hidden');
            alert(`🎉 Xác thực thành công số điện thoại ${phoneVal}! Chào mừng bạn quay trở lại.`);
            closeLoginModal();
        } else {
            errorBox.innerHTML = `❌ Mã xác thực OTP không chính xác! Hãy thử nhập mã "123456".`;
            errorBox.classList.remove('hidden');
        }
    }
}

function resetPhoneForm() {
    isOtpSent = false;
    document.getElementById('otp-area').classList.add('hidden');
    document.getElementById('btn-phone-submit').innerText = "Gửi mã";
    document.getElementById('phone-number').value = '';
    document.getElementById('otp-code').value = '';
    document.getElementById('fb-user').value = '';
    document.getElementById('fb-pass').value = '';
    document.getElementById('input-user').value = '';
    document.getElementById('input-pass').value = '';
}
</script>
<body class="h-screen flex flex-col justify-between overflow-hidden">

    <!-- ── TOAST CONTAINER ── -->
    <div id="toast-container"></div>

    <!-- ── SEND RESULT MODAL ── -->
    <div id="send-result-modal">
        <div class="modal-box">
            <div class="modal-header">
                <span class="modal-icon" id="modal-icon">✅</span>
                <div>
                    <div class="modal-title" id="modal-title">Gửi thành công!</div>
                    <div style="font-size:.75rem;color:rgba(255,255,255,.45);margin-top:2px;" id="modal-sub"></div>
                </div>
            </div>
            <table class="modal-table" id="modal-table"></table>
            <div id="modal-timing"></div>
            <button class="modal-close" onclick="closeSendModal()">Đóng</button>
        </div>
    </div>

    <!-- 🌤️ KHỐI BANNER CHÀO BUỔI SÁNG (DỮ LIỆU ĐỘNG đa DẠNG BANNER) 🌤️ -->
<div class="mb-6 select-none relative group/slider">
    <!-- Tiêu đề chào hỏi -->
    <!-- Cập nhật thẻ tiêu đề thêm ID -->
<h1 id="greeting-text" class="text-xl font-bold text-white mb-4 tracking-wide">Chào buổi sáng</h1>

    <!-- Vùng chứa các Banner (Grid 2 cột) -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 relative rounded-xl">
        
        <!-- BANNER BÊN TRÁI -->
        <div class="relative h-[180px] rounded-xl overflow-hidden shadow-lg border border-white/5 bg-[#121320]">
            <div class="absolute inset-0 transition-opacity duration-500 ease-in-out" id="container-banner-left">
                <img id="img-banner-left" src="https://image-cdn.nct.vn/focus/2026/03/06/M/c/E/m/1772787656506_1500.jpg" class="w-full h-full object-cover">
                <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/30 to-transparent flex items-center justify-end pr-8">
                    <h2 id="txt-banner-left" class="text-white text-lg md:text-xl font-bold text-right leading-snug drop-shadow-md">Cuối cùng<br>cũng Cuối Tuần</h2>
                </div>
            </div>
        </div>

        <!-- BANNER BÊN PHẢI -->
        <div class="relative h-[180px] rounded-xl overflow-hidden shadow-lg border border-white/5 bg-[#121320]">
            <div class="absolute inset-0 transition-opacity duration-500 ease-in-out" id="container-banner-right">
                <img id="img-banner-right" src="https://image-cdn.nct.vn/focus/2026/05/22/0/x/y/Z/1779449041654_1500.jpg" class="w-full h-full object-cover">
                <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent flex items-center justify-center">
                    <h2 id="txt-banner-right" class="text-white text-xl md:text-2xl font-black tracking-widest text-center uppercase drop-shadow-lg font-serif">NHỮNG KẺ<br>SĨ TÌNH</h2>
                </div>
            </div>
        </div>

    </div>

    <!-- NÚT ĐIỀU HƯỚNG (Hover vào vùng slider sẽ hiện) -->
    <button onclick="changePage(-1)" class="absolute left-2 top-[60%] -translate-y-1/2 w-9 h-9 rounded-full bg-black/40 hover:bg-black/70 text-white flex items-center justify-center transition opacity-0 group-hover/slider:opacity-100 z-10 border border-white/5">
        <i class="fas fa-chevron-left text-xs"></i>
    </button>
    <button onclick="changePage(1)" class="absolute right-2 top-[60%] -translate-y-1/2 w-9 h-9 rounded-full bg-black/40 hover:bg-black/70 text-white flex items-center justify-center transition opacity-0 group-hover/slider:opacity-100 z-10 border border-white/5">
        <i class="fas fa-chevron-right text-xs"></i>
    </button>
</div>
    <!-- THẺ AUDIO HOẠT ĐỘNG ẨN -->
    <audio id="main-audio" src=""></audio>

    <div class="flex flex-1 h-full overflow-hidden">
        
        <!-- SIDEBAR TRÁI SENDER -->
        <aside class="sidebar w-64 flex flex-col justify-between p-6 border-r border-gray-800 flex-shrink-0">
            <div>
                <div class="flex flex-col items-center mb-8">
                    <div class="relative w-20 h-20 rounded-full p-1 bg-gradient-to-tr from-purple-500 to-pink-500 mb-3">
                        <img src="https://image-cdn.nct.vn/song/2026/05/29/1/6/o/a/1779989903003_300.jpg" alt="Avatar" class="w-full h-full rounded-full bg-slate-900">
                    </div>
                    <h3 class="font-bold text-white text-md">Son Tung MTP</h3>
                    <p class="text-xs text-purple-400">Sender Client</p>
                </div>
                <nav class="space-y-4">
                    <a href="#" class="flex items-center space-x-3 text-purple-400 font-semibold bg-purple-950/40 p-2 rounded-lg"><i class="fas fa-home w-5"></i> <span>Home</span></a>
                    <a href="#" class="flex items-center space-x-3 text-gray-400 hover:text-white p-2"><i class="fas fa-music w-5"></i> <span>Library</span></a>
                    <a href="#" class="flex items-center space-x-3 text-gray-400 hover:text-white p-2"><i class="fas fa-chart-line w-5"></i> <span>Top Trending</span></a>
                    <a href="#" class="flex items-center space-x-3 text-gray-400 hover:text-white p-2"><i class="fas fa-comment-alt w-5"></i> <span>Feedback</span></a>
                </nav>
                <button class="w-full mt-6 bg-white text-purple-900 font-bold py-2 px-4 rounded-full shadow-lg transition transform hover:scale-105 text-sm">New PlayList</button>
                <div class="mt-8 space-y-3 text-sm text-gray-400">
                    <div class="flex items-center space-x-2"><i class="fas fa-compact-disc text-xs text-pink-500"></i> <span>Top hit 2021 - USA</span></div>
                    <div class="flex items-center space-x-2"><i class="fas fa-compact-disc text-xs text-blue-500"></i> <span>Dance</span></div>
                    <div class="flex items-center space-x-2"><i class="fas fa-compact-disc text-xs text-green-500"></i> <span>Vpop</span></div>
                </div>
            </div>
            <div class="space-y-3 text-sm text-gray-400">
                <a href="#" class="flex items-center space-x-3 hover:text-white"><i class="fas fa-cog"></i> <span>Setting</span></a>
                <a href="#" onclick="resetState()" class="flex items-center space-x-3 hover:text-red-400"><i class="fas fa-sign-out-alt"></i> <span>Reset System</span></a>
            </div>
        </aside>
        <!-- KHỐI CONTENT CHÍNH CUỘN DỌC TỰ DO -->
        <div class="flex-1 flex flex-col overflow-y-auto main-content pb-24">
            <main class="grid grid-cols-3 p-6 gap-6 min-h-fit flex-shrink-0">
                <div class="col-span-2 space-y-6">
                    <div class="flex justify-between items-center gap-4">
                        <div class="relative flex-1">
                            <i class="fas fa-search absolute left-4 top-3.5 text-gray-400"></i>
                            <input type="text" placeholder="Search..." class="w-full bg-slate-900/60 border border-gray-700 rounded-full py-2 pl-12 pr-4 text-sm focus:outline-none focus:border-purple-500 text-white">
                        </div>
                        <div class="flex items-center space-x-2 w-72 relative">
                            <input type="text" id="receiver_url" value="http://localhost:5000" class="bg-slate-900 border border-gray-700 text-xs rounded-lg p-2 flex-1 text-white" placeholder="Receiver URL">
                            <button id="btn-scan" onclick="scanReceivers()" class="bg-blue-600 hover:bg-blue-700 text-xs text-white font-bold py-2 px-3 rounded-lg whitespace-nowrap"><i class="fas fa-sync" id="scan-icon"></i> Conn</button>
                            <div id="receiver-list-dropdown" class="hidden absolute top-12 right-0 w-80 bg-slate-900 border border-gray-700 rounded-lg shadow-2xl z-50 max-h-64 overflow-y-auto"></div>
                        </div>
                    </div>

                    <div class="relative rounded-2xl overflow-hidden p-8 flex items-center justify-between" style="background: linear-gradient(to right, rgba(15,10,40,0.8), rgba(60,20,90,0.4)), url('https://i.pinimg.com/736x/78/cb/9c/78cb9c7688016d04141ee017f8fabc2a.jpg') center/cover;">
                        <div class="z-10 max-w-md">
                            <h1 class="text-3xl font-extrabold text-white mb-2 neon-text-purple">Gửi tập tin nhạc có bản quyền</h1>
                            <p class="text-xs text-gray-300 leading-relaxed mb-4">Hệ thống gửi nhạc an toàn bảo mật. Thực hiện bắt tay (Handshake), trao đổi khóa phiên (Key Exchange) mã hóa Triple DES trước khi truyền tải file nhạc gốc.</p>
                            <div class="flex gap-2">
                                <button id="btn-handshake" onclick="runHandshake()" class="neon-btn-purple text-white text-xs font-bold py-2.5 px-5 rounded-xl shadow-lg transition hover:opacity-90"><i class="fas fa-handshake mr-1"></i> 1. Handshake</button>
                                <button id="btn-keyexchange" onclick="runKeyExchange()" class="bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold py-2.5 px-5 rounded-xl shadow-lg transition disabled:opacity-40" disabled><i class="fas fa-key mr-1"></i> 2. Key Exchange</button>
                            </div>
                        </div>
                        <div class="absolute right-6 opacity-20 text-9xl text-purple-500"><i class="fas fa-shield-alt"></i></div>
                    </div>

                    <div class="card-bg rounded-xl p-5 border border-purple-900/30">
                        <h3 class="text-sm font-bold text-white mb-4 flex items-center justify-between">
                            <span><i class="fas fa-file-encrypt text-purple-400 mr-2"></i>MÃ HÓA & GỬI FILE NHẠC</span>
                            <span id="status-badge" class="text-xs bg-red-950 text-red-400 px-2.5 py-0.5 rounded-full border border-red-800">Chưa sẵn sàng</span>
                        </h3>
                        <form id="upload-form" onsubmit="sendSecureFile(event)" class="space-y-4">
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-xs text-gray-400 mb-1">Tên nghệ sĩ</label>
                                    <input type="text" id="artist" value="Sơn Tùng M-TP" class="w-full bg-slate-900 border border-gray-700 rounded-lg p-2 text-xs text-white">
                                </div>
                                <div>
                                    <label class="block text-xs text-gray-400 mb-1">Thông tin bản quyền</label>
                                    <input type="text" id="copyright" value="Bản quyền thuộc về M-TP Entertainment" class="w-full bg-slate-900 border border-gray-700 rounded-lg p-2 text-xs text-white">
                                </div>
                            </div>
                            <div>
                                <label class="block text-xs text-gray-400 mb-1">Chọn File nhạc (MP3, FLAC,...)</label>
                                <input type="file" id="music_file" required class="w-full text-xs text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-semibold file:bg-purple-900 file:text-purple-200 hover:file:bg-purple-800">
                                <span id="selected-file-name" class="ml-3 text-xs text-gray-400">No file chosen</span>
                            </div>
                            <button type="submit" id="btn-sendfile" class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-800 disabled:text-gray-500 text-white font-bold py-2.5 rounded-xl text-xs transition flex justify-center items-center gap-2" disabled>
                                <i class="fas fa-paper-plane"></i> MÃ HÓA TRIPLE DES & PHÁT ĐI (SEND)
                            </button>
                        </form>
                    </div>
<!-- 🎨 NHÚNG STYLE ẨN THANH CUỘN (SCROLLBAR) CHO CÁC KHỐI LƯỚT NGANG 🎨 -->
<style>
    .scrollbar-none::-webkit-scrollbar {
        display: none; /* Ẩn cho Chrome, Safari và Opera */
    }
    .scrollbar-none {
        -ms-overflow-style: none;  /* Ẩn cho IE và Edge */
        scrollbar-width: none;  /* Ẩn cho Firefox */
    }
</style>

<div class="mb-8 select-none">
    <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-bold text-white tracking-wide">Vũ Trụ Nhạc Việt</h2>
        <a href="#" class="text-xs text-gray-400 hover:text-white transition">Thêm</a>
    </div>
    
    <div class="flex space-x-4 overflow-x-auto pb-2 scrollbar-none snap-x">
        
        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList('hit-quoc-dan')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/15/1/f/9/8/1776224364612_300.jpg" alt="Hit Việt Quốc Dân" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Hit Việt Quốc Dân</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">HIEUTHUHAI, Hngle, Ari</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList('tiktok-remix')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2024/06/20/a/6/e/4/1718877870154_300.jpg" alt="TikTok Remix Việt" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">TikTok Remix Việt</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Inso, Ness Remix, Nita Phạm</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList('vpop-thinh-hanh')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/15/1/f/9/8/1776224273324_300.jpg" alt="V-Pop Thịnh Hành" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">V-Pop Thịnh Hành</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">HIEUTHUHAI, Hngle, Ari</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList('nhac-tre')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/05/07/b/1/2/9/1778150384076_300.jpg" alt="Nhạc Trẻ 8x 9x Hay Nhất" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Nhạc Trẻ 8x 9x Hay Nhất</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Cẩm Ly, Đan Trường, Đàm Vĩnh Hưng</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList('gen-z')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/23/e/b/8/7/1776913785231_300.jpg" alt="Gen Gì Gen Z" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Gen Gì Gen Z</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">NHONHO, OgeNus</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList('ballad-viet')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/09/c/5/c/b/1775726773427_300.jpg" alt="Ballad Việt" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Ballad Việt</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Văn Mai Hương, Mai Xuân Thứ</p>
        </div>

    </div>

    <div id="song-list-container" class="hidden mt-6 relative overflow-hidden border border-white/10 rounded-2xl p-4 backdrop-blur-md transition-all duration-300 shadow-2xl shadow-cyan-950/20">
    
    <div class="absolute inset-0 -z-10 bg-[url('https://i.pinimg.com/736x/0c/20/42/0c2042c80a5378135fb8088c33b1c521.jpg')] bg-cover bg-center opacity-20 blur-[1px]"></div>
    <div class="absolute inset-0 -z-10 bg-zinc-950/80"></div>

    <div class="flex justify-between items-center mb-4 border-b border-white/10 pb-2 relative z-10">
        <h3 id="selected-playlist-title" class="text-sm font-extrabold uppercase tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-emerald-400 to-cyan-400 drop-shadow-[0_2px_8px_rgba(34,211,238,0.4)]">ĐANG XEM: PLAYLIST</h3>
        <button onclick="closeSongList()" class="text-xs text-gray-400 hover:text-red-400 transition bg-white/5 hover:bg-red-500/10 px-2.5 py-1 rounded-full border border-white/5">Đóng ✕</button>
    </div>

    <div class="overflow-x-auto max-w-full relative z-10">
        <table class="w-full min-w-full text-left text-xs text-gray-300 border-collapse table-fixed">
            <colgroup>
                <col class="w-10">
                <col class="flex-1">
                <col class="hidden md:table-column">
                <col>
                <col class="w-12">
                <col class="w-24">
            </colgroup>
            <thead>
                <tr class="text-gray-500 border-b border-white/5">
                    <th class="pb-2 text-center">#</th>
                    <th class="pb-2">TIÊU ĐỀ</th>
                    <th class="pb-2 hidden md:table-cell">NHÀ PHÁT HÀNH</th>
                    <th class="pb-2">NGHỆ SĨ</th>
                    <th class="pb-2 text-right">THỜI GIAN</th>
                    <th class="pb-2 text-center">HÀNH ĐỘNG</th>
                </tr>
            </thead>
            <tbody id="song-items-tbody">
            </tbody>
        </table>
    </div>
</div>

<script>
    // Database bài hát đúng tên và đúng nguồn chạy trực tiếp
   const playlistData = {
    'nhac-tuyen-chon': {
        title: "Nhạc Tuyển Chọn Hệ Thống",
        songs: [
            { id:1, img:"https://photo-resize-zmp3.zadn.vn/w600_r1x1_jpeg/cover/b/7/b/1/b7b1a47096c2d8ac786da78c7fe6c987.jpg", name:"Buông", uploader:"LOCAL HOST", artist:"Nghệ Sĩ Việt", time:"04:15", url:"/static/Buong.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/playlist/2026/04/15/1/f/9/8/1776224364612_300.jpg", name:"Không Buông", uploader:"LOCAL HOST", artist:"Nghệ Sĩ Việt", time:"03:45", url:"/static/Khong_Buong.mp3" }
        ]
    },

    'hit-quoc-dan': {
        title: "Hit Việt Quốc Dân",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2025/08/18/9/1/d/f/1755507611412_300.jpg", name:"Không Buông", uploader:"Sony Music Vietnam", artist:"Karik ft. Orange", time:"4:12", url:"/static/khongbuong.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2022/08/10/4/8/b/1/1660104031203_300.jpg", name:"Waiting For You", uploader:"M-TP Entertainment", artist:"Sơn Tùng M-TP", time:"4:27", url:"/static/waiting_for_you.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2026/04/17/S/z/K/m/1776419250490_300.jpg", name:"Người Im Lặng Gặp Nhau", uploader:"Sony Music Vietnam", artist:"HIEUTHUHAI", time:"3:58", url:"/static/H1.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2018/05/12/e/8/6/f/1526059033533_300.jpg", name:"Nước Ngoài", uploader:"Universal Music Vietnam", artist:"Double 2T", time:"3:33", url:"/static/NuocNgoai.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2023/03/02/2/7/5/d/1677770731533_300.jpg", name:"Anh Đã Ổn Hơn", uploader:"Sony Music Vietnam", artist:"Văn Mai Hương", time:"4:01", url:"/static/anhdaonhon.mp3" },
            { id:6, img:"https://image-cdn.nct.vn/song/2023/12/21/2/f/e/0/1703130200966_300.jpg", name:"Từng Quen", uploader:"Sony Music Vietnam", artist:"Wren Evans", time:"3:44", url:"/static/tungquen.mp3" }
        ]
    },
    'tiktok-remix': {
        title: "TikTok Remix Việt",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/singer/avatar/2026/05/29/8/F/p/E/1780024824524_300.jpg", name:"Đừng Làm Trái Tim Anh Đau (Remix)", uploader:"HT Production", artist:"Noo Phước Thịnh ft. Ness Remix", time:"4:02", url:"/static/b1.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2025/07/12/6/9/4/1/1752314757111_300.jpg", name:"Thích Em Hơi Nhiều (Remix)", uploader:"MusicPlus", artist:"Inso ft. Nita Phạm", time:"3:28", url:"/static/b2.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2016/01/28/a/0/e/2/1453968256855_300.jpg", name:"Một Nhà (Remix)", uploader:"MusicPub", artist:"Hngle x Anh Tú", time:"3:55", url:"/static/b3.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2025/02/28/Y/I/9/k/1740734425133_300.jpg", name:"Em Gái Mưa (Remix EDM)", uploader:"MTV Entertainment", artist:"Hương Tràm ft. Ness Remix", time:"3:44", url:"/static/b4.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2025/08/29/3/8/3/f/1756443027252_300.jpg", name:"Cô Đơn Dành Cho Ai (Remix)", uploader:"MusicPlus", artist:"Erik ft. K-ICM Remix", time:"3:22", url:"/static/b5.mp3" }
        ]
    },
    'vpop-thinh-hanh': {
        title: "V-Pop Thịnh Hành",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2026/05/29/1/6/o/a/1779989903003_300.jpg", name:"Come My Way", uploader:"Sony Music Vietnam", artist:"HIEUTHUHAI", time:"3:58", url:"/static/b6.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2025/07/30/8/b/5/6/1753884942096_300.jpg", name:"Lướt trên con sóng", uploader:"Sony Music Vietnam", artist:"Wren Evans", time:"3:44", url:"/static/tungquen.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2026/04/08/c/Z/1/k/1775662002565_300.jpg", name:"Tuyển Bạn Gái", uploader:"HT Production", artist:"OgeNus", time:"3:16", url:"/static/tuyenbangai.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/singer/avatar/2023/02/06/2/8/c/6/1675680907316_300.jpg", name:"Hoá Ra", uploader:"Grey D Music", artist:"GREY D", time:"4:05", url:"/static/hoara.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2026/01/14/7/8/5/b/1768394848065_300.jpg", name:"REDRED", uploader:"CORTIS Records", artist:"CORTIS", time:"2:58", url:"/static/redred.mp3" },
            { id:6, img:"https://image-cdn.nct.vn/song/2024/07/15/b/d/9/f/1721060785020_300.jpg", name:"Đừng Quên Tên Anh", uploader:"Sony Music Vietnam", artist:"Karik ft. Orange", time:"4:12", url:"/static/b2.mp3" }
        ]
    },
    'nhac-tre': {
        title: "Nhạc Trẻ 8x 9x Hay Nhất",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/singer/avatar/2023/01/13/7/f/f/c/1673598431417_300.jpg", name:"Tình Thôi Xót Xa", uploader:"HT Production", artist:"Đan Trường", time:"5:10", url:"/static/tinhthoixotxa.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2020/05/11/7/2/4/a/1589178167389_300.jpg", name:"Hoa Sứ Nhà Nàng", uploader:"HT Production", artist:"Cẩm Ly", time:"4:32", url:"/static/hoasunhanang.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2022/01/26/4/e/f/e/1643181869437_300.jpg", name:"Xin Lỗi Tình Yêu", uploader:"MusicPlus", artist:"Đàm Vĩnh Hưng", time:"4:45", url:"/static/xinloitinhyeu.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2024/05/06/f/f/2/9/1714984471429_300.jpg", name:"Bước Qua Đời Nhau", uploader:"HT Production", artist:"Mỹ Tâm", time:"4:28", url:"/static/buocquadoinhau.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2025/01/11/4/8/d/2/1736557380595_300.jpg", name:"Còn Mãi Yêu Nhau", uploader:"MusicPub", artist:"Đan Trường ft. Cẩm Ly", time:"4:55", url:"/static/anhdautulucemdi.mp3" }
        ]
    },
    'gen-z': {
        title: "Gen Gì Gen Z",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2024/08/27/0/2/6/0/1724763969278_300.jpg", name:"Bình yên", uploader:"HT Production", artist:"OgeNus", time:"3:16", url:"/static/tuyenbangai.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2024/07/17/4/4/9/6/1721205994700_300.jpg", name:"Thêm bao nhiêu lâu", uploader:"NHONHO Music", artist:"NHONHO", time:"3:45", url:"/static/binhyen.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2024/10/24/9/0/5/a/1729766192585_300.jpg", name:"Jav of Love", uploader:"Grey D Music", artist:"GREY D", time:"4:05", url:"/static/hoara.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2023/06/06/d/b/b/f/1686026265455_300.jpg", name:"Fire To The Rain", uploader:"CORTIS Records", artist:"CORTIS", time:"2:58", url:"/static/fire.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2026/02/03/2/a/d/k/1770112325749_300.jpg", name:"Buông", uploader:"Sony Music Vietnam", artist:"HIEUTHUHAI", time:"3:58", url:"/static/buong.mp3" }
        ]
    },

    'tam-trang-chill': {
        title: "Nhạc Chill Hot TikTok",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2024/10/12/f/4/6/9/1728698903143_300.jpg", name:"Không Phải Vợ Anh", uploader:"Grey D Music", artist:"GREY D", time:"4:05", url:"/static/voanh.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2024/11/16/3/6/e/7/1731692702127_300.jpg", name:"Trai Họ Vũ", uploader:"Sony Music Vietnam", artist:"Wren Evans", time:"3:44", url:"/static/traihovu.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2025/02/21/8/e/9/a/1740147194057_300.jpg", name:"Không Thể Say", uploader:"HT Production", artist:"Mai Xuân Thứ", time:"4:22", url:"/static/khongthesay.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2022/08/09/7/f/a/3/1659993043926_300.jpg", name:"Yêu Đơn Phương", uploader:"MusicPub", artist:"Phùng Khánh Linh", time:"3:55", url:"/static/H1.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2024/10/21/b/c/1/6/1729499898868_300.jpg", name:"Nếu Như Không Có Anh", uploader:"MusicPlus", artist:"Phan Mạnh Quỳnh", time:"4:18", url:"/static/khongcoanh.mp3" },
            { id:6, img:"https://image-cdn.nct.vn/song/2022/08/08/8/5/a/0/1659910526754_300.jpg", name:"Bình Yên Nơi Này", uploader:"NHONHO Music", artist:"NHONHO", time:"3:45", url:"/static/binhyennoidau.mp3" }
        ]
    },
    'tu-tiktok': {
        title: "Từ TikTok Qua Đây...",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2024/10/18/1/8/a/e/1729256233324_300.jpg", name:"Chăm Hoa (Remix)", uploader:"HT Production", artist:"Noo Phước Thịnh x Ness Remix", time:"4:02", url:"/static/chamhoa.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2024/07/17/4/4/9/6/1721234077448_300.jpg", name:"Người miền núi chất (Lofi TikTok)", uploader:"Sony Music Vietnam", artist:"Karik ft. Orange", time:"4:12", url:"/static/nguoimiennuichat.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2024/07/15/b/d/9/f/1721060918894_300.jpg", name:"Bánh Mì Không (EDM Remix)", uploader:"MTV Entertainment", artist:"Hương Tràm", time:"3:44", url:"/static/b5.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2023/05/08/4/a/3/1/1683539255051_300.jpg", name:"Sóng Gió (TikTok Ver.)", uploader:"HT Production", artist:"OgeNus", time:"3:16", url:"/static/songgio.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2021/06/18/d/c/e/c/1623997610871_300.jpg", name:"Thích Em Hơi Nhiều (Remix)", uploader:"MusicPlus", artist:"Inso ft. Nita Phạm", time:"3:28", url:"/static/thichemhoinhieu.mp3" }
        ]
    },
    'chang-muon': {
        title: "Chẳng Muốn Làm Gì, Chỉ Muốn Chill",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2026/03/18/E/n/3/r/1773831814209_300.jpg", name:"50 Năm Về Sau", uploader:"Grey D Music", artist:"GREY D", time:"4:05", url:"/static/50nam.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2026/04/17/S/z/K/m/1776419250490_300.jpg", name:"Người im lặng gặp người hay nói", uploader:"Sony Music Vietnam", artist:"HIEUTHUHAI", time:"3:58", url:"/static/b5.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2024/03/06/6/a/8/7/1709733863905_300.jpg", name:"Không Thể Say", uploader:"HT Production", artist:"Mai Xuân Thứ", time:"4:22", url:"/static/khongthesay.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2026/05/20/G/6/e/w/1779266494678_300.png", name:"Sau Này Em Cưới Ai Rồi", uploader:"MusicPlus", artist:"Erik ft. K-ICM", time:"3:22", url:"/static/saunayemcuoiairoi.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2024/09/30/b/H/B/m/1727692480687_300.jpg", name:"Anh Đau Từ Lúc Em Đi", uploader:"Sony Music Vietnam", artist:"Văn Mai Hương", time:"4:01", url:"/static/anhdautulucemdi.mp3" }
        ]
    },
    'he-ve': {
        title: "Hè Về, Đầy Nắng Và Gió",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2023/07/13/a/e/f/0/1689234585612_300.jpg", name:"À Lôi", uploader:"MusicPub", artist:"Phùng Khánh Linh", time:"3:55", url:"/static/aloi.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2023/03/02/2/7/5/d/1677742823841_300.jpg", name:"Đúng Nhận Sai Cãi", uploader:"Sony Music Vietnam", artist:"Wren Evans", time:"3:44", url:"/static/dungnhansaicai.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2023/07/01/0/3/d/5/1688157700707_300.jpg", name:"Thanh Âm Miền Núi", uploader:"CORTIS Records", artist:"CORTIS", time:"2:58", url:"/static/thanhammiennui.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2022/08/08/8/5/a/0/1659910526754_300.jpg", name:"Bình Yên Nơi Này", uploader:"NHONHO Music", artist:"NHONHO", time:"3:45", url:"/static/binhyennoidau.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/singer/avatar/2018/01/22/4/3/2/2/1516606862183_300.jpg", name:"Nếu Như Không Có Anh", uploader:"MusicPlus", artist:"Phan Mạnh Quỳnh", time:"4:18", url:"/static/khongcoanh.mp3" }
        ]
    },
    'lofi-chill': {
        title: "Lofi Chill Cho Ngày Mưa",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2025/01/07/6/3/2/f/1736223570982_300.jpg", name:"APT", uploader:"Grey D Music", artist:"GREY D", time:"4:05", url:"/static/APT.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2024/04/12/e/8/f/1/1712883965578_300.jpg", name:"Espresso", uploader:"HT Production", artist:"Mai Xuân Thứ", time:"4:22", url:"/static/Es.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2024/04/19/9/f/8/5/1713502935428_300.jpg", name:"Fortnight", uploader:"MusicPlus", artist:"Phan Mạnh Quỳnh", time:"4:18", url:"/static/Fortnight.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2024/08/16/f/b/9/5/1723784458729_300.jpg", name:"Die With A Smile", uploader:"Sony Music Vietnam", artist:"Văn Mai Hương", time:"4:01", url:"/static/die.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2024/05/24/a/0/8/2/1716526796690_300.jpg", name:"How Sweet", uploader:"MusicPub", artist:"Phùng Khánh Linh", time:"3:55", url:"/static/howsweet.mp3" }
        ]
    },
    'du-bao': {
        title: "Dự Báo Thời Tiết Hôm Nay",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2026/01/20/k/V/o/X/1768907693001_300.jpg", name:"Hôn Lễ Của Em", uploader:"Grey D Music", artist:"GREY D", time:"4:05", url:"/static/honlecuaem.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2025/07/07/e/5/e/6/1751897309156_300.jpg", name:"Anh Đã Không Biết Cách Yêu Em", uploader:"Sony Music Vietnam", artist:"HIEUTHUHAI", time:"3:58", url:"/static/xinloitinhyeu.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2025/11/08/n/Y/p/k/1762597175318_300.jpg", name:"Đớn Đau Vô Cùng", uploader:"MusicPub", artist:"Phùng Khánh Linh", time:"3:55", url:"/static/dungquentenanh.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2025/11/01/w/2/b/r/1761976272369_300.jpg", name:"Thiệp Hồng Sai Tên", uploader:"MusicPlus", artist:"Erik ft. K-ICM", time:"3:22", url:"/static/thiephongsaiten.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2025/03/28/6/8/9/5/1743168335425_300.jpg", name:"Sự Ưu Tiên Của Em", uploader:"Sony Music Vietnam", artist:"Wren Evans", time:"3:44", url:"/static/50nam.mp3" }
        ]
    },
    'ballad-viet': {
        title: "Ballad Việt",
        songs: [
            { id:1, img:"https://image-cdn.nct.vn/song/2025/09/12/5/0/5/2/1757660514686_300.jpg", name:"Có Mình Và Ta", uploader:"Sony Music Vietnam", artist:"Văn Mai Hương", time:"4:01", url:"/static/cominhvata.mp3" },
            { id:2, img:"https://image-cdn.nct.vn/song/2025/04/25/9/6/f/d/1745570268232_300.jpg", name:"Cơ Hội Cuối", uploader:"HT Production", artist:"Mai Xuân Thứ", time:"4:22", url:"/static/cohoicuoi.mp3" },
            { id:3, img:"https://image-cdn.nct.vn/song/2026/03/20/1/x/7/E/1773944272948_300.jpg", name:"Mở Lòng Vì Ai", uploader:"MusicPub", artist:"Phùng Khánh Linh", time:"3:55", url:"/static/molongviai.mp3" },
            { id:4, img:"https://image-cdn.nct.vn/song/2026/01/19/f/6/0/f/1768796387929_300.jpg", name:"Kẻ Say Tình", uploader:"MusicPlus", artist:"Phan Mạnh Quỳnh", time:"4:18", url:"/static/kesaytinh.mp3" },
            { id:5, img:"https://image-cdn.nct.vn/song/2024/11/21/5/9/b/6/1732160020288_300.jpg", name:"Mất Kết Nối", uploader:"Universal Music Vietnam", artist:"Double 2T", time:"3:33", url:"/static/matketnoi.mp3" }
        ]
    },
};
    let currentOpenPlaylist = null;

    // 1. Hàm Xử Lý Ẩn Hiện Khối Danh Sách Bài Hát
    function toggleSongList(playlistId) {
        const container = document.getElementById('song-list-container');
        const titleElem = document.getElementById('selected-playlist-title');
        const tbody = document.getElementById('song-items-tbody');

        if (currentOpenPlaylist === playlistId) {
            closeSongList();
            return;
        }

        const data = playlistData[playlistId];
        if (!data) return;

        titleElem.innerText = `>_ ĐANG XEM: ${data.title.toUpperCase()}`;
        tbody.innerHTML = '';
        
            data.songs.forEach(song => {
            // Chuyển ký tự chuỗi an toàn để truyền vào hàm onclick
            const songParam = btoa(unescape(encodeURIComponent(JSON.stringify(song))));
            tbody.innerHTML += `
                <tr class="border-b border-white/5 hover:bg-white/5 transition group">
                    <td class="py-3 text-center text-gray-500 group-hover:text-[#00ffcc] cursor-pointer w-10" onclick="playSong('${songParam}', this)"><i class="fas fa-play text-[9px] opacity-0 group-hover:opacity-100 transition mr-1"></i><span class="group-hover:hidden">${song.id}</span></td>
                    <td class="py-3 font-medium text-white flex items-center space-x-2 cursor-pointer flex-1 min-w-0" onclick="playSong('${songParam}', this)">
                        <img src="${song.img}" class="w-8 h-8 flex-shrink-0 rounded object-cover shadow">
                        <span class="hover:text-[#00ffcc] transition truncate">${song.name}</span>
                    </td>
                    <td class="py-3 text-gray-400 hidden md:table-cell cursor-pointer min-w-0" onclick="playSong('${songParam}', this)">${song.uploader}</td>
                    <td class="py-3 text-gray-400 cursor-pointer min-w-0" onclick="playSong('${songParam}', this)">${song.artist}</td>
                    <td class="py-3 text-right text-gray-500 group-hover:text-white pr-2 cursor-pointer w-12" onclick="playSong('${songParam}', this)">${song.time}</td>
                    <td class="py-3 text-center w-24 flex-shrink-0"><button onclick="event.stopPropagation(); selectForEncrypt('${songParam}')" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button></td>
                </tr>
            `;
        });

        container.classList.remove('hidden');
        currentOpenPlaylist = playlistId;
        container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function closeSongList() {
        document.getElementById('song-list-container').classList.add('hidden');
        currentOpenPlaylist = null;
    }

    // 2. Hàm Xử Lý Phát Nhạc Trực Tiếp
    let lastSelectedRow = null;
    function playSong(base64Data, rowElem) {
        // Giải mã ngược lấy Object bài hát
        const song = JSON.parse(decodeURIComponent(escape(atob(base64Data))));
        
        // Gán thông tin bài hát lên thanh Player điều khiển ở chân trang
        document.getElementById('player-title').innerText = song.name.length > 32 ? song.name.slice(0, 30) + '...' : song.name;
        document.getElementById('player-artist').innerText = song.artist;
        document.getElementById('player-icon').className = 'fas fa-headphones-alt text-white';

        // Gán đường dẫn nhạc cho bottom player nhưng KHÔNG tự động phát
        const bottomAudio = document.getElementById('main-audio');
        if (bottomAudio) {
            bottomAudio.src = song.url;
            bottomAudio.pause();
            bottomAudio.currentTime = 0;
        }

        const footerPlayIcon = document.getElementById('btn-master-play');
        if (footerPlayIcon) {
            footerPlayIcon.className = 'fas fa-play-circle text-white';
        }

        // Highlight selected row
        try {
            if (lastSelectedRow) lastSelectedRow.classList.remove('bg-white/5', 'text-[#00ffcc]');
            if (rowElem) { rowElem.classList.add('bg-white/5'); lastSelectedRow = rowElem; }
        } catch(e) {}
    }

    // Chọn bài để mã hóa: tải file từ url và gán vào input#music_file
    async function selectForEncrypt(base64Data) {
        const song = JSON.parse(decodeURIComponent(escape(atob(base64Data))));
        const fileInput = document.getElementById('music_file');
        const selectedName = document.getElementById('selected-file-name');
        try {
            // fetch the audio as blob
            const res = await fetch(song.url);
            if (!res.ok) throw new Error('Fetch failed ' + res.status);
            const blob = await res.blob();
            // try to derive extension from url
            const parts = song.url.split('/');
            const rawName = parts[parts.length-1] || 'track';
            const file = new File([blob], rawName, { type: blob.type || 'audio/mpeg' });

            // create DataTransfer to set file input
            const dt = new DataTransfer();
            dt.items.add(file);
            fileInput.files = dt.files;

            if (selectedName) selectedName.innerText = file.name;
            showToast('success','Đã chọn','Bài hát đã được tải vào ô File để mã hóa');
        } catch (err) {
            console.error('selectForEncrypt error', err);
            showToast('error','Lỗi','Không thể tải bài hát để mã hóa');
        }
    }

    function formatTime(secs) {
        let m = Math.floor(secs / 60), s = Math.floor(secs % 60);
        return (m < 10 ? '0' + m : m) + ':' + (s < 10 ? '0' + s : s);
    }
</script>
<div class="mb-8 select-none w-full">
    <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-bold text-white tracking-wide">Album Hot</h2>
        <a href="#" class="text-xs text-gray-400 hover:text-white transition">Thêm</a>
    </div>
    
    <div class="flex space-x-5 overflow-x-auto pb-3 scrollbar-none snap-x w-full">
        
        <div class="flex-shrink-0 w-[160px] md:w-[180px] snap-start group cursor-pointer" onclick="toggleAlbumList('hvl')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-3 shadow-lg border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/06/16/y/b/g/w/1781628591343_300.jpg" alt="HVL" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
            </div>
            <h4 class="text-xs font-bold text-white truncate tracking-wide">HVL</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">RPT MCK</p>
        </div>

        <div class="flex-shrink-0 w-[160px] md:w-[180px] snap-start group cursor-pointer" onclick="toggleAlbumList('trai-tim-bang-bo')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-3 shadow-lg border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/06/16/u/a/7/a/1781610379323_300.jpg" alt="trái tim băng bó" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
            </div>
            <h4 class="text-xs font-bold text-white truncate tracking-wide">trái tim băng bó</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Dangrangto, Donal</p>
        </div>

        <div class="flex-shrink-0 w-[160px] md:w-[180px] snap-start group cursor-pointer" onclick="toggleAlbumList('you-seem-pretty-sad')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-3 shadow-lg border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/06/13/F/B/b/O/1781286630238_300.jpg" alt="you seem pretty sad" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
            </div>
            <h4 class="text-xs font-bold text-white truncate tracking-wide">you seem pretty sad for a girl...</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Olivia Rodrigo</p>
        </div>

        <div class="flex-shrink-0 w-[160px] md:w-[180px] snap-start group cursor-pointer" onclick="toggleAlbumList('exs')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-3 shadow-lg border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/06/12/z/n/o/s/1781240546690_300.jpg" alt="EXs" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
            </div>
            <h4 class="text-xs font-bold text-white truncate tracking-wide">EXs</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Chi Pu</p>
        </div>

        <div class="flex-shrink-0 w-[160px] md:w-[180px] snap-start group cursor-pointer" onclick="toggleAlbumList('mua-u-te')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-3 shadow-lg border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/06/03/T/l/V/I/1780474465331_300.jpg" alt="MÙA Ủ TÊ" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
            </div>
            <h4 class="text-xs font-bold text-white truncate tracking-wide">MÙA Ủ TÊ</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Juky San</p>
        </div>

    </div>
</div>

<div id="album-details-container" class="hidden mt-6 relative overflow-hidden border border-white/10 rounded-2xl p-6 backdrop-blur-md transition-all duration-300 shadow-2xl shadow-zinc-950/50 w-full bg-zinc-900/30">
    
    <div id="album-bg-blur" class="absolute inset-0 -z-10 bg-cover bg-center opacity-15 blur-xl scale-110"></div>
    <div class="absolute inset-0 -z-10 bg-gradient-to-b from-zinc-950/60 via-zinc-950/90 to-zinc-950"></div>

    <div class="absolute top-4 right-4 z-20">
        <button onclick="closeAlbumList()" class="text-xs text-gray-400 hover:text-red-400 transition bg-white/5 hover:bg-red-500/10 px-3 py-1.5 rounded-full border border-white/5">Đóng ✕</button>
    </div>

    <div class="flex flex-col sm:flex-row items-center sm:items-end space-y-4 sm:space-y-0 sm:space-x-6 mb-8 relative z-10 pt-4">
        <div class="w-36 h-36 md:w-44 md:h-44 flex-shrink-0 rounded-lg overflow-hidden shadow-2xl border border-white/10">
            <img id="album-detail-img" src="" alt="Album Art" class="w-full h-full object-cover">
        </div>
        <div class="flex-1 text-center sm:text-left">
            <span class="text-[11px] font-bold tracking-wider text-cyan-400 uppercase bg-cyan-500/10 px-2.5 py-1 rounded-md border border-cyan-500/20">Album • 2026</span>
            <h3 id="album-detail-title" class="text-xl md:text-3xl font-black text-white mt-3 tracking-wide drop-shadow-md">TÊN ALBUM</h3>
            <p id="album-detail-artist" class="text-xs text-gray-400 mt-1.5 font-medium">Nghệ sĩ phát hành</p>
            
            <div class="flex items-center justify-center sm:justify-start space-x-3 mt-5">
                <button class="flex items-center space-x-2 bg-gradient-to-r from-cyan-400 to-emerald-400 hover:from-cyan-300 hover:to-emerald-300 text-zinc-950 font-bold text-xs px-5 py-2.5 rounded-full shadow-lg shadow-cyan-500/20 transition-all duration-200 transform hover:scale-102">
                    <i class="fas fa-play text-[10px]"></i>
                    <span>Phát tất cả</span>
                </button>
                <button class="flex items-center space-x-2 bg-white/5 hover:bg-white/10 text-white border border-white/10 font-bold text-xs px-5 py-2.5 rounded-full transition-all duration-200">
                    <i class="fas fa-download text-[10px]"></i>
                    <span>Tải về</span>
                </button>
            </div>
        </div>
    </div>

    <div class="overflow-x-auto max-w-full relative z-10">
        <table class="w-full min-w-full text-left text-xs text-gray-300 border-collapse table-fixed">
            <colgroup>
                <col class="w-12">
                <col class="flex-1">
                <col class="w-1/3">
                <col class="w-16">
                <col class="w-20">
            </colgroup>
            <thead>
                <tr class="text-gray-500 border-b border-white/5 font-semibold tracking-wider text-[11px]">
                    <th class="pb-3 text-center">#</th>
                    <th class="pb-3">TIÊU ĐỀ</th>
                    <th class="pb-3">NGHỆ SĨ</th>
                    <th class="pb-3 text-right"><i class="far fa-clock text-xs"></i></th>
                    <th class="pb-3 text-center">HÀNH ĐỘNG</th>
                </tr>
            </thead>
            <tbody id="album-songs-tbody"></tbody>
        </table>
    </div>
</div>


<script>
// Kho dữ liệu bài hát thật của các Album để render lên màn hình
const albumsData = {
    'hvl': {
        title: "HVL",
        artist: "RPT MCK",
        image: "https://image-cdn.nct.vn/playlist/2026/06/16/y/b/g/w/1781628591343_300.jpg",
        songs: [
            { title: "70k", artists: "RPT MCK", duration: "02:45" },
            { title: "Suy Suốt Mùa Đông", artists: "RPT MCK, tlinh", duration: "03:20" },
            { title: "Thôi Em Đừng Đi", artists: "RPT MCK", duration: "03:02" }
        ]
    },
    'trai-tim-bang-bo': {
        title: "trái tim băng bó",
        artist: "Dangrangto, Donal",
        image: "https://image-cdn.nct.vn/playlist/2026/06/16/u/a/7/a/1781610379323_300.jpg",
        songs: [
            { title: "xương rồng (intro)", artists: "Dangrangto, Donal, Smiley Panda", duration: "04:05" },
            { title: "my lil b*tch", artists: "Dangrangto, Donal, TeuYungBoy, Smiley Panda", duration: "03:39" },
            { title: "cây màu đen", artists: "Dangrangto, Donal, Lwki, MR LANH", duration: "04:43" }
        ]
    },
    'you-seem-pretty-sad': {
        title: "you seem pretty sad for a girl...",
        artist: "Olivia Rodrigo",
        image: "https://image-cdn.nct.vn/playlist/2026/06/13/F/B/b/O/1781286630238_300.jpg",
        songs: [
            { title: "vampire", artists: "Olivia Rodrigo", duration: "03:39" },
            { title: "bad idea right?", artists: "Olivia Rodrigo", duration: "03:04" },
            { title: "get him back!", artists: "Olivia Rodrigo", duration: "03:31" }
        ]
    },
    'exs': {
        title: "EXs",
        artist: "Chi Pu",
        image: "https://image-cdn.nct.vn/playlist/2026/06/12/z/n/o/s/1781240546690_300.jpg",
        songs: [
            { title: "Hoa Hồng Gai", artists: "Chi Pu", duration: "03:12" },
            { title: "Đóa Hoa Hồng", artists: "Chi Pu", duration: "03:27" },
            { title: "Miss Showbiz", artists: "Chi Pu", duration: "03:45" }
        ]
    },
    'mua-u-te': {
        title: "MÙA Ủ TÊ",
        artist: "Juky San",
        image: "https://image-cdn.nct.vn/playlist/2026/06/03/T/l/V/I/1780474465331_300.jpg",
        songs: [
            { title: "MÙA Ủ TÊ (Intro)", artists: "Juky San", duration: "01:15" },
            { title: "Thở Độc Lập", artists: "Juky San", duration: "03:34" },
            { title: "Khóc Lên Kỷ Niệm", artists: "Juky San", duration: "04:01" }
        ]
    }
};

// Hàm xử lý mở rộng và hiển thị chi tiết khi Click vào từng Album
function toggleAlbumList(albumId) {
    const container = document.getElementById('album-details-container');
    const album = albumsData[albumId];

    if (album) {
        // 1. Cập nhật Banner thông tin của Album được chọn
        document.getElementById('album-detail-title').innerText = album.title;
        document.getElementById('album-detail-artist').innerText = album.artist;
        document.getElementById('album-detail-img').src = album.image;
        document.getElementById('album-bg-blur').style.backgroundImage = `url('${album.image}')`;

        // 2. Tự động sinh (render) danh sách hàng bài hát tương ứng vào bảng HTML
        const tbody = document.getElementById('album-songs-tbody');
        tbody.innerHTML = ''; // Làm sạch dữ liệu cũ trước đó

        album.songs.forEach((song, index) => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-white/5 border-b border-white/5 transition group/row";
            tr.innerHTML = `
                <td class="py-3 text-center text-gray-500 font-medium group-hover/row:text-cyan-400">${index + 1}</td>
                <td class="py-3 font-semibold text-white truncate">${song.title}</td>
                <td class="py-3 text-gray-400 truncate">${song.artists}</td>
                <td class="py-3 text-right text-gray-400 pr-2">${song.duration}</td>
                <td class="py-3 text-center">
                    <button class="border border-cyan-400 text-cyan-400 hover:bg-cyan-400 hover:text-black font-semibold text-[10px] px-3 py-1 rounded transition duration-200 shadow-md shadow-cyan-400/5">
                        Chọn
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // 3. Hiển thị khối chi tiết Album lên màn hình
        container.classList.remove('hidden');
        
        // Cuộn mượt màn hình xuống khu vực bài hát mới mở rộng
        container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
}

// Hàm đóng khu vực xem Album chi tiết
function closeAlbumList() {
    document.getElementById('album-details-container').classList.add('hidden');
}
</script>
<!-- 🌊 HÀNG THỨ HAI: TÂM TRẠNG HÔM NAY 🌊 -->
<div class="mb-8 select-none w-full">
    <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-bold text-white tracking-wide">Tâm Trạng Hôm Nay</h2>
        <a href="#" class="text-xs text-gray-400 hover:text-white transition">Thêm</a>
    </div>
    
    <div class="flex w-full justify-between overflow-x-auto pb-2 scrollbar-none snap-x">
        
        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('tam-trang-chill')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2025/07/29/0/a/0/c/1753758572742_300.jpg" alt="Nhạc Chill hot TikTok" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Nhạc Chill hot TikTok</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Minh Vương M4U, H2O Music</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('tu-tiktok')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2025/10/01/0/5/c/c/1759313741436_300.jpg" alt="Từ Tiktok qua đây..." class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Từ Tiktok qua đây...</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Minh Vương M4U, H2O Music</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('chang-muon')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2025/07/25/a/2/1/0/1753435482545_300.jpg" alt="Chẳng muốn làm gì" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Chẳng muốn làm gì, chỉ...</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">HIEUTHUHAI, HURRYKNG</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('he-ve')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/07/a/b/f/a/1775557627897_300.jpg" alt="Hè về, đầy nắng và gió" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Hè về, đầy nắng và gió</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Phùng Khánh Linh, LBI</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('lofi-chill')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2025/10/08/9/3/9/c/1759918759677_300.jpg" alt="Lofi Chill Cho Ngày Mưa" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Lofi Chill Cho Ngày Mưa</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Thiên Tú, ACV, GREY D</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('du-bao')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/15/1/f/9/8/1776247556559_300.jpg" alt="Dự báo thời tiết hôm nay" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Dự báo thời tiết hôm nay</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">GREY D, BEAST</p>
        </div>

    </div>

    <div id="song-list-container-2" class="hidden mt-6 relative overflow-hidden border border-white/10 rounded-2xl p-4 backdrop-blur-md transition-all duration-300 shadow-2xl shadow-cyan-950/20">
    
        <div class="absolute inset-0 -z-10 bg-[url('https://images.unsplash.com/photo-1514525253161-7a46d19cd819?q=80&w=1200')] bg-cover bg-center opacity-20 blur-[1px]"></div>
        <div class="absolute inset-0 -z-10 bg-zinc-950/80"></div>

        <div class="flex justify-between items-center mb-4 border-b border-white/10 pb-2 relative z-10">
            <h3 id="selected-playlist-title-2" class="text-sm font-extrabold uppercase tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-emerald-400 to-cyan-400 drop-shadow-[0_2px_8px_rgba(34,211,238,0.4)]">ĐANG XEM: PLAYLIST</h3>
            <button onclick="closeSongList2()" class="text-xs text-gray-400 hover:text-red-400 transition bg-white/5 hover:bg-red-500/10 px-2.5 py-1 rounded-full border border-white/5">Đóng ✕</button>
        </div>

        <div class="overflow-x-auto max-w-full relative z-10">
            <table class="w-full min-w-full text-left text-xs text-gray-300 border-collapse table-fixed">
                <colgroup>
                    <col class="w-10">
                    <col class="flex-1">
                    <col class="hidden md:table-column">
                    <col>
                    <col class="w-12">
                    <col class="w-24">
                </colgroup>
                <thead>
                    <tr class="text-gray-500 border-b border-white/5">
                        <th class="pb-2 text-center">#</th>
                        <th class="pb-2">TIÊU ĐỀ</th>
                        <th class="pb-2 hidden md:table-cell">NHÀ PHÁT HÀNH</th>
                        <th class="pb-2">NGHỆ SĨ</th>
                        <th class="pb-2 text-right">THỜI GIAN</th>
                        <th class="pb-2 text-center">HÀNH ĐỘNG</th>
                    </tr>
                </thead>
                <tbody id="song-items-tbody-2"></tbody>
            </table>
        </div>
    </div>
</div>
<!-- 🌊 HÀNG THỨ HAI: TÂM TRẠNG HÔM NAY 🌊 -->
<div class="mb-8 select-none w-full">
    <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-bold text-white tracking-wide">Yêu & Chill</h2>
        <a href="#" class="text-xs text-gray-400 hover:text-white transition">Thêm</a>
    </div>
    
    <div class="flex w-full justify-between overflow-x-auto pb-2 scrollbar-none snap-x">
        
        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('tam-trang-chill')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/06/3/1/e/d/1775470800076_300.jpg" alt="Nhạc Chill hot TikTok" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Hương Mùa Hè</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Minh Vương M4U, H2O Music</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('tu-tiktok')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/04/03/9/6/8/f/1775203314632_300.jpg" alt="Từ Tiktok qua đây..." class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Yêu Em Như.....</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Minh Vương M4U, H2O Music</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('chang-muon')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/05/14/5/8/b/a/1778740667773_300.jpg" alt="Chẳng muốn làm gì" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Summer Party-Bữa Tiệc Ngày....</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">HIEUTHUHAI, HURRYKNG</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('he-ve')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/06/02/c/5/d/c/1780370802784_300.jpg" alt="Hè về, đầy nắng và gió" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Nghe Như Tình Yêu</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Phùng Khánh Linh, LBI</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('lofi-chill')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2025/05/27/d/d/4/6/1748343486679_300.jpg" alt="Lofi Chill Cho Ngày Mưa" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Một Đêm Say</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">Thiên Tú, ACV, GREY D</p>
        </div>

        <div class="flex-shrink-0 w-[150px] md:w-[165px] snap-start group cursor-pointer" onclick="toggleSongList2('du-bao')">
            <div class="relative w-full aspect-square rounded-xl overflow-hidden mb-2.5 shadow-md border border-white/5 bg-zinc-900">
                <img src="https://image-cdn.nct.vn/playlist/2026/03/24/1/c/1/5/1774348374000_300.jpg" alt="Dự báo thời tiết hôm nay" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute top-2 right-2 w-5 h-5 rounded-full bg-black/40 flex items-center justify-center backdrop-blur-sm">
                    <i class="fas fa-music text-[9px] text-white/70"></i>
                </div>
            </div>
            <h4 class="text-xs font-semibold text-white truncate tracking-wide">Nghe Đi Nghe Lại</h4>
            <p class="text-[11px] text-gray-400 truncate mt-0.5">GREY D, BEAST</p>
        </div>

    </div>

    <div id="song-list-container-2" class="hidden mt-6 relative overflow-hidden border border-white/10 rounded-2xl p-4 backdrop-blur-md transition-all duration-300 shadow-2xl shadow-cyan-950/20">
    
        <div class="absolute inset-0 -z-10 bg-[url('https://images.unsplash.com/photo-1514525253161-7a46d19cd819?q=80&w=1200')] bg-cover bg-center opacity-20 blur-[1px]"></div>
        <div class="absolute inset-0 -z-10 bg-zinc-950/80"></div>

        <div class="flex justify-between items-center mb-4 border-b border-white/10 pb-2 relative z-10">
            <h3 id="selected-playlist-title-2" class="text-sm font-extrabold uppercase tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-emerald-400 to-cyan-400 drop-shadow-[0_2px_8px_rgba(34,211,238,0.4)]">ĐANG XEM: PLAYLIST</h3>
            <button onclick="closeSongList2()" class="text-xs text-gray-400 hover:text-red-400 transition bg-white/5 hover:bg-red-500/10 px-2.5 py-1 rounded-full border border-white/5">Đóng ✕</button>
        </div>

        <div class="overflow-x-auto max-w-full relative z-10">
            <table class="w-full min-w-full text-left text-xs text-gray-300 border-collapse table-fixed">
                <colgroup>
                    <col class="w-10">
                    <col class="flex-1">
                    <col class="hidden md:table-column">
                    <col>
                    <col class="w-12">
                    <col class="w-24">
                </colgroup>
                <thead>
                    <tr class="text-gray-500 border-b border-white/5">
                        <th class="pb-2 text-center">#</th>
                        <th class="pb-2">TIÊU ĐỀ</th>
                        <th class="pb-2 hidden md:table-cell">NHÀ PHÁT HÀNH</th>
                        <th class="pb-2">NGHỆ SĨ</th>
                        <th class="pb-2 text-right">THỜI GIAN</th>
                        <th class="pb-2 text-center">HÀNH ĐỘNG</th>
                    </tr>
                </thead>
                <tbody id="song-items-tbody-2"></tbody>
            </table>
        </div>
    </div>
</div>
</div>
                    <!-- 🚀 KHỐI NGHỆ SĨ THỊNH HÀNH - ĐỒNG BỘ CHUẨN THEO ẢNH MẪU image_9551dc.jpg 🚀 -->
<div class="mb-6 select-none">
    <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-bold text-white tracking-wide">Nghệ Sĩ Thịnh Hành</h2>
        <a href="#" class="text-xs text-gray-400 hover:text-white transition">Thêm</a>
    </div>
    
    <!-- Thanh cuộn ngang mượt mà, ẩn scrollbar nhưng vẫn kéo được -->
    <div class="flex space-x-4 overflow-x-auto pb-3 scrollbar-none snap-x">
        
        <!-- Ca sĩ 1: HIEUTHUHAI -->
        <div class="flex-shrink-0 w-[170px] bg-[#181928]/40 rounded-xl p-3 border border-white/5 hover:bg-[#202136]/60 transition duration-300 snap-start group">
            <div class="relative w-full aspect-square rounded-lg overflow-hidden mb-3 shadow-lg">
                <img src="https://image-cdn.nct.vn/singer/avatar/2026/03/30/1/g/a/T/1774841335489_300.jpg" alt="HIEUTHUHAI" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <!-- Overlay bóng mờ dưới đáy ảnh giống Spotify/NCT để nổi chữ -->
                <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/20 to-transparent flex flex-col justify-end p-2.5">
                    <h4 class="text-xs font-bold text-white tracking-wider truncate">HIEUTHUHAI</h4>
                    <p class="text-[10px] text-gray-400 truncate mt-0.5">71197 người theo dõi</p>
                </div>
            </div>
            <button type="button" class="w-full py-1.5 text-[11px] font-semibold text-white bg-zinc-800/80 hover:bg-zinc-700 rounded-full border border-zinc-700/50 transition">Theo dõi</button>
            <div class="mt-2.5 pt-2 border-t border-white/5 flex items-center space-x-2 opacity-70 group-hover:opacity-100 transition">
                <i class="fas fa-play-circle text-purple-400 text-xs"></i>
                <span class="text-[10px] text-gray-400 truncate">Người Im Lặng Gặp Nhau</span>
            </div>
        </div>

        <!-- Ca sĩ 2: Minh Huy -->
        <div class="flex-shrink-0 w-[170px] bg-[#181928]/40 rounded-xl p-3 border border-white/5 hover:bg-[#202136]/60 transition duration-300 snap-start group">
            <div class="relative w-full aspect-square rounded-lg overflow-hidden mb-3 shadow-lg">
                <img src="https://image-cdn.nct.vn/singer/avatar/2026/05/04/z/U/i/k/1777863705507_300.jpg" alt="Minh Huy" class="w-full h-full object-cover grayscale transition duration-300 group-hover:scale-105">
                <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/20 to-transparent flex flex-col justify-end p-2.5">
                    <h4 class="text-xs font-bold text-white tracking-wider truncate">Minh Huy</h4>
                    <p class="text-[10px] text-gray-400 truncate mt-0.5">2710 người theo dõi</p>
                </div>
            </div>
            <button type="button" class="w-full py-1.5 text-[11px] font-semibold text-white bg-zinc-800/80 hover:bg-zinc-700 rounded-full border border-zinc-700/50 transition">Theo dõi</button>
            <div class="mt-2.5 pt-2 border-t border-white/5 flex items-center space-x-2 opacity-70 group-hover:opacity-100 transition">
                <i class="fas fa-play-circle text-purple-400 text-xs"></i>
                <span class="text-[10px] text-gray-400 truncate">Ngày Rời Chuyến Bay</span>
            </div>
        </div>

        <!-- Ca sĩ 3: OgeNus -->
        <div class="flex-shrink-0 w-[170px] bg-[#181928]/40 rounded-xl p-3 border border-white/5 hover:bg-[#202136]/60 transition duration-300 snap-start group">
            <div class="relative w-full aspect-square rounded-lg overflow-hidden mb-3 shadow-lg">
                <img src="https://image-cdn.nct.vn/singer/avatar/2025/04/17/P/Y/W/X/1744864477416_300.jpg" alt="OgeNus" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/20 to-transparent flex flex-col justify-end p-2.5">
                    <h4 class="text-xs font-bold text-white tracking-wider truncate">OgeNus</h4>
                    <p class="text-[10px] text-gray-400 truncate mt-0.5">8089 người theo dõi</p>
                </div>
            </div>
            <button type="button" class="w-full py-1.5 text-[11px] font-semibold text-white bg-zinc-800/80 hover:bg-zinc-700 rounded-full border border-zinc-700/50 transition">Theo dõi</button>
            <div class="mt-2.5 pt-2 border-t border-white/5 flex items-center space-x-2 opacity-70 group-hover:opacity-100 transition">
                <i class="fas fa-play-circle text-purple-400 text-xs"></i>
                <span class="text-[10px] text-emerald-400 font-medium truncate">Tuyển Bạn Gái</span>
            </div>
        </div>

        <!-- Ca sĩ 4: CORTIS -->
        <div class="flex-shrink-0 w-[170px] bg-[#181928]/40 rounded-xl p-3 border border-white/5 hover:bg-[#202136]/60 transition duration-300 snap-start group">
            <div class="relative w-full aspect-square rounded-lg overflow-hidden mb-3 shadow-lg">
                <img src="https://image-cdn.nct.vn/singer/avatar/2026/04/20/V/e/B/P/1776681636314_300.jpg" alt="CORTIS" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/20 to-transparent flex flex-col justify-end p-2.5">
                    <h4 class="text-xs font-bold text-white tracking-wider truncate">CORTIS</h4>
                    <p class="text-[10px] text-gray-400 truncate mt-0.5">14584 người theo dõi</p>
                </div>
            </div>
            <button type="button" class="w-full py-1.5 text-[11px] font-semibold text-white bg-zinc-800/80 hover:bg-zinc-700 rounded-full border border-zinc-700/50 transition">Theo dõi</button>
            <div class="mt-2.5 pt-2 border-t border-white/5 flex items-center space-x-2 opacity-70 group-hover:opacity-100 transition">
                <i class="fas fa-play-circle text-purple-400 text-xs"></i>
                <span class="text-[10px] text-gray-400 truncate">REDRED</span>
            </div>
        </div>

        <!-- Ca sĩ 5: Đỗ Hoàng Long -->
        <div class="flex-shrink-0 w-[170px] bg-[#181928]/40 rounded-xl p-3 border border-white/5 hover:bg-[#202136]/60 transition duration-300 snap-start group">
            <div class="relative w-full aspect-square rounded-lg overflow-hidden mb-3 shadow-lg">
                <img src="https://image-cdn.nct.vn/singer/avatar/2026/02/06/z/4/v/o/1770348442798_300.jpg" alt="Đỗ Hoàng Long" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/20 to-transparent flex flex-col justify-end p-2.5">
                    <h4 class="text-xs font-bold text-white tracking-wider truncate">Đỗ Hoàng Long</h4>
                    <p class="text-[10px] text-gray-400 truncate mt-0.5">270 người theo dõi</p>
                </div>
            </div>
            <button type="button" class="w-full py-1.5 text-[11px] font-semibold text-white bg-zinc-800/80 hover:bg-zinc-700 rounded-full border border-zinc-700/50 transition">Theo dõi</button>
            <div class="mt-2.5 pt-2 border-t border-white/5 flex items-center space-x-2 opacity-70 group-hover:opacity-100 transition">
                <i class="fas fa-play-circle text-purple-400 text-xs"></i>
                <span class="text-[10px] text-gray-400 truncate">Trạng Thái Mộng Mơ</span>
            </div>
        </div>

        <!-- Ca sĩ 6: GREY D -->
        <div class="flex-shrink-0 w-[170px] bg-[#181928]/40 rounded-xl p-3 border border-white/5 hover:bg-[#202136]/60 transition duration-300 snap-start group">
            <div class="relative w-full aspect-square rounded-lg overflow-hidden mb-3 shadow-lg">
                <img src="https://image-cdn.nct.vn/singer/avatar/2026/03/26/n/v/j/N/1774522375114_300.jpeg" alt="GREY D" class="w-full h-full object-cover transition duration-300 group-hover:scale-105">
                <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/20 to-transparent flex flex-col justify-end p-2.5">
                    <h4 class="text-xs font-bold text-white tracking-wider truncate">GREY D</h4>
                    <p class="text-[10px] text-gray-400 truncate mt-0.5">22070 người theo dõi</p>
                </div>
            </div>
            <button type="button" class="w-full py-1.5 text-[11px] font-semibold text-white bg-zinc-800/80 hover:bg-zinc-700 rounded-full border border-zinc-700/50 transition">Theo dõi</button>
            <div class="mt-2.5 pt-2 border-t border-white/5 flex items-center space-x-2 opacity-70 group-hover:opacity-100 transition">
                <i class="fas fa-play-circle text-purple-400 text-xs"></i>
                <span class="text-[10px] text-gray-400 truncate">hoá ra...</span>
            </div>
        </div>

    </div>
</div>
                    <!-- DANH SÁCH TOP TRENDING ĐÃ ĐƯỢC ĐỔ URL NGHE THỰC TẾ -->
                    <div>
                        <h2 class="text-md font-bold text-white mb-3">Top Trending</h2>
                        <div class="space-y-2">
                            <!-- Bài 1 -->
                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">01</span>
                                    <div class="w-10 h-10 rounded-lg bg-purple-900 flex items-center justify-center"><i class="fas fa-compact-disc text-white animate-spin-slow"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Không Buông (Lofi Ver.)</h4>
                                        <p class="text-xs text-gray-400">Adele & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>3:20</span>
                                    <button type="button" onclick="playMusic('Không Buông (Lofi Ver.)', 'Adele & Music Pop', '/static/khongbuong.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Không Buông (Lofi Ver.)', artist:'Adele & Music Pop', url:'/static/khongbuong.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>
                            <!-- Bài 2 -->
                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Buông</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('Buông', 'Trúc Nhân & Music Pop', '/static/Buông.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>

                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Come My Way</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('comemyway', 'Trúc Nhân & Music Pop', '/static/comemyway.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>

                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Đừng Quên Tên Anh</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('Buông', 'Trúc Nhân & Music Pop', '/static/dungquentenanh.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>

                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Hóa Ra</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('Buông', 'Trúc Nhân & Music Pop', '/static/hoara.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>

                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Kẻ Say Tình</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('Buông', 'Trúc Nhân & Music Pop', '/static/kesaytinh.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>

                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Người Miền Núi Chất</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('Buông', 'Trúc Nhân & Music Pop', '/static/nguoimiennuichat.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>

                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Sóng Gió</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('Buông', 'Trúc Nhân & Music Pop', '/static/songgio.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>

                            <div class="flex items-center justify-between p-3 card-bg rounded-xl hover:bg-opacity-80 transition duration-200">
                                <div class="flex items-center space-x-4">
                                    <span class="text-purple-400 font-bold w-4">02</span>
                                    <div class="w-10 h-10 rounded-lg bg-pink-900 flex items-center justify-center"><i class="fas fa-music text-white"></i></div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-white">Sau Này Em Cưới Ai Rồi</h4>
                                        <p class="text-xs text-gray-400">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-3 text-xs text-gray-400">
                                    <span>4:12</span>
                                    <button type="button" onclick="playMusic('Buông', 'Trúc Nhân & Music Pop', '/static/saunayemcuoiairoi.mp3')" class="text-purple-400 text-2xl hover:scale-110 transition"><i class="fas fa-play-circle"></i></button>
                                    <button type="button" onclick="selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg'})))))" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
                <div class="col-span-1 space-y-6">
                    <!-- 🎵 THỂ LOẠI / XU HƯỚNG (BÊN PHẢI) -->
                    <div class="card-bg rounded-xl p-4 mb-6">
                        <h3 class="text-sm font-bold text-white mb-3 flex items-center justify-between">
                            <span class="flex items-center gap-2"><i class="fas fa-fire-alt text-orange-300"></i>Thể loại / Xu hướng</span>
                            <span class="text-[10px] text-gray-400">Click</span>
                        </h3>

                        <div class="flex flex-col gap-2">
                            <button type="button" onclick="toggleGenre('lofi-chill')" class="w-full text-left px-3 py-2 rounded-lg border border-white/5 bg-white/0 hover:bg-white/5 transition flex items-center justify-between">
                                <span class="flex items-center gap-2"><i class="fas fa-moon text-cyan-300 text-xs"></i><span class="text-xs font-semibold text-white">Lofi Chill</span></span>
                                <i class="fas fa-chevron-right text-[10px] text-gray-500"></i>
                            </button>
                            <button type="button" onclick="toggleGenre('vpop-thinh-hanh')" class="w-full text-left px-3 py-2 rounded-lg border border-white/5 bg-white/0 hover:bg-white/5 transition flex items-center justify-between">
                                <span class="flex items-center gap-2"><i class="fas fa-headphones text-purple-300 text-xs"></i><span class="text-xs font-semibold text-white">V-Pop Thịnh Hành</span></span>
                                <i class="fas fa-chevron-right text-[10px] text-gray-500"></i>
                            </button>
                            <button type="button" onclick="toggleGenre('tiktok-remix')" class="w-full text-left px-3 py-2 rounded-lg border border-white/5 bg-white/0 hover:bg-white/5 transition flex items-center justify-between">
                                <span class="flex items-center gap-2"><i class="fas fa-bolt text-emerald-300 text-xs"></i><span class="text-xs font-semibold text-white">TikTok Remix</span></span>
                                <i class="fas fa-chevron-right text-[10px] text-gray-500"></i>
                            </button>
                            <button type="button" onclick="toggleGenre('ballad-viet')" class="w-full text-left px-3 py-2 rounded-lg border border-white/5 bg-white/0 hover:bg-white/5 transition flex items-center justify-between">
                                <span class="flex items-center gap-2"><i class="fas fa-heart text-pink-300 text-xs"></i><span class="text-xs font-semibold text-white">Ballad Việt</span></span>
                                <i class="fas fa-chevron-right text-[10px] text-gray-500"></i>
                            </button>
                            <button type="button" onclick="toggleGenre('nhac-tuyen-chon')" class="w-full text-left px-3 py-2 rounded-lg border border-white/5 bg-white/0 hover:bg-white/5 transition flex items-center justify-between">
                                <span class="flex items-center gap-2"><i class="fas fa-star text-yellow-300 text-xs"></i><span class="text-xs font-semibold text-white">Nhạc Tuyển Chọn</span></span>
                                <i class="fas fa-chevron-right text-[10px] text-gray-500"></i>
                            </button>
                        </div>

                        <div id="genre-panel" class="mt-4 hidden">
                            <div class="flex items-center justify-between mb-2">
                                <div class="text-xs font-extrabold text-cyan-300 uppercase tracking-wide" id="genre-title">Đang xem</div>
                                <button type="button" onclick="closeGenrePanel()" class="text-[10px] text-gray-400 hover:text-red-400 transition bg-white/5 hover:bg-red-500/10 px-2 py-1 rounded-full border border-white/5">Đóng</button>
                            </div>

                            <div class="max-h-64 overflow-y-auto pr-1">
                                <table class="w-full text-left text-[11px] text-gray-300 border-collapse table-fixed">
                                    <thead>
                                        <tr class="text-gray-500 border-b border-white/10">
                                            <th class="py-2 w-8 text-center">#</th>
                                            <th class="py-2">Bài</th>
                                            <th class="py-2 w-16 text-right">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody id="genre-tbody"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <script>
                        let currentOpenGenre = null;
                        function toggleGenre(genreId) {
                            const panel = document.getElementById('genre-panel');
                            const title = document.getElementById('genre-title');
                            const tbody = document.getElementById('genre-tbody');
                            if (!panel || !title || !tbody) return;

                            if (currentOpenGenre === genreId) {
                                closeGenrePanel();
                                return;
                            }

                            const data = playlistData[genreId];
                            if (!data) return;

                            currentOpenGenre = genreId;
                            panel.classList.remove('hidden');
                            title.innerText = data.title;

                            tbody.innerHTML = '';
                            (data.songs || []).forEach((song, idx) => {
                                const songParam = btoa(unescape(encodeURIComponent(JSON.stringify(song))));
                                tbody.innerHTML += `
                                    <tr class="border-b border-white/5 hover:bg-white/5 transition">
                                        <td class="py-2 text-center text-gray-500">${idx + 1}</td>
                                        <td class="py-2">
                                            <div class="flex items-center gap-2">
                                                <img src="${song.img}" class="w-6 h-6 rounded object-cover" />
                                                <div class="min-w-0">
                                                    <div class="text-white font-semibold truncate">${song.name}</div>
                                                    <div class="text-[10px] text-gray-400 truncate">${song.artist}</div>
                                                </div>
                                            </div>
                                        </td>
                                        <td class="py-2 text-right">
                                            <div class="flex justify-end gap-2">
                                                <button type="button" onclick="playSong('${songParam}', null)" class="px-2 py-1 text-[10px] text-cyan-300 bg-cyan-400/10 border border-cyan-400/20 rounded-full hover:bg-cyan-400/20 transition">Phát</button>
                                                <button type="button" onclick="selectForEncrypt('${songParam}')" class="px-2 py-1 text-[10px] text-white bg-[#7c3aed]/20 border border-[#7c3aed]/30 rounded-full hover:bg-[#7c3aed]/30 transition">Chọn</button>
                                            </div>
                                        </td>
                                    </tr>
                                `;
                            });
                        }

                        function closeGenrePanel() {
                            const panel = document.getElementById('genre-panel');
                            if (!panel) return;
                            panel.classList.add('hidden');
                            currentOpenGenre = null;
                        }
                    </script>

                    <div class="card-bg rounded-xl p-4">
                        <h3 class="text-sm font-bold text-white mb-3">Popular Artist</h3>
                        <div class="space-y-3">

                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">Sơn Tùng MTP</h4>
                                        <p class="text-[10px] text-gray-400">10Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/playlist/2023/10/29/T/3/N/M/1698564351580.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">Double 2T</h4>
                                        <p class="text-[10px] text-gray-400">5Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2026/06/11/0/a/q/n/1781168116965_300.jpeg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">Binz</h4>
                                        <p class="text-[10px] text-gray-400">15Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2026/03/26/n/v/j/N/1774522375114_300.jpeg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">Grey D</h4>
                                        <p class="text-[10px] text-gray-400">50Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2023/03/03/a/5/a/8/1677826163685_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">MCK</h4>
                                        <p class="text-[10px] text-gray-400">5Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/playlist/2026/06/16/u/a/7/a/1781610379323_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">DangRangTo</h4>
                                        <p class="text-[10px] text-gray-400">5Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2020/08/06/9/a/7/b/1596692465856_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">Đen Vâu</h4>
                                        <p class="text-[10px] text-gray-400">5Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2020/11/16/6/5/0/2/1605494004450_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">Dế choắt</h4>
                                        <p class="text-[10px] text-gray-400">5Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2026/06/12/d/y/d/M/1781247553969_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">Mono</h4>
                                        <p class="text-[10px] text-gray-400">5Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2023/03/03/a/5/a/8/1677826163685_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">MCK</h4>
                                        <p class="text-[10px] text-gray-400">10Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full bg-slate-700" src="https://image-cdn.nct.vn/singer/avatar/2026/03/30/1/g/a/T/1774841335489_300.jpg">
                                    <div>
                                        <h4 class="text-xs font-semibold text-white">HIEU THU HAI</h4>
                                        <p class="text-[10px] text-gray-400">10Tr Followers</p>
                                    </div>
                                </div>
                                <div class="text-gray-400 text-xs"><i class="far fa-heart"></i></div>
                            </div>
                        </div>
                    </div>

                    <div class="card-bg rounded-3xl p-5 mb-6">
                        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-5">
                            <div>
                                <h2 class="text-md font-bold text-white">TikTok Top Mix</h2>
                                <p class="text-xs text-gray-400">Các bài thật, chọn để mã hóa và gửi trực tiếp.</p>
                            </div>
                            <button type="button" onclick="playRandomTrack()" class="inline-flex items-center gap-2 rounded-full border border-purple-400/30 bg-purple-500/10 text-purple-200 px-4 py-2 text-xs font-semibold hover:bg-purple-500/20 transition">
                                <i class="fas fa-random"></i> Phát ngẫu nhiên
                            </button>
                        </div>
                        <div class="grid gap-4 grid-cols-1 sm:grid-cols-2 xl:grid-cols-3">
                            <div class="group overflow-hidden rounded-3xl border border-white/10 bg-[#16161f] shadow-lg transition hover:border-purple-500/40">
                                <div class="relative overflow-hidden">
                                    <img src="https://image-cdn.nct.vn/song/2026/02/03/2/a/d/k/1770112325749_300.jpg" alt="Buông" class="w-full h-44 object-cover transition duration-300 group-hover:scale-105">
                                    <div class="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-3">
                                        <h3 class="text-sm font-bold text-white truncate">Buông</h3>
                                        <p class="text-[11px] text-gray-300 truncate">Trúc Nhân & Music Pop</p>
                                    </div>
                                </div>
                                <div class="p-4 space-y-3">
                                    <div class="flex items-center justify-between text-[11px] text-gray-400">
                                        <span>4:12</span>
                                        <span>Buông</span>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="playSong(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/buong.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg', time:'4:12'})))), null)" class="flex-1 rounded-full bg-[#00ffcc]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#00ffcc]/35 transition">Phát</button>
                                        <button onclick="event.stopPropagation(); selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/buong.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg', time:'4:12'})))))" class="flex-1 rounded-full bg-[#7c3aed]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#7c3aed]/35 transition">Chọn</button>
                                    </div>
                                </div>
                            </div>

                            <div class="group overflow-hidden rounded-3xl border border-white/10 bg-[#16161f] shadow-lg transition hover:border-purple-500/40">
                                <div class="relative overflow-hidden">
                                    <img src="https://image-cdn.nct.vn/song/2025/08/18/9/1/d/f/1755507611412_300.jpg" alt="Không Buông (Lofi Ver.)" class="w-full h-44 object-cover transition duration-300 group-hover:scale-105">
                                    <div class="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-3">
                                        <h3 class="text-sm font-bold text-white truncate">Không Buông (Lofi Ver.)</h3>
                                        <p class="text-[11px] text-gray-300 truncate">Adele & Music Pop</p>
                                    </div>
                                </div>
                                <div class="p-4 space-y-3">
                                    <div class="flex items-center justify-between text-[11px] text-gray-400">
                                        <span>3:20</span>
                                        <span>Lofi</span>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="playSong(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Không Buông (Lofi Ver.)', artist:'Adele & Music Pop', url:'/static/tuyenbangai.mp3', img:'https://image-cdn.nct.vn/song/2024/05/10/Z/z/P/X/1715335736956_300.jpg', time:'3:20'})))), null)" class="flex-1 rounded-full bg-[#00ffcc]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#00ffcc]/35 transition">Phát</button>
                                        <button onclick="event.stopPropagation(); selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Không Buông (Lofi Ver.)', artist:'Adele & Music Pop', url:'/static/tuyenbangai.mp3', img:'https://image-cdn.nct.vn/song/2024/05/10/Z/z/P/X/1715335736956_300.jpg', time:'3:20'})))))" class="flex-1 rounded-full bg-[#7c3aed]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#7c3aed]/35 transition">Chọn</button>
                                    </div>
                                </div>
                            </div>

                            <div class="group overflow-hidden rounded-3xl border border-white/10 bg-[#16161f] shadow-lg transition hover:border-purple-500/40">
                                <div class="relative overflow-hidden">
                                    <img src="https://image-cdn.nct.vn/song/2026/04/20/8/h/t/J/1776679785851_300.jpg" alt="REDRED" class="w-full h-44 object-cover transition duration-300 group-hover:scale-105">
                                    <div class="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-3">
                                        <h3 class="text-sm font-bold text-white truncate">REDRED</h3>
                                        <p class="text-[11px] text-gray-300 truncate">CORTIS</p>
                                    </div>
                                </div>
                                <div class="p-4 space-y-3">
                                    <div class="flex items-center justify-between text-[11px] text-gray-400">
                                        <span>2:58</span>
                                        <span>EDM</span>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="playSong(btoa(unescape(encodeURIComponent(JSON.stringify({name:'REDRED', artist:'CORTIS', url:'/static/redred.mp3', img:'https://image-cdn.nct.vn/song/2024/10/08/M/v/z/a/1728367891245_300.jpg', time:'2:58'})))), null)" class="flex-1 rounded-full bg-[#00ffcc]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#00ffcc]/35 transition">Phát</button>
                                        <button onclick="event.stopPropagation(); selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'REDRED', artist:'CORTIS', url:'/static/redred.mp3', img:'https://image-cdn.nct.vn/song/2024/10/08/M/v/z/a/1728367891245_300.jpg', time:'2:58'})))))" class="flex-1 rounded-full bg-[#7c3aed]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#7c3aed]/35 transition">Chọn</button>
                                    </div>
                                </div>
                            </div>

                            <div class="group overflow-hidden rounded-3xl border border-white/10 bg-[#16161f] shadow-lg transition hover:border-purple-500/40">
                                <div class="relative overflow-hidden">
                                    <img src="https://image-cdn.nct.vn/singer/avatar/2024/10/09/d/l/l/X/1728460262644_300.jpg" alt="Một Nhà Remix" class="w-full h-44 object-cover transition duration-300 group-hover:scale-105">
                                    <div class="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-3">
                                        <h3 class="text-sm font-bold text-white truncate">Một Nhà Remix</h3>
                                        <p class="text-[11px] text-gray-300 truncate">Hngle x Anh Tú</p>
                                    </div>
                                </div>
                                <div class="p-4 space-y-3">
                                    <div class="flex items-center justify-between text-[11px] text-gray-400">
                                        <span>3:55</span>
                                        <span>Remix</span>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="playSong(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Một Nhà Remix', artist:'Hngle x Anh Tú', url:'/static/Một Nhà Remix.mp3', img:'https://image-cdn.nct.vn/song/2025/01/07/I/g/Y/O/1736262155028_300.jpg', time:'3:55'})))), null)" class="flex-1 rounded-full bg-[#00ffcc]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#00ffcc]/35 transition">Phát</button>
                                        <button onclick="event.stopPropagation(); selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Một Nhà Remix', artist:'Hngle x Anh Tú', url:'/static/Một Nhà Remix.mp3', img:'https://image-cdn.nct.vn/song/2025/01/07/I/g/Y/O/1736262155028_300.jpg', time:'3:55'})))))" class="flex-1 rounded-full bg-[#7c3aed]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#7c3aed]/35 transition">Chọn</button>
                                    </div>
                                </div>
                            </div>

                            <div class="group overflow-hidden rounded-3xl border border-white/10 bg-[#16161f] shadow-lg transition hover:border-purple-500/40">
                                <div class="relative overflow-hidden">
                                    <img src="https://image-cdn.nct.vn/song/2022/06/30/7/b/2/2/1656578646637_300.jpg" alt="Thích Em Hơi Nhiều (Remix)" class="w-full h-44 object-cover transition duration-300 group-hover:scale-105">
                                    <div class="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-3">
                                        <h3 class="text-sm font-bold text-white truncate">Thích Em Hơi Nhiều</h3>
                                        <p class="text-[11px] text-gray-300 truncate">Inso ft. Nita Phạm</p>
                                    </div>
                                </div>
                                <div class="p-4 space-y-3">
                                    <div class="flex items-center justify-between text-[11px] text-gray-400">
                                        <span>3:28</span>
                                        <span>Remix</span>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="playSong(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Thích Em Hơi Nhiều', artist:'Inso ft. Nita Phạm', url:'/static/thichemhoinhieu.mp3', img:'https://image-cdn.nct.vn/song/2024/06/20/a/6/e/4/1718877870154_300.jpg', time:'3:28'})))), null)" class="flex-1 rounded-full bg-[#00ffcc]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#00ffcc]/35 transition">Phát</button>
                                        <button onclick="event.stopPropagation(); selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Thích Em Hơi Nhiều', artist:'Inso ft. Nita Phạm', url:'/static/thichemhoinhieu.mp3', img:'https://image-cdn.nct.vn/song/2024/06/20/a/6/e/4/1718877870154_300.jpg', time:'3:28'})))))" class="flex-1 rounded-full bg-[#7c3aed]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#7c3aed]/35 transition">Chọn</button>
                                    </div>
                                </div>
                            </div>

                            <div class="group overflow-hidden rounded-3xl border border-white/10 bg-[#16161f] shadow-lg transition hover:border-purple-500/40">
                                <div class="relative overflow-hidden">
                                    <img src="https://image-cdn.nct.vn/song/2026/04/17/S/z/K/m/1776419250490_300.jpg" alt="Người Im Lặng Gặp Người Hay Nói" class="w-full h-44 object-cover transition duration-300 group-hover:scale-105">
                                    <div class="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-3">
                                        <h3 class="text-sm font-bold text-white truncate">Người Im Lặng Gặp Người Hay Nói</h3>
                                        <p class="text-[11px] text-gray-300 truncate">Sơn Tùng MTP</p>
                                    </div>
                                </div>
                                <div class="p-4 space-y-3">
                                    <div class="flex items-center justify-between text-[11px] text-gray-400">
                                        <span>3:58</span>
                                        <span>Pop</span>
                                    </div>
                                    <div class="flex gap-2">
                                        <button onclick="playSong(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Người Im Lặng Gặp Người Hay Nói', artist:'Sơn Tùng MTP', url:'/static/LƯỚT TRÊN CON SÓNG.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg', time:'3:58'})))), null)" class="flex-1 rounded-full bg-[#00ffcc]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#00ffcc]/35 transition">Phát</button>
                                        <button onclick="event.stopPropagation(); selectForEncrypt(btoa(unescape(encodeURIComponent(JSON.stringify({name:'Người Im Lặng Gặp Người Hay Nói', artist:'Sơn Tùng MTP', url:'/static/LƯỚT TRÊN CON SÓNG.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg', time:'3:58'})))))" class="flex-1 rounded-full bg-[#7c3aed]/20 px-3 py-2 text-[11px] font-semibold text-white hover:bg-[#7c3aed]/35 transition">Chọn</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card-bg rounded-3xl p-5 border border-white/10 bg-slate-950/80">
                        <div class="flex items-center justify-between mb-4">
                            <div>
                                <h3 class="text-sm font-bold text-white">Bảng Xếp Hạng</h3>
                                <p class="text-[11px] text-gray-400">Top nhạc đang thịnh hành</p>
                            </div>
                            <button class="text-xs text-cyan-300 px-3 py-1 rounded-full bg-white/5 border border-cyan-500/20 hover:bg-cyan-500/10 transition">Thêm</button>
                        </div>
                        <div class="space-y-4 text-[12px] text-gray-300">
                            <div class="rounded-3xl p-4 bg-gradient-to-br from-slate-900/80 to-slate-950 border border-white/10 shadow-sm">
                                <div class="flex items-center justify-between mb-3">
                                    <span class="text-white font-semibold">Top 50 Bài Hát Thịnh Hành</span>
                                    <button onclick="playMusic('Come My Way', 'Sơn Tùng M-TP', '/static/comemyway.mp3')" class="text-xs px-3 py-1 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/20 hover:bg-cyan-500/25 transition">Phát</button>
                                </div>
                                <div class="space-y-3">
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <span class="text-sm text-cyan-300 font-bold">1</span>
                                            <div>
                                                <div class="font-semibold text-white">Come My Way</div>
                                                <div class="text-[10px] text-gray-400">Sơn Tùng M-TP, Tyga</div>
                                            </div>
                                        </div>
                                        <button onclick="playMusic('Come My Way', 'Sơn Tùng M-TP', '/static/comemyway.mp3')" class="text-gray-400 hover:text-white"><i class="fas fa-play"></i></button>
                                    </div>
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <span class="text-sm text-gray-400">2</span>
                                            <div>
                                                <div class="font-medium text-white">Không Buông</div>
                                                <div class="text-[10px] text-gray-400">Hngle, Ari</div>
                                            </div>
                                        </div>
                                        <button onclick="playMusic('Không Buông', 'Hngle, Ari', '/static/buong.mp3')" class="text-gray-400 hover:text-white"><i class="fas fa-play"></i></button>
                                    </div>
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <span class="text-sm text-gray-400">3</span>
                                            <div>
                                                <div class="font-medium text-white">Người Im Lặng Gặp Người Hay Nói</div>
                                                <div class="text-[10px] text-gray-400">Sơn Tùng MTP</div>
                                            </div>
                                        </div>
                                        <button onclick="playMusic('Người Im Lặng Gặp Người Hay Nói', 'Sơn Tùng MTP', '/static/traihovu.mp3')" class="text-gray-400 hover:text-white"><i class="fas fa-play"></i></button>
                                    </div>
                                </div>
                            </div>

                            <div class="rounded-3xl p-4 bg-gradient-to-br from-slate-900/80 to-slate-950 border border-white/10 shadow-sm">
                                <div class="flex items-center justify-between mb-3">
                                    <span class="text-white font-semibold">Top Nhạc Việt</span>
                                    <button onclick="playMusic('Sau Này Em Cưới Ai Rồi', 'Trúc Nhân', '/static/saunayemcuoiairoi.mp3')" class="text-xs px-3 py-1 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/20 hover:bg-cyan-500/25 transition">Phát</button>
                                </div>
                                <div class="space-y-3">
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <span class="text-sm text-cyan-300 font-bold">1</span>
                                            <div>
                                                <div class="font-semibold text-white">Buông</div>
                                                <div class="text-[10px] text-gray-400">Trúc Nhân</div>
                                            </div>
                                        </div>
                                        <button onclick="playMusic('Buông', 'Trúc Nhân', '/static/buong.mp3')" class="text-gray-400 hover:text-white"><i class="fas fa-play"></i></button>
                                    </div>
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <span class="text-sm text-gray-400">2</span>
                                            <div>
                                                <div class="font-medium text-white">Tuyển Bạn Gái</div>
                                                <div class="text-[10px] text-gray-400">OgeNus</div>
                                            </div>
                                        </div>
                                        <button onclick="playMusic('Tuyển Bạn Gái', 'OgeNus', '/static/tuyenbangai.mp3')" class="text-gray-400 hover:text-white"><i class="fas fa-play"></i></button>
                                    </div>
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <span class="text-sm text-gray-400">3</span>
                                            <div>
                                                <div class="font-medium text-white">REDRED</div>
                                                <div class="text-[10px] text-gray-400">CORTIS</div>
                                            </div>
                                        </div>
                                        <button onclick="playMusic('REDRED', 'CORTIS', '/static/redred.mp3')" class="text-gray-400 hover:text-white"><i class="fas fa-play"></i></button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="card-bg rounded-xl p-4 flex flex-col h-[28rem]">
                        <h3 class="text-sm font-bold text-cyan-400 mb-2 flex items-center justify-between">
                            <span><i class="fas fa-terminal mr-1"></i> CRYPTO TRANSLATION LOGS</span>
                        </h3>
                        <div id="log-container" class="flex-1 bg-slate-950/80 rounded-lg p-3 font-mono text-[11px] overflow-y-auto space-y-2 text-gray-300">
                            <span class="text-gray-500">// Hệ thống bảo mật sẵn sàng...</span>
                        </div>
                    </div>
                </div>
            </main>
            <!-- FOOTER NCT CHUẨN PIXEL -->
            <footer class="nct-footer w-full pt-10 pb-6 px-12 space-y-8 mt-auto flex-shrink-0">
                <div class="flex items-center justify-between gap-4 border-b border-[#2d2e2e] pb-8 overflow-x-auto">
                    <div class="flex items-center space-x-1 font-black text-2xl tracking-tighter text-white opacity-90"><i class="fas fa-bolt text-xl mr-1"></i>M MUSIC</div>
                    <div class="flex items-center space-x-1 font-serif font-bold text-2xl italic tracking-wider text-white opacity-80">VIBENATION</div>
                    <div class="flex items-center space-x-2 text-xl font-semibold tracking-tight text-white opacity-80"><i class="fas fa-apple-whole text-xl text-red-500"></i> The Orchard.</div>
                    <div class="flex items-center font-mono font-black text-2xl tracking-widest text-white border-x border-gray-700 px-4 opacity-75">VIEENT</div>
                    <div class="flex items-center text-xl font-bold tracking-tight text-white opacity-80"><i class="fas fa-guitar mr-1"></i>HT PRODUCTION</div>
                    <div class="flex items-center text-2xl font-black text-white font-mono opacity-90">DAO<span class="text-xs block font-normal tracking-normal text-gray-400 text-center">MUSIC ENT</span></div>
                    <div class="flex items-center space-x-1 font-sans text-xl font-bold text-white opacity-80"><i class="fas fa-compact-disc"></i> namviet media</div>
                </div>

                <div class="grid grid-cols-12 gap-6 items-start">
                    <div class="col-span-9 space-y-4 text-[11.5px] leading-[1.7]">
                        <div class="flex items-center space-x-3">
                            <div class="w-10 h-10 rounded-full bg-white flex flex-col items-center justify-center font-black text-black text-sm select-none shadow-md">
                                <span class="leading-none text-[13px] tracking-tighter font-serif">|||</span>
                                <span class="leading-none text-[9px] -mt-0.5 tracking-tight font-sans">NCT</span>
                            </div>
                            <div>
                                <h3 class="text-[14px] font-bold text-white tracking-wide uppercase">Công Ty Cổ Phần N C T</h3>
                                <p class="text-[11px] text-[#848585] font-light -mt-0.5">nhaccuatui®</p>
                            </div>
                        </div>

                        <ul class="space-y-1 text-[#959696] list-none pl-0">
                            <li class="flex items-start"><span class="mr-2 text-[#646565]">•</span> Giấy phép cung cấp dịch vụ mạng xã hội trực tuyến số 140/GP-BTTTT do Bộ Thông tin và Truyền thông cấp.</li>
                            <li class="flex items-start"><span class="mr-2 text-[#646565]">•</span> Giấy Chứng nhận Đăng ký Kinh doanh số 0305535715 do Sở Kế hoạch và Đầu tư thành phố Hồ Chí Minh cấp ngày 01/03/2008.</li>
                            <li class="flex items-start"><span class="mr-2 text-[#646565]">•</span> Nhân sự chịu trách nhiệm quản lý nội dung thông tin: <span class="text-white font-medium ml-1">Ông Phan Hoài Nam</span></li>
                            <li class="flex items-start"><span class="mr-2 text-[#646565]">•</span> Địa chỉ: Tầng 19, Tòa nhà 678, số 67 Hoàng Văn Thái, Phường Tân Phú, Quận 7, TP. Hồ Chí Minh.</li>
                            <li class="flex items-start">
                                <span class="mr-2 text-[#646565]">•</span> Email: <a href="mailto:support@nct.vn" class="text-cyan-400 hover:underline mx-1">support@nct.vn</a> | Số điện thoại: <span class="text-white ml-1">(028) 3868 7979</span>
                            </li>
                        </ul>

                        <div class="flex space-x-2 pt-3">
                            <div class="bg-black text-white px-3 py-1.5 rounded-md flex items-center space-x-2 border border-[#333] cursor-pointer hover:bg-zinc-900 transition">
                                <i class="fab fa-apple text-lg"></i>
                                <div class="text-left leading-none"><p class="text-[8px] text-gray-400">Download on the</p><p class="text-[11px] font-bold">App Store</p></div>
                            </div>
                            <div class="bg-black text-white px-3 py-1.5 rounded-md flex items-center space-x-2 border border-[#333] cursor-pointer hover:bg-zinc-900 transition">
                                <i class="fab fa-google-play text-md text-emerald-400"></i>
                                <div class="text-left leading-none"><p class="text-[8px] text-gray-400">GET IT ON</p><p class="text-[11px] font-bold">Google Play</p></div>
                            </div>
                            <div class="bg-black text-white px-3 py-1.5 rounded-md flex items-center space-x-2 border border-[#333] cursor-pointer hover:bg-zinc-900 transition">
                                <i class="fas fa-store text-md text-red-500"></i>
                                <div class="text-left leading-none"><p class="text-[8px] text-gray-400">EXPLORE IT ON</p><p class="text-[11px] font-bold">AppGallery</p></div>
                            </div>
                        </div>
                    </div>

                    <div class="col-span-3 flex flex-col items-end justify-between h-full pt-2 self-stretch">
                        <div class="space-y-3 flex flex-col items-end">
                            <div class="bg-[#0070ba] text-white font-bold text-[10px] px-3 py-1.5 rounded flex items-center space-x-1.5 border border-blue-400 shadow-sm">
                                <i class="fas fa-shield-alt text-xs"></i>
                                <span class="tracking-wide uppercase text-[9px]">ĐÃ THÔNG BÁO BỘ CÔNG THƯƠNG</span>
                            </div>
                            <div class="flex text-[10px] font-bold tracking-tight rounded overflow-hidden border border-zinc-700 shadow-sm">
                                <span class="bg-[#cc0000] text-white px-2 py-1 font-mono">DMCA</span>
                                <span class="bg-[#4ca64c] text-slate-950 px-2 py-1 uppercase">PROTECTED</span>
                            </div>
                        </div>

                        <div class="flex items-center space-x-2 mt-8">
                            <span class="text-[11px] text-[#747575] mr-1">Find us on</span>
                            <a href="#" class="w-8 h-8 rounded-lg bg-[#2d2e2e] flex items-center justify-center text-white hover:bg-blue-600 transition"><i class="fab fa-facebook-f text-sm"></i></a>
                            <a href="#" class="w-8 h-8 rounded-lg bg-[#2d2e2e] flex items-center justify-center text-white hover:bg-zinc-800 transition"><i class="fab fa-tiktok text-sm"></i></a>
                            <a href="#" class="w-8 h-8 rounded-lg bg-[#2d2e2e] flex items-center justify-center text-white hover:bg-pink-600 transition"><i class="fab fa-indigo-600 transition"><i class="fab fa-instagram text-sm"></i></a>
                            <a href="#" class="w-8 h-8 rounded-lg bg-[#2d2e2e] flex items-center justify-center text-white text-[10px] font-bold hover:bg-blue-400 transition">Zalo</a>
                        </div>
                    </div>
                </div>

                <div class="border-t border-[#2d2e2e] pt-4 flex justify-between items-center text-[11px] text-[#747575]">
                    <div class="flex space-x-4">
                        <a href="#" class="hover:text-white">Chính Sách Bảo Mật</a>
                        <span>•</span>
                        <a href="#" class="hover:text-white">Chính Sách SHTT</a>
                        <span>•</span>
                        <a href="#" class="hover:text-white">Thỏa Thuận Sử Dụng</a>
                    </div>
                    <div>© NCT Corp. All rights reserved</div>
                </div>
            </footer>
        </div>
    </div>

    <!-- AUDIO PLAYER BOTTOM BAR - FIXED ĐÁY HOÀN TOÀN ĐỒNG BỘ -->
    <div class="fixed bottom-0 left-0 right-0 h-20 glass-player px-6 flex items-center justify-between z-50">
        <div class="flex items-center space-x-3 w-1/4">
            <div class="w-12 h-12 rounded-lg bg-gradient-to-br from-purple-600 to-indigo-900 flex items-center justify-center shadow-lg border border-purple-500/30">
                <i id="player-icon" class="fas fa-headphones-alt text-white text-xl"></i>
            </div>
            <div class="overflow-hidden">
                <h4 id="player-title" class="text-sm font-bold text-white truncate">Chưa chọn bài hát</h4>
                <p id="player-artist" class="text-xs text-gray-400 truncate">Vui lòng chọn bài ở playlist</p>
            </div>
        </div>
        
        <!-- Khu vực điều khiển trung tâm -->
        <div class="flex flex-col items-center space-y-1 w-2/4">
            <div class="flex items-center space-x-6 text-gray-400">
                <button onclick="playRandomTrack()" class="hover:text-white transition" title="Phát ngẫu nhiên"><i class="fas fa-random text-xs"></i></button>
                <button class="hover:text-white transition"><i class="fas fa-step-backward text-sm"></i></button>
                <!-- Nút Play/Pause lớn -->
                <button onclick="togglePlayPause()" class="text-white text-3xl hover:scale-110 transition duration-150">
                    <i id="btn-master-play" class="fas fa-play-circle"></i>
                </button>
                <button class="hover:text-white transition"><i class="fas fa-step-forward text-sm"></i></button>
                <button class="hover:text-white transition"><i class="fas fa-redo text-xs"></i></button>
            </div>
            
            <!-- Tiến trình bài hát -->
            <div class="w-full flex items-center space-x-2 text-[10px] text-gray-400 select-none">
                <span id="time-current">0:00</span>
                <div id="progress-container" class="flex-1 bg-gray-700 h-1.5 rounded-full cursor-pointer relative hover:h-2 transition-all">
                    <div id="progress-bar" class="bg-gradient-to-r from-purple-500 to-pink-500 w-0 h-full rounded-full relative"></div>
                </div>
                <span id="time-duration">0:00</span>
            </div>
        </div>
        
        <div class="flex items-center justify-end space-x-4 w-1/4 text-gray-400 text-sm">
            <button class="hover:text-pink-500 transition"><i class="fas fa-heart"></i></button>
            <button class="hover:text-white transition"><i class="fas fa-share-alt"></i></button>
            <div class="flex items-center space-x-1.5">
                <i class="fas fa-volume-up text-xs"></i>
                <input type="range" id="volume-slider" min="0" max="1" step="0.05" value="0.7" class="w-16 h-1 bg-gray-600 rounded-lg appearance-none cursor-pointer accent-purple-500">
            </div>
        </div>
    </div>

    <!-- JAVASCRIPT XỬ LÝ TRÌNH PHÁT NHẠC THỜI GIAN THỰC -->
    <script>
        const bottomAudio = document.getElementById('main-audio');
        const masterPlayIcon = document.getElementById('btn-master-play');
        const progressBar = document.getElementById('progress-bar');
        const progressContainer = document.getElementById('progress-container');
        const timeCurrent = document.getElementById('time-current');
        const timeDuration = document.getElementById('time-duration');
        const playerTitle = document.getElementById('player-title');
        const playerArtist = document.getElementById('player-artist');
        const playerIcon = document.getElementById('player-icon');
        const volumeSlider = document.getElementById('volume-slider');

        // Hàm click phát nhạc từ hàng đợi Top Trending
        function playMusic(title, artist, streamUrl) {
            playerTitle.innerText = title;
            playerArtist.innerText = artist;
            bottomAudio.src = streamUrl;
            bottomAudio.onerror = () => console.error('Audio load error', bottomAudio.error, streamUrl);
            bottomAudio.load();
            bottomAudio.muted = false;
            bottomAudio.currentTime = 0;
            bottomAudio.play().then(() => {
                masterPlayIcon.className = "fas fa-pause-circle text-pink-500";
                playerIcon.className = "fas fa-compact-disc text-pink-400 animate-spin";
            }).catch(err => {
                console.error('Audio play failed:', err);
                masterPlayIcon.className = "fas fa-play-circle text-white";
                playerIcon.className = "fas fa-headphones-alt text-white";
            });
        }

        function encodeSong(songObj) {
            return btoa(unescape(encodeURIComponent(JSON.stringify(songObj))));
        }

        // Bấm dừng/phát nhanh ở thanh điều khiển đáy
        function togglePlayPause() {
            if (!bottomAudio.src) return;
            if (bottomAudio.paused) {
                bottomAudio.play();
                masterPlayIcon.className = "fas fa-pause-circle text-pink-500";
                playerIcon.className = "fas fa-compact-disc text-pink-400 animate-spin";
            } else {
                bottomAudio.pause();
                masterPlayIcon.className = "fas fa-play-circle text-white";
                playerIcon.className = "fas fa-headphones-alt text-white";
            }
        }

        function playRandomTrack() {
            const randomSongPool = [
                { name:'Buông', artist:'Trúc Nhân & Music Pop', url:'/static/Buông.mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg', time:'4:12' },
                { name:'Không Buông (Lofi Ver.)', artist:'Adele & Music Pop', url:'/static/khongbuong.mp3', img:'https://image-cdn.nct.vn/song/2024/05/10/Z/z/P/X/1715335736956_300.jpg', time:'3:20' },
                { name:'REDRED', artist:'CORTIS', url:'/static/REDRED.mp3', img:'https://image-cdn.nct.vn/song/2024/10/08/M/v/z/a/1728367891245_300.jpg', time:'2:58' },
                { name:'Một Nhà Remix', artist:'Hngle x Anh Tú', url:'/static/Một Nhà Remix.mp3', img:'https://image-cdn.nct.vn/song/2025/01/07/I/g/Y/O/1736262155028_300.jpg', time:'3:55' },
                { name:'Thích Em Hơi Nhiều', artist:'Inso ft. Nita Phạm', url:'/static/Thích Em Hơi Nhiều.mp3', img:'https://image-cdn.nct.vn/song/2024/06/20/a/6/e/4/1718877870154_300.jpg', time:'3:28' },
                { name:'Người Im Lặng Gặp Người Hay Nói', artist:'Sơn Tùng MTP', url:'/static/Người Im Lặng Gặp Người Hay Nói (1).mp3', img:'https://image-cdn.nct.vn/song/2024/03/15/4/c/b/d/1710498649541_300.jpg', time:'3:58' }
            ];
            const song = randomSongPool[Math.floor(Math.random() * randomSongPool.length)];
            playSong(encodeSong(song), null);
            showToast('info', 'Ngẫu nhiên', `Phát ngẫu nhiên: ${song.name}`);
        }

        // Định dạng thời gian giây -> mm:ss
        function formatTime(secs) {
            if (isNaN(secs)) return "0:00";
            const m = Math.floor(secs / 60);
            const s = Math.floor(secs % 60);
            return `${m}:${s < 10 ? '0' : ''}${s}`;
        }

        // Đồng bộ tiến trình chạy nhạc
        bottomAudio.addEventListener('timeupdate', () => {
            const pct = (bottomAudio.currentTime / bottomAudio.duration) * 100;
            progressBar.style.width = `${pct}%`;
            timeCurrent.innerText = formatTime(bottomAudio.currentTime);
        });

        // Đọc tổng thời gian khi file nhạc load xong
        bottomAudio.addEventListener('loadedmetadata', () => {
            timeDuration.innerText = formatTime(bottomAudio.duration);
        });

        // Tua nhạc khi click lên thanh tiến trình
        progressContainer.addEventListener('click', (e) => {
            if (!bottomAudio.src || isNaN(bottomAudio.duration)) return;
            const width = progressContainer.clientWidth;
            const clickX = e.offsetX;
            bottomAudio.currentTime = (clickX / width) * bottomAudio.duration;
        });

        // Điều chỉnh âm lượng
        volumeSlider.addEventListener('input', (e) => {
            bottomAudio.volume = e.target.value;
        });

        // Tự động dừng hiệu ứng quay khi nhạc hết bài
        bottomAudio.addEventListener('ended', () => {
            masterPlayIcon.className = "fas fa-play-circle text-white";
            playerIcon.className = "fas fa-headphones-alt text-white";
            progressBar.style.width = "0%";
            timeCurrent.innerText = "0:00";
        });


        // ─── PHẦN MÃ LOGIC API HỆ THỐNG MẬT MÃ (GIỮ NGUYÊN BẢN CŨ) ───
        async function setReceiver() {
            const url = document.getElementById('receiver_url').value;
            const res = await fetch('/api/set_receiver', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ url })
            });
            const data = await res.json();
            if(data.status === 'ok') showToast('info','📡 Đã kết nối Receiver', data.url);
            updateStatus();
        }

        async function scanReceivers() {
            const btn = document.getElementById('btn-scan');
            const icon = document.getElementById('scan-icon');
            const dropdown = document.getElementById('receiver-list-dropdown');

            icon.classList.add('animate-spin');
            btn.disabled = true;
            dropdown.classList.remove('hidden');
            dropdown.innerHTML = `<div class="p-3 text-xs text-gray-400 flex items-center gap-2"><i class="fas fa-spinner animate-spin"></i> Đang quét mạng LAN, vui lòng chờ...</div>`;

            try {
                const res = await fetch('/api/scan_receivers');
                const data = await res.json();
                const list = data.receivers || [];

                if (list.length === 0) {
                    dropdown.innerHTML = `<div class="p-3 text-xs text-gray-400">Không tìm thấy Receiver nào đang chạy gần đây. Hãy chắc chắn ứng dụng Receiver đã được mở.</div>`;
                } else {
                    dropdown.innerHTML = list.map(r => `
                        <div class="p-3 text-xs text-gray-200 hover:bg-slate-800 cursor-pointer border-b border-gray-800 last:border-b-0 flex items-center justify-between" onclick="selectReceiver('${r.url}')">
                            <span><i class="fas fa-desktop text-purple-400 mr-2"></i>${r.ip}<span class="text-gray-500">:${r.port}</span></span>
                            <span class="text-green-400 text-[10px] flex items-center gap-1"><i class="fas fa-circle" style="font-size:6px;"></i> online</span>
                        </div>
                    `).join('');
                }
            } catch (e) {
                dropdown.innerHTML = `<div class="p-3 text-xs text-red-400">Lỗi khi quét mạng: ${e.message}</div>`;
            } finally {
                icon.classList.remove('animate-spin');
                btn.disabled = false;
            }
        }

        async function selectReceiver(url) {
            document.getElementById('receiver_url').value = url;
            document.getElementById('receiver-list-dropdown').classList.add('hidden');
            await setReceiver();
        }

        document.addEventListener('click', (e) => {
            const dropdown = document.getElementById('receiver-list-dropdown');
            const btn = document.getElementById('btn-scan');
            if (dropdown && !dropdown.classList.contains('hidden') && !dropdown.contains(e.target) && !btn.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });

        async function runHandshake() {
            const btn = document.getElementById('btn-handshake');
            btn.innerHTML = `<i class="fas fa-spinner animate-spin"></i>...`;
            const res = await fetch('/api/handshake', { method: 'POST' });
            btn.innerHTML = `<i class="fas fa-handshake mr-1"></i> 1. Handshake`;
            updateStatus();
        }

        async function runKeyExchange() {
            const btn = document.getElementById('btn-keyexchange');
            btn.innerHTML = `<i class="fas fa-spinner animate-spin"></i>...`;
            const res = await fetch('/api/key_exchange', { method: 'POST' });
            btn.innerHTML = `<i class="fas fa-key mr-1"></i> 2. Key Exchange`;
            updateStatus();
        }

        async function sendSecureFile(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-sendfile');
            const fileInput = document.getElementById('music_file');
            if (fileInput.files.length === 0) return;

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('artist', document.getElementById('artist').value);
            formData.append('copyright', document.getElementById('copyright').value);

            btn.innerHTML = `🔒 ĐANG TRUYỀN MÃ HÓA...`;
            btn.disabled = true;

            const res = await fetch('/api/send_file', { method: 'POST', body: formData });
            const data = await res.json();
            if (data.status === 'ACK') {
                showSendModal(true, data);
            } else {
                showSendModal(false, data);
            }
            btn.innerHTML = `<i class="fas fa-paper-plane"></i> MÃ HÓA TRIPLE DES & PHÁT ĐI (SEND)`;
            btn.disabled = false;
            updateStatus();
        }

        async function updateStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                const badge = document.getElementById('status-badge');
                if (data.key_exchange) {
                    badge.innerText = "Sẵn sàng mã hóa";
                    badge.className = "text-xs bg-emerald-950 text-emerald-400 px-2.5 py-0.5 rounded-full border border-emerald-800";
                    document.getElementById('btn-sendfile').disabled = false;
                } else if (data.handshake) {
                    badge.innerText = "Đã Handshake";
                    badge.className = "text-xs bg-yellow-950 text-yellow-400 px-2.5 py-0.5 rounded-full border border-yellow-800";
                    document.getElementById('btn-keyexchange').disabled = false;
                }
                const container = document.getElementById('log-container');
                container.innerHTML = "";
                data.log.forEach(item => {
                    let color = item.level==='success'?"text-emerald-400":item.level==='error'?"text-red-400":"text-cyan-400";
                    container.innerHTML += `<div class="${color}">[${item.time}] ${item.msg}</div>`;
                });
                container.scrollTop = container.scrollHeight;
            } catch(e){}
        }

        async function resetState() {
            if(!confirm("Reset hệ thống mật mã?")) return;
            await fetch('/api/reset', {method: 'POST'});
            location.reload();
        }

        // ── TOAST SYSTEM ──
        function showToast(type, title, msg, duration=4500) {
            const icons = {success:'✅', error:'❌', info:'ℹ️'};
            const tc = document.getElementById('toast-container');
            const t = document.createElement('div');
            t.className = `toast toast-${type}`;
            t.innerHTML = `<span class="toast-icon">${icons[type]||'💬'}</span>
                <div class="toast-body"><div class="toast-title">${title}</div><div class="toast-msg">${msg}</div></div>
                <span class="toast-close" onclick="this.parentElement.remove()">✕</span>`;
            tc.appendChild(t);
            setTimeout(()=>{ t.classList.add('toast-out'); setTimeout(()=>t.remove(), 300); }, duration);
        }

        // ── SEND RESULT MODAL ──
        function showSendModal(ok, data) {
            const modal = document.getElementById('send-result-modal');
            document.getElementById('modal-icon').textContent = ok ? '🎉' : '❌';
            const titleEl = document.getElementById('modal-title');
            titleEl.textContent = ok ? 'Gửi file thành công!' : 'Gửi thất bại — NACK';
            titleEl.className = 'modal-title ' + (ok ? 'success' : 'error');
            document.getElementById('modal-sub').textContent = ok 
                ? `File "${data.filename}" đã được mã hóa Triple DES và truyền đi an toàn`
                : (data.error || 'Lỗi không xác định');

            const rows = ok ? [
                ['📁 File', data.filename],
                ['📦 Kích thước gốc', data.filesize_kb + ' KB'],
                ['🔒 Kích thước gói', data.packet_size_kb + ' KB'],
                ['⏱ Tổng thời gian', (data.timing?.total || 0) + ' ms'],
            ] : [['❗ Lỗi', data.error || 'NACK nhận được']];

            const table = document.getElementById('modal-table');
            table.innerHTML = rows.map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('');

            const timingDiv = document.getElementById('modal-timing');
            if (ok && data.timing) {
                const t = data.timing;
                const entries = Object.entries(t).filter(([k,v])=>typeof v==='number' && v>0 && k!=='total');
                const max = Math.max(...entries.map(([,v])=>v));
                timingDiv.innerHTML = '<div style="font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">⏱ Chi tiết thời gian</div>' +
                    entries.map(([k,v])=>`<div class="timing-row">
                        <div class="timing-label"><span>${k}</span><span>${v}ms</span></div>
                        <div class="timing-track"><div class="timing-fill" style="width:${Math.round(v/max*100)}%"></div></div>
                    </div>`).join('');
            } else { timingDiv.innerHTML = ''; }

            modal.classList.add('show');
        }
        function closeSendModal() { document.getElementById('send-result-modal').classList.remove('show'); }
        document.getElementById('send-result-modal').addEventListener('click', function(e){ if(e.target===this) closeSendModal(); });


    // ── TOGGLE SONG LIST 2 (Tâm Trạng section) ──
    let currentOpenPlaylist2 = null;
    function toggleSongList2(playlistId) {
        const container = document.getElementById('song-list-container-2');
        const titleElem = document.getElementById('selected-playlist-title-2');
        const tbody = document.getElementById('song-items-tbody-2');
        if (currentOpenPlaylist2 === playlistId) { closeSongList2(); return; }
        const data = playlistData[playlistId];
        if (!data) return;
        titleElem.innerText = '>_ ĐANG XEM: ' + data.title.toUpperCase();
        tbody.innerHTML = '';
        data.songs.forEach(song => {
            const songParam = btoa(unescape(encodeURIComponent(JSON.stringify(song))));
            tbody.innerHTML += `<tr class="border-b border-white/5 hover:bg-white/5 transition group">
                <td class="py-3 text-center text-gray-500 group-hover:text-[#00ffcc] cursor-pointer w-10" onclick="playSong('${songParam}', this)"><i class="fas fa-play text-[9px] opacity-0 group-hover:opacity-100 transition mr-1"></i><span class="group-hover:hidden">${song.id}</span></td>
                <td class="py-3 font-medium text-white flex items-center space-x-2 cursor-pointer flex-1 min-w-0" onclick="playSong('${songParam}', this)"><img src="${song.img}" class="w-8 h-8 flex-shrink-0 rounded object-cover shadow"><span class="hover:text-[#00ffcc] transition truncate">${song.name}</span></td>
                <td class="py-3 text-gray-400 hidden md:table-cell cursor-pointer min-w-0" onclick="playSong('${songParam}', this)">${song.uploader}</td>
                <td class="py-3 text-gray-400 cursor-pointer min-w-0" onclick="playSong('${songParam}', this)">${song.artist}</td>
                <td class="py-3 text-right text-gray-500 group-hover:text-white pr-2 cursor-pointer w-12" onclick="playSong('${songParam}', this)">${song.time}</td>
                <td class="py-3 text-center w-24 flex-shrink-0"><button onclick="event.stopPropagation(); selectForEncrypt('${songParam}')" class="px-2 py-1 text-xs text-white bg-[#00ffcc]/20 hover:bg-[#00ffcc]/40 rounded border border-[#00ffcc] hover:text-[#00ffcc] transition whitespace-nowrap">Chọn</button></td>
            </tr>`;
        });
        container.classList.remove('hidden');
        currentOpenPlaylist2 = playlistId;
        container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    function closeSongList2() {
        document.getElementById('song-list-container-2').classList.add('hidden');
        currentOpenPlaylist2 = null;
    }

        setInterval(updateStatus, 3000);
        window.onload = updateStatus;
    // 1. Khai báo kho danh sách Banner (Thích thêm bao nhiêu trang tùy ý bạn vào đây)
const bannerPages = [
    {
        // TRANG 1 (Mặc định ban đầu)
        left: {
            img: "https://image-cdn.nct.vn/focus/2026/03/06/M/c/E/m/1772787656506_1500.jpg",
            text: "Cuối cùng<br>cũng Cuối Tuần"
        },
        right: {
            img: "https://image-cdn.nct.vn/focus/2026/05/22/0/x/y/Z/1779449041654_1500.jpg",
            text: "NHỮNG KẺ<br>SĨ TÌNH"
        }
    },
    {
        // TRANG 2 (K-POP GEN 4 như ảnh mẫu bạn vừa gửi)
        left: {
            img: "https://image-cdn.nct.vn/focus/2025/05/23/4/7/F/6/1747993051351_1500.jpg",
            text: "Giai Điệu<br>Cho Ngày Mới"
        },
        right: {
            img: "https://image-cdn.nct.vn/focus/2026/05/22/7/5/D/f/1779437689038_1500.jpg",
            text: "K-POP<br>GEN 4"
        }
    },
    {
        // TRANG 3 (Bạn có thể tự do đổi ảnh và chữ tại đây)
        left: {
            img: "https://images.unsplash.com/photo-1511671782779-c97d3d27a1d4?auto=format&fit=crop&w=1000&q=80",
            text: "Chill Lofi<br>Đêm Khuya"
        },
        right: {
            img: "https://images.unsplash.com/photo-1506157786151-b8491531f063?auto=format&fit=crop&w=1000&q=80",
            text: "VŨ ĐIỆU<br>ROCK SÔI ĐỘNG"
        }
    }
];

let currentPageIndex = 0;

// 2. Hàm xử lý đổi trang kèm hiệu ứng Fade chớp mượt mà
function changePage(direction) {
    // Tính toán index trang tiếp theo (Vòng lặp vô hạn)
    currentPageIndex = (currentPageIndex + direction + bannerPages.length) % bannerPages.length;

    const containerLeft = document.getElementById('container-banner-left');
    const containerRight = document.getElementById('container-banner-right');
    
    const imgLeft = document.getElementById('img-banner-left');
    const txtLeft = document.getElementById('txt-banner-left');
    const imgRight = document.getElementById('img-banner-right');
    const txtRight = document.getElementById('txt-banner-right');

    if (!containerLeft || !containerRight) return;

    // Bước A: Ẩn mờ dần hai ô banner hiện tại (Giảm opacity về 0)
    containerLeft.style.opacity = '0';
    containerRight.style.opacity = '0';

    // Bước B: Đợi hiệu ứng ẩn chạy xong (250ms) thì đổi ruột dữ liệu và hiện lên lại
    setTimeout(() => {
        const data = bannerPages[currentPageIndex];

        // Cập nhật dữ liệu trang mới cho bên Trái
        imgLeft.src = data.left.img;
        txtLeft.innerHTML = data.left.text;

        // Cập nhật dữ liệu trang mới cho bên Phải
        imgRight.src = data.right.img;
        txtRight.innerHTML = data.right.text;

        // Hiện mượt mà trở lại (Tăng opacity lên 1)
        containerLeft.style.opacity = '1';
        containerRight.style.opacity = '1';
    }, 250); 
}

// (Tùy chọn) Cứ sau mỗi 8 giây tự động lật sang trang tiếp theo cho bắt mắt
setInterval(() => {
    changePage(1);
}, 8000);

function updateGreeting() {
    const greetingElement = document.getElementById('greeting-text');
    if (!greetingElement) return;

    // Lấy số giờ hiện tại (từ 0 đến 23)
    const currentHour = new Date().getHours();
    let greetingString = "";

    // Phân chia khung giờ logic thực tế
    if (currentHour >= 5 && currentHour < 12) {
        greetingString = "Chào buổi sáng 🌤️";
    } else if (currentHour >= 12 && currentHour < 18) {
        greetingString = "Chào buổi chiều ☀️";
    } else {
        greetingString = "Chào buổi tối 🌙";
    }

    // Cập nhật text lên giao diện
    greetingElement.innerText = greetingString;
}

// Chạy ngay lập tức khi trang vừa tải xong
document.addEventListener('DOMContentLoaded', () => {
    updateGreeting();
    
    // (Tùy chọn) Cứ mỗi 1 phút kiểm tra lại giờ một lần để tự nhảy lời chào nếu người dùng treo tab lâu
    setInterval(updateGreeting, 60000);
});
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(CYBERPUNK_UI)


if __name__ == '__main__': 
    # Ghi nhận log hệ thống khi Sender khởi động
    add_log("🚀 Sender App khởi động tại http://0.0.0.0:5001", "info")
    
    # Khởi chạy Flask App ở cổng 5001
    app.run(host='0.0.0.0', port=5001, debug=False)