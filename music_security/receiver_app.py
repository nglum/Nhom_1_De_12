import sys
import os

# Thêm thư mục hiện tại vào Python path để import được crypto_utils
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import socket
import threading
import json
import time
import base64
import hashlib
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from crypto_utils import (
    generate_rsa_keypair, load_rsa_private_key, load_rsa_public_key,
    rsa_decrypt_session_key, rsa_verify,
    triple_des_decrypt, des_decrypt_metadata,
    verify_integrity_hash, b64decode, b64encode,
    generate_iv
)

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)

# ─── State bộ nhớ ───
STATE = {
    "private_key_pem": None,
    "public_key_pem": None,
    "session_key": None,
    "sender_public_key_pem": None,
    "handshake_done": False,
    "key_exchange_done": False,
    "log": [],
    "received_files": []
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RECEIVED_DIR = os.path.join(BASE_DIR, "received")
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
        STATE["session_key"] = session_key
        STATE["sender_public_key_pem"] = sender_public_key.encode()
        
        msg_bytes = metadata_signed.encode()
        valid = rsa_verify(sender_public_key.encode(), msg_bytes, signature)

        if valid:
            STATE["key_exchange_done"] = True
            add_log("✅ Xác thực chữ ký RSA/SHA-512 hợp lệ", "success")
            return jsonify({"status": "ok", "msg": "Key exchange thành công"})
        else:
            return jsonify({"error": "Chữ ký không hợp lệ"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
    return send_from_directory(RECEIVED_DIR, filename, as_attachment=True)


@app.route('/stream/<filename>')
def stream_file(filename):
    """Phát trực tiếp file nhạc đã giải mã trong trình duyệt (không ép tải về)."""
    return send_from_directory(RECEIVED_DIR, filename, as_attachment=False, conditional=True)


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
CYBERPUNK_RECEIVER_UI = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Serendipity Music - Secure Receiver Hub</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #0d0e22; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
        .sidebar { background-color: #12132c; }
        .main-content { background-color: #0f1026; }
        .card-bg { background-color: #1b1c42; }
        .neon-text-cyan { color: #00ffff; text-shadow: 0 0 10px rgba(0,255,255,0.5); }
        .glass-player { background: rgba(27,28,66,0.85); backdrop-filter: blur(12px); border-top: 1px solid rgba(255,255,255,0.1); }
        .nct-footer { background-color: #1e1f1f !important; color: #a5a6a6 !important; }
        .nct-footer a { color: #a5a6a6; transition: color 0.2s; }
        .nct-footer a:hover { color: #fff; text-decoration: underline; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f1026; }
        ::-webkit-scrollbar-thumb { background: #1c305c; border-radius: 3px; }

        /* ── TOAST ── */
        #toast-container { position:fixed; top:20px; right:20px; z-index:9999; display:flex; flex-direction:column; gap:10px; pointer-events:none; }
        .toast { display:flex; align-items:flex-start; gap:12px; min-width:320px; max-width:420px; padding:14px 18px; border-radius:14px; border:1px solid; box-shadow:0 8px 32px rgba(0,0,0,.5); backdrop-filter:blur(12px); animation:toastIn .35s cubic-bezier(.34,1.56,.64,1) forwards; pointer-events:all; }
        .toast.toast-success { background:rgba(16,185,129,.15); border-color:rgba(16,185,129,.4); }
        .toast.toast-error   { background:rgba(239,68,68,.15);  border-color:rgba(239,68,68,.4); }
        .toast.toast-info    { background:rgba(6,182,212,.15);  border-color:rgba(6,182,212,.4); }
        .toast.toast-out { animation:toastOut .3s ease forwards; }
        .toast-icon  { font-size:1.4rem; flex-shrink:0; }
        .toast-body  { flex:1; }
        .toast-title { font-weight:700; font-size:.88rem; margin-bottom:2px; }
        .toast-success .toast-title { color:#34d399; }
        .toast-error  .toast-title  { color:#f87171; }
        .toast-info   .toast-title  { color:#22d3ee; }
        .toast-msg   { font-size:.78rem; color:rgba(255,255,255,.6); line-height:1.5; }
        .toast-close { font-size:.8rem; color:rgba(255,255,255,.4); cursor:pointer; }
        @keyframes toastIn  { from{opacity:0;transform:translateX(40px) scale(.9)} to{opacity:1;transform:translateX(0) scale(1)} }
        @keyframes toastOut { from{opacity:1} to{opacity:0;transform:translateX(40px)} }

        /* ── RECEIVED FILE CARD ── */
        .file-received-card { background:linear-gradient(135deg,rgba(6,182,212,.08),rgba(99,102,241,.08)); border:1px solid rgba(6,182,212,.2); border-radius:14px; padding:14px 16px; margin-bottom:12px; transition:all .2s; }
        .file-received-card:hover { border-color:rgba(6,182,212,.5); box-shadow:0 0 20px rgba(6,182,212,.1); }
        .file-name-badge { font-family:monospace; font-size:.82rem; font-weight:700; color:#22d3ee; }
        .crypto-tag { display:inline-flex; font-size:.65rem; padding:2px 8px; border-radius:6px; font-weight:600; margin:2px; }
        .tag-3des { background:rgba(139,92,246,.2); color:#a78bfa; border:1px solid rgba(139,92,246,.3); }
        .tag-rsa  { background:rgba(6,182,212,.2);  color:#22d3ee; border:1px solid rgba(6,182,212,.3); }
        .tag-sha  { background:rgba(16,185,129,.2); color:#34d399; border:1px solid rgba(16,185,129,.3); }
        .timing-mini { display:flex; gap:6px; flex-wrap:wrap; margin-top:6px; }
        .timing-chip { font-size:.62rem; font-family:monospace; background:rgba(255,255,255,.05); color:rgba(255,255,255,.45); padding:2px 7px; border-radius:4px; }

        /* ── PROGRESS STEPS ── */
        .step-indicator { display:flex; align-items:center; gap:0; margin-bottom:20px; }
        .step-dot { width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:.75rem; font-weight:700; flex-shrink:0; border:2px solid; transition:all .3s; font-family:monospace; }
        .step-dot.pending { background:rgba(255,255,255,.05); border-color:rgba(255,255,255,.12); color:rgba(255,255,255,.3); }
        .step-dot.active  { background:linear-gradient(135deg,#06b6d4,#3b82f6); border-color:transparent; color:#fff; box-shadow:0 0 16px rgba(6,182,212,.4); }
        .step-dot.done    { background:linear-gradient(135deg,#10b981,#059669); border-color:transparent; color:#fff; box-shadow:0 0 12px rgba(16,185,129,.4); }
        .step-line { flex:1; height:2px; background:rgba(255,255,255,.08); }
        .step-line.done { background:linear-gradient(90deg,#10b981,rgba(255,255,255,.08)); }
        .step-label { font-size:.65rem; color:rgba(255,255,255,.4); text-align:center; margin-top:4px; }
        .step-label.active { color:#22d3ee; }
        .step-label.done   { color:#34d399; }

        /* ── WAVEFORM ── */
        .waveform-recv { display:flex; align-items:center; gap:2px; height:28px; }
        .wr-bar { width:3px; border-radius:3px; background:linear-gradient(180deg,#06b6d4,#3b82f6); animation:wr 1.4s ease-in-out infinite; }
        @keyframes wr { 0%,100%{height:3px;opacity:.3} 50%{height:24px;opacity:1} }
        .wr-bar:nth-child(1){animation-delay:0s}.wr-bar:nth-child(2){animation-delay:.1s}.wr-bar:nth-child(3){animation-delay:.2s}
        .wr-bar:nth-child(4){animation-delay:.3s}.wr-bar:nth-child(5){animation-delay:.4s}.wr-bar:nth-child(6){animation-delay:.3s}
        .wr-bar:nth-child(7){animation-delay:.2s}.wr-bar:nth-child(8){animation-delay:.1s}
        .waveform-recv.idle .wr-bar { animation-play-state:paused; height:4px; opacity:.2; }

        /* ── KEY DISPLAY ── */
        .key-box { background:#0a0914; border:1px solid rgba(6,182,212,.2); border-radius:10px; padding:10px 12px; font-family:monospace; font-size:.68rem; color:#06b6d4; word-break:break-all; line-height:1.7; max-height:80px; overflow-y:auto; }
        .key-box::-webkit-scrollbar { width:3px; }
        .key-box::-webkit-scrollbar-thumb { background:#1c305c; border-radius:2px; }
    </style>
</head>
<body class="h-screen flex flex-col justify-between overflow-hidden">

    <!-- TOAST CONTAINER -->
    <div id="toast-container"></div>

    <div class="flex flex-1 h-full overflow-hidden">
        <!-- SIDEBAR TRÁI -->
        <aside class="sidebar w-64 flex flex-col justify-between p-6 border-r border-cyan-900/30 flex-shrink-0">
            <div>
                <div class="flex flex-col items-center mb-8">
                    <div class="relative w-20 h-20 rounded-full p-1 bg-gradient-to-tr from-cyan-400 to-blue-600 mb-3">
                        <img src="https://image-cdn.nct.vn/singer/avatar/2026/03/30/1/g/a/T/1774841335489_300.jpg" alt="Avatar" class="w-full h-full rounded-full bg-slate-900">
                    </div>
                    <h3 class="font-bold text-white text-md">Secure Receiver</h3>
                    <p class="text-xs text-cyan-400">Port 5000 · Online</p>
                    <div class="flex items-center gap-1.5 mt-2">
                        <div class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
                        <span class="text-xs text-emerald-400 font-semibold">Đang lắng nghe</span>
                    </div>
                </div>
                <nav class="space-y-3">
                    <a href="#" class="flex items-center space-x-3 text-cyan-400 font-semibold bg-cyan-950/40 p-2 rounded-lg"><i class="fas fa-home w-5"></i><span>Dashboard</span></a>
                    <a href="#" onclick="scrollToFiles()" class="flex items-center space-x-3 text-gray-400 hover:text-white p-2 transition"><i class="fas fa-folder-open w-5"></i><span>File Nhận</span></a>
                    <a href="#" onclick="scrollToLog()" class="flex items-center space-x-3 text-gray-400 hover:text-white p-2 transition"><i class="fas fa-terminal w-5"></i><span>Crypto Logs</span></a>
                    <a href="#" onclick="scrollToKeys()" class="flex items-center space-x-3 text-gray-400 hover:text-white p-2 transition"><i class="fas fa-key w-5"></i><span>Key Info</span></a>
                </nav>
            </div>
            <div class="space-y-3 text-sm text-gray-400">
                <!-- Stats mini -->
                <div class="bg-cyan-950/20 border border-cyan-900/30 rounded-xl p-3 space-y-2">
                    <div class="flex justify-between text-xs"><span class="text-gray-400">File đã nhận</span><span id="sb-count" class="text-cyan-400 font-bold">0</span></div>
                    <div class="flex justify-between text-xs"><span class="text-gray-400">Handshake</span><span id="sb-hs" class="text-gray-500">⏳</span></div>
                    <div class="flex justify-between text-xs"><span class="text-gray-400">Session Key</span><span id="sb-sk" class="text-gray-500">⏳</span></div>
                </div>
                <a href="#" onclick="resetAll()" class="flex items-center space-x-3 hover:text-red-400 transition"><i class="fas fa-redo"></i><span>Reset System</span></a>
            </div>
        </aside>

        <!-- MAIN CONTENT -->
        <div class="flex-1 flex flex-col overflow-y-auto main-content pb-28" id="main-scroll">
            <main class="grid grid-cols-3 p-6 gap-6">

                <!-- COL TRÁI: 2/3 -->
                <div class="col-span-2 space-y-6">

                    <!-- BANNER HERO -->
                    <div class="relative rounded-2xl overflow-hidden p-7 flex items-center justify-between min-h-[160px]"
                         style="background: linear-gradient(135deg, rgba(6,20,60,0.92), rgba(0,80,100,0.5)), url('https://image-cdn.nct.vn/focus/2026/05/22/0/x/y/Z/1779449041654_1500.jpg') center/cover;">
                        <div class="z-10 max-w-md">
                            <div class="flex items-center gap-2 mb-2">
                                <div class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></div>
                                <span class="text-xs text-cyan-400 font-semibold tracking-widest uppercase">Secure Receiver Hub</span>
                            </div>
                            <h1 class="text-2xl font-extrabold text-white mb-2 neon-text-cyan">Nhận File Nhạc Bản Quyền</h1>
                            <p class="text-xs text-gray-300 leading-relaxed">Giải mã Triple DES · Xác thực RSA/SHA-512 · Kiểm tra toàn vẹn · Lưu file an toàn</p>
                        </div>
                        <!-- Waveform animated -->
                        <div class="waveform-recv" id="hero-wave">
                            <div class="wr-bar"></div><div class="wr-bar"></div><div class="wr-bar"></div>
                            <div class="wr-bar"></div><div class="wr-bar"></div><div class="wr-bar"></div>
                            <div class="wr-bar"></div><div class="wr-bar"></div>
                        </div>
                        <div class="absolute right-6 opacity-10 text-9xl text-cyan-500"><i class="fas fa-satellite-dish"></i></div>
                    </div>

                    <!-- STEP INDICATOR -->
                    <div class="card-bg rounded-xl p-5 border border-cyan-900/30">
                        <h3 class="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4">Tiến trình kết nối</h3>
                        <div class="step-indicator">
                            <div class="flex flex-col items-center gap-1">
                                <div class="step-dot active" id="sd1">1</div>
                                <div class="step-label active" id="sl1">Handshake</div>
                            </div>
                            <div class="step-line" id="sl-line1"></div>
                            <div class="flex flex-col items-center gap-1">
                                <div class="step-dot pending" id="sd2">2</div>
                                <div class="step-label" id="sl2">Trao khóa</div>
                            </div>
                            <div class="step-line" id="sl-line2"></div>
                            <div class="flex flex-col items-center gap-1">
                                <div class="step-dot pending" id="sd3">3</div>
                                <div class="step-label" id="sl3">Nhận file</div>
                            </div>
                        </div>

                        <!-- Thuật toán chips -->
                        <div class="flex flex-wrap gap-2 mt-2">
                            <span class="crypto-tag tag-3des"><i class="fas fa-lock mr-1"></i>Triple DES/CBC</span>
                            <span class="crypto-tag tag-rsa"><i class="fas fa-key mr-1"></i>RSA 1024-bit OAEP</span>
                            <span class="crypto-tag tag-sha"><i class="fas fa-fingerprint mr-1"></i>SHA-512 Integrity</span>
                            <span class="crypto-tag tag-3des"><i class="fas fa-database mr-1"></i>DES Metadata</span>
                        </div>
                    </div>

                    <!-- FILE ĐÃ NHẬN -->
                    <div class="card-bg rounded-xl p-5 border border-cyan-900/30" id="files-section">
                        <div class="flex items-center justify-between mb-4">
                            <h3 class="text-sm font-bold text-white flex items-center gap-2">
                                <i class="fas fa-folder-open text-cyan-400"></i> File Đã Nhận
                            </h3>
                            <span id="file-count-badge" class="text-xs bg-cyan-950 text-cyan-400 px-2.5 py-0.5 rounded-full border border-cyan-800">0 files</span>
                        </div>
                        <div id="files-container">
                            <div class="text-center py-10 text-gray-600" id="empty-msg">
                                <i class="fas fa-satellite-dish text-3xl mb-3 block text-gray-700"></i>
                                <p class="text-sm">Chưa nhận file nào</p>
                                <p class="text-xs mt-1">Đang lắng nghe kết nối từ Người Gửi...</p>
                            </div>
                        </div>
                    </div>

                    <!-- KEY INFO -->
                    <div class="card-bg rounded-xl p-5 border border-cyan-900/30" id="keys-section">
                        <h3 class="text-sm font-bold text-white mb-4 flex items-center gap-2">
                            <i class="fas fa-shield-alt text-cyan-400"></i> Thông Tin Khóa Bảo Mật
                        </h3>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <p class="text-xs text-gray-500 mb-1 uppercase tracking-wider">RSA Public Key (Receiver)</p>
                                <div class="key-box" id="key-pub-display">Chưa tạo khóa...</div>
                            </div>
                            <div>
                                <p class="text-xs text-gray-500 mb-1 uppercase tracking-wider">Session Key Status</p>
                                <div class="key-box" id="key-sk-display">Chưa nhận Session Key...</div>
                            </div>
                        </div>
                    </div>

                </div>

                <!-- COL PHẢI: 1/3 -->
                <div class="col-span-1 space-y-5">

                    <!-- POPULAR ARTIST giống sender -->
                    <div class="card-bg rounded-xl p-4">
                        <h3 class="text-sm font-bold text-white mb-3">Popular Artist</h3>
                        <div class="space-y-3">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full" src="https://image-cdn.nct.vn/singer/avatar/2026/03/30/1/g/a/T/1774841335489_300.jpg">
                                    <div><h4 class="text-xs font-semibold text-white">HIEUTHUHAI</h4><p class="text-[10px] text-gray-400">71K Followers</p></div>
                                </div>
                                <i class="far fa-heart text-gray-400 text-xs"></i>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full" src="https://image-cdn.nct.vn/singer/avatar/2026/03/26/n/v/j/N/1774522375114_300.jpeg">
                                    <div><h4 class="text-xs font-semibold text-white">GREY D</h4><p class="text-[10px] text-gray-400">22K Followers</p></div>
                                </div>
                                <i class="far fa-heart text-gray-400 text-xs"></i>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full" src="https://image-cdn.nct.vn/singer/avatar/2026/04/20/V/e/B/P/1776681636314_300.jpg">
                                    <div><h4 class="text-xs font-semibold text-white">CORTIS</h4><p class="text-[10px] text-gray-400">14K Followers</p></div>
                                </div>
                                <i class="far fa-heart text-gray-400 text-xs"></i>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img class="w-8 h-8 rounded-full" src="https://image-cdn.nct.vn/singer/avatar/2025/04/17/P/Y/W/X/1744864477416_300.jpg">
                                    <div><h4 class="text-xs font-semibold text-white">OgeNus</h4><p class="text-[10px] text-gray-400">8K Followers</p></div>
                                </div>
                                <i class="far fa-heart text-gray-400 text-xs"></i>
                            </div>
                        </div>
                    </div>

                    <!-- CRYPTO LOG -->
                    <div class="card-bg rounded-xl p-4 flex flex-col" style="height:340px;" id="log-section">
                        <h3 class="text-sm font-bold text-cyan-400 mb-2 flex items-center justify-between">
                            <span><i class="fas fa-terminal mr-1"></i> CRYPTO LOGS</span>
                            <button onclick="clearLog()" class="text-xs text-gray-600 hover:text-gray-400 transition">Xóa</button>
                        </h3>
                        <div id="log-container" class="flex-1 bg-slate-950/80 rounded-lg p-3 font-mono text-[11px] overflow-y-auto space-y-1 text-gray-300">
                            <span class="text-gray-600">// Receiver sẵn sàng lắng nghe...</span>
                        </div>
                    </div>

                    <!-- THỐNG KÊ -->
                    <div class="card-bg rounded-xl p-4">
                        <h3 class="text-sm font-bold text-white mb-3"><i class="fas fa-chart-bar text-cyan-400 mr-1"></i> Thống Kê</h3>
                        <div class="grid grid-cols-2 gap-3">
                            <div class="bg-cyan-950/30 rounded-xl p-3 border border-cyan-900/30">
                                <div class="text-xs text-gray-400 mb-1">File nhận</div>
                                <div class="text-xl font-bold font-mono text-cyan-400" id="stat-files">0</div>
                            </div>
                            <div class="bg-emerald-950/30 rounded-xl p-3 border border-emerald-900/30">
                                <div class="text-xs text-gray-400 mb-1">Trạng thái</div>
                                <div class="text-sm font-bold text-emerald-400" id="stat-status">Chờ</div>
                            </div>
                        </div>
                    </div>

                </div>
            </main>

            <!-- FOOTER -->
            <footer class="nct-footer w-full pt-8 pb-5 px-12 mt-auto flex-shrink-0">
                <div class="border-t border-[#2d2e2e] pt-4 flex justify-between items-center text-[11px] text-[#747575]">
                    <div class="flex space-x-4">
                        <a href="#" class="hover:text-white">Chính Sách Bảo Mật</a><span>•</span>
                        <a href="#" class="hover:text-white">Chính Sách SHTT</a><span>•</span>
                        <a href="#" class="hover:text-white">Thỏa Thuận Sử Dụng</a>
                    </div>
                    <div>© 2024 SecureMusic Receiver · Triple DES + RSA 1024 + SHA-512</div>
                </div>
            </footer>
        </div>
    </div>

    <!-- PLAYER BAR DƯỚI (giống sender) -->
    <audio id="recv-audio" class="hidden" preload="none"></audio>
    <div class="fixed bottom-0 left-0 right-0 h-20 glass-player px-6 flex items-center justify-between z-50">
        <div class="flex items-center space-x-3 w-1/4">
            <div onclick="toggleRecvPlay()" class="w-12 h-12 rounded-lg bg-gradient-to-br from-cyan-600 to-blue-900 flex items-center justify-center shadow-lg border border-cyan-500/30 cursor-pointer hover:opacity-80 transition">
                <i id="player-icon-recv" class="fas fa-satellite-dish text-white text-xl"></i>
            </div>
            <div><h4 id="recv-player-title" class="text-sm font-bold text-white truncate">Secure Receiver</h4>
            <p id="recv-player-sub" class="text-xs text-gray-400 truncate">Chờ kết nối từ Sender...</p></div>
        </div>
        <div class="flex flex-col items-center space-y-1 w-2/4">
            <div class="flex items-center space-x-5 text-gray-400 text-sm">
                <i class="fas fa-shield-alt text-cyan-500"></i>
                <span class="text-xs font-mono text-cyan-400" id="recv-status-bar">⏳ Đang chờ Handshake...</span>
                <i class="fas fa-lock text-cyan-500"></i>
            </div>
            <div class="w-full flex items-center space-x-2 text-[10px] text-gray-400">
                <span id="recv-time-current" class="text-cyan-500 font-mono">0:00</span>
                <div id="recv-progress-container" class="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden cursor-pointer">
                    <div id="recv-progress" class="bg-gradient-to-r from-cyan-500 to-blue-500 h-full rounded-full transition-all duration-150" style="width:0%"></div>
                </div>
                <span id="recv-time-total" class="text-cyan-500 font-mono">0:00</span>
            </div>
        </div>
        <div class="flex items-center justify-end space-x-3 w-1/4 text-xs text-gray-400">
            <span class="border border-cyan-900/50 text-cyan-500 px-2 py-1 rounded font-mono">Triple DES</span>
            <span class="border border-emerald-900/50 text-emerald-500 px-2 py-1 rounded font-mono">SHA-512</span>
            <span class="animate-pulse border border-cyan-500/50 text-cyan-400 px-2 py-1 rounded font-mono text-[9px]">LIVE</span>
        </div>
    </div>


    <script>
        let logData = [], fileData = [], currentStep = 1;

        // ── TOAST ──
        function showToast(type, title, msg, duration=4000) {
            const icons = {success:'✅', error:'❌', info:'ℹ️'};
            const tc = document.getElementById('toast-container');
            const t = document.createElement('div');
            t.className = `toast toast-${type}`;
            t.innerHTML = `<span class="toast-icon">${icons[type]||'💬'}</span>
                <div class="toast-body"><div class="toast-title">${title}</div><div class="toast-msg">${msg}</div></div>
                <span class="toast-close" onclick="this.parentElement.remove()">✕</span>`;
            tc.appendChild(t);
            setTimeout(()=>{ t.classList.add('toast-out'); setTimeout(()=>t.remove(),300); }, duration);
        }

        // ── STEPS ──
        function setStep(step) {
            currentStep = step;
            for(let i=1; i<=3; i++) {
                const dot = document.getElementById('sd'+i);
                const lbl = document.getElementById('sl'+i);
                const lin = document.getElementById('sl-line'+i);
                dot.className = 'step-dot ' + (i<step?'done':i===step?'active':'pending');
                lbl.className = 'step-label ' + (i<step?'done':i===step?'active':'');
                dot.textContent = i < step ? '✓' : i;
                if(lin) lin.className = 'step-line' + (i<step?' done':'');
            }
            const statuses = {1:'⏳ Handshake...', 2:'🔐 Trao khóa...', 3:'✅ Sẵn sàng nhận'};
            document.getElementById('recv-status-bar').textContent = statuses[step] || '✅ Online';
        }

        // ── RENDER FILES ──
        function renderFiles(files) {
            const container = document.getElementById('files-container');
            const badge = document.getElementById('file-count-badge');
            const empty = document.getElementById('empty-msg');
            badge.textContent = files.length + ' files';
            document.getElementById('stat-files').textContent = files.length;
            document.getElementById('sb-count').textContent = files.length;
            if(files.length === 0) { if(empty) empty.style.display=''; return; }
            if(empty) empty.style.display='none';

            const existing = container.querySelectorAll('.file-received-card').length;
            for(let i=existing; i<files.length; i++) {
                const f = files[i];
                const timingHtml = Object.entries(f.timing||{}).map(([k,v])=>
                    `<span class="timing-chip">${k}: ${v}ms</span>`).join('');
                const div = document.createElement('div');
                div.className = 'file-received-card';
                div.innerHTML = `
                    <div class="flex items-start justify-between mb-2">
                        <div class="file-name-badge">🎵 ${f.filename}</div>
                        <div class="flex items-center gap-1.5 flex-shrink-0">
                            <button onclick="playFile('${f.filename}')" class="text-[10px] bg-emerald-900/40 text-emerald-400 border border-emerald-800 px-2.5 py-1 rounded-lg hover:bg-emerald-800/40 transition"><i class="fas fa-play mr-1"></i>Nghe</button>
                            <a href="/download/${f.filename}" class="text-[10px] bg-cyan-900/40 text-cyan-400 border border-cyan-800 px-2.5 py-1 rounded-lg hover:bg-cyan-800/40 transition" download>⬇ Tải</a>
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-1 mb-2">
                        <span class="crypto-tag tag-3des">Triple DES ✓</span>
                        <span class="crypto-tag tag-rsa">Chữ ký ✓</span>
                        <span class="crypto-tag tag-sha">SHA-512 ✓</span>
                    </div>
                    <div class="text-xs text-gray-400 space-y-0.5">
                        <div>📦 ${f.size_kb} KB · 🎤 ${f.artist||'N/A'} · © ${f.copyright||'N/A'}</div>
                        <div class="text-[10px] text-gray-600 font-mono">SHA-256: ${(f.hash_sha256||'').slice(0,40)}...</div>
                        <div class="text-[10px] text-gray-600">🕐 ${f.timestamp}</div>
                    </div>
                    <div class="timing-mini">${timingHtml}</div>`;
                container.appendChild(div);

                // Toast thông báo file mới
                showToast('success', '✅ Nhận file thành công!', `${f.filename} · ${f.size_kb}KB · SHA-512 ✓ · RSA ✓`, 6000);
                document.getElementById('recv-player-sub').textContent = 'Đã giải mã · ' + f.size_kb + ' KB · Bấm "Nghe" để phát';
                document.getElementById('hero-wave').classList.remove('idle');
            }
        }

        // ── MAIN POLL ──
        async function updateStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();

                // Steps
                if(data.key_exchange) setStep(3);
                else if(data.handshake) setStep(2);
                else setStep(1);

                // Sidebar
                document.getElementById('sb-hs').textContent = data.handshake ? '✅' : '⏳';
                document.getElementById('sb-hs').style.color = data.handshake ? '#34d399' : '#6b7280';
                document.getElementById('sb-sk').textContent = data.session_key_ready ? '✅' : '⏳';
                document.getElementById('sb-sk').style.color = data.session_key_ready ? '#34d399' : '#6b7280';
                document.getElementById('stat-status').textContent = data.key_exchange ? '🟢 Active' : data.handshake ? '🟡 Auth' : '⚪ Chờ';

                // Public key display
                if(data.public_key && document.getElementById('key-pub-display').textContent.includes('Chưa')) {
                    const pk = data.public_key;
                    document.getElementById('key-pub-display').textContent = pk.slice(0,120) + '...';
                }
                if(data.session_key_ready) {
                    document.getElementById('key-sk-display').textContent = '✅ Session Key đã nhận · 24 bytes · Triple DES ready';
                    document.getElementById('key-sk-display').style.color = '#34d399';
                }

                // Log
                if(data.log && data.log.length > logData.length) {
                    const newLogs = data.log.slice(logData.length);
                    const container = document.getElementById('log-container');
                    newLogs.forEach(item => {
                        const color = item.level==='success'?'text-emerald-400':item.level==='error'?'text-red-400':'text-cyan-400';
                        container.innerHTML += `<div class="${color}">[${item.time}] ${item.msg}</div>`;
                    });
                    container.scrollTop = container.scrollHeight;
                    logData = data.log;
                }

                // Files
                if(data.received_files) renderFiles(data.received_files);

            } catch(e) {}
        }

        function clearLog() {
            document.getElementById('log-container').innerHTML = '<span class="text-gray-600">// Log cleared...</span>';
            logData = [];
        }
        function scrollToFiles() { document.getElementById('files-section').scrollIntoView({behavior:'smooth'}); }
        function scrollToLog()   { document.getElementById('log-section').scrollIntoView({behavior:'smooth'}); }
        function scrollToKeys()  { document.getElementById('keys-section').scrollIntoView({behavior:'smooth'}); }

        async function resetAll() {
            if(!confirm('Reset toàn bộ Receiver?')) return;
            await fetch('/api/reset', {method:'POST'});
            logData = []; fileData = [];
            clearLog();
            document.getElementById('files-container').innerHTML = '<div class="text-center py-10 text-gray-600" id="empty-msg"><i class="fas fa-satellite-dish text-3xl mb-3 block text-gray-700"></i><p class="text-sm">Chưa nhận file nào</p></div>';
            document.getElementById('key-pub-display').textContent = 'Chưa tạo khóa...';
            document.getElementById('key-sk-display').textContent = 'Chưa nhận Session Key...';
            document.getElementById('key-sk-display').style.color = '';
            setStep(1);
            showToast('info', '🔄 Reset thành công', 'Receiver đã về trạng thái ban đầu');
        }

        // ── AUDIO PLAYER THẬT (NGHE TRỰC TIẾP FILE ĐÃ GIẢI MÃ) ──
        const recvAudio = document.getElementById('recv-audio');
        let currentPlayingFile = null;

        function formatTime(sec) {
            if (!isFinite(sec) || sec < 0) sec = 0;
            const m = Math.floor(sec / 60);
            const s = Math.floor(sec % 60).toString().padStart(2, '0');
            return `${m}:${s}`;
        }

        function playFile(filename) {
            const titleEl = document.getElementById('recv-player-title');
            const subEl = document.getElementById('recv-player-sub');
            const iconEl = document.getElementById('player-icon-recv');

            if (currentPlayingFile === filename && !recvAudio.paused) {
                recvAudio.pause();
                return;
            }

            if (currentPlayingFile !== filename) {
                recvAudio.src = '/stream/' + filename;
                currentPlayingFile = filename;
            }
            recvAudio.play().catch(err => {
                showToast('error', '❌ Không thể phát file', err.message);
            });
            titleEl.textContent = '🎵 ' + filename;
            subEl.textContent = 'Đang phát · giải mã thành công · Triple DES ✓';
            iconEl.className = 'fas fa-compact-disc text-cyan-400 animate-spin';
        }

        function toggleRecvPlay() {
            if (!currentPlayingFile) {
                showToast('info', 'ℹ️ Chưa có bài hát', 'Hãy bấm "Nghe" trên một file đã nhận trước.');
                return;
            }
            if (recvAudio.paused) {
                recvAudio.play();
            } else {
                recvAudio.pause();
            }
        }

        recvAudio.addEventListener('play', () => {
            document.getElementById('player-icon-recv').className = 'fas fa-compact-disc text-cyan-400 animate-spin';
        });
        recvAudio.addEventListener('pause', () => {
            document.getElementById('player-icon-recv').className = 'fas fa-satellite-dish text-white';
        });
        recvAudio.addEventListener('ended', () => {
            document.getElementById('player-icon-recv').className = 'fas fa-satellite-dish text-white';
            document.getElementById('recv-player-sub').textContent = 'Đã phát xong · Bấm "Nghe" để nghe lại';
            document.getElementById('recv-progress').style.width = '0%';
            document.getElementById('recv-time-current').textContent = '0:00';
        });
        recvAudio.addEventListener('loadedmetadata', () => {
            document.getElementById('recv-time-total').textContent = formatTime(recvAudio.duration);
        });
        recvAudio.addEventListener('timeupdate', () => {
            if (!recvAudio.duration) return;
            const pct = (recvAudio.currentTime / recvAudio.duration) * 100;
            document.getElementById('recv-progress').style.width = pct + '%';
            document.getElementById('recv-time-current').textContent = formatTime(recvAudio.currentTime);
        });
        recvAudio.addEventListener('error', () => {
            showToast('error', '❌ Lỗi phát nhạc', 'Không tải được file âm thanh.');
        });

        document.getElementById('recv-progress-container').addEventListener('click', (e) => {
            if (!recvAudio.duration) return;
            const rect = e.currentTarget.getBoundingClientRect();
            const ratio = (e.clientX - rect.left) / rect.width;
            recvAudio.currentTime = ratio * recvAudio.duration;
        });

        setInterval(updateStatus, 2000);
        updateStatus();
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(CYBERPUNK_RECEIVER_UI)


# ─────────────────────────────────────────
# Khởi chạy ứng dụng Receiver Web App
# ─────────────────────────────────────────

if __name__ == '__main__':
    # Ghi nhận log hệ thống khi bắt đầu chạy
    add_log("🚀 Receiver Server khởi động tại http://0.0.0.0:5000", "info")
    
    # Chạy Receiver ở cổng 5000 (Để debug=False hoặc True tùy bạn nhé)
    app.run(host='0.0.0.0', port=5000, debug=False)