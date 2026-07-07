"""
Admin Notification System - An toàn bảo mật
Hệ thống thông báo cho admin khi phát hiện spam/tấn công
Mô phỏng email và SMS notification
"""

import smtplib
import json
import time
import random
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from typing import List, Dict, Optional, Any
from flask import request, jsonify


class SecurityEvent:
    """Đại diện cho sự kiện bảo mật cần thông báo"""
    def __init__(self, event_type: str, source_ip: str, details: str, severity: str = "medium"):
        self.event_type = event_type
        self.source_ip = source_ip
        self.details = details
        self.severity = severity
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.id = f"SEC-{int(time.time())}-{random.randint(1000, 9999)}"


class EmailNotifier:
    """Gửi thông báo qua email cho admin"""
    
    def __init__(self, smtp_server: str = "smtp.example.com", 
                 smtp_port: int = 587,
                 sender_email: str = "admin@security.local",
                 sender_password: str = "password"):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.admin_emails = ["admin@company.com"]
        
    def send_alert(self, event: SecurityEvent, vuln_info: Optional[dict] = None) -> bool:
        """Gửi email cảnh báo bảo mật với thông tin chi tiết"""
        try:
            subject = f"[{event.severity.upper()}] Cảnh báo bảo mật: {event.event_type}"
            
            vuln_section = ""
            if vuln_info:
                vuln_section = f"""
THÔNG TIN LỖ HỔNG:
- Loại: {vuln_info['name']}
- Mô tả: {vuln_info['description']}
- Nguyên nhân: {vuln_info['root_cause']}
- Tác động: {vuln_info['impact']}

CÁCH KHẮC PHỤC:
"""
                for i, step in enumerate(vuln_info['remediation'], 1):
                    vuln_section += f"{i}. {step}\n"
            
            body = f"""
⚠️ CẢNH BÁO BẢO MẬT ⚠️

Mã sự kiện: {event.id}
Thời gian: {event.timestamp}
Mức độ: {event.severity.upper()}

Loại tấn công: {event.event_type}
IP nguồn: {event.source_ip}
Chi tiết: {event.details}
{vuln_section}
Hành động cần thực hiện:
1. Kiểm tra logs hệ thống ngay
2. Phân tích traffic từ IP {event.source_ip}
3. Cân nhắc chặn IP khỏi mạng

---
Admin Security System - Auto-generated Alert
"""
            
            print(f"\n[EMAIL] 📧 Đã gửi cảnh báo tới {self.admin_emails}")
            print(f"  Subject: {subject}")
            if vuln_info:
                print(f"  Vulnerability: {vuln_info['name']}")
            
            return True
            
        except Exception as e:
            print(f"[EMAIL ERROR] Không thể gửi email: {e}")
            return False


class SMSNotifier:
    """Gửi thông báo qua SMS cho admin"""
    
    def __init__(self, api_key: str = "demo_api_key", 
                 api_url: str = "https://api.sms.local"):
        self.api_key = api_key
        self.api_url = api_url
        self.admin_phones = ["+84912345678"]
        
    def send_alert(self, event: SecurityEvent, vuln_info: Optional[dict] = None) -> bool:
        """Gửi SMS cảnh báo bảo mật với thông tin lỗ hổng"""
        try:
            vuln_name = vuln_info['name'] if vuln_info else event.event_type
            message = f"🚨 [{event.severity.upper()}] {vuln_name} từ {event.source_ip}. "
            
            if vuln_info:
                message += f"Root cause: {vuln_info['root_cause'][:30]}... "
            
            message += "Action: Block IP and investigate."
            
            print(f"\n[SMS] 📱 Đã gửi SMS tới {self.admin_phones}")
            print(f"  Message: {message}")
            
            return True
            
        except Exception as e:
            print(f"[SMS ERROR] Không thể gửi SMS: {e}")
            return False


class SecurityMonitor:
    """Monitor trung tâm - theo dõi và phát hiện tấn công"""
    
    def __init__(self):
        self.events: List[SecurityEvent] = []
        self.suspicious_ips = {}
        self.email_notifier = EmailNotifier()
        self.sms_notifier = SMSNotifier()
        self.blocked_ips = set()
        self.request_counts = {}
        self.session_key_history = {}
        
    def detect_spam(self, ip_address: str, user_agent: str = "") -> Optional[SecurityEvent]:
        """Phát hiện spam requests"""
        current_time = time.time()
        
        if ip_address not in self.request_counts:
            self.request_counts[ip_address] = []
        
        self.request_counts[ip_address].append(current_time)
        
        self.request_counts[ip_address] = [
            t for t in self.request_counts[ip_address] 
            if current_time - t < 60
        ]
        
        if len(self.request_counts[ip_address]) > 100:
            event = SecurityEvent(
                event_type="spam",
                source_ip=ip_address,
                details=f"Spam requests: {len(self.request_counts[ip_address])} requests in 60s",
                severity="high"
            )
            self.events.append(event)
            return event
            
        return None
    
    def detect_brute_force(self, ip_address: str, failed_attempts: int) -> Optional[SecurityEvent]:
        """Phát hiện brute force attack"""
        if failed_attempts >= 5:
            event = SecurityEvent(
                event_type="brute_force",
                source_ip=ip_address,
                details=f"Failed login attempts: {failed_attempts}",
                severity="critical"
            )
            self.events.append(event)
            return event
        return None
    
    def detect_sql_injection(self, ip_address: str, query: str) -> Optional[SecurityEvent]:
        """Phát hiện SQL injection attempt"""
        sql_keywords = ["DROP TABLE", "DELETE FROM", "INSERT INTO", "UNION SELECT", 
                       "OR 1=1", "OR '1'='1'", "--", "; --"]
        
        query_upper = query.upper()
        for keyword in sql_keywords:
            if keyword in query_upper:
                event = SecurityEvent(
                    event_type="sql_injection",
                    source_ip=ip_address,
                    details=f"Suspicious SQL pattern detected: {query[:100]}",
                    severity="critical"
                )
                self.events.append(event)
                return event
        return None
    
    def detect_dos(self, ip_address: str, request_size: int) -> Optional[SecurityEvent]:
        """Phát hiện Denial of Service"""
        if request_size > 10 * 1024 * 1024:
            event = SecurityEvent(
                event_type="ddos",
                source_ip=ip_address,
                details=f"Oversized request: {request_size/1024/1024:.2f}MB",
                severity="high"
            )
            self.events.append(event)
            return event
        return None
    
    def detect_mitm(self, ip_address: str, session_key: bytes) -> Optional[SecurityEvent]:
        """Phát hiện MITM attack - thay thế session key"""
        key_hash = hash(session_key)
        
        if ip_address in self.session_key_history:
            if self.session_key_history[ip_address] != key_hash:
                event = SecurityEvent(
                    event_type="mitm_attack",
                    source_ip=ip_address,
                    details=f"Session key changed unexpectedly. Possible MITM attack.",
                    severity="critical"
                )
                self.events.append(event)
                return event
        
        self.session_key_history[ip_address] = key_hash
        return None
    
    def detect_fake_sender(self, ip_address: str, sender_pub_key: str, authorized_keys: Optional[List[str]] = None) -> Optional[SecurityEvent]:
        """Phát hiện Fake Sender - public key không hợp lệ"""
        if authorized_keys is None:
            authorized_keys = []
        
        if authorized_keys and sender_pub_key not in authorized_keys:
            event = SecurityEvent(
                event_type="fake_sender",
                source_ip=ip_address,
                details=f"Unauthorized sender public key detected. Key length: {len(sender_pub_key)} chars",
                severity="critical"
            )
            self.events.append(event)
            return event
        
        if len(sender_pub_key) < 100:
            event = SecurityEvent(
                event_type="fake_sender",
                source_ip=ip_address,
                details=f"Suspiciously short public key: {len(sender_pub_key)} chars. Likely fake sender.",
                severity="critical"
            )
            self.events.append(event)
            return event
        
        return None
    
    def detect_path_traversal(self, ip_address: str, requested_path: str) -> Optional[SecurityEvent]:
        """Phát hiện Path Traversal attack"""
        traversal_patterns = ["../", "..\\", ".../", "etc/passwd", "windows", "system32", "config"]
        path_lower = requested_path.lower()
        
        for pattern in traversal_patterns:
            if pattern in path_lower:
                event = SecurityEvent(
                    event_type="path_traversal",
                    source_ip=ip_address,
                    details=f"Path traversal attempt detected: {requested_path[:100]}",
                    severity="high"
                )
                self.events.append(event)
                return event
        return None
    
    def _get_vulnerability_info(self, event: SecurityEvent) -> Dict[str, Any]:
        """Trả về thông tin chi tiết về lỗ hổng"""
        vuln_db: Dict[str, Dict[str, Any]] = {
            "spam": {
                "name": "Spam/DoS Attack",
                "description": "Gửi hàng loạt requests làm quá tải server, gây từ chối dịch vụ",
                "root_cause": "Thiếu rate limiting chi tiết và IP reputation system.",
                "impact": "Server chậm/không phản hồi, người dùng hợp lệ bị từ chối.",
                "remediation": [
                    "Tăng rate limit lên 200 req/60s per IP",
                    "Implement sliding window rate limiting",
                    "Sử dụng Cloudflare/WAF",
                    "Thêm CAPTCHA sau 10 requests"
                ]
            },
            "ddos": {
                "name": "Oversized Request Attack",
                "description": "Gửi file cực lớn để làm đầy ổ đĩa",
                "root_cause": "Thiếu disk quota và file validation.",
                "impact": "Ổ đĩa đầy, server crash.",
                "remediation": [
                    "Giảm MAX_CONTENT_LENGTH",
                    "Thêm disk quota",
                    "File type validation",
                    "Monitor disk usage"
                ]
            },
            "sql_injection": {
                "name": "SQL Injection",
                "description": "Chèn SQL code vào parameters",
                "root_cause": "Sử dụng raw SQL queries thay vì parameterized queries.",
                "impact": "Đọc/xóa dữ liệu database.",
                "remediation": [
                    "Dùng parameterized queries",
                    "Implement ORM",
                    "Input validation",
                    "Database permission最小化"
                ]
            },
            "mitm_attack": {
                "name": "Man-in-the-Middle Attack",
                "description": "Thay thế session key để giải mã file",
                "root_cause": "Thiếu certificate pinning, dùng HTTP.",
                "impact": "Hacker giải mã được file.",
                "remediation": [
                    "Implement TLS/SSL",
                    "Certificate pinning",
                    "Monitor session key"
                ]
            },
            "fake_sender": {
                "name": "Fake Sender Attack",
                "description": "Giả mạo Sender gửi file độc hại",
                "root_cause": "Thiếu whitelist public keys.",
                "impact": "Nhận file chứa malware.",
                "remediation": [
                    "Tạo whitelist authorized senders",
                    "Verify public key",
                    "Antivirus scanning",
                    "Check file magic bytes"
                ]
            },
            "path_traversal": {
                "name": "Path Traversal Attack",
                "description": "Đọc file nhạy cảm qua directory traversal",
                "root_cause": "Thiếu validate filename.",
                "impact": "Data leak.",
                "remediation": [
                    "Dùng secure_filename()",
                    "Whitelist characters",
                    "Chroot container"
                ]
            }
        }
        
        if event.event_type in vuln_db:
            return vuln_db[event.event_type]
        
        return {
            "name": event.event_type,
            "description": event.details,
            "root_cause": "Unknown - cần điều tra thêm",
            "impact": "Potential security breach",
            "remediation": [
                "Kiểm tra logs hệ thống",
                "Phân tích traffic",
                "Chặn IP tạm thời"
            ]
        }
    
    def notify_admin(self, event: SecurityEvent):
        """Gửi thông báo cho admin với chi tiết lỗ hổng"""
        vuln_info = self._get_vulnerability_info(event)
        
        print(f"\n{'='*70}")
        print(f"🚨 PHÁT HIỆN TẤN CÔNG: {event.event_type.upper()}")
        print(f"   IP: {event.source_ip}")
        print(f"   Mức độ: {event.severity}")
        print(f"   Mã sự kiện: {event.id}")
        print(f"   Thời gian: {event.timestamp}")
        
        print(f"\n📊 THÔNG TIN LỖ HỔNG:")
        print(f"   Loại: {vuln_info['name']}")
        print(f"   Mô tả: {vuln_info['description']}")
        print(f"   Nguyên nhân: {vuln_info['root_cause']}")
        print(f"   Tác động: {vuln_info['impact']}")
        print(f"\n🛠️ CÁCH KHẮC PHỤC:")
        for i, step in enumerate(vuln_info['remediation'], 1):
            print(f"   {i}. {step}")
        
        self.email_notifier.send_alert(event, vuln_info)
        
        if event.severity == "critical":
            self.sms_notifier.send_alert(event, vuln_info)
        
        print(f"{'='*70}")
    
    def block_ip(self, ip_address: str):
        """Chặn IP đáng ngờ"""
        self.blocked_ips.add(ip_address)
        print(f"🔒 Đã chặn IP: {ip_address}")
    
    def is_blocked(self, ip_address: str) -> bool:
        """Kiểm tra IP có bị chặn không"""
        return ip_address in self.blocked_ips


# Global instance - used by admin routes
security_monitor = SecurityMonitor()


def init_security_monitor(app, ip_header: str = "X-Forwarded-For") -> SecurityMonitor:
    """
    Khởi tạo security monitor cho Flask app
    Tự động theo dõi tất cả requests
    """
    global security_monitor
    security_monitor = SecurityMonitor()
    
    @app.before_request
    def check_security():
        """Kiểm tra bảo mật trước mỗi request"""
        ip_address: str = request.remote_addr or ""
        if ip_header in request.headers:
            ip_address = request.headers[ip_header].split(",")[0].strip() or ip_address
        
        if not ip_address:
            return None
        
        if security_monitor.is_blocked(ip_address):
            return jsonify({"error": "Access denied"}), 403
        
        user_agent = request.headers.get("User-Agent", "") or ""
        spam_event = security_monitor.detect_spam(ip_address, user_agent)
        if spam_event:
            security_monitor.notify_admin(spam_event)
            security_monitor.block_ip(ip_address)
            return jsonify({"error": "Too many requests"}), 429
        
        # Detect SQL injection in query parameters
        if request.args:
            query_string = str(request.query_string)
            sql_event = security_monitor.detect_sql_injection(ip_address, query_string)
            if sql_event:
                security_monitor.notify_admin(sql_event)
                security_monitor.block_ip(ip_address)
                return jsonify({"error": "Malicious request detected"}), 400
        
        # Detect DoS (oversized request)
        if request.content_length and request.content_length > 10 * 1024 * 1024:
            dos_event = security_monitor.detect_dos(ip_address, request.content_length)
            if dos_event:
                security_monitor.notify_admin(dos_event)
                return jsonify({"error": "Request too large"}), 413
    
    return security_monitor


if __name__ == "__main__":
    # Demo
    monitor = SecurityMonitor()
    
    test_ip = "192.168.1.100"
    for i in range(105):
        event = monitor.detect_spam(test_ip)
    
    if event:
        monitor.notify_admin(event)
        monitor.block_ip(test_ip)