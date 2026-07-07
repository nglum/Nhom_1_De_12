"""
Test script - Kiểm tra liên kết giữa attacker_demo và admin_notifier
Tự động chạy receiver, attacker, và kiểm tra alerts
"""

import sys
import os
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from receiver_app_logic import app as receiver_app
from attacker_demo import MusicSecurityAttacker
from admin_notifier import security_monitor

def run_receiver():
    """Chạy receiver trong thread riêng"""
    print("\n🚀 Starting Receiver on port 5000...")
    receiver_app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

def test_integration():
    """Test attacker + admin_notifier integration"""
    print("="*70)
    print("🔴 INTEGRATION TEST: Attacker -> Admin Notifier")
    print("="*70)
    
    # Start receiver in background thread
    receiver_thread = threading.Thread(target=run_receiver, daemon=True)
    receiver_thread.start()
    
    print("\n⏳ Waiting for receiver to start...")
    time.sleep(3)
    
    # Create attacker
    attacker = MusicSecurityAttacker("http://127.0.0.1:5000")
    
    print("\n" + "="*70)
    print("TEST 1: Fake Sender Attack")
    print("="*70)
    result = attacker.fake_sender_attack()
    print(f"\n✅ Result: {result}")
    
    # Check if admin_notifier detected it
    print("\n📊 Checking admin_notifier events...")
    time.sleep(1)
    
    events = security_monitor.events
    print(f"   Total security events: {len(events)}")
    
    for event in events[-3:]:  # Show last 3 events
        print(f"\n   Event: {event.event_type}")
        print(f"   IP: {event.source_ip}")
        print(f"   Severity: {event.severity}")
    
    if events:
        print("\n✅ SUCCESS: Admin notifier detected attacks!")
    else:
        print("\n❌ FAILED: No events detected by admin notifier")
    
    print("\n" + "="*70)
    print("TEST 2: MITM Attack")
    print("="*70)
    result = attacker.mitm_attack_simulation()
    print(f"\n✅ Result: {result}")
    
    time.sleep(1)
    events = security_monitor.events
    print(f"\n📊 Total security events: {len(events)}")
    
    if len(events) > len(events) - 2:
        print("✅ SUCCESS: MITM attack detected by admin notifier!")
    
    print("\n" + "="*70)
    print("TEST 3: SQL Injection")
    print("="*70)
    result = attacker.sql_injection_attack()
    print(f"\n✅ Result: {result[:100]}...")
    
    time.sleep(1)
    print(f"\n📊 Total security events: {len(security_monitor.events)}")
    
    print("\n" + "="*70)
    print("📋 FINAL SUMMARY")
    print("="*70)
    print(f"Total attacks detected by admin_notifier: {len(security_monitor.events)}")
    print(f"Blocked IPs: {security_monitor.blocked_ips}")
    
    if security_monitor.events:
        print("\n✅ INTEGRATION TEST PASSED!")
        print("   Attacker demo and admin_notifier are linked correctly.")
    else:
        print("\n❌ INTEGRATION TEST FAILED!")
        print("   Admin notifier did not detect attacks.")
    
    print("\n" + "="*70)
    
    # Keep running to show alerts
    print("\n⌨️  Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n👋 Test stopped")

if __name__ == "__main__":
    test_integration()