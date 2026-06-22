#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import time
import requests

app = Flask(__name__)
CORS(app)

DISCORD_WEBHOOK_URL = "discord webhook url"

# Track blocked IPs and latest attacker
blocked_ips = {}
latest_attacker = None

def send_discord(message, color=0xFF0000):
    payload = {
        "embeds": [{
            "title": "🛡️ IP Block Action",
            "description": message,
            "color": color,
            "footer": {
                "text": f"Zeek IDS • {time.strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"[ERROR] Discord: {e}")

def block_ip(ip):
    try:
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            return False, f"{ip} is already blocked"
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        blocked_ips[ip] = time.strftime('%Y-%m-%d %H:%M:%S')
        return True, f"{ip} blocked successfully"
    except Exception as e:
        return False, str(e)

def unblock_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        if ip in blocked_ips:
            del blocked_ips[ip]
        return True, f"{ip} unblocked successfully"
    except Exception as e:
        return False, str(e)

@app.route('/block', methods=['POST'])
def handle_block():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"status": "error", "message": "No IP provided"}), 400
    success, message = block_ip(ip)
    if success:
        send_discord(
            f"🚫 **IP Blocked**\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"**IP:** `{ip}`\n"
            f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"**Action:** Blocked via iptables",
            color=0xFF0000
        )
        print(f"[BLOCKED] {ip}")
        return jsonify({"status": "success", "message": message}), 200
    else:
        return jsonify({"status": "error", "message": message}), 400

@app.route('/unblock', methods=['POST'])
def handle_unblock():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"status": "error", "message": "No IP provided"}), 400
    success, message = unblock_ip(ip)
    if success:
        send_discord(
            f"✅ **IP Unblocked**\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"**IP:** `{ip}`\n"
            f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"**Action:** Removed from iptables",
            color=0x00FF00
        )
        print(f"[UNBLOCKED] {ip}")
        return jsonify({"status": "success", "message": message}), 200
    else:
        return jsonify({"status": "error", "message": message}), 400

@app.route('/blocked', methods=['GET'])
def list_blocked():
    return jsonify({"status": "success", "blocked_ips": blocked_ips}), 200

@app.route('/latest_attacker', methods=['GET'])
def get_latest_attacker():
    return jsonify({"status": "success", "ip": latest_attacker}), 200

@app.route('/report_attacker', methods=['POST'])
def report_attacker():
    global latest_attacker
    data = request.json
    ip = data.get('ip')
    if ip and ip not in ('127.0.0.1', '192.168.122.1', '-'):
        latest_attacker = ip
        print(f"[ATTACKER] Latest attacker updated: {ip}")
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "ignored"}), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    print("=" * 50)
    print(" Zeek Block Agent running on port 5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False)
