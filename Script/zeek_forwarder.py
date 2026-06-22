#!/usr/bin/env python3
import time
import requests
import threading

# ─── Configuration ────────────────────────────────────────────────
LOKI_URL = "http://192.168.122.1:3100/loki/api/v1/push"
DISCORD_WEBHOOK_URL = " discord webhook url "
GRAFANA_URL = "http://192.168.122.1:3000"
BLOCK_AGENT_URL = "http://localhost:5000"

LOG_FILES = {
    "notice": "/opt/zeek/spool/zeek/notice.log",
    "conn": "/opt/zeek/spool/zeek/conn.log",
    "smb_mapping": "/opt/zeek/spool/zeek/smb_mapping.log",
    "smb_files": "/opt/zeek/spool/zeek/smb_files.log",
    "smb_cmd": "/opt/zeek/spool/zeek/smb_cmd.log",
}

ALERT_LOG_TYPES = ["notice", "smb_mapping", "smb_files", "smb_cmd"]
DISCORD_COOLDOWN = 30
last_discord_time = {}

# ─── Loki ─────────────────────────────────────────────────────────
def push_to_loki(line, log_type):
    ts = str(int(time.time() * 1e9))
    payload = {
        "streams": [{
            "stream": {"job": "zeek", "log_type": log_type},
            "values": [[ts, line.strip()]]
        }]
    }
    try:
        resp = requests.post(LOKI_URL, json=payload, timeout=5)
        if resp.status_code not in (200, 204):
            print(f"[WARN] Loki returned {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Loki push failed: {e}")

# ─── Block Agent ──────────────────────────────────────────────────
def report_attacker_to_agent(ip):
    """Send latest attacker IP to block agent"""
    try:
        requests.post(
            f"{BLOCK_AGENT_URL}/report_attacker",
            json={"ip": ip},
            timeout=3
        )
        print(f"[AGENT] Reported attacker: {ip}")
    except Exception as e:
        print(f"[WARN] Could not report to block agent: {e}")

# ─── Discord ──────────────────────────────────────────────────────
def extract_ip(line, log_type):
    try:
        parts = line.strip().split('\t')
        if log_type == "notice" and len(parts) > 13:
            return parts[13]
        elif log_type in ("smb_mapping", "smb_files", "smb_cmd") and len(parts) > 2:
            return parts[2]
        return None
    except Exception:
        return None

def get_alert_title(log_type):
    titles = {
        "notice": "🚨 Port Scan Detected",
        "smb_mapping": "⚠️ SMB Share Enumeration Detected",
        "smb_files": "🔴 SMB Unauthorized File Access",
        "smb_cmd": "🔶 SMB Command Executed",
    }
    return titles.get(log_type, "⚠️ Zeek Alert")

def get_alert_color(log_type):
    colors = {
        "notice": 0xFF0000,
        "smb_mapping": 0xFF8C00,
        "smb_files": 0xFF0000,
        "smb_cmd": 0xFF4500,
    }
    return colors.get(log_type, 0xFF0000)

def send_discord_alert(line, log_type):
    src_ip = extract_ip(line, log_type)
    description = (
        f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"**Type:** {log_type.upper()}\n"
    )
    if src_ip and src_ip != '-':
        description += f"**Source IP:** `{src_ip}`\n"
    description += f"\n**Raw Log:**\n```{line.strip()[:300]}```"

    payload = {
        "embeds": [{
            "title": get_alert_title(log_type),
            "description": description,
            "color": get_alert_color(log_type),
            "footer": {
                "text": f"Zeek IDS • {time.strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }],
        "components": [{
            "type": 1,
            "components": [{
                "type": 2,
                "style": 5,
                "label": "📊 Open Grafana Dashboard",
                "url": GRAFANA_URL
            }]
        }]
    }

    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"[ERROR] Discord alert failed: {e}")

def watch(log_type, filepath):
    print(f"[*] Watching {log_type}: {filepath}")
    while not __import__('os').path.exists(filepath):
        time.sleep(2)
    with open(filepath, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            if line.startswith('#'):
                continue
            push_to_loki(line, log_type)
            if log_type in ALERT_LOG_TYPES:
                now = time.time()
                last = last_discord_time.get(log_type, 0)
                if now - last >= DISCORD_COOLDOWN:
                    last_discord_time[log_type] = now
                    send_discord_alert(line, log_type)
                    src_ip = extract_ip(line, log_type)
                    if src_ip and src_ip != '-':
                        report_attacker_to_agent(src_ip)

def main():
    startup_payload = {
        "embeds": [{
            "title": "🟢 Zeek IDS Started",
            "description": f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "color": 0x00FF00
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=startup_payload, timeout=5)
    except Exception as e:
        print(f"[ERROR] Startup Discord message failed: {e}")

    threads = []
    for log_type, filepath in LOG_FILES.items():
        t = threading.Thread(
            target=watch,
            args=(log_type, filepath),
            daemon=True
        )
        t.start()
        threads.append(t)

    print("[*] All watchers running. Press Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown_payload = {
            "embeds": [{
                "title": "🔴 Zeek IDS Stopped",
                "description": f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
                "color": 0xFF0000
            }]
        }
        try:
            requests.post(DISCORD_WEBHOOK_URL, json=shutdown_payload, timeout=5)
        except:
            pass
        print("\n[*] Stopped.")

if __name__ == "__main__":
    main()
