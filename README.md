# Network Intrusion Detection Using Zeek with Grafana Visualization and Discord Alerting

A real-time network intrusion detection system built on Zeek IDS, designed to detect port scans and SMB-based attacks. Zeek logs are forwarded to Grafana via Loki for live visualization, with Discord alerts on detection. Includes an active response panel in Grafana to block/unblock attacker IPs via iptables directly from the dashboard.

## Environment Setup

**Host Machine:** Arch Linux (Lenovo Legion Slim 5i)
**Virtualization:** QEMU/KVM via Virt-Manager
**Network:** libvirt default NAT Network (`192.168.122.0/24`)

| VM | OS | IP | Role |
|---|---|---|---|
| ubuntu-zeek | Ubuntu Server 22.04 | 192.168.122.108 | Victim + Zeek |
| kali-attacker | Kali Linux | 192.168.122.122 | Attacker |
| Arch host | Arch Linux | 192.168.122.1 | Loki + Grafana |

---

## Configuration
 
### Loki and Grafana Installation (Arch Host)
 
Loki acts as the log aggregation backend that receives Zeek logs from the forwarder script. Grafana connects to Loki as a datasource and renders the dashboard. Both are run as Docker containers on the Arch host using host networking so they can communicate with the Ubuntu VM directly. The `GF_PANELS_DISABLE_SANITIZE_HTML` flag is required to allow the IP Block Control panel to run JavaScript for the block/unblock buttons.
 
```bash
docker run -d --name loki --network host -v ~/zeek-project/loki-config.yaml:/etc/loki/local-config.yaml grafana/loki:latest -config.file=/etc/loki/local-config.yaml
 
docker run -d --name grafana --network host -e "GF_PANELS_DISABLE_SANITIZE_HTML=true" grafana/grafana:latest
```
 
### Zeek Installation (Ubuntu Server 22.04 VM)
 
Zeek is installed on the victim VM from the official OpenSUSE security repository, as it is not available in the default Ubuntu apt sources. This installs Zeek 8 along with `zeekctl`, the management utility used to deploy and control the Zeek process.
 
```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/zeek.list
 
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | sudo gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null
 
sudo apt update
sudo apt install zeek -y
```
 
### node.cfg (Ubuntu Server VM)
 
`node.cfg` tells Zeek how to run, in this case as a standalone node on the local machine. The `interface` value must match the actual network interface name of the VM that faces the NAT network. Run `ip a` to confirm the interface name before editing.
 
```bash
sudo nano /opt/zeek/etc/node.cfg
```
 
```ini
[zeek]
type=standalone
host=localhost
interface=enp1s0
```
 
### zeekctl.cfg (Ubuntu Server VM)
 
The `-C` flag disables IP checksum validation. This is necessary in virtualized environments where checksums are often offloaded to the hypervisor and arrive at Zeek already incorrect, which would otherwise cause Zeek to silently drop packets and miss traffic.
 
```bash
sudo nano /opt/zeek/etc/zeekctl.cfg
```
 
```
ZeekArgs = -C
```
 
### Custom Detection Script — detect-scan.zeek (Ubuntu Server VM)
 
This script adds custom port scan detection to Zeek. It tracks how many distinct destination ports each source IP connects to within a 60-second window. If a single source hits more than 20 different ports, Zeek raises a `Port_Scan` notice, which gets picked up by the forwarder and triggers a Discord alert.
 
```bash
sudo nano /opt/zeek/share/zeek/site/detect-scan.zeek
```
 
```zeek
# Custom port scan detection for Zeek 8
module PortScan;
 
export {
    redef enum Notice::Type += {
        Port_Scan
    };
}
 
global distinct_ports: table[addr] of set[port] &create_expire=60sec;
 
event new_connection(c: connection)
    {
    local src = c$id$orig_h;
    local dst_port = c$id$resp_p;
 
    if ( src !in distinct_ports )
        distinct_ports[src] = set();
 
    add distinct_ports[src][dst_port];
 
    if ( |distinct_ports[src]| > 20 )
        {
        NOTICE([$note=Port_Scan,
                $msg=fmt("Port scan detected from %s (%d ports)",
                                src, |distinct_ports[src]|),
                $src=src,
                $identifier=cat(src)]);
        }
    }
```
 
### local.zeek (Ubuntu Server VM)
 
`local.zeek` is Zeek's main site policy file, loaded on every deploy. Adding entries here enables the notice framework, SMB command logging, periodic stats, and loads the custom port scan detection script created above. Without these `@load` directives, Zeek will run but none of the detection or SMB logging will be active.
 
```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```
 
```
@load frameworks/notice
@load policy/misc/stats
@load policy/protocols/smb/log-cmds
@load site/detect-scan
```
 
### SMB Configuration (Ubuntu Server VM)
 
A Samba share is set up on the victim VM to simulate a real SMB attack surface. The shared directory is intentionally left open with guest access and a plaintext file named `secret.txt` to act as a target for the attacker to enumerate and exfiltrate during the demonstration.
 
```bash
sudo mkdir -p /srv/shared
sudo chmod 777 /srv/shared
echo "confidential data" | sudo tee /srv/shared/secret.txt
sudo nano /etc/samba/smb.conf
```
 
In `smb.conf` add:
 
```ini
[shared]
path = /srv/shared
browseable = yes
read only = no
guest ok = yes
public = yes
```
 
### Deploy Zeek (Ubuntu Server VM)
 
`zeekctl deploy` applies all configuration changes, installs policies, and (re)starts the Zeek process. Run `status` afterward to confirm Zeek is running on the correct interface before starting the forwarder script.
 
```bash
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```
 
---

## Python Scripts

Two scripts handle log forwarding and active response. Run both after configuration is complete:

```bash
python3 zeek_forwarder.py
python3 block_agent.py
```

### [zeek_forwarder.py](zeek_forwarder.py)

The forwarder monitors five Zeek log files simultaneously using threading, forwards all entries to Loki, and sends Discord alerts for security-relevant log types.

### [block_agent.py](block_agent.py)

The block agent is a Flask REST API that receives commands from the Grafana dashboard and executes iptables rules on the Ubuntu VM.

---

## Grafana Dashboard

The Grafana dashboard provides real-time visualization across the following panels:

| Panel | Description |
|---|---|
| Total Alerts | Total Zeek security alerts in the selected time range. Includes port scans, SMB enumeration, and unauthorized access attempts. |
| Live Connections (30s) | Active network connections in the last 30 seconds. A sudden spike may indicate a port scan or flood attack. |
| SMB Events | Total SMB events detected. SMB is commonly targeted for lateral movement, credential theft, and unauthorized file access. |
| SMB File Access | Number of file access attempts on SMB shares. Unauthorized reads/writes indicate active data exfiltration or tampering. |
| Connection Timeline | Real-time graph of all network connections. A sharp spike indicates reconnaissance activity such as an Nmap port scan. |
| Top Source IPs | Tracks the top 10 source IPs by connection count. Use this panel to identify which IP to block. |
| Zeek Security Alerts | Live feed of all security notices: port scan detections, dropped packets, and custom detection rules. |
| SMB Share Enumeration | Logs of SMB share mapping activity from tools like enum4linux or smbclient. |
| SMB File Activity | Records of file operations over SMB. Shows when an attacker accesses, reads, or downloads files. |
| SMB Commands | Detailed log of SMB commands executed during a session. Useful for forensic reconstruction of the attack. |
| IP Block Control | Active response panel. Block or unblock attacker IPs directly from the dashboard using iptables on the monitored Ubuntu VM. |
| General Network Logs | Full raw log stream from all Zeek log sources combined. |

The `dashboard.json` configuration file is included in this repository.

---

## Attack Demonstration

### Nmap Port Scanning

```bash
nmap -sC -sV -p- --min-rate=1000 192.168.122.108
```

Zeek detects the scan and triggers a `PortScan::Port_Scan` notice. The Grafana log alert and Discord webhook both fire with the source IP and raw log details.

### SMB Share Enumeration (enum4linux)

```bash
enum4linux -a 192.168.122.108
```

Zeek logs SMB mapping activity. A Discord alert fires with type `SMB_MAPPING` and the attacker's source IP.

### SMB File Access (smbclient)

```bash
smbclient //192.168.122.108/shared -N
smb: \> ls
smb: \> get secret.txt
```

Zeek logs the file operation. A Discord alert fires with type `SMB_FILES` identifying unauthorized file access on the shared directory.

---

## Active Response

The Grafana IP Block Control panel shows the latest detected attacker IP. Clicking "USE THIS IP" auto-fills the target field. Clicking "BLOCK IP" sends the IP to `block_agent.py`, which runs an iptables DROP rule on the Ubuntu VM. The blocked IP appears in the Blocked IPs list, and a Discord webhook notification confirms the action.

Blocked IPs can be removed using the "UNBLOCK IP" button. Discord will also send a notification confirming the IP has been removed from iptables.

---

## Conclusion and Suggestion

### Conclusion

This project successfully developed a real-time network intrusion detection system targeting SMB-based attacks using Zeek as the core detection engine, integrated with a custom Python pipeline, Grafana for visualization, Loki for log aggregation, Discord for alerting, and an active response mechanism via iptables.

The system was able to detect all three stages of the simulated attack scenario: port scan reconnaissance, SMB share enumeration, and unauthorized file access. And respond to each stage with real-time dashboard updates, Discord notifications, and manual IP blocking through the Grafana interface.

### Suggestion

- Currently blocked IPs are stored in memory and lost when `block_agent.py` restarts. A future improvement would store the blocked IP list in a JSON file or SQLite database so blocks persist across restarts and can be audited later.
- The current pipeline communicates over plain HTTP between the forwarder, Loki, and block agent. Adding TLS encryption would make the system suitable for deployment in environments where network security of the monitoring pipeline itself is a concern.

---

## Requirements

**Hardware:**
- Laptop

**Operating System:**
- Ubuntu Server
- Kali Linux

**Software:**
- virt-manager
- Ms. Word
- Canva

---

## File Information

| No. | File Name | Description |
|---|---|---|
| 1 | [zeek_forwarder.py](zeek_forwarder.py) | Zeek log forwarder |
| 2 | [block_agent.py](block_agent.py) | Flask active response API |
| 3 | detect-scan.zeek | Custom Zeek port scan detection script |
| 4 | local.zeek | Zeek site policy configuration |
| 5 | node.cfg | Zeek node and interface configuration |
| 6 | zeekctl.cfg | Zeek controller configuration |
| 7 | dashboard.json | Grafana dashboard configuration |
| 8 | loki-config.yaml | Loki configuration file |
| 9 | Project Paper | This document |
| 10 | Presentation | Presentation slide |
