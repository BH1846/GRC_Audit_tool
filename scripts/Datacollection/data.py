import os
import platform
import subprocess
import ctypes
import json
import re
import psutil
import time
from scapy.all import sniff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fpdf import FPDF
from tqdm import tqdm
from datetime import datetime

def is_admin():
    """Check if the script is running with admin/root privileges."""
    if platform.system() == "Windows":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0  # Linux root check

def get_login_logs():
    """Fetch latest user login logs based on the OS."""
    print("[+] Collecting latest login logs...")
    if platform.system() == "Linux":
        logs = subprocess.run(["last"], capture_output=True, text=True)
    elif platform.system() == "Windows":
        if is_admin():
            logs = subprocess.run(
                ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4624 or EventID=4625)]]", "/f:text"],
                capture_output=True,
                text=True
            )
        else:
            logs = subprocess.run(
                ["powershell", "Get-WinEvent -LogName Security -MaxEvents 50"],
                capture_output=True,
                text=True
            )
    else:
        return {"error": "Unsupported OS"}

    return logs.stdout

def collect_user_logs():
    """Collect current logged-in users."""
    users = psutil.users()
    return [{"user": u.name, "terminal": u.terminal, "host": u.host, "started": u.started} for u in users]

def capture_network_packets(packet_count=10):
    """Capture network packets and return summaries."""
    packets = []
    def process_packet(packet):
        packets.append(packet.summary())
    sniff(prn=process_packet, count=packet_count, store=0)
    return packets

def collect_pam_or_event_logs():
    """Collect privileged access logs (Linux PAM or Windows Event Logs)."""
    system = platform.system()
    if system == "Linux":
        logs = os.popen("grep 'PAM' /var/log/auth.log | tail -n 10").read()
    elif system == "Windows":
        logs = os.popen('wevtutil qe Security /c:10 /rd:true /f:text').read()
    else:
        logs = "Unsupported OS"
    return logs

class FileMonitor(FileSystemEventHandler):
    """Monitor file system changes."""
    def __init__(self):
        self.changes = []

    def on_modified(self, event):
        self.changes.append(f"Modified: {event.src_path}")

    def on_created(self, event):
        self.changes.append(f"Created: {event.src_path}")

    def on_deleted(self, event):
        self.changes.append(f"Deleted: {event.src_path}")

def monitor_filesystem(path="/", duration=10):
    """Monitor file system changes for a given duration."""
    event_handler = FileMonitor()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    time.sleep(duration)
    observer.stop()
    observer.join()
    return event_handler.changes

def collect_security_data():
    """Collect security logs from multiple sources."""
    return {
        "login_logs": get_login_logs().split("\n"),
        "user_logs": collect_user_logs(),
        "network_traffic": capture_network_packets(),
        "privileged_access_logs": collect_pam_or_event_logs().split("\n"),
        "file_system_changes": monitor_filesystem(path="C:\\" if platform.system() == "Windows" else "/", duration=10)
    }

def save_as_json(data, filename="security_logs.json"):
    """Save logs as a JSON file."""
    with open(filename, "w") as json_file:
        json.dump(data, json_file, indent=4)
    print(f"JSON report saved as {filename}")

def save_as_pdf(data, filename="security_report.pdf"):
    """Save logs as a PDF file."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    pdf.cell(200, 10, txt="Security Logs Report", ln=True, align="C")
    pdf.ln(10)

    for key, value in data.items():
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(0, 10, txt=key.replace("_", " ").title(), ln=True)
        pdf.set_font("Arial", size=10)
        
        if isinstance(value, list):
            for item in value:
                pdf.multi_cell(0, 5, txt=str(item))
        else:
            pdf.multi_cell(0, 5, txt=str(value))
        pdf.ln(5)

    pdf.output(filename)
    print(f"PDF report saved as {filename}")

def analyze_logs(log_file):
    """Analyze the log file for suspicious activity."""
    suspicious_patterns = [
        "failed password",
        "account failed",
        "privilege escalation",
        "unauthorized",
        "bad password",
        "invalid user",
        "escalation",
        "error",
        "denied",
    ]

    if not os.path.exists(log_file):
        print(f"Error: Log file '{log_file}' not found.")
        return

    with open(log_file, "r", encoding="utf-8") as f:
        logs = json.load(f)

    suspicious_count = {pattern: 0 for pattern in suspicious_patterns}

    for key, log_list in logs.items():
        if isinstance(log_list, list):
            for line in log_list:
                for pattern in suspicious_patterns:
                    if isinstance(line, str) and re.search(pattern, line, re.IGNORECASE):
                        print(f"🚨 Suspicious activity detected in {key}: {line.strip()}")
                        suspicious_count[pattern] += 1

    print("\n✅ Audit Summary:")
    for pattern, count in suspicious_count.items():
        print(f"{pattern}: {count} occurrence(s) found.")

    if sum(suspicious_count.values()) == 0:
        print("🎉 No suspicious activity detected.")

def update_security_logs():
    """Fetch security logs, save to JSON/PDF, and analyze."""
    logs = collect_security_data()
    json_path = "security_logs.json"
    pdf_path = "security_report.pdf"

    save_as_json(logs, json_path)
    save_as_pdf(logs, pdf_path)
    analyze_logs(json_path)

    print(f"\n[✔] Logs successfully updated!\n   📂 JSON: {json_path}\n   📂 PDF: {pdf_path}")

if __name__ == "__main__":
    update_security_logs()
