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
from datetime import datetime

# Check if script is running with admin/root privileges
def is_admin():
    if platform.system() == "Windows":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0  # Linux root check

# Fetch login logs
def get_login_logs():
    logs = []
    if platform.system() == "Linux":
        output = subprocess.run(["last"], capture_output=True, text=True).stdout
        logs = output.split("\n")
    elif platform.system() == "Windows" and is_admin():
        output = subprocess.run(
            ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4624 or EventID=4625)]]", "/f:text"],
            capture_output=True,
            text=True
        ).stdout
        logs = output.split("\n")
    return logs

# Collect logged-in users
def collect_user_logs():
    return [{"user": u.name, "terminal": u.terminal, "host": u.host, "started": u.started} for u in psutil.users()]

# Capture network packets
def capture_network_packets(packet_count=10):
    packets = []
    def process_packet(packet):
        packets.append(packet.summary())
    sniff(prn=process_packet, count=packet_count, store=0)
    return packets

# Collect PAM or Event logs
def collect_pam_or_event_logs():
    system = platform.system()
    logs = []
    if system == "Linux":
        logs = os.popen("grep 'PAM' /var/log/auth.log | tail -n 10").read().split("\n")
    elif system == "Windows":
        logs = os.popen('wevtutil qe Security /c:10 /rd:true /f:text').read().split("\n")
    return logs

# Monitor filesystem changes
class FileMonitor(FileSystemEventHandler):
    def __init__(self):
        self.changes = []

    def on_modified(self, event):
        self.changes.append(f"Modified: {event.src_path}")

    def on_created(self, event):
        self.changes.append(f"Created: {event.src_path}")

    def on_deleted(self, event):
        self.changes.append(f"Deleted: {event.src_path}")

def monitor_filesystem(path="/", duration=10):
    event_handler = FileMonitor()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    time.sleep(duration)
    observer.stop()
    observer.join()
    return event_handler.changes

# Collect security logs
def collect_security_data():
    return {
        "timestamp": str(datetime.now()),
        "login_logs": get_login_logs(),
        "user_logs": collect_user_logs(),
        "network_traffic": capture_network_packets(),
        "privileged_access_logs": collect_pam_or_event_logs(),
        "file_system_changes": monitor_filesystem(path="C:\\" if platform.system() == "Windows" else "/", duration=10)
    }

# Compliance check function
def check_compliance(logs):
    compliance_issues = []

    # GDPR Violations (e.g., unauthorized access, excessive logging of personal data)
    for log in logs.get("login_logs", []):
        if "unauthorized" in log.lower() or "failed password" in log.lower():
            compliance_issues.append({"violation": "GDPR", "details": log})

    # ISO 27001 Violations (e.g., failed authentication, privilege escalation)
    for log in logs.get("privileged_access_logs", []):
        if "failed" in log.lower() or "denied" in log.lower():
            compliance_issues.append({"violation": "ISO 27001", "details": log})

    # HIPAA Violations (e.g., unauthorized access to sensitive files)
    for change in logs.get("file_system_changes", []):
        if "deleted" in change.lower():
            compliance_issues.append({"violation": "HIPAA", "details": change})

    return compliance_issues if compliance_issues else [{"message": "No compliance violations found."}]

# Save logs to JSON
def save_as_json(data, filename):
    with open(filename, "w") as json_file:
        json.dump(data, json_file, indent=4)
    print(f"[✔] JSON report saved as {filename}")

# Save security logs to PDF
def save_security_pdf(data, filename="security_report.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)

    pdf.cell(200, 10, "Security Report", ln=True, align="C")
    pdf.ln(10)

    for key, value in data.items():
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, key.replace("_", " ").title(), ln=True)
        pdf.cell(0, 1, "_" * 90, ln=True)  # Underline
        pdf.ln(5)

        pdf.set_font("Arial", size=10)

        if isinstance(value, list):
            for item in value:
                pdf.multi_cell(0, 6, f"  - {str(item)}")
            pdf.ln(5)
        else:
            pdf.multi_cell(0, 5, str(value))
        pdf.ln(5)

    pdf.output(filename)
    print(f"[✔] Security PDF report saved as {filename}")

# Save compliance report to PDF
def save_compliance_pdf(compliance_issues, filename="compliance_report.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)

    pdf.cell(200, 10, "Compliance Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Compliance Issues", ln=True)
    pdf.cell(0, 1, "_" * 90, ln=True)  # Underline
    pdf.ln(5)

    pdf.set_font("Arial", size=10)

    if compliance_issues and not ("message" in compliance_issues[0]):
        for issue in compliance_issues:
            pdf.multi_cell(0, 6, f"  - {issue['violation']}: {issue['details']}")
            pdf.ln(2)
    else:
        pdf.cell(0, 6, "No compliance violations found.", ln=True)

    pdf.output(filename)
    print(f"[✔] Compliance PDF report saved as {filename}")

# Generate detailed reports
def generate_report():
    logs = collect_security_data()
    compliance_issues = check_compliance(logs)

    save_as_json({"security_logs": logs}, "security_report.json")
    save_as_json({"compliance_results": compliance_issues}, "compliance_report.json")

    save_security_pdf(logs, "security_report.pdf")
    save_compliance_pdf(compliance_issues, "compliance_report.pdf")

    print("\n[✔] Reports successfully generated!\n")

# Run the script
if __name__ == "__main__":
    generate_report()
