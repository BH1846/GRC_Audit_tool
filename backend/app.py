import os
import platform
import ctypes
import json
import time
import re
from datetime import datetime
from scapy.all import sniff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fpdf import FPDF
from flask import Flask, jsonify, send_file
from flask_cors import CORS

if platform.system() == "Windows":
    import win32evtlog
elif platform.system() == "Linux":
    import glob

app = Flask(__name__)
CORS(app)

LOG_JSON_PATH = "logs/compliance_audit.json"
PDF_REPORT_PATH = "logs/compliance_audit.pdf"


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0 if platform.system() == "Windows" else os.geteuid() == 0


def get_login_logs():
    logs = []
    if platform.system() == "Linux":
        try:
            with open("/var/log/auth.log", "r", encoding="utf-8") as file:
                logs = file.readlines()
        except FileNotFoundError:
            logs = ["No auth.log found"]
    elif platform.system() == "Windows" and is_admin():
        server = 'localhost'
        log_type = 'Security'
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        for event in events:
            if event.EventID in [4624, 4625]:  # Successful & failed login
                logs.append(f"Event ID: {event.EventID}, Time: {event.TimeGenerated}")
    return logs


def capture_network_packets(packet_count=5):
    packets = []
    def process_packet(packet):
        packets.append(packet.summary())
    sniff(prn=process_packet, count=packet_count, store=0)
    return packets


class FileMonitor(FileSystemEventHandler):
    def __init__(self):
        self.changes = []
    def on_modified(self, event):
        self.changes.append(f"Modified: {event.src_path}")
    def on_created(self, event):
        self.changes.append(f"Created: {event.src_path}")
    def on_deleted(self, event):
        self.changes.append(f"Deleted: {event.src_path}")


def monitor_filesystem(path="C:\\" if platform.system() == "Windows" else "/", duration=5):
    event_handler = FileMonitor()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    time.sleep(duration)
    observer.stop()
    observer.join()
    return event_handler.changes


def collect_security_data():
    return {
        "timestamp": str(datetime.now()),
        "login_logs": get_login_logs(),
        "network_traffic": capture_network_packets(),
        "file_system_changes": monitor_filesystem()
    }


def check_compliance(logs):
    compliance_issues = []
    for log in logs.get("login_logs", []):
        if re.search(r"failed|unauthorized", log, re.IGNORECASE):
            compliance_issues.append({"violation": "GDPR", "details": log})
    for change in logs.get("file_system_changes", []):
        if "deleted" in change.lower():
            compliance_issues.append({"violation": "HIPAA", "details": change})
    return compliance_issues if compliance_issues else [{"message": "No compliance violations found."}]


def analyze_suspicious_logs(logs):
    suspicious_patterns = {
        "failed password": 0, "account failed": 0, "privilege escalation": 0,
        "unauthorized": 0, "bad password": 0, "invalid user": 0, "error": 0, "denied": 0
    }
    detected_logs = []

    # Debug: Print logs being analyzed
    print("Analyzing logs...")
    for log in logs.get("login_logs", []):
        print(f"Log: {log}")  # Print each log to inspect its content
        for pattern in suspicious_patterns:
            if pattern in log.lower():
                detected_logs.append(f"Suspicious activity detected: {log}")
                suspicious_patterns[pattern] += 1

    # Debug: Print suspicious patterns
    print(f"Suspicious patterns: {suspicious_patterns}")

    return detected_logs, suspicious_patterns


def save_as_json(data):
    os.makedirs(os.path.dirname(LOG_JSON_PATH), exist_ok=True)
    with open(LOG_JSON_PATH, "w") as json_file:
        json.dump(data, json_file, indent=4)


def generate_pdf_report(compliance_results, suspicious_logs, summary):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, "Compliance Audit Report", ln=True, align="C")
    pdf.ln(10)

    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Date: {current_date}", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", style="B", size=14)
    pdf.cell(200, 10, "Detected Compliance Issues:", ln=True)
    pdf.set_font("Arial", size=12)
    for issue in compliance_results:
        pdf.multi_cell(0, 10, f"- {issue.get('violation', 'Unknown')}: {issue.get('details', '')}")
    pdf.ln(10)

    pdf.set_font("Arial", style="B", size=14)
    pdf.cell(200, 10, "Detected Suspicious Logs:", ln=True)
    pdf.set_font("Arial", size=12)
    for log in suspicious_logs:
        pdf.multi_cell(0, 10, log)
    pdf.ln(10)

    os.makedirs(os.path.dirname(PDF_REPORT_PATH), exist_ok=True)
    pdf.output(PDF_REPORT_PATH, "F")


@app.route("/run-audit", methods=["GET"])
def run_audit():
    logs = collect_security_data()
    compliance_results = check_compliance(logs)
    suspicious_logs, summary = analyze_suspicious_logs(logs)
    report_data = {"date": datetime.now().strftime("%d-%b-%Y"), "compliance_results": compliance_results,
                   "suspicious_logs": suspicious_logs, "summary": summary}
    save_as_json(report_data)
    generate_pdf_report(compliance_results, suspicious_logs, summary)
    return jsonify({"message": "Audit completed successfully.", "date": report_data["date"]})


@app.route("/get-audit-results", methods=["GET"])
def get_audit_results():
    if os.path.exists(LOG_JSON_PATH):
        with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify({"message": "Audit results retrieved successfully", "date": data.get("date", "N/A")})
    return jsonify({"error": "No audit results available"}), 404


@app.route("/download-report", methods=["GET"])
def download_report():
    if os.path.exists(PDF_REPORT_PATH):
        return send_file(PDF_REPORT_PATH, as_attachment=True)
    return jsonify({"error": "Report not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)