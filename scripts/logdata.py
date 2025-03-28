import os
import platform
import ctypes
import json
import re
from fpdf import FPDF
from tqdm import tqdm
from datetime import datetime

try:
    import win32evtlog
    import win32evtlogutil
except ImportError:
    pass  # Ignore if running on Linux

def is_admin():
    """Check if the script is running with admin/root privileges."""
    if platform.system() == "Windows":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0  # Linux root check

def get_login_logs():
    """Fetch the latest 15 login logs based on the OS."""
    print("[+] Collecting latest login logs...")

    if platform.system() == "Linux":
        log_path = "/var/log/auth.log"
        if not os.path.exists(log_path):
            return {"error": "Login log file not found"}

        with open(log_path, "r", encoding="utf-8") as log_file:
            logs = log_file.readlines()[-15:]  # Get last 15 lines
    
    elif platform.system() == "Windows":
        logs = []
        log_type = "Security"
        
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total_events = 15  # Fetch the latest 15 events
            count = 0

            while count < total_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for event in events:
                    if event.EventID in [4624, 4625]:  # Logon Success/Failure
                        logs.append(win32evtlogutil.SafeFormatMessage(event, log_type))
                        count += 1
                        if count >= total_events:
                            break
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            return {"error": f"Failed to read Windows Event Log: {e}"}

        logs = logs[:15]  # Ensure we have only the latest 15 logs
    else:
        return {"error": "Unsupported OS"}

    return "\n".join(logs)

def save_as_json(log_data, filename="login_logs.json"):
    """Save logs as a JSON file with progress tracking."""
    file_path = os.path.abspath(filename)
    print(f"[+] Saving logs as JSON to: {file_path}")

    with tqdm(total=100, desc="Generating JSON", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
        with open(filename, "w") as json_file:
            json.dump({"logs": log_data.split("\n")}, json_file, indent=4)
        pbar.update(100)

    return file_path

def save_as_pdf(log_data, filename="login_logs.pdf"):
    """Save logs as a PDF file with progress tracking."""
    file_path = os.path.abspath(filename)
    print(f"[+] Saving logs as PDF to: {file_path}")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    lines = log_data.split("\n")

    with tqdm(total=len(lines), desc="Generating PDF", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
        for line in lines:
            pdf.multi_cell(0, 5, line)
            pbar.update(1)

    pdf.output(filename)
    return file_path

def analyze_logs(log_file):
    """Analyze the log file for suspicious activity."""
    suspicious_patterns = [
        "failed password",  # Linux failed login
        "account failed",  # Windows failed login
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
        logs = json.load(f)["logs"]

    suspicious_count = {pattern: 0 for pattern in suspicious_patterns}

    for line in logs:
        for pattern in suspicious_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                print(f"🚨 Suspicious activity detected: {line.strip()}")
                suspicious_count[pattern] += 1

    print("\n✅ Audit Summary:")
    for pattern, count in suspicious_count.items():
        print(f"{pattern}: {count} occurrence(s) found.")

    if sum(suspicious_count.values()) == 0:
        print("🎉 No suspicious activity detected.")

def update_latest_logs():
    """Fetch latest logs and update JSON and PDF files."""
    logs = get_login_logs()

    if isinstance(logs, str):
        json_path = save_as_json(logs, "latest_login_logs.json")
        pdf_path = save_as_pdf(logs, "latest_login_logs.pdf")
        print(f"\n[✔] Logs successfully updated!\n   📂 JSON: {json_path}\n   📂 PDF: {pdf_path}")
        analyze_logs(json_path)
    else:
        print("[✖] Error fetching logs:", logs)

# Run the latest log update and analysis
if __name__ == "__main__":
    update_latest_logs()
