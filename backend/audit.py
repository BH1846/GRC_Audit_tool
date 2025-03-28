import os
import platform
import subprocess
import ctypes
import json
import re
from fpdf import FPDF
from tqdm import tqdm

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

def save_as_json(log_data, filename="logs/latest_login_logs.json"):
    """Save logs as a JSON file with progress tracking."""
    file_path = os.path.abspath(filename)
    print(f"[+] Saving logs as JSON to: {file_path}")

    with tqdm(total=100, desc="Generating JSON", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
        with open(filename, "w") as json_file:
            json.dump({"logs": log_data.split("\n")}, json_file, indent=4)
        pbar.update(100)

    return file_path

def save_as_pdf(log_data, filename="logs/latest_login_logs.pdf"):
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

    # Check if the file exists
    if not os.path.exists(log_file):
        print(f"Error: Log file '{log_file}' not found.")
        return

    # Open and read the log file
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
        json_path = save_as_json(logs, "logs/latest_login_logs.json")
        pdf_path = save_as_pdf(logs, "logs/latest_login_logs.pdf")
        print(f"\n[✔] Logs successfully updated!\n   📂 JSON: {json_path}\n   📂 PDF: {pdf_path}")
        analyze_logs(json_path)
        return {"success": True, "json_path": json_path, "pdf_path": pdf_path}
    else:
        print("[✖] Error fetching logs:", logs)
        return {"error": str(logs)}
