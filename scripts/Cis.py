import os
import platform
import json
import subprocess
from datetime import datetime
from fpdf import FPDF

# File Paths for reports
LOG_JSON_PATH = os.path.join(os.path.dirname(__file__), "reports/cis_compliance_results.json")
PDF_REPORT_PATH = os.path.join(os.path.dirname(__file__), "reports/cis_compliance_results.pdf")

def run_command(command):
    """Execute a shell command and return its output as a string."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing command: {e}"

def check_linux_cis():
    """Perform a few basic CIS compliance checks for Linux."""
    results = {}

    # 1. Check if SELinux is enabled
    selinux_status = run_command("getenforce") if os.path.exists("/usr/sbin/getenforce") else "Not Installed"
    results["SELinux"] = "Compliant" if selinux_status == "Enforcing" else "Non-Compliant"

    # 2. Check if the firewall is enabled (using UFW)
    firewall_status = run_command("ufw status | grep -i active")
    results["Firewall"] = "Enabled" if "active" in firewall_status.lower() else "Disabled"

    # 3. Check password policy (minimum password length)
    min_pass_length = run_command("grep -E '^PASS_MIN_LEN' /etc/login.defs | awk '{print $2}'")
    try:
        results["Min Password Length"] = "Compliant" if min_pass_length and int(min_pass_length) >= 12 else "Non-Compliant"
    except ValueError:
        results["Min Password Length"] = "Non-Compliant"

    # 4. Check if root login via SSH is disabled
    ssh_root_status = run_command("grep '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}'")
    results["Root SSH Access"] = "Compliant" if ssh_root_status.lower() == "no" else "Non-Compliant"

    # 5. Check if password expiration is set (90 days max)
    pass_max_days = run_command("grep -E '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}'")
    try:
        results["Password Expiration"] = "Compliant" if pass_max_days and int(pass_max_days) <= 90 else "Non-Compliant"
    except ValueError:
        results["Password Expiration"] = "Non-Compliant"

    return results

def check_windows_cis():
    """Perform a few basic CIS compliance checks for Windows."""
    results = {}

    # 1. Check if Windows Defender is enabled (real-time monitoring should be enabled)
    defender_status = run_command("powershell.exe Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring").strip()
    results["Windows Defender"] = "Compliant" if defender_status.lower() == "false" else "Non-Compliant"

    # 2. Check if Firewall is enabled. If all profiles are disabled, then mark it as "Disabled"
    firewall_status_output = run_command("powershell.exe (Get-NetFirewallProfile).Enabled").strip()
    firewall_status_list = firewall_status_output.splitlines()
    if all(status.strip().lower() == "false" for status in firewall_status_list):
        results["Firewall"] = "Disabled"
    else:
        results["Firewall"] = "Enabled"

    # 3. Check password policy (minimum password length)
    pass_length = run_command('powershell.exe net accounts | findstr "Minimum password length"')
    min_length = pass_length.split(":")[-1].strip() if pass_length else "Unknown"
    try:
        results["Min Password Length"] = "Compliant" if min_length.isdigit() and int(min_length) >= 12 else "Non-Compliant"
    except ValueError:
        results["Min Password Length"] = "Non-Compliant"

    # 4. Check if remote desktop is disabled (if disabled then compliant)
    rdp_status = run_command('powershell.exe (Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server").fDenyTSConnections').strip()
    results["Remote Desktop Access"] = "Compliant" if rdp_status == "1" else "Non-Compliant"

    return results

def generate_pdf_report(results):
    """Generate a PDF report from the CIS compliance results."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", style="B", size=16)

    pdf.cell(200, 10, "CIS Compliance Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", style="B", size=14)
    pdf.cell(200, 10, f"Generated on: {datetime.now().strftime('%d-%b-%Y')}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(200, 10, "Compliance Checks:", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", size=12)
    for key, status in results.items():
        pdf.cell(200, 10, f"{key}: {status}", ln=True)

    os.makedirs(os.path.dirname(PDF_REPORT_PATH), exist_ok=True)
    pdf.output(PDF_REPORT_PATH, "F")

def run_cis_audit():
    """Determine the OS, perform CIS compliance checks, save JSON results, and generate a PDF report."""
    os_type = platform.system()
    compliance_results = {}

    if os_type == "Linux":
        compliance_results = check_linux_cis()
    elif os_type == "Windows":
        compliance_results = check_windows_cis()
    else:
        compliance_results["Error"] = "Unsupported OS"

    # Save results to JSON
    os.makedirs(os.path.dirname(LOG_JSON_PATH), exist_ok=True)
    with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(compliance_results, f, indent=4)

    # Generate PDF report
    generate_pdf_report(compliance_results)

    return compliance_results

if __name__ == "__main__":
    results = run_cis_audit()
    print(json.dumps(results, indent=4))
    print(f"CIS Compliance report saved at {PDF_REPORT_PATH}")
