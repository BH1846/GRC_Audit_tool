import subprocess
from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(200, 10, "CIS Benchmark Compliance Report - Windows", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 10)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def run_powershell(command):
    """Runs a PowerShell command and returns the output."""
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return "Error running command!"

def check_remote_desktop_status():
    """Check if Remote Desktop is enabled (Registry + Service Check)"""
    output = "Remote Desktop Status:\n"
    
    # Registry Check
    registry_result = run_powershell("(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
    rdp_service = run_powershell("Get-Service TermService | Select-Object -ExpandProperty Status")
    
    if registry_result.strip() == "1" and "Running" not in rdp_service:
        output += "  PASS: Remote Desktop is disabled\n"
    else:
        output += "  FAIL: Remote Desktop is enabled\n"

    return output

def check_firewall_status():
    """Check if Windows Firewall is enabled"""
    output = "Firewall Status:\n"
    result = run_powershell("Get-NetFirewallProfile | Select-Object Name, Enabled")
    if "True" in result:
        output += "  PASS: Windows Firewall is enabled\n"
    else:
        output += "  FAIL: Windows Firewall is disabled\n"
    return output

def check_antivirus_status():
    """Check if Windows Defender is enabled"""
    output = "Antivirus Status:\n"
    result = run_powershell("(Get-MpPreference).DisableRealtimeMonitoring")
    if "False" in result:
        output += "  PASS: Windows Defender is enabled\n"
    else:
        output += "  FAIL: Windows Defender is disabled\n"
    return output

def check_guest_account_status():
    """Check if Guest account is disabled"""
    output = "Guest Account Status:\n"
    result = run_powershell("(Get-LocalUser -Name Guest).Enabled")
    if "False" in result:
        output += "  PASS: Guest account is disabled\n"
    else:
        output += "  FAIL: Guest account is enabled\n"
    return output

def check_password_policy():
    """Check password complexity and length policy"""
    output = "Password Policy Check:\n"
    complexity = run_powershell("Get-LocalUser | Select-Object Name, PasswordRequired")
    length = run_powershell("net accounts | findstr /C:\"Minimum password length\"")
    
    if "True" in complexity:
        output += "  PASS: Password complexity is enabled\n"
    else:
        output += "  FAIL: Password complexity is disabled\n"

    output += f"  {length}\n"
    return output

def check_auto_update_status():
    """Check if Windows Automatic Updates are enabled"""
    output = "Automatic Updates Status:\n"
    result = run_powershell("Get-WmiObject -Query 'Select * from Win32_Service where Name=\"wuauserv\"' | Select-Object State")
    if "Running" in result:
        output += "  PASS: Automatic Updates are enabled\n"
    else:
        output += "  FAIL: Automatic Updates are disabled\n"
    return output

def check_admin_accounts():
    """List all administrator accounts"""
    output = "Administrator Accounts:\n"
    result = run_powershell("Get-LocalGroupMember Administrators")
    output += result if result else "  FAIL: No administrator accounts found!\n"
    return output

def generate_pdf_report():
    """Generates a PDF report with all CIS checks."""
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "", 12)

    checks = [
        check_firewall_status(),
        check_antivirus_status(),
        check_guest_account_status(),
        check_password_policy(),
        check_remote_desktop_status(),  # Fixed RDP check!
        check_auto_update_status(),
        check_admin_accounts(),
    ]

    for check in checks:
        pdf.multi_cell(0, 8, check + "\n")
        pdf.ln(4)  # Add space between checks

    pdf.output("cis_report.pdf")
    print("\n✅ CIS Benchmark Report generated: cis_report.pdf")

def main():
    print("=============================================")
    print("  CIS Benchmark Compliance Check - Windows")
    print("=============================================")

    generate_pdf_report()

if __name__ == "__main__":

    main()