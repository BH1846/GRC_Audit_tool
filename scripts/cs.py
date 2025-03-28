import os
import winreg
import json
import shutil
import datetime
import getpass
import psutil
import socket
import platform
from win32com.client import Dispatch
from fpdf import FPDF
from collections import defaultdict

# Enhanced Function to check Windows Password Policies
def get_password_policy():
    policies = defaultdict(dict)
    
    try:
        # Account Policies
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            policies['Account Policies']['LimitBlankPasswordUse'] = winreg.QueryValueEx(key, "LimitBlankPasswordUse")[0] == 1
            policies['Account Policies']['NoLMHash'] = winreg.QueryValueEx(key, "NoLMHash")[0] == 1
            try:
                policies['Account Policies']['RestrictAnonymousSAM'] = winreg.QueryValueEx(key, "RestrictAnonymousSAM")[0] == 1
            except:
                policies['Account Policies']['RestrictAnonymousSAM'] = "Not configured"

        # Password Complexity
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            policies['Password Complexity']['RequireStrongKey'] = winreg.QueryValueEx(key, "RequireStrongKey")[0] == 1
            policies['Password Complexity']['DisablePasswordChange'] = winreg.QueryValueEx(key, "DisablePasswordChange")[0] == 0

       

        # Check for built-in administrator account status
        policies['User Accounts']['BuiltInAdminActive'] = "Check manually: net user Administrator"

        # Check for password never expires on user accounts
        policies['User Accounts']['PasswordNeverExpires'] = "Use 'net user [username]' to check"

        # Check for empty passwords
        policies['User Accounts']['EmptyPasswords'] = "Use 'net user' to check all accounts"

    except Exception as e:
        policies['Error'] = str(e)
    
    return policies

# Enhanced Function to check data retention rules
def check_data_retention():
    retention = {
        'RecycleBin_Over30Days': [],
        'RecycleBin_LargeFiles': [],
        'TempFiles_Over7Days': [],
        'TempFiles_LargeFiles': [],
        'LogFiles_Over30Days': [],
        'LogFiles_LargeFiles': [],
        'SystemHealth': {}
    }
    now = datetime.datetime.now()
    
    # 1. Recycle Bin Analysis
    recycle_bin_paths = [
        f"C:\\Users\\{getpass.getuser()}\\$Recycle.Bin",
        "C:\\$Recycle.Bin"
    ]
    
    for path in recycle_bin_paths:
        if os.path.exists(path):
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.exists(file_path):
                            ctime = datetime.datetime.fromtimestamp(os.path.getctime(file_path))
                            age = (now - ctime).days
                            size = os.path.getsize(file_path) / (1024 * 1024)  # in MB
                            
                            if age > 30:
                                retention['RecycleBin_Over30Days'].append(f"{file_path} (Age: {age}d, Size: {size:.2f}MB)")
                            if size > 100:
                                retention['RecycleBin_LargeFiles'].append(f"{file_path} (Size: {size:.2f}MB)")
                    except:
                        continue

    # 2. Temporary Files Analysis
    temp_paths = [
        os.getenv('TEMP'),
        os.getenv('TMP'),
        "C:\\Windows\\Temp",
        f"C:\\Users\\{getpass.getuser()}\\AppData\\Local\\Temp"
    ]
    
    for path in temp_paths:
        if path and os.path.exists(path):
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.exists(file_path):
                            ctime = datetime.datetime.fromtimestamp(os.path.getctime(file_path))
                            age = (now - ctime).days
                            size = os.path.getsize(file_path) / (1024 * 1024)  # in MB
                            
                            if age > 7:
                                retention['TempFiles_Over7Days'].append(f"{file_path} (Age: {age}d)")
                            if size > 50:
                                retention['TempFiles_LargeFiles'].append(f"{file_path} (Size: {size:.2f}MB)")
                    except:
                        continue

    # 3. Log Files Analysis
    log_paths = [
        "C:\\Windows\\System32\\LogFiles",
        "C:\\Windows\\Logs",
        "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive"
    ]
    
    for path in log_paths:
        if os.path.exists(path):
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.exists(file_path):
                            ctime = datetime.datetime.fromtimestamp(os.path.getctime(file_path))
                            age = (now - ctime).days
                            size = os.path.getsize(file_path) / (1024 * 1024)  # in MB
                            
                            if age > 30:
                                retention['LogFiles_Over30Days'].append(f"{file_path} (Age: {age}d)")
                            if size > 20:
                                retention['LogFiles_LargeFiles'].append(f"{file_path} (Size: {size:.2f}MB)")
                    except:
                        continue

    # 4. System Health Checks
    disk_usage = shutil.disk_usage("C:\\")
    retention['SystemHealth']['DiskUsage'] = f"{disk_usage.used / disk_usage.total * 100:.2f}%"
    
    # Check for system restore points older than 90 days
    retention['SystemHealth']['OldRestorePoints'] = "Check manually: vssadmin list shadows"
    
    # Check Windows Update cleanup
    retention['SystemHealth']['WindowsUpdateCleanup'] = "Check manually: cleanmgr /sageset:65535 & cleanmgr /sagerun:65535"
    
    return retention

# Enhanced PDF report generation
def generate_pdf_report(password_policy, data_retention):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Add a page
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Comprehensive Policy Compliance Report", ln=True, align="C")
    pdf.ln(10)
    
    # System Information
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "System Information", ln=True)
    pdf.set_font("Arial", "", 10)
    
    system_info = {
        "Hostname": socket.gethostname(),
        "OS": platform.platform(),
        "User": getpass.getuser(),
        "Report Date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    for key, value in system_info.items():
        pdf.cell(200, 6, f"{key}: {value}", ln=True)
    pdf.ln(10)
    
    # Password Policy Section
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Password Policy Compliance", ln=True)
    pdf.set_font("Arial", "", 10)
    
    for category, settings in password_policy.items():
        if category == 'Error':
            pdf.set_text_color(255, 0, 0)
            pdf.cell(200, 6, f"ERROR: {settings}", ln=True)
            pdf.set_text_color(0, 0, 0)
            continue
            
        pdf.set_font("Arial", "B", 10)
        pdf.cell(200, 6, f"{category}:", ln=True)
        pdf.set_font("Arial", "", 10)
        
        for setting, value in settings.items():
            color = (0, 0, 0)  # Black for normal
            if isinstance(value, bool):
                color = (0, 128, 0) if value else (255, 0, 0)  # Green for compliant, Red for non-compliant
            
            pdf.set_text_color(*color)
            pdf.cell(200, 6, f"  {setting}: {value}", ln=True)
            pdf.set_text_color(0, 0, 0)
    
    pdf.ln(10)
    
    # Data Retention Section
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Data Retention Compliance", ln=True)
    pdf.set_font("Arial", "", 10)
    
    for category, items in data_retention.items():
        pdf.set_font("Arial", "B", 10)
        pdf.cell(200, 6, f"{category.replace('_', ' ')}:", ln=True)
        pdf.set_font("Arial", "", 10)
        
        if isinstance(items, dict):
            for key, value in items.items():
                pdf.cell(200, 6, f"  {key}: {value}", ln=True)
        elif isinstance(items, list):
            for item in items[:10]:  # Show first 10 items to avoid huge reports
                pdf.cell(200, 6, f"  - {item}", ln=True)
            if len(items) > 10:
                pdf.cell(200, 6, f"  ... and {len(items)-10} more items", ln=True)
        else:
            pdf.cell(200, 6, f"  {items}", ln=True)
    
    # Summary Page
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "Compliance Summary", ln=True)
    pdf.ln(10)
    
    # Password Policy Summary
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Password Policy Findings:", ln=True)
    pdf.set_font("Arial", "", 10)
    
    critical_issues = 0
    for category, settings in password_policy.items():
        if category == 'Error':
            continue
        for setting, value in settings.items():
            if isinstance(value, bool) and not value:
                critical_issues += 1
                pdf.set_text_color(255, 0, 0)
                pdf.cell(200, 6, f"- Non-compliant: {category} > {setting}", ln=True)
                pdf.set_text_color(0, 0, 0)
    
    if critical_issues == 0:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(200, 6, "- No critical password policy issues found", ln=True)
        pdf.set_text_color(0, 0, 0)
    
    pdf.ln(10)
    
    # Data Retention Summary
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Data Retention Findings:", ln=True)
    pdf.set_font("Arial", "", 10)
    
    retention_issues = sum(len(v) for k, v in data_retention.items() if isinstance(v, list))
    if retention_issues > 0:
        pdf.set_text_color(255, 0, 0)
        pdf.cell(200, 6, f"- Found {retention_issues} potential data retention issues", ln=True)
        pdf.set_text_color(0, 0, 0)
        
        for category, items in data_retention.items():
            if isinstance(items, list) and items:
                pdf.cell(200, 6, f"  - {len(items)} in {category.replace('_', ' ')}", ln=True)
    else:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(200, 6, "- No data retention issues found", ln=True)
        pdf.set_text_color(0, 0, 0)
    
    # Recommendations
    pdf.ln(10)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Recommendations:", ln=True)
    pdf.set_font("Arial", "", 10)
    
    recommendations = [
        "1. Review and enforce strong password policies for all accounts",
        "2. Regularly clean up temporary files and recycle bins",
        "3. Implement automated log rotation and archiving",
        "4. Monitor disk usage and set up alerts for critical levels",
        "5. Review system restore points and clean up old ones",
        "6. Schedule regular Windows Update cleanup",
        "7. Audit user accounts for password expiration compliance"
    ]
    
    for rec in recommendations:
        pdf.cell(200, 6, rec, ln=True)
    
    # Save the PDF
    pdf.output("Comprehensive_Policy_Compliance_Report.pdf")

# Main execution
if __name__ == "__main__": 
    print("Running comprehensive policy compliance check...")
    password_policy = get_password_policy()
    data_retention = check_data_retention()
    generate_pdf_report(password_policy, data_retention)
    print("Compliance report generated: Comprehensive_Policy_Compliance_Report.pdf")