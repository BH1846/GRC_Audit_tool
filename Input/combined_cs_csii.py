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

import os
import wmi
import winreg
import socket
import platform
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

# Initialize WMI for system information
c = wmi.WMI()

### Helper Functions ###
def get_registry_value(key_path, value_name, hive=winreg.HKEY_LOCAL_MACHINE):
    """Helper function to read registry values."""
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return value
    except:
        return None

def check_service_status(service_name):
    """Check if a Windows service is running."""
    try:
        service = c.Win32_Service(Name=service_name)
        return "Running" if service and service[0].State == "Running" else "Stopped"
    except:
        return "Unknown"

### PCI-DSS Compliance Checks ###
def check_firewall():
    """Check if Windows Firewall is enabled for all profiles."""
    try:
        firewall_domain = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            "EnableFirewall"
        )
        firewall_private = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            "EnableFirewall"
        )
        firewall_public = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            "EnableFirewall"
        )
        
        status = "Enabled" if all([firewall_domain == 1, firewall_private == 1, firewall_public == 1]) else "Partially Enabled"
        details = f"Domain: {'On' if firewall_domain == 1 else 'Off'}, Private: {'On' if firewall_private == 1 else 'Off'}, Public: {'On' if firewall_public == 1 else 'Off'}"
        return f"{status} ({details})"
    except:
        return "Unknown"

def check_antivirus():
    """Check if an antivirus is installed, running, and up-to-date."""
    try:
        av = c.Win32_Product(Name="Microsoft Defender Antivirus")
        if not av:
            return "Third-party AV installed (verify manually)"
        
        # Check Defender status
        defender = c.Win32_Service(Name="WinDefend")
        signatures = c.Win32_ComputerSystem()
        return "Microsoft Defender Running" if defender and defender[0].State == "Running" else "Microsoft Defender Not Running"
    except:
        return "Unknown"

def check_secure_boot():
    """Check if Secure Boot is enabled."""
    try:
        secure_boot = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled"
        )
        return "Enabled" if secure_boot == 1 else "Disabled"
    except:
        return "Unknown"

def check_usb_restriction():
    """Check if USB storage is restricted."""
    try:
        usb_stor = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\USBSTOR",
            "Start"
        )
        return "Restricted" if usb_stor == 4 else "Not Restricted"
    except:
        return "Unknown"

def check_applocker():
    """Check if AppLocker (Application Whitelisting) is enabled."""
    try:
        applocker = get_registry_value(
            r"SOFTWARE\Policies\Microsoft\Windows\SrpV2",
            "EnforcementMode"
        )
        return "Enabled" if applocker == 1 else "Disabled"
    except:
        return "Unknown"

def check_rdp_security():
    """Check Remote Desktop Protocol security settings."""
    try:
        # Check if NLA is enabled
        nla = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication"
        )
        # Check if RDP is restricted to specific groups
        allow_ts = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections"
        )
        return "Secure (NLA Enabled)" if nla == 1 and allow_ts == 0 else "Insecure"
    except:
        return "Unknown"

def check_smb_v1():
    """Check if SMBv1 protocol is disabled."""
    try:
        smbv1 = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1"
        )
        return "Disabled" if smbv1 == 0 else "Enabled (Vulnerable)"
    except:
        return "Unknown"

### HIPAA Compliance Checks ###
def check_mfa():
    """Check if Multi-Factor Authentication (MFA) is enabled."""
    try:
        # Check for Windows Hello for Business
        hello = get_registry_value(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
            "EnableHelloForBusiness"
        )
        return "Windows Hello Enabled" if hello == 1 else "Check manually (depends on authentication method)"
    except:
        return "Unknown"

def check_password_policy():
    """Check password policy for complexity and length."""
    try:
        # Check password complexity
        complexity = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "NoLMHash"
        )
        # Check minimum password length
        min_length = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "MinimumPasswordLength"
        )
        return f"Complexity: {'Enabled' if complexity == 1 else 'Disabled'}, Min Length: {min_length if min_length else 'Not Set'}"
    except:
        return "Unknown"

def check_bitlocker_status():
    """Check if BitLocker is enabled on system drive."""
    try:
        volumes = c.Win32_EncryptableVolume()
        statuses = []
        for vol in volumes:
            if vol.DriveLetter:  # Only check drives with letters
                status = "Encrypted" if vol.ProtectionStatus == 1 else "Not Encrypted"
                statuses.append(f"{vol.DriveLetter}: {status}")
        return ", ".join(statuses) if statuses else "No encrypted volumes found"
    except:
        return "Unknown"

def check_audit_logging():
    """Check if audit logging is enabled for key events."""
    try:
        # Check audit policy settings
        account_logon = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "AuditAccountLogon"
        )
        logon_events = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "AuditLogonEvents"
        )
        object_access = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "AuditObjectAccess"
        )
        policy_change = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "AuditPolicyChange"
        )
        
        enabled_audits = []
        if account_logon == 1: enabled_audits.append("AccountLogon")
        if logon_events == 1: enabled_audits.append("LogonEvents")
        if object_access == 1: enabled_audits.append("ObjectAccess")
        if policy_change == 1: enabled_audits.append("PolicyChange")
        
        return "Enabled for: " + ", ".join(enabled_audits) if enabled_audits else "Minimal auditing"
    except:
        return "Unknown"

def check_power_shell_logging():
    """Check if PowerShell logging is enabled."""
    try:
        script_block = get_registry_value(
            r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging"
        )
        module_logging = get_registry_value(
            r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
            "EnableModuleLogging"
        )
        transcription = get_registry_value(
            r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
            "EnableTranscripting"
        )
        
        enabled_logs = []
        if script_block == 1: enabled_logs.append("ScriptBlock")
        if module_logging == 1: enabled_logs.append("Module")
        if transcription == 1: enabled_logs.append("Transcription")
        
        return "Enabled for: " + ", ".join(enabled_logs) if enabled_logs else "Disabled"
    except:
        return "Unknown"

def check_encrypted_connections():
    """Check if encrypted connections are enforced."""
    try:
        # Check for LDAP signing requirement
        ldap_signing = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
            "LDAPServerIntegrity"
        )
        # Check for SMB encryption
        smb_encryption = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "RequireSecuritySignature"
        )
        
        results = []
        if ldap_signing == 2: results.append("LDAP Signing Required")
        if smb_encryption == 1: results.append("SMB Encryption Required")
        
        return ", ".join(results) if results else "Not Enforced"
    except:
        return "Unknown"

### SOC2 Compliance Checks ###
def check_event_logging():
    """Check if critical security events are logged with proper retention."""
    try:
        security_log = c.Win32_NTEventlogFile(LogFileName="Security")
        if security_log:
            max_size = security_log[0].MaxFileSize
            retention = get_registry_value(
                r"SYSTEM\CurrentControlSet\Services\Eventlog\Security",
                "Retention"
            )
            retention_days = "Overwrite as needed" if retention == 0 else f"{retention} days retention"
            return f"Max size: {int(max_size)/1024:.1f} MB, Retention: {retention_days}"
        return "Security log not found"
    except:
        return "Unknown"

def check_unused_admin_accounts():
    """Check for unused admin accounts (90+ days)."""
    try:
        users = c.Win32_UserAccount(LocalAccount=True)
        admin_group = c.Win32_Group(Name="Administrators")[0]
        admin_sids = [user.PartComponent for user in c.Win32_GroupUser(GroupComponent=admin_group.path_())]
        
        inactive_admins = []
        for user in users:
            if user.path_() in admin_sids and user.Disabled == False:
                # Check last login time (simplified - would need more sophisticated check in production)
                inactive_admins.append(user.Name)
        
        return f"{len(inactive_admins)} active admin accounts" if inactive_admins else "No active admin accounts found"
    except:
        return "Unknown"

def check_file_integrity_monitoring():
    """Check if File Integrity Monitoring (FIM) is enabled."""
    try:
        # Check if Windows Defender ATP is running (which includes FIM)
        defender_atp = c.Win32_Service(Name="Sense")
        return "Windows Defender ATP Running" if defender_atp and defender_atp[0].State == "Running" else "No FIM detected"
    except:
        return "Unknown"

def check_windows_update_status():
    """Check if Windows Update is enabled and last update time."""
    try:
        update_service = c.Win32_Service(Name="wuauserv")
        if update_service and update_service[0].State == "Running":
            # Get last update time
            session = c.Win32_UpdateSession()
            searcher = session[0].CreateUpdateSearcher()
            history = searcher.GetTotalHistoryCount()
            last_update = searcher.QueryHistory(0, 1)[0].Date if history > 0 else "Never"
            return f"Enabled, Last update: {last_update}"
        return "Disabled"
    except:
        return "Unknown"

def check_remote_management():
    """Check remote management settings."""
    try:
        # Check WinRM service status
        winrm = check_service_status("WinRM")
        # Check PowerShell remoting
        ps_remoting = get_registry_value(
            r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
            "AllowAutoConfig"
        )
        return f"WinRM: {winrm}, PS Remoting: {'Enabled' if ps_remoting == 1 else 'Disabled'}"
    except:
        return "Unknown"

def check_user_account_control():
    """Check User Account Control (UAC) settings."""
    try:
        uac = get_registry_value(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA"
        )
        uac_level = get_registry_value(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin"
        )
        levels = {
            0: "Never notify",
            1: "Notify on changes",
            2: "Notify with secure desktop",
            3: "Always notify"
        }
        return f"UAC: {'Enabled' if uac == 1 else 'Disabled'}, Level: {levels.get(uac_level, 'Unknown')}"
    except:
        return "Unknown"

def check_network_access():
    """Check network access and sharing settings."""
    try:
        # Check network sharing
        sharing = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff",
            "NewNetworkWindowOff"
        )
        # Check password protected sharing
        pwd_sharing = get_registry_value(
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "RestrictNullSessAccess"
        )
        return f"Network sharing: {'Enabled' if sharing == 1 else 'Disabled'}, Password protected: {'Yes' if pwd_sharing == 1 else 'No'}"
    except:
        return "Unknown"

def check_system_info():
    """Gather basic system information."""
    try:
        computer_system = c.Win32_ComputerSystem()[0]
        os_info = c.Win32_OperatingSystem()[0]
        return {
            "Hostname": socket.gethostname(),
            "OS Name": os_info.Caption,
            "OS Version": os_info.Version,
            "System Manufacturer": computer_system.Manufacturer,
            "System Model": computer_system.Model,
            "Total Physical Memory": f"{int(computer_system.TotalPhysicalMemory)/1024/1024/1024:.1f} GB",
            "Number of Processors": computer_system.NumberOfProcessors,
            "Last Boot Time": os_info.LastBootUpTime.split('.')[0]
        }
    except:
        return {"System Info": "Could not retrieve system information"}

### Compliance Data Collection ###
def collect_compliance_data():
    """Collect all compliance data."""
    system_info = check_system_info()
    
    compliance_data = {
        "System Information": system_info,
        "PCI-DSS Compliance": {
            "Firewall Status": check_firewall(),
            "Antivirus Status": check_antivirus(),
            "Secure Boot": check_secure_boot(),
            "USB Storage Restriction": check_usb_restriction(),
            "Application Whitelisting": check_applocker(),
            "RDP Security": check_rdp_security(),
            "SMBv1 Protocol": check_smb_v1(),
            "User Account Control": check_user_account_control()
        },
        "HIPAA Compliance": {
            "Multi-Factor Authentication (MFA)": check_mfa(),
            "Password Policy": check_password_policy(),
            "Disk Encryption": check_bitlocker_status(),
            "Audit Logging": check_audit_logging(),
            "PowerShell Logging": check_power_shell_logging(),
            "Encrypted Connections": check_encrypted_connections(),
            "Remote Management": check_remote_management()
        },
        "SOC2 Compliance": {
            "Event Logging": check_event_logging(),
            "Admin Accounts": check_unused_admin_accounts(),
            "File Integrity Monitoring": check_file_integrity_monitoring(),
            "Windows Update Status": check_windows_update_status(),
            "Network Access Settings": check_network_access()
        }
    }
    
    return compliance_data

### PDF Report Generation ###
def generate_pdf(report_data, filename="compliance_report.pdf"):
    """Generate a PDF report from the compliance data."""
    c = canvas.Canvas(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Windows Compliance Gap Analysis Report")
    c.setFont("Helvetica", 10)
    c.drawString(100, 735, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    y_position = 700
    
    # System Information
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position, "System Information:")
    y_position -= 20
    
    system_info = report_data.pop("System Information")
    if isinstance(system_info, dict):
        c.setFont("Helvetica", 10)
        for key, value in system_info.items():
            c.drawString(120, y_position, f"{key}: {value}")
            y_position -= 15
            if y_position < 50:
                c.showPage()
                y_position = 750
    else:
        c.drawString(120, y_position, str(system_info))
        y_position -= 20
    
    y_position -= 10
    
    # Compliance Sections
    for section, checks in report_data.items():
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, y_position, f"{section}:")
        y_position -= 20
        
        # Create table data
        table_data = [["Check", "Status"]]
        for key, value in checks.items():
            table_data.append([key, value])
        
        # Create table
        table = Table(table_data, colWidths=[300, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        # Draw table
        table.wrapOn(c, 400, 200)
        table.drawOn(c, 100, y_position - (len(checks) * 20))
        
        y_position -= (len(checks) * 20) + 40
        if y_position < 100:
            c.showPage()
            y_position = 750
    
    # Summary and Recommendations
    c.showPage()
    y_position = 750
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, y_position, "Summary and Recommendations")
    y_position -= 30
    
    c.setFont("Helvetica", 10)
    recommendations = [
        "1. Ensure all security controls are enabled according to your compliance requirements",
        "2. Regularly review and update security configurations",
        "3. Monitor logs for suspicious activities",
        "4. Keep systems updated with the latest security patches",
        "5. Implement additional controls where gaps are identified"
    ]
    
    for rec in recommendations:
        c.drawString(100, y_position, rec)
        y_position -= 15
    
    c.save()

# Main execution
if __name__ == "__main__":
    print("Running Windows Compliance Gap Analysis...")
    compliance_data = collect_compliance_data()
    generate_pdf(compliance_data)
    print(f"Compliance report generated: compliance_report.pdf")