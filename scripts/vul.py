#!/usr/bin/env python3
"""
Enhanced Windows Vulnerability Scanner
Continuously monitors Windows systems and generates comprehensive JSON/PDF reports
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
import threading
import logging
import winreg
import wmi
import psutil
import re
import ctypes
from datetime import datetime
from collections import defaultdict
import schedule
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

# Configuration
CONFIG = {
    "scan_interval": 300,  # 5 minutes
    "log_file": "C:\\Windows\\Temp\\vulnscanner.log",
    "report_dir": "C:\\VulnerabilityReports",
    "alert_threshold": "high",  # low, medium, high, critical
    "cve_check": True,
    "patch_check": True,
    "service_check": True,
    "process_monitor": True,
    "registry_check": True,
    "user_audit": True,
    "max_pdf_rows": 30  # Rows per PDF page
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['log_file']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('WinVulnScanner')

class WindowsVulnerabilityScanner:
    def __init__(self):
        self.system_info = self.get_system_info()
        self.vulnerabilities = []
        self.alerts = []
        self.wmi_conn = wmi.WMI()
        self.load_signatures()
        self.setup_directories()
        
    def setup_directories(self):
        """Ensure required directories exist"""
        if not os.path.exists(CONFIG['report_dir']):
            os.makedirs(CONFIG['report_dir'])
        
    def get_system_info(self):
        """Collect comprehensive Windows system information"""
        try:
            cs = self.wmi_conn.Win32_ComputerSystem()[0]
            os_info = self.wmi_conn.Win32_OperatingSystem()[0]
            
            return {
                'hostname': socket.gethostname(),
                'os_name': platform.system(),
                'os_version': platform.version(),
                'os_build': os_info.BuildNumber,
                'architecture': platform.machine(),
                'manufacturer': cs.Manufacturer,
                'model': cs.Model,
                'processor': self.wmi_conn.Win32_Processor()[0].Name,
                'total_ram': round(int(cs.TotalPhysicalMemory) / (1024**3), 2),  # GB
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'users': [u.Name for u in self.wmi_conn.Win32_UserAccount()],
                'last_boot': os_info.LastBootUpTime,
                'python_version': platform.python_version(),
                'scan_time': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get system info: {str(e)}")
            return {}
    
    def load_signatures(self):
        """Load Windows-specific vulnerability signatures"""
        self.signatures = {
            'cve': [
                {
                    'id': 'CVE-2020-0601',
                    'name': 'Windows CryptoAPI Spoofing Vulnerability',
                    'check': 'powershell Get-HotFix -Id KB4534273, KB4534271',
                    'pattern': r'Installed',
                    'severity': 'critical',
                    'os_versions': ['10', '2016', '2019']
                }
            ],
            'services': [
                {
                    'name': 'Telnet',
                    'state': 'Running',
                    'severity': 'high',
                    'description': 'Telnet service is enabled (insecure protocol)'
                }
            ],
            'registry': [
                {
                    'path': r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
                    'key': 'RestrictAnonymous',
                    'value': '1',
                    'severity': 'medium',
                    'description': 'Anonymous SID/Name translation should be restricted'
                }
            ],
            'files': [
                {
                    'path': r'C:\Windows\System32\drivers\etc\hosts',
                    'permissions': '644',
                    'severity': 'medium'
                }
            ]
        }
    
    def continuous_scan(self):
        """Run continuous scanning"""
        logger.info("Starting Windows real-time vulnerability monitoring")
        
        # Initial scan
        self.full_scan()
        
        # Schedule periodic scans
        schedule.every(CONFIG['scan_interval']).seconds.do(self.full_scan)
        
        # Run in background
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(1)
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        # Monitor for alerts
        try:
            while True:
                if self.alerts:
                    alert = self.alerts.pop(0)
                    self.handle_alert(alert)
                time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("Stopping vulnerability monitoring")
            sys.exit(0)
    
    def full_scan(self):
        """Perform comprehensive Windows vulnerability scan"""
        scan_time = datetime.now().isoformat()
        logger.info(f"Starting Windows scan at {scan_time}")
        
        self.vulnerabilities = []
        
        if CONFIG['cve_check']:
            self.check_known_cves()
        
        if CONFIG['patch_check']:
            self.check_missing_patches()
        
        if CONFIG['service_check']:
            self.check_vulnerable_services()
        
        if CONFIG['registry_check']:
            self.check_registry_settings()
        
        if CONFIG['process_monitor']:
            self.check_running_processes()
        
        if CONFIG['user_audit']:
            self.check_user_accounts()
        
        self.generate_reports()
        self.evaluate_alerts()
        
        logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
    
    def check_known_cves(self):
        """Check for known Windows CVEs"""
        logger.info("Checking for known Windows CVEs")
        
        for cve in self.signatures.get('cve', []):
            # Check if CVE applies to this OS version
            if 'os_versions' in cve:
                if not any(v in self.system_info.get('os_build', '') for v in cve['os_versions']):
                    continue
            
            try:
                result = subprocess.run(
                    ['powershell', '-Command', cve['check']],
                    capture_output=True,
                    text=True,
                    shell=True
                )
                
                if result.returncode == 0 and not re.search(cve['pattern'], result.stdout):
                    self.vulnerabilities.append({
                        'type': 'cve',
                        'id': cve['id'],
                        'name': cve['name'],
                        'severity': cve['severity'],
                        'description': f"Missing patch for {cve['name']} (CVE-{cve['id']})",
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception as e:
                logger.warning(f"Failed to check CVE {cve['id']}: {str(e)}")
    
    def check_missing_patches(self):
        """Check for missing Windows updates"""
        logger.info("Checking for missing Windows patches")
        
        try:
            # Get installed patches
            hotfixes = [hf.HotFixID for hf in self.wmi_conn.Win32_QuickFixEngineering()]
            
            # Check critical patches (example)
            critical_patches = ['KB5005039', 'KB5005043', 'KB5005565']
            
            for patch in critical_patches:
                if patch not in hotfixes:
                    self.vulnerabilities.append({
                        'type': 'missing_patch',
                        'kb': patch,
                        'severity': 'high',
                        'description': f"Missing critical Windows update {patch}",
                        'timestamp': datetime.now().isoformat()
                    })
        except Exception as e:
            logger.error(f"Patch check failed: {str(e)}")
    
    def check_vulnerable_services(self):
        """Check for vulnerable Windows services"""
        logger.info("Checking Windows services")
        
        try:
            for service in self.wmi_conn.Win32_Service():
                for vuln_service in self.signatures.get('services', []):
                    if service.Name == vuln_service['name'] and service.State == vuln_service['state']:
                        self.vulnerabilities.append({
                            'type': 'service',
                            'name': service.Name,
                            'state': service.State,
                            'severity': vuln_service['severity'],
                            'description': vuln_service['description'],
                            'timestamp': datetime.now().isoformat()
                        })
        except Exception as e:
            logger.error(f"Service check failed: {str(e)}")
    
    def check_registry_settings(self):
        """Check for insecure Windows registry settings"""
        logger.info("Checking Windows registry")
        
        for reg in self.signatures.get('registry', []):
            try:
                path_parts = reg['path'].split('\\')
                hive = path_parts[0]
                key_path = '\\'.join(path_parts[1:])
                
                # Map hive to registry constant
                hive_map = {
                    'HKLM': winreg.HKEY_LOCAL_MACHINE,
                    'HKCU': winreg.HKEY_CURRENT_USER,
                    'HKCR': winreg.HKEY_CLASSES_ROOT,
                    'HKU': winreg.HKEY_USERS
                }
                
                with winreg.OpenKey(hive_map[hive], key_path) as key:
                    value, _ = winreg.QueryValueEx(key, reg['key'])
                    if str(value) != reg['value']:
                        self.vulnerabilities.append({
                            'type': 'registry',
                            'path': reg['path'],
                            'key': reg['key'],
                            'current_value': str(value),
                            'recommended_value': reg['value'],
                            'severity': reg['severity'],
                            'description': reg['description'],
                            'timestamp': datetime.now().isoformat()
                        })
            except Exception as e:
                logger.warning(f"Registry check failed for {reg['path']}: {str(e)}")
    
    def check_running_processes(self):
        """Check for suspicious Windows processes"""
        logger.info("Checking running processes")
        
        suspicious_processes = [
            'mimikatz', 'cobaltstrike', 'metasploit', 'netcat',
            'nc.exe', 'powersploit', 'empire', 'processhacker'
        ]
        
        for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                proc_cmd = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                
                for suspicious in suspicious_processes:
                    if suspicious in proc_name or suspicious in proc_cmd:
                        self.vulnerabilities.append({
                            'type': 'suspicious_process',
                            'name': proc.info['name'],
                            'pid': proc.pid,
                            'severity': 'critical',
                            'description': f"Suspicious process {proc.info['name']} running",
                            'cmdline': proc.info['cmdline'],
                            'timestamp': datetime.now().isoformat()
                        })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def check_user_accounts(self):
        """Audit Windows user accounts for security issues"""
        logger.info("Checking user accounts")
        
        try:
            # Check for password never expires
            for user in self.wmi_conn.Win32_UserAccount():
                if user.PasswordExpires == False and user.Name != "Guest":
                    self.vulnerabilities.append({
                        'type': 'user_account',
                        'username': user.Name,
                        'severity': 'medium',
                        'description': f"User {user.Name} password never expires",
                        'timestamp': datetime.now().isoformat()
                    })
                
                # Check for admin accounts
                if user.LocalAccount and user.Enabled and user.Name not in ['Administrator', 'Guest']:
                    groups = [g.Name for g in user.associators(wmi_result_class='Win32_Group')]
                    if 'Administrators' in groups:
                        self.vulnerabilities.append({
                            'type': 'user_account',
                            'username': user.Name,
                            'severity': 'high',
                            'description': f"Standard user {user.Name} has administrative privileges",
                            'timestamp': datetime.now().isoformat()
                        })
        except Exception as e:
            logger.error(f"User audit failed: {str(e)}")
    
    def evaluate_alerts(self):
        """Evaluate vulnerabilities and generate alerts"""
        for vuln in self.vulnerabilities:
            if self.should_alert(vuln['severity']):
                self.alerts.append(vuln)
                logger.warning(f"ALERT: {vuln['description']} (Severity: {vuln['severity']})")
    
    def should_alert(self, severity):
        """Determine if vulnerability meets alert threshold"""
        severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold = severity_levels.get(CONFIG['alert_threshold'].lower(), 2)
        return severity_levels.get(severity.lower(), 0) >= threshold
    
    def handle_alert(self, alert):
        """Handle alert based on severity"""
        logger.warning(f"Handling alert: {alert['description']}")
        
        if alert['severity'] == 'critical':
            self.respond_to_critical(alert)
    
    def respond_to_critical(self, alert):
        """Take Windows-specific action for critical vulnerabilities"""
        logger.critical(f"Taking action for critical vulnerability: {alert['description']}")
        
        try:
            if alert['type'] == 'suspicious_process':
                os.kill(alert['pid'], 9)
                logger.info(f"Terminated suspicious process PID {alert['pid']}")
            
            elif alert['type'] == 'service':
                subprocess.run(
                    ['net', 'stop', alert['name'], '/y'],
                    check=True,
                    shell=True
                )
                logger.info(f"Stopped vulnerable service {alert['name']}")
        except Exception as e:
            logger.error(f"Failed to respond to alert: {str(e)}")
    
    def generate_reports(self):
        """Generate both JSON and PDF reports"""
        report_data = {
            'system': self.system_info,
            'vulnerabilities': self.vulnerabilities,
            'stats': {
                'total': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            }
        }
        
        # Generate JSON report
        json_path = os.path.join(
            CONFIG['report_dir'],
            f"windows_vulnscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        logger.info(f"JSON report saved to {json_path}")
        
        # Generate PDF report
        pdf_path = json_path.replace('.json', '.pdf')
        self.generate_pdf_report(pdf_path, report_data)
        logger.info(f"PDF report saved to {pdf_path}")
    
    def generate_pdf_report(self, pdf_path, report_data):
        """Generate professional PDF report"""
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Get or create custom styles
        if not hasattr(styles, 'ReportTitle'):
            styles.add(ParagraphStyle(
                name='ReportTitle',
                parent=styles['Heading1'],
                fontSize=16,
                alignment=TA_CENTER,
                spaceAfter=20
            ))
        
        if not hasattr(styles, 'SectionHeader'):
            styles.add(ParagraphStyle(
                name='SectionHeader',
                parent=styles['Heading2'],
                fontSize=12,
                spaceBefore=12,
                spaceAfter=6
            ))
        
        # Report content
        elements = []
        
        # Title
        elements.append(Paragraph("Windows Vulnerability Scan Report", styles['ReportTitle']))
        elements.append(Paragraph(f"Generated: {report_data['system']['scan_time']}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # System Information
        elements.append(Paragraph("System Information", styles['SectionHeader']))
        sys_info = [
            ["Hostname", report_data['system']['hostname']],
            ["OS", f"{report_data['system']['os_name']} {report_data['system']['os_version']}"],
            ["Architecture", report_data['system']['architecture']],
            ["Processor", report_data['system']['processor']],
            ["RAM", f"{report_data['system']['total_ram']} GB"],
            ["IP Address", report_data['system']['ip_address']],
            ["Last Boot", report_data['system']['last_boot']]
        ]
        sys_table = Table(sys_info, colWidths=[150, 300])
        sys_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        elements.append(sys_table)
        elements.append(Spacer(1, 20))
        
        # Vulnerabilities
        elements.append(Paragraph("Vulnerabilities Found", styles['SectionHeader']))
        
        if not report_data['vulnerabilities']:
            elements.append(Paragraph("No vulnerabilities detected", styles['Normal']))
        else:
            # Group vulnerabilities by severity
            vuln_by_severity = defaultdict(list)
            for vuln in report_data['vulnerabilities']:
                vuln_by_severity[vuln['severity']].append(vuln)
            
            # Process each severity group
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in vuln_by_severity:
                    elements.append(Paragraph(f"{severity.capitalize()} Severity Issues", styles['Heading3']))
                    
                    # Create vulnerability table
                    vuln_data = [["Type", "Description", "Timestamp"]]
                    for vuln in vuln_by_severity[severity]:
                        vuln_data.append([
                            vuln['type'],
                            vuln['description'],
                            datetime.fromisoformat(vuln['timestamp']).strftime('%Y-%m-%d %H:%M')
                        ])
                    
                    # Create table with alternating row colors
                    vuln_table = Table(vuln_data, colWidths=[80, 300, 100])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('BACKGROUND', (0, 1), (-1, -1), 
                         colors.lightgrey if severity == 'critical' else 
                         colors.lightsteelblue if severity == 'high' else 
                         colors.lemonchiffon if severity == 'medium' else 
                         colors.honeydew),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                    ]))
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 10))
        
        # Build PDF document
        doc.build(elements)

if __name__ == "__main__":
    # Check for admin privileges
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        logger.error("This script requires Administrator privileges")
        sys.exit(1)
    
    scanner = WindowsVulnerabilityScanner()
    scanner.continuous_scan()