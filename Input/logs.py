import win32evtlog
import win32evtlogutil
import win32net
import win32security
import win32api
import socket
import platform
import os
import datetime
import json
import ctypes
import logging
from concurrent.futures import ThreadPoolExecutor
import psutil
import winreg
from fpdf import FPDF

def setup_logging():
    logging.basicConfig(
        filename='audit_errors.log',
        level=logging.ERROR,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def get_windows_auth_logs(limit=500):
    server = None  # Local machine
    logtype = 'Security'
    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    events = []
    try:
        while len(events) < limit:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break
            for record in records:
                if record.EventID in (4624, 4625):
                    try:
                        inserts = record.StringInserts if record.StringInserts else []
                        events.append({
                            'event_id': record.EventID,
                            'timestamp': record.TimeGenerated.Format(),
                            'username': inserts[5] if len(inserts) > 5 else 'N/A',
                            'ip': inserts[18] if len(inserts) > 18 else 'N/A',
                            'status': 'success' if record.EventID == 4624 else 'failed',
                            'logon_type': inserts[8] if len(inserts) > 8 else 'N/A'
                        })
                    except Exception as e:
                        logging.error(f"Error parsing auth log: {e}")
    finally:
        win32evtlog.CloseEventLog(hand)
    return events[:limit]

def get_windows_user_permissions():
    users = []
    resume = 0
    try:
        while True:
            result, total, resume = win32net.NetUserEnum(None, 2, 0, resume)  # Replaced FILTER_NORMAL_ACCOUNT with 0
            for user in result:
                try:
                    sid, domain, _ = win32security.LookupAccountName(None, user['name'])
                    users.append({
                        'username': user['name'],
                        'privilege_level': user['priv'],
                        'last_login': str(user['last_logon']),
                        'is_admin': 'Administrators' in domain
                    })
                except Exception as e:
                    logging.error(f"Error getting user permissions for {user['name']}: {e}")
            if not resume:
                break
    except Exception as e:
        logging.error(f"Error enumerating users: {e}")
    return users

def get_network_connections():
    try:
        connections = []
        for conn in psutil.net_connections(kind='tcp'):
            connections.append({
                'local_ip': conn.laddr.ip,
                'local_port': conn.laddr.port,
                'remote_ip': conn.raddr.ip if conn.raddr else 'N/A',
                'remote_port': conn.raddr.port if conn.raddr else 'N/A',
                'state': conn.status,
                'pid': conn.pid
            })
        return connections
    except Exception as e:
        logging.error(f"Error getting network connections: {e}")
        return []

def get_registry_value(key, subkey, value_name):
    """ Helper function to safely get registry values. """
    try:
        with winreg.OpenKey(key, subkey) as reg_key:
            return winreg.QueryValueEx(reg_key, value_name)[0]
    except FileNotFoundError:
        return None
    except Exception as e:
        return f"Error: {str(e)}"

def get_system_config():
    config = {
        'os_info': {
            'system': platform.system(),
            'version': platform.version(),
            'release': platform.release(),
            'architecture': platform.architecture()[0],
            'last_boot': datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
        },
        'firewall': {},
        'patches': {}
    }

    # Firewall Status
    firewall_key = r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
    config['firewall']['enabled'] = get_registry_value(winreg.HKEY_LOCAL_MACHINE, firewall_key, 'EnableFirewall')
    config['firewall']['default_in'] = get_registry_value(winreg.HKEY_LOCAL_MACHINE, firewall_key, 'DefaultInboundAction')
    config['firewall']['default_out'] = get_registry_value(winreg.HKEY_LOCAL_MACHINE, firewall_key, 'DefaultOutboundAction')

    # Installed patches
    patches_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
    config['patches']['last_success'] = get_registry_value(winreg.HKEY_LOCAL_MACHINE, patches_key, 'LastSuccessTime')
    config['patches']['last_error'] = get_registry_value(winreg.HKEY_LOCAL_MACHINE, patches_key, 'LastError')

    return config

def generate_pdf_report(data, filename):
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, txt="Windows Security Audit Report", ln=True, align="C")

    pdf.ln(10)
    
    # Audit Metadata
    pdf.set_font('Arial', '', 12)
    pdf.cell(200, 10, txt="Metadata:", ln=True)
    pdf.cell(200, 10, txt=f"  Audit Time: {data['metadata']['audit_time']}", ln=True)
    pdf.cell(200, 10, txt=f"  System: {data['metadata']['system']}", ln=True)
    pdf.cell(200, 10, txt=f"  Audit Version: {data['metadata']['audit_version']}", ln=True)
    
    pdf.ln(10)

    # Authentication Logs
    pdf.cell(200, 10, txt="Authentication Logs:", ln=True)
    for log in data['authentication_logs']:
        pdf.cell(200, 10, txt=f"  - Event ID: {log['event_id']}", ln=True)
        pdf.cell(200, 10, txt=f"    Status: {log['status']}", ln=True)
        pdf.cell(200, 10, txt=f"    Username: {log['username']}", ln=True)
        pdf.cell(200, 10, txt=f"    IP: {log['ip']}", ln=True)
        pdf.cell(200, 10, txt=f"    Logon Type: {log['logon_type']}", ln=True)
        pdf.ln(5)

    pdf.ln(10)

    # User Permissions
    pdf.cell(200, 10, txt="User Permissions:", ln=True)
    for user in data['user_permissions']:
        pdf.cell(200, 10, txt=f"  - Username: {user['username']}", ln=True)
        pdf.cell(200, 10, txt=f"    Privilege Level: {user['privilege_level']}", ln=True)
        pdf.cell(200, 10, txt=f"    Last Login: {user['last_login']}", ln=True)
        pdf.cell(200, 10, txt=f"    Admin: {user['is_admin']}", ln=True)
        pdf.ln(5)

    pdf.ln(10)

    # Network Connections
    pdf.cell(200, 10, txt="Network Connections:", ln=True)
    for conn in data['network_connections']:
        pdf.cell(200, 10, txt=f"  - Local IP: {conn['local_ip']}:{conn['local_port']}", ln=True)
        pdf.cell(200, 10, txt=f"    Remote IP: {conn['remote_ip']}:{conn['remote_port']}", ln=True)
        pdf.cell(200, 10, txt=f"    State: {conn['state']}", ln=True)
        pdf.cell(200, 10, txt=f"    PID: {conn['pid']}", ln=True)
        pdf.ln(5)

    pdf.ln(10)

    # System Config
    pdf.cell(200, 10, txt="System Configuration:", ln=True)
    pdf.cell(200, 10, txt=f"  OS: {data['system_config']['os_info']['system']} {data['system_config']['os_info']['release']} ({data['system_config']['os_info']['architecture']})", ln=True)
    pdf.cell(200, 10, txt=f"  Last Boot: {data['system_config']['os_info']['last_boot']}", ln=True)
    pdf.cell(200, 10, txt=f"  Firewall Enabled: {data['system_config']['firewall'].get('enabled', False)}", ln=True)
    pdf.cell(200, 10, txt=f"  Last Patch Success: {data['system_config']['patches'].get('last_success', 'N/A')}", ln=True)

    # Save PDF
    pdf.output(filename)
    print(f"PDF Report saved as {filename}")

def run_security_audit():
    print("Starting Windows Security Audit...")

    with ThreadPoolExecutor() as executor:
        future_auth_logs = executor.submit(get_windows_auth_logs)
        future_user_permissions = executor.submit(get_windows_user_permissions)
        future_network_connections = executor.submit(get_network_connections)
        future_system_config = executor.submit(get_system_config)

        audit_report = {
            'metadata': {
                'audit_time': datetime.datetime.now().isoformat(),
                'system': socket.gethostname(),
                'audit_version': '1.2'
            },
            'authentication_logs': future_auth_logs.result(),
            'user_permissions': future_user_permissions.result(),
            'network_connections': future_network_connections.result(),
            'system_config': future_system_config.result()
        }

    # Save JSON Report
    json_filename = f"windows_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_filename, 'w') as f:
        json.dump(audit_report, f, indent=2, default=str)
    
    print(f"\nAudit completed. JSON Report saved to {json_filename}")

    # Generate PDF Report
    pdf_filename = f"windows_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    generate_pdf_report(audit_report, pdf_filename)

    print(f"\nSummary Statistics:")
    print(f"- Authentication Events: {len(audit_report['authentication_logs'])}")
    print(f"- Users Audited: {len(audit_report['user_permissions'])}")
    print(f"- Active Connections: {len(audit_report['network_connections'])}")
    print(f"- Firewall Enabled: {audit_report['system_config']['firewall'].get('enabled', 'N/A')}")

if __name__ == "__main__":
    setup_logging()
    run_security_audit()
