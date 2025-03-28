import json
import platform
import socket
import subprocess
import psutil
from datetime import datetime
from fpdf import FPDF  # For PDF export (install with: pip install fpdf)

def get_system_info():
    """Collect hardware, OS, network, and software data"""
    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system": {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.architecture()[0],
            "machine": platform.machine()
        },
        "hardware": {
            "processor": platform.processor(),
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "available_ram_gb": round(psutil.virtual_memory().available / (1024**3), 2)
        },
        "storage": [],
        "network": [],
        "software": get_installed_software()
    }

    # Disk information
    for part in psutil.disk_partitions(all=False):
        if part.fstype:
            usage = psutil.disk_usage(part.mountpoint)
            info["storage"].append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2)
            })

    # Network information
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                info["network"].append({
                    "interface": name,
                    "ip_address": addr.address,
                    "netmask": addr.netmask
                })

    return info

def get_installed_software():
    """Get installed software (Windows only)"""
    try:
        cmd = [
            "powershell",
            "Get-ItemProperty",
            "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
            "|", "Select-Object", "DisplayName,DisplayVersion,Publisher,InstallDate",
            "|", "ConvertTo-Json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return json.loads(result.stdout) if result.stdout else []
    except:
        return []

def generate_json_report(data, filename="asset_inventory.json"):
    """Generate JSON report"""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"JSON report generated: {filename}")

def generate_pdf_report(data, filename="asset_inventory.pdf"):
    """Generate PDF report"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    
    # Title
    pdf.cell(200, 10, txt="Asset Inventory Report", ln=1, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    
    # System Information
    pdf.cell(200, 10, txt="System Information", ln=1, align="L")
    for key, value in data["system"].items():
        pdf.cell(200, 10, txt=f"{key.title()}: {value}", ln=1)
    pdf.ln(5)
    
    # Hardware Information
    pdf.cell(200, 10, txt="Hardware Information", ln=1, align="L")
    for key, value in data["hardware"].items():
        pdf.cell(200, 10, txt=f"{key.title().replace('_', ' ')}: {value}", ln=1)
    pdf.ln(5)
    
    # Storage Information
    pdf.cell(200, 10, txt="Storage Devices", ln=1, align="L")
    for disk in data["storage"]:
        pdf.cell(200, 10, txt=f"Device: {disk['device']}", ln=1)
        pdf.cell(200, 10, txt=f"Mountpoint: {disk['mountpoint']}", ln=1)
        pdf.cell(200, 10, txt=f"Size: {disk['total_gb']} GB (Used: {disk['used_gb']} GB)", ln=1)
        pdf.ln(2)
    
    # Network Information
    pdf.cell(200, 10, txt="Network Interfaces", ln=1, align="L")
    for net in data["network"]:
        pdf.cell(200, 10, txt=f"Interface: {net['interface']}", ln=1)
        pdf.cell(200, 10, txt=f"IP Address: {net['ip_address']}", ln=1)
        pdf.ln(2)
    
    # Installed Software
    pdf.cell(200, 10, txt="Installed Software", ln=1, align="L")
    for software in data["software"]:
        if 'DisplayName' in software:
            pdf.cell(200, 10, txt=f"- {software['DisplayName']} (v{software.get('DisplayVersion', '?')})", ln=1)
    
    pdf.output(filename)
    print(f"PDF report generated: {filename}")

if __name__ == "__main__":
    print("Collecting system information...")
    inventory_data = get_system_info()
    
    print("Generating reports...")
    generate_json_report(inventory_data)
    generate_pdf_report(inventory_data)
    
    print("Asset inventory completed!")