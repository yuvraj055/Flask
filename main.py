from flask import Flask, render_template, request, send_file
import subprocess
import winreg
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)

# Security check functions (existing and new)

def check_firewall_status():
    try:
        output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error fetching firewall status: {e}"

def check_antivirus_status():
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        return "Antivirus Status: Active"
    except Exception as e:
        return f"Error checking antivirus status: {e}"

def check_windows_update_status():
    try:
        output = subprocess.check_output("powershell Get-WindowsUpdateLog", shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error fetching Windows Update status: {e}"

# New security checks

def check_admin_status():
    try:
        output = subprocess.check_output("net session", shell=True, text=True)
        return "User is an Administrator" if "Access denied" not in output else "User is not an Administrator"
    except subprocess.CalledProcessError as e:
        return f"Error checking admin status: {e}"

def check_audit_policy():
    try:
        output = subprocess.check_output("auditpol /get /category:*", shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error checking audit policy: {e}"

def check_installed_patches():
    try:
        output = subprocess.check_output("wmic qfe list", shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error fetching installed patches: {e}"

def check_account_lockout_policy():
    try:
        output = subprocess.check_output("net accounts", shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error checking account lockout policy: {e}"

# Main audit function
def system_audit():
    return {
        "firewall_status": check_firewall_status(),
        "antivirus_status": check_antivirus_status(),
        "windows_update_status": check_windows_update_status(),
        "admin_status": check_admin_status(),
        "audit_policy": check_audit_policy(),
        "installed_patches": check_installed_patches(),
        "account_lockout_policy": check_account_lockout_policy(),
    }

# Improved PDF generation function
def generate_pdf(audit_results):
    filename = "audit_report.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph("System Security Audit Report", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 12))

    for section, result in audit_results.items():
        section_title = Paragraph(f"<b>{section.replace('_', ' ').title()}:</b>", styles["Heading2"])
        elements.append(section_title)
        elements.append(Spacer(1, 6))
        
        # Wrap long outputs for better visibility
        result = result.replace('\n', '<br/>')
        result_text = Paragraph(f"<pre>{result}</pre>", styles["BodyText"])

        elements.append(result_text)
        elements.append(Spacer(1, 12))

    doc.build(elements)
    return filename

# Flask routes
@app.route("/", methods=["GET", "POST"])
def dashboard():
    audit_results = None
    if request.method == "POST":
        audit_results = system_audit()  # Run the audit when button is clicked
        return render_template("dashboard.html", audit=audit_results)
    
    return render_template("dashboard.html", audit=audit_results)

@app.route("/download_report")
def download_report():
    audit_results = system_audit()  # Run the audit to get the latest data
    pdf_filename = generate_pdf(audit_results)
    return send_file(pdf_filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
