#!/usr/bin/env python3
import json
import html
import sys
import argparse
from pathlib import Path
from datetime import datetime
import os
import subprocess
import pathlib
import getpass
from PyPDF2 import PdfReader, PdfWriter

def parse_args():
    parser = argparse.ArgumentParser(description="Generate WinSentry PDF Report")
    parser.add_argument("input_json", help="Path to input JSON file")
    parser.add_argument("output_pdf", help="Path to output PDF file")
    return parser.parse_args()

def validate_schema(data):
    required_keys = {"scan_metadata", "risk_score", "scoring_weights", "modules"}
    if not all(k in data for k in required_keys):
        raise ValueError(f"Invalid JSON schema. Missing one of: {required_keys}")
    
    for mod_name, mod_data in data["modules"].items():
        if "status" not in mod_data or "findings" not in mod_data:
            raise ValueError(f"Module {mod_name} is missing 'status' or 'findings'.")
        
        for f in mod_data["findings"]:
            for fk in ["id", "severity", "title", "detail", "recommendation"]:
                if fk not in f:
                    raise ValueError(f"Finding in {mod_name} missing key '{fk}': {f}")

def safe_html(text):
    if text is None:
        return ""
    return html.escape(str(text))

def render_tags(finding):
    tags_html = ""
    if "signature_status" in finding:
        status = safe_html(finding["signature_status"])
        color = "#4CAF50" if status == "Valid" else "#F44336"
        tags_html += f'<div class="tag" style="background-color: {color};">Sig: {status}</div>'
    if "signer_subject" in finding and finding["signer_subject"]:
        subject = safe_html(finding["signer_subject"])
        tags_html += f'<div class="tag tag-blue">Signer: {subject}</div>'
    if "lookalike_match" in finding and finding["lookalike_match"]:
        match = safe_html(finding["lookalike_match"])
        tags_html += f'<div class="tag tag-red">Lookalike: {match}</div>'
    return f'<div class="tags-container">{tags_html}</div>' if tags_html else ""

def render_remediation(finding):
    if "remediation_command" in finding and finding["remediation_command"]:
        cmd = safe_html(finding["remediation_command"])
        return f'<div class="remediation-box"><strong>Run this yourself:</strong><br><code>{cmd}</code></div>'
    return ""

def generate_findings_table(findings):
    if not findings:
        return "<p class=\"no-findings\">No findings.</p>"
    
    html_out = "<table class=\"findings\"><thead><tr><th style=\"width: 10%;\">ID</th><th style=\"width: 12%;\">Severity</th><th style=\"width: 25%;\">Title</th><th style=\"width: 33%;\">Detail</th><th style=\"width: 20%;\">Recommendation</th></tr></thead><tbody>"
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["severity"], 5)):
        sev = safe_html(f["severity"])
        sev_class = f"sev-{sev.lower()}"
        
        detail_html = safe_html(f["detail"]).replace("\n", "<br>")
        tags = render_tags(f)
        remediation = render_remediation(f)
        
        html_out += f"""
        <tr>
            <td>{safe_html(f["id"])}</td>
            <td><span class="severity-badge {sev_class}">{sev}</span></td>
            <td>{safe_html(f["title"])}<br/>{tags}</td>
            <td class="code-wrap">{detail_html}{remediation}</td>
            <td>{safe_html(f["recommendation"])}</td>
        </tr>
        """
    html_out += "</tbody></table>"
    return html_out

def generate_html(data):
    meta = data["scan_metadata"]
    risk_score = data["risk_score"]
    
    # Calculate severity counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for mod_data in data["modules"].values():
        for f in mod_data["findings"]:
            s = f.get("severity")
            if s in sev_counts:
                sev_counts[s] += 1
                
    # Determine gauge color
    gauge_color = "#4CAF50" if risk_score >= 80 else "#FF9800" if risk_score >= 50 else "#F44336"
    
    # Module descriptions
    module_descriptions = {
        "registry_autoruns": "Checks Windows Registry keys commonly used for persistence and auto-starting malware.",
        "scheduled_tasks": "Analyzes scheduled tasks for suspicious binaries, scripts, or abnormal execution parameters.",
        "services": "Scans Windows services for unquoted paths, malicious executables, or rogue installations.",
        "active_connections": "Monitors active network connections for communication with suspicious IP addresses or ports.",
        "running_processes": "Detects anomalies in running processes, lookalike names, and unsigned executables.",
        "process_injection": "Identifies memory anomalies that might indicate code injection or hollowing.",
        "wmi_persistence": "Scans WMI event filters and consumers used for fileless malware persistence.",
        "user_accounts": "Checks for recently added or hidden user accounts that attackers use for backdoor access.",
        "security_events": "Analyzes Windows Event Logs for failed logins, cleared logs, or other suspicious activity.",
        "file_system": "Scans critical system directories for unexpected files, executables, or scripts."
    }

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WinSentry Report - {safe_html(meta.get('hostname', 'Unknown'))}</title>
    <style>
        body {{
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            background-color: #F8F9FA;
            color: #212529;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header-table {{
            width: 100%;
            background-color: #FFFFFF;
            padding: 20px;
            margin-bottom: 25px;
            border: 1px solid #DEE2E6;
        }}
        h1 {{
            color: #1A1D20;
            margin-bottom: 20px;
            text-align: center;
        }}
        .score-gauge {{
            font-size: 3rem;
            font-weight: bold;
            color: {gauge_color};
            text-align: center;
            margin-bottom: 5px;
        }}
        .stat-box {{
            background-color: #F8F9FA;
            padding: 15px;
            text-align: center;
            border: 1px solid #DEE2E6;
        }}
        .stat-box .count {{
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .sev-critical {{ color: #D32F2F; }}
        .sev-high {{ color: #F57C00; }}
        .sev-medium {{ color: #FBC02D; }}
        .sev-low {{ color: #1976D2; }}
        .sev-info {{ color: #757575; }}
        
        .severity-badge {{
            font-weight: bold;
            padding: 4px 8px;
            color: #FFFFFF;
            font-size: 0.85em;
            text-align: center;
            display: block;
        }}
        .severity-badge.sev-critical {{ background-color: #D32F2F; }}
        .severity-badge.sev-high {{ background-color: #F57C00; }}
        .severity-badge.sev-medium {{ background-color: #FBC02D; }}
        .severity-badge.sev-low {{ background-color: #1976D2; }}
        .severity-badge.sev-info {{ background-color: #757575; }}
        
        .module-section {{
            background-color: #FFFFFF;
            padding: 20px;
            margin-bottom: 30px;
            border: 1px solid #DEE2E6;
        }}
        .module-header {{
            border-bottom: 2px solid #E9ECEF;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        .module-description {{
            color: #6C757D;
            font-size: 0.9em;
            margin-top: -10px;
            margin-bottom: 15px;
        }}
        h2, h3 {{ 
            margin-top: 0; 
            color: #343A40;
        }}
        
        table.findings {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            border: 1px solid #DEE2E6;
        }}
        table.findings th, table.findings td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #DEE2E6;
            border-right: 1px solid #DEE2E6;
            vertical-align: top;
        }}
        table.findings th {{ 
            background-color: #E9ECEF; 
            font-weight: bold;
            color: #495057;
        }}
        table.findings tr:nth-child(even) {{
            background-color: #F8F9FA;
        }}
        
        .code-wrap {{
            font-family: Consolas, monospace;
            font-size: 0.85em;
            color: #D81B60;
            background-color: #FDF4F6;
            padding: 2px 4px;
            border: 1px solid #F8D7DA;
            display: block;
            margin-bottom: 5px;
        }}
        
        .tags-container {{
            margin-top: 8px;
        }}
        .tag {{
            font-size: 0.75em;
            color: #fff;
            background-color: #6C757D;
            padding: 3px 6px;
            margin-top: 3px;
            display: block;
        }}
        .tag-blue {{ background-color: #0288D1; }}
        .tag-red {{ background-color: #D32F2F; }}
        
        .remediation-box {{
            margin-top: 10px;
            background-color: #E8F5E9;
            padding: 10px;
            border-left: 4px solid #4CAF50;
        }}
        .remediation-box code {{
            color: #2E7D32;
            font-family: Consolas, monospace;
            font-weight: bold;
        }}
        .remediation-box strong {{
            color: #1B5E20;
            display: block;
            margin-bottom: 4px;
        }}
        
        .diff-section {{
            border-left: 4px solid #1976D2;
        }}
        .no-findings {{
            color: #28A745;
            font-weight: bold;
            padding: 10px;
            background-color: #E8F5E9;
            border: 1px solid #C8E6C9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>WinSentry Security Report</h1>
        
        <table class="header-table">
            <tr>
                <td style="width: 35%; vertical-align: top;">
                    <h3 style="margin-bottom: 10px; color: #495057;">Scan Metadata</h3>
                    <p style="margin: 4px 0;"><strong>Hostname:</strong> {safe_html(meta.get('hostname'))}</p>
                    <p style="margin: 4px 0;"><strong>Time (UTC):</strong> {safe_html(meta.get('scan_time_utc'))}</p>
                    <p style="margin: 4px 0;"><strong>Admin:</strong> {safe_html(str(meta.get('ran_as_admin')))}</p>
                    <p style="margin: 4px 0;"><strong>Operator:</strong> {safe_html(meta.get('operator'))}</p>
                </td>
                <td style="width: 25%; vertical-align: middle; text-align: center;">
                    <div class="score-gauge">{risk_score}/100</div>
                    <div style="color: #6C757D; font-weight: bold; font-size: 1.1em;">Risk Score</div>
                </td>
                <td style="width: 40%; vertical-align: middle;">
                    <table style="width: 100%;">
                        <tr>
                            <td class="stat-box"><div class="count sev-critical">{sev_counts["CRITICAL"]}</div><span style="font-size: 0.8em; color: #6C757D;">CRITICAL</span></td>
                            <td class="stat-box"><div class="count sev-high">{sev_counts["HIGH"]}</div><span style="font-size: 0.8em; color: #6C757D;">HIGH</span></td>
                            <td class="stat-box"><div class="count sev-medium">{sev_counts["MEDIUM"]}</div><span style="font-size: 0.8em; color: #6C757D;">MEDIUM</span></td>
                            <td class="stat-box"><div class="count sev-low">{sev_counts["LOW"]}</div><span style="font-size: 0.8em; color: #6C757D;">LOW</span></td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        
        <div class="module-section">
            <div class="module-header">
                <h2>Scoring Weights</h2>
            </div>
            <pre style="color: #495057; font-size: 0.9em; white-space: pre-wrap; background-color: #F8F9FA; padding: 10px; border: 1px solid #DEE2E6;">
Formula: module_score = max_weight - (critical_count * 15 + high_count * 10 + medium_count * 5 + low_count * 2)
Floored at 0. Total score is the sum of all module scores.

Weights:
{safe_html(json.dumps(data.get("scoring_weights", dict()), indent=2))}
            </pre>
        </div>
"""

    if "diff" in data:
        diff = data["diff"]
        html_content += f"""
        <div class="module-section diff-section">
            <div class="module-header">
                <h2>Diff (Comparison)</h2>
            </div>
            <p class="module-description">Shows the differences between this scan and the baseline comparison scan.</p>
            <h3>New Findings</h3>
            {generate_findings_table(diff.get("new", []))}
            <h3 style="margin-top: 20px;">Resolved Findings</h3>
            {generate_findings_table(diff.get("resolved", []))}
            <h3 style="margin-top: 20px;">Unchanged Findings</h3>
            {generate_findings_table(diff.get("unchanged", []))}
        </div>
        """

    for mod_name, mod_data in data["modules"].items():
        status = safe_html(mod_data.get("status"))
        status_color = "#28A745" if status == "ok" else "#F57C00"
        description = module_descriptions.get(mod_name, "Analyzes system components for security risks.")
        
        html_content += f"""
        <div class="module-section">
            <div class="module-header">
                <h2>{safe_html(mod_name).replace('_', ' ').title()} <span style="font-size: 0.6em; color: {status_color};">[{status}]</span></h2>
            </div>
            <p class="module-description">{safe_html(description)}</p>
            {generate_findings_table(mod_data.get("findings", []))}
        </div>
        """

    html_content += """
    </div>
</body>
</html>
"""
    return html_content

def generate_pdf(html_content, final_pdf_path, password):
    from xhtml2pdf import pisa
    import io
    import os
    
    is_base64 = final_pdf_path == "BASE64"
    if not is_base64:
        final_pdf_path = os.path.abspath(final_pdf_path)
    
    # Use xhtml2pdf to generate PDF natively in memory
    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf_buffer)
    
    if pisa_status.err:
        raise RuntimeError("xhtml2pdf failed to generate PDF.")
        
    pdf_buffer.seek(0)
    
    # Encrypt the PDF
    reader = PdfReader(pdf_buffer)
    writer = PdfWriter()
    
    for page in reader.pages:
        writer.add_page(page)
        
    writer.encrypt(password)
    
    # Write the encrypted PDF directly to the final file safely
    final_buffer = io.BytesIO()
    writer.write(final_buffer)
    
    if is_base64:
        import base64
        sys.stdout.write("BASE64_PDF_START\n")
        sys.stdout.write(base64.b64encode(final_buffer.getvalue()).decode('utf-8'))
        sys.stdout.write("\nBASE64_PDF_END\n")
        sys.stdout.flush()
        return

    fds_to_close = []
    fd = -1
    try:
        while True:
            fd = os.open(final_pdf_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_BINARY', 0))
            if fd > 2:
                break
            fds_to_close.append(fd)
        os.write(fd, final_buffer.getvalue())
    finally:
        if fd > 2:
            try:
                os.close(fd)
            except:
                pass
        for bad_fd in fds_to_close:
            try:
                os.close(bad_fd)
            except:
                pass

def main():
    import os
    # Prevent Windows CRT bug where FD 0, 1, or 2 are reused for writing
    try:
        _dummy1 = open(os.devnull, 'r')
        _dummy2 = open(os.devnull, 'w')
        _dummy3 = open(os.devnull, 'w')
    except:
        pass

    args = parse_args()

    password = None

    try:
        if args.input_json == "-":
            # Read from standard input (pipeline)
            payload = sys.stdin.read()
            if not payload.strip():
                raise ValueError("No data received from standard input.")
            
            # The first line is the password, the rest is JSON
            if "\n" not in payload:
                raise ValueError("Invalid STDIN format. Expected password on first line.")
            
            password_line, json_str = payload.split("\n", 1)
            password = password_line.strip()
            
            if not password:
                print("Error: Password is required to encrypt the PDF.", file=sys.stderr)
                sys.exit(1)
                
            data = json.loads(json_str)
        else:
            # Fallback for manual file reading (still requires getpass here if not piped)
            print("PDF Encryption Setup", file=sys.stderr)
            password = getpass.getpass("Enter a strong password to lock the report: ")
            if not password:
                print("Error: Password is required to encrypt the PDF.", file=sys.stderr)
                sys.exit(1)
            with open(args.input_json, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        validate_schema(data)
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    html_content = generate_html(data)
    
    try:
        generate_pdf(html_content, args.output_pdf, password)
        print(f"Successfully generated encrypted PDF report at: {args.output_pdf}")
    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        sys.stderr.write(f"An error occurred: {e}\n{err_msg}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
