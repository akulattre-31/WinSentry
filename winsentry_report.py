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
        tags_html += f'<span class="tag" style="background-color: {color};">Sig: {status}</span>'
    if "signer_subject" in finding and finding["signer_subject"]:
        subject = safe_html(finding["signer_subject"])
        tags_html += f'<span class="tag tag-blue">Signer: {subject}</span>'
    if "lookalike_match" in finding and finding["lookalike_match"]:
        match = safe_html(finding["lookalike_match"])
        tags_html += f'<span class="tag tag-red">Lookalike: {match}</span>'
    return f'<div class="tags-container">{tags_html}</div>' if tags_html else ""

def render_remediation(finding):
    if "remediation_command" in finding and finding["remediation_command"]:
        cmd = safe_html(finding["remediation_command"])
        return f'<div class="remediation-box"><strong>Run this yourself:</strong><br><code>{cmd}</code></div>'
    return ""

def generate_findings_table(findings):
    if not findings:
        return "<p>No findings.</p>"
    
    html_out = "<table><thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Detail</th><th>Recommendation</th></tr></thead><tbody>"
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
            <td>{safe_html(f["title"])}{tags}</td>
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

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WinSentry Report - {safe_html(meta.get('hostname', 'Unknown'))}</title>
    <style>
        :root {{
            --bg-color: #121212;
            --surface-color: #1E1E1E;
            --text-primary: #FFFFFF;
            --text-secondary: #B0B0B0;
            --border-color: #333333;
            --critical: #F44336;
            --high: #FF9800;
            --medium: #FFEB3B;
            --low: #2196F3;
            --info: #9E9E9E;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header-card {{
            background-color: var(--surface-color);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid var(--border-color);
        }}
        .score-gauge {{
            font-size: 3rem;
            font-weight: bold;
            color: {gauge_color};
            text-align: center;
        }}
        .stats-grid {{
            display: flex;
            gap: 15px;
        }}
        .stat-box {{
            background-color: #2D2D2D;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            min-width: 80px;
        }}
        .stat-box .count {{
            font-size: 1.5rem;
            font-weight: bold;
        }}
        .sev-critical {{ color: var(--critical); }}
        .sev-high {{ color: var(--high); }}
        .sev-medium {{ color: var(--medium); }}
        .sev-low {{ color: var(--low); }}
        .sev-info {{ color: var(--info); }}
        
        .severity-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            background-color: #333;
        }}
        
        .module-section {{
            background-color: var(--surface-color);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }}
        h2, h3 {{ margin-top: 0; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ background-color: #2D2D2D; }}
        
        .code-wrap {{
            font-family: Consolas, monospace;
            font-size: 0.9em;
            word-break: break-all;
            color: #E0E0E0;
        }}
        
        .tags-container {{
            margin-top: 6px;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}
        .tag {{
            font-size: 0.75em;
            padding: 2px 6px;
            border-radius: 3px;
            color: #fff;
            background-color: #555;
        }}
        .tag-blue {{ background-color: #1976D2; }}
        .tag-red {{ background-color: #D32F2F; }}
        
        .remediation-box {{
            margin-top: 10px;
            background-color: #121212;
            border-left: 3px solid #FF9800;
            padding: 8px;
            border-radius: 4px;
        }}
        .remediation-box code {{
            color: #4CAF50;
            user-select: all;
            font-family: Consolas, monospace;
        }}
        .remediation-box strong {{
            color: #FF9800;
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        
        .diff-section {{
            border-left: 4px solid #2196F3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>WinSentry Security Report</h1>
        
        <div class="header-card">
            <div>
                <h3>Scan Metadata</h3>
                <p><strong>Hostname:</strong> {safe_html(meta.get('hostname'))}</p>
                <p><strong>Time (UTC):</strong> {safe_html(meta.get('scan_time_utc'))}</p>
                <p><strong>Admin:</strong> {safe_html(str(meta.get('ran_as_admin')))}</p>
                <p><strong>Operator:</strong> {safe_html(meta.get('operator'))}</p>
            </div>
            
            <div>
                <div class="score-gauge">{risk_score}/100</div>
                <div style="text-align: center; color: var(--text-secondary);">Risk Score</div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box"><div class="count sev-critical">{sev_counts["CRITICAL"]}</div>CRITICAL</div>
                <div class="stat-box"><div class="count sev-high">{sev_counts["HIGH"]}</div>HIGH</div>
                <div class="stat-box"><div class="count sev-medium">{sev_counts["MEDIUM"]}</div>MEDIUM</div>
                <div class="stat-box"><div class="count sev-low">{sev_counts["LOW"]}</div>LOW</div>
            </div>
        </div>
        
        <div class="module-section">
            <h2>Scoring Weights</h2>
            <pre style="color: var(--text-secondary); font-size: 0.9em; white-space: pre-wrap;">
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
            <h2>Diff (Comparison)</h2>
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
        status_color = "#4CAF50" if status == "ok" else "#FF9800"
        
        html_content += f"""
        <div class="module-section">
            <h2>{safe_html(mod_name).replace('_', ' ').title()} <span style="font-size: 0.6em; color: {status_color};">[{status}]</span></h2>
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
    import tempfile
    
    # Create temp files
    temp_dir = tempfile.mkdtemp()
    html_path = os.path.join(temp_dir, "temp.html")
    temp_pdf_path = os.path.join(temp_dir, "temp.pdf")
    
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    html_abs = str(pathlib.Path(html_path).absolute())
    temp_pdf_abs = str(pathlib.Path(temp_pdf_path).absolute())
    
    # Use MS Edge to generate PDF natively
    edge_cmd = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "--headless",
        "--disable-gpu",
        f"--print-to-pdf={temp_pdf_abs}",
        html_abs
    ]
    try:
        subprocess.run(edge_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Encrypt the PDF
        reader = PdfReader(temp_pdf_abs)
        writer = PdfWriter()
        
        for page in reader.pages:
            writer.add_page(page)
            
        writer.encrypt(password)
        
        with open(final_pdf_path, "wb") as f:
            writer.write(f)
            
    finally:
        # Secure cleanup attempt
        if os.path.exists(html_path):
            os.remove(html_path)
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)
        os.rmdir(temp_dir)

def main():
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
        print(f"Error generating PDF: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
