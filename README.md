<div align="center">
  <h1>🛡️ WinSentry</h1>
  <p><strong>A zero-trace, purely local, read-only Windows security posture auditor.</strong></p>
</div>

---

## 🌟 What is WinSentry?

**WinSentry** is a powerful defensive blue-team tool designed to give you a complete, unvarnished look at your Windows machine's security and system health. 

It acts like an X-ray for your PC, combining the insights of Windows Defender and PC Health Manager into one unified, offline, and beautifully formatted encrypted PDF report. 

Best of all? **It changes absolutely nothing.** It is a strict "look but don't touch" tool, meaning it is 100% safe to run on any machine without the fear of it breaking your system or sending your data to the cloud.

---

## 🤔 Why use WinSentry?

In an era of cloud telemetry and "smart" autonomous tools, WinSentry takes a step back to pure transparency and control:

- 🛑 **Zero Network Footprint:** WinSentry does not phone home. It makes no API calls, no telemetry requests, and has no cloud dashboard. Your data stays on your machine.
- 🚫 **Zero Mutation:** It only reads data. It will never install patches, disable services, or quarantine files automatically.
- 🥷 **Zero Trace:** The moment the scan finishes, the tool produces an AES-encrypted PDF locked with your password. All intermediate data and logs are securely wiped from your drive.
- 💡 **Actionable Intelligence:** When WinSentry finds an issue (like a disabled Defender setting), it gives you the exact PowerShell command to fix it yourself. *You* remain in the driver's seat.

---

## 🔍 What does it scan?

WinSentry evaluates 8 critical modules of your system:
1. 🛡️ **Defender Health:** Real-time protection, tamper protection, exclusions, and signature age.
2. 🚨 **Defender Activity:** A history of threats Defender has already caught.
3. 💻 **System Health:** Physical disk health, TPM status, OS version readiness, and system restore points.
4. 🔌 **Remote Access:** Open RDP ports, active sessions, and installed remote-access software (like AnyDesk or TeamViewer).
5. 🌐 **Network:** Established connections and open listening ports.
6. 🪤 **Persistence:** Unsigned binaries in auto-start folders and sneaky "typosquatting" malware disguising itself as core Windows processes.
7. 👥 **Accounts:** Local users and administrators with non-expiring passwords.
8. 🩹 **Patching:** Your most recent Windows update history.

---

## 🚀 How to Use WinSentry

### Prerequisites
- Windows 10 or Windows 11.
- Administrator privileges (for the most accurate scan).
- No installations required!

### Step 1: Run the Scanner
1. Open PowerShell as **Administrator**.
2. Navigate to the folder containing WinSentry.
3. Run the following command to temporarily allow the script to execute (this does not permanently weaken your machine's security policy):
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\WinSentry.ps1
   ```
4. You will be prompted to enter a **password**. This password will be used to lock the final PDF report.

### Step 2: Review your Report
Once the scan finishes, WinSentry will securely wipe all temporary data and generate a single file:
📄 `WinSentry_Report_Encrypted.pdf`

Open this PDF using the password you provided. You'll see a dynamic Risk Score (0-100), severity breakdowns, and detailed findings. 

### Step 3: (Optional) Compare Scans
Want to see what changed since your last scan? You can pass an older JSON report (if you chose to save one manually) to see a diff of new and resolved issues:
```powershell
.\WinSentry.ps1 -CompareTo "C:\path\to\old_report.json"
```

---

## 🔬 Sibling Tool: `winsentry-lookup.ps1`
Because the main `WinSentry.ps1` script is strictly offline, we've included a completely separate tool for investigating suspicious files found in your report.

Run `.\winsentry-lookup.ps1 -Path "C:\suspicious\file.exe"` to compute the file's hash locally. It will explicitly ask for your permission before securely querying VirusTotal's API to see if the file is known malware. (Requires a free VirusTotal API key).

---

<div align="center">
  <p>Built for personal auditing & blue-team defense.</p>
</div>
