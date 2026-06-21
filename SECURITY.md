# WinSentry v1 Security Boundaries & Usage

**Author:** Akul Attre

This document outlines the strict security boundaries, design philosophy, and usage constraints of WinSentry v1.

## 1. What WinSentry.ps1 Does NOT Do

WinSentry is designed to be a fully local, zero-network-footprint, read-only auditor.
- **No Remote Calls:** The main scanner `WinSentry.ps1` will never phone home, send telemetry, query external APIs (like VirusTotal or MSRC), or perform DNS lookups.
- **No State Mutation:** It will never modify a setting, disable a control, or change any system configuration. All cmdlets used are strictly read-only.
- **No Credential Access:** It will never read, log, display, or write password hashes, SAM contents, saved credentials, or any secret material.
- **No Evasion:** The tool uses standard administrative cmdlets. It contains zero obfuscation or detection-evasion logic. It is meant to be indistinguishable from routine admin activity.
- **No Auto-Remediation:** While WinSentry provides an optional `remediation_command` field for certain findings, this command is strictly informational text for the operator to copy and execute manually. WinSentry will never auto-execute fixes under any flag.

## 2. Execution Policy
WinSentry.ps1 should be run with a process-level bypass:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\WinSentry.ps1
```
This `-Scope Process` only affects the current PowerShell process and does not weaken the machine's overall policy.

## 3. winsentry-lookup.ps1
This project includes a secondary script, `winsentry-lookup.ps1`. **This script is deliberately separate and consent-gated.**
- It is the ONLY script in this package that makes a network call (to the VirusTotal API).
- It must be run manually, on a single file at a time.
- It will explicitly prompt for a `y/N` confirmation before making any network call.
- It only ever uploads a file hash, never the file content itself.
- The existence of this separate script is what guarantees the main `WinSentry.ps1` scanner remains 100% offline and safe to run in any environment.

## 4. Zero-Trace Execution & Output
WinSentry v1 is designed to leave zero unencrypted data on disk after a scan:
- The script securely prompts for a password at runtime (`Read-Host -AsSecureString`).
- The report is built and passed to the generator entirely via random temporary files.
- The `winsentry_report.exe` calls Microsoft Edge headlessly to create a PDF and encrypts it with AES via the provided password.
- All temporary files (JSON data, intermediate HTML/PDF) are securely wiped (`[System.IO.File]::WriteAllBytes` with random data before deletion) before the tool exits.
- The only artifact left on disk is `WinSentry_Report_Encrypted.pdf`.

## 5. Code Signing
For any distribution beyond personal use, it is highly recommended to sign `WinSentry.ps1` using `Set-AuthenticodeSignature`. This ensures that consumers and AppLocker/WDAC-managed machines can verify its provenance.
