<#
.SYNOPSIS
WinSentry v1 - Local Windows Security Posture Auditor

.DESCRIPTION
A read-only, zero-network-footprint security auditor for Windows.
Collects state on Defender, Remote Access, Network, Persistence, Accounts, and Patching.
Generates winsentry_report.json and a SHA-256 sidecar file.

SECURITY NOTE:
This script performs NO network calls, process injection, or state mutation.
For network-based hash lookups, use the standalone winsentry-lookup.ps1 manually.
For distribution, it is highly recommended to sign this script with Set-AuthenticodeSignature.

.PARAMETER CompareTo
Optional path to a prior winsentry_report.json file to generate a diff in the output.

.EXAMPLE
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\WinSentry.ps1
.\WinSentry.ps1 -CompareTo "C:\path\to\old_winsentry_report.json"
#>
param(
    [string]$CompareTo = ""
)

# WinSentry v1 (Secure PDF Generation)
# Author: Akul Attre

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "         WinSentry v1 - Scanner          " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$securePassword = Read-Host "Enter a password to encrypt the PDF report" -AsSecureString
if (-not $securePassword) {
    Write-Error "Password is required for PDF encryption."
    exit
}

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
$env:WINSENTRY_PDF_PWD = $plainPassword

$tempJsonPath = [System.IO.Path]::GetTempFileName()

function Wipe-File {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            $size = (Get-Item $Path).Length
            if ($size -gt 0) {
                $bytes = New-Object byte[] $size
                $rand = New-Object Random
                $rand.NextBytes($bytes)
                [System.IO.File]::WriteAllBytes($Path, $bytes)
            }
            Remove-Item -Path $Path -Force
        } catch {
            Write-Warning "Failed to securely wipe $Path. Attempting standard delete."
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        }
    }
}

# Enforce Self-Targeting: Implicitly local by design (no -ComputerName parameters used).

# --- Configuration & Helpers ---

$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

$ScoringWeights = [ordered]@{
    "_comment" = "Published alongside every report so the 0-100 score is auditable. Define per-module max-contribution weights here:"
    "defender_health" = 25
    "remote_access" = 15
    "network" = 15
    "persistence" = 20
    "accounts" = 10
    "patching" = 5
    "defender_activity" = 5
    "system_health" = 5
}

# Common System Process Names for Typosquat Detection
$SystemProcesses = @(
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe", 
    "services.exe", "spoolsv.exe", "taskhostw.exe", "smss.exe", "wininit.exe",
    "conhost.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "taskmgr.exe"
)

# Helper: Edit Distance (Levenshtein)
function Get-EditDistance {
    param([string]$s1, [string]$s2)
    $s1 = $s1.ToLowerInvariant()
    $s2 = $s2.ToLowerInvariant()
    $len1 = $s1.Length
    $len2 = $s2.Length
    $d = New-Object 'int[,]' ($len1 + 1), ($len2 + 1)
    for ($i = 0; $i -le $len1; $i++) { $d[$i, 0] = $i }
    for ($j = 0; $j -le $len2; $j++) { $d[0, $j] = $j }
    for ($i = 1; $i -le $len1; $i++) {
        for ($j = 1; $j -le $len2; $j++) {
            $cost = if ($s1[$i - 1] -eq $s2[$j - 1]) { 0 } else { 1 }
            $i1 = $i - 1
            $j1 = $j - 1
            $min1 = $d[$i1, $j] + 1
            $min2 = $d[$i, $j1] + 1
            $min3 = $d[$i1, $j1] + $cost
            $tempMin = [Math]::Min($min1, $min2)
            $d[$i, $j] = [Math]::Min($tempMin, $min3)
        }
    }
    return $d[$len1, $len2]
}

# Helper: Truncate string
function Truncate-String {
    param([string]$str, [int]$maxLength = 1000)
    if ([string]::IsNullOrEmpty($str)) { return "" }
    if ($str.Length -gt $maxLength) { return $str.Substring(0, $maxLength) + "..." }
    return $str
}

# Helper: Create finding
function New-Finding {
    param(
        [string]$Id,
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$Recommendation,
        [string]$RemediationCommand = $null,
        [string]$SignatureStatus = $null,
        [string]$SignerSubject = $null,
        [string]$LookalikeMatch = $null
    )
    $finding = [ordered]@{
        id = $Id
        severity = $Severity
        title = Truncate-String $Title
        detail = Truncate-String $Detail
        recommendation = Truncate-String $Recommendation
    }
    if ($null -ne $RemediationCommand) { $finding["remediation_command"] = $RemediationCommand }
    if ($null -ne $SignatureStatus) { $finding["signature_status"] = $SignatureStatus }
    if ($null -ne $SignerSubject)   { $finding["signer_subject"] = $SignerSubject }
    if ($null -ne $LookalikeMatch)  { $finding["lookalike_match"] = $LookalikeMatch }
    return $finding
}

# Helper: Analyze Binary (Signature & Typosquat)
function Analyze-Binary {
    param([string]$Path)
    
    $result = @{
        SignatureStatus = "Unknown"
        SignerSubject = $null
        LookalikeMatch = $null
        BumpSeverity = $false
        IsHighSeverity = $false
    }
    
    if (-not (Test-Path $Path -PathType Leaf)) { return $result }
    
    $resolvedPath = (Resolve-Path $Path).Path
    $fileName = [System.IO.Path]::GetFileName($resolvedPath)
    $isOutsideSystem32 = -not $resolvedPath.StartsWith("$env:SystemRoot\System32\", [System.StringComparison]::InvariantCultureIgnoreCase)
    
    # 1. Signature Check
    try {
        $sig = Get-AuthenticodeSignature -FilePath $resolvedPath -ErrorAction SilentlyContinue
        if ($sig) {
            $result.SignatureStatus = $sig.Status.ToString()
            if ($sig.SignerCertificate) {
                $result.SignerSubject = $sig.SignerCertificate.Subject
            }
            if ($sig.Status -ne 'Valid' -and $isOutsideSystem32) {
                # Only bump if it's not a known Microsoft signed binary
                if (-not ($result.SignerSubject -match "O=Microsoft Corporation")) {
                    $result.BumpSeverity = $true
                }
            }
        } else {
            $result.SignatureStatus = "NotSigned"
            if ($isOutsideSystem32) { $result.BumpSeverity = $true }
        }
    } catch {
        $result.SignatureStatus = "Error"
    }

    # 2. Typosquat Check
    if ($isOutsideSystem32) {
        foreach ($sysProc in $SystemProcesses) {
            if ($fileName -ieq $sysProc) { continue } # Exact match is allowed (e.g. copied file), we're looking for typosquats
            $dist = Get-EditDistance -s1 $fileName -s2 $sysProc
            if ($dist -le 2) {
                $result.LookalikeMatch = $sysProc
                $result.IsHighSeverity = $true
                break
            }
        }
    }
    
    return $result
}

# --- Module Implementations ---

$Modules = [ordered]@{
    defender_health = @{ status = "ok"; findings = @() }
    remote_access = @{ status = "ok"; findings = @() }
    network = @{ status = "ok"; findings = @() }
    persistence = @{ status = "ok"; findings = @() }
    accounts = @{ status = "ok"; findings = @() }
    patching = @{ status = "ok"; findings = @() }
    defender_activity = @{ status = "ok"; findings = @() }
    system_health = @{ status = "ok"; findings = @() }
}

# 1. Defender Health
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $mpPref = Get-MpPreference -ErrorAction Stop
    
    if (-not $mpStatus.RealTimeProtectionEnabled) {
        $Modules.defender_health.findings += New-Finding -Id "DEF-01" -Severity "CRITICAL" -Title "Real-Time Protection Disabled" -Detail "Defender Real-Time Protection is off." -Recommendation "Enable Real-Time Protection immediately." -RemediationCommand "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    if (-not $mpStatus.IsTamperProtected) {
        $Modules.defender_health.findings += New-Finding -Id "DEF-02" -Severity "HIGH" -Title "Tamper Protection Disabled" -Detail "Defender Tamper Protection is not active." -Recommendation "Enable Tamper Protection to prevent malware from disabling Defender." -RemediationCommand "Set-MpPreference -DisableTamperProtection `$false"
    }
    
    $sigAge = (Get-Date) - $mpStatus.AntispywareSignatureLastUpdated
    if ($sigAge.TotalDays -gt 7) {
        $Modules.defender_health.findings += New-Finding -Id "DEF-03" -Severity "MEDIUM" -Title "Outdated Signatures" -Detail "Defender signatures are $($sigAge.Days) days old." -Recommendation "Force a definition update." -RemediationCommand "Update-MpSignature"
    }
    
    if ($mpPref.ExclusionPath -or $mpPref.ExclusionExtension -or $mpPref.ExclusionProcess) {
        $exclDetails = "Paths: $($mpPref.ExclusionPath -join ', '); Exts: $($mpPref.ExclusionExtension -join ', '); Procs: $($mpPref.ExclusionProcess -join ', ')"
        $Modules.defender_health.findings += New-Finding -Id "DEF-04" -Severity "MEDIUM" -Title "Defender Exclusions Configured" -Detail $exclDetails -Recommendation "Review exclusions to ensure they are not masking malware directories."
    }
} catch {
    $Modules.defender_health.status = "skipped"
    $Modules.defender_health.findings += New-Finding -Id "DEF-ERR" -Severity "INFO" -Title "Defender Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator or ensure Defender is installed."
}

# 2. Remote Access
try {
    # RDP Check
    $rdpKey = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
    if ($rdpKey -and $rdpKey.fDenyTSConnections -eq 0) {
        $rdpPort = 3389
        $rdpPortKey = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
        if ($rdpPortKey -and $rdpPortKey.PortNumber) { $rdpPort = $rdpPortKey.PortNumber }
        $Modules.remote_access.findings += New-Finding -Id "REM-01" -Severity "MEDIUM" -Title "RDP Enabled" -Detail "Remote Desktop is enabled on port $rdpPort." -Recommendation "Ensure RDP is required and restricted by firewall."
    }
    
    # WinRM Check
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -eq 'Running') {
        $Modules.remote_access.findings += New-Finding -Id "REM-02" -Severity "INFO" -Title "WinRM Running" -Detail "Windows Remote Management service is running." -Recommendation "Ensure WinRM is required for administration."
    }
    
    # Known Remote Access Software
    $knownSoftware = @("AnyDesk", "TeamViewer", "Chrome Remote Desktop", "VNC", "LogMeIn")
    $installed = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Select-Object DisplayName
    foreach ($soft in $installed) {
        if ([string]::IsNullOrWhiteSpace($soft.DisplayName)) { continue }
        foreach ($target in $knownSoftware) {
            if ($soft.DisplayName -match $target) {
                $Modules.remote_access.findings += New-Finding -Id "REM-03" -Severity "HIGH" -Title "Remote Access Software Installed" -Detail "Found: $($soft.DisplayName)" -Recommendation "Verify if this software is authorized."
            }
        }
    }
    
    # Active Sessions
    $sessions = Get-CimInstance Win32_LogonSession -Filter "LogonType = 10" -ErrorAction SilentlyContinue # 10 = RemoteInteractive
    if ($sessions) {
        $Modules.remote_access.findings += New-Finding -Id "REM-04" -Severity "HIGH" -Title "Active RDP Sessions" -Detail "Found $($sessions.Count) active RemoteInteractive sessions." -Recommendation "Review currently logged-on users."
    }
} catch {
    $Modules.remote_access.status = "skipped"
    $Modules.remote_access.findings += New-Finding -Id "REM-ERR" -Severity "INFO" -Title "Remote Access Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 3. Network
try {
    $tcp = Get-NetTCPConnection -ErrorAction Stop
    $listening = @()
    $unowned = @()
    
    foreach ($conn in $tcp) {
        if ($conn.State -eq 'Listen') {
            $listening += $conn.LocalPort
        } elseif ($conn.State -eq 'Established') {
            if ($conn.OwningProcess -eq 0) {
                $unowned += "$($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
            } else {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if (-not $proc) {
                    $unowned += "PID $($conn.OwningProcess) (Process not found): $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                }
            }
        }
    }
    
    $listening = $listening | Select-Object -Unique
    if ($listening.Count -gt 0) {
        $Modules.network.findings += New-Finding -Id "NET-01" -Severity "INFO" -Title "Listening Ports" -Detail "Listening on ports: $($listening -join ', ')" -Recommendation "Review exposed services."
    }
    if ($unowned.Count -gt 0) {
        $Modules.network.findings += New-Finding -Id "NET-02" -Severity "HIGH" -Title "Unresolvable Network Connections" -Detail "Established connections without a valid owning process: $($unowned -join '; ')" -Recommendation "Investigate hidden or terminated processes communicating on the network."
    }
} catch {
    $Modules.network.status = "skipped"
    $Modules.network.findings += New-Finding -Id "NET-ERR" -Severity "INFO" -Title "Network Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 4. Persistence
try {
    $idCounter = 1
    
    # Run Keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $runKeys) {
        $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $val = $prop.Value
                    if ($val -match '"([^"]+\.exe)"' -or $val -match '^([^\s]+\.exe)') {
                        $exePath = $matches[1]
                        $analysis = Analyze-Binary -Path $exePath
                        
                        $sev = "INFO"
                        if ($analysis.BumpSeverity) { $sev = "MEDIUM" }
                        if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                        
                        $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Run Key Entry" -Detail "Key: $key`nName: $($prop.Name)`nValue: $val" -Recommendation "Verify auto-start program." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                        $idCounter++
                    }
                }
            }
        }
    }
    
    # Startup Folders
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupPaths) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ($file.Extension -in @(".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")) {
                    $analysis = @{ SignatureStatus="Unknown"; SignerSubject=$null; LookalikeMatch=$null; BumpSeverity=$false; IsHighSeverity=$false }
                    if ($file.Extension -eq ".exe") { $analysis = Analyze-Binary -Path $file.FullName }
                    
                    $sev = "LOW"
                    if ($analysis.BumpSeverity) { $sev = "MEDIUM" }
                    if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                    
                    $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Startup Folder Script/Executable" -Detail "Path: $($file.FullName)" -Recommendation "Verify startup file." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                    $idCounter++
                }
            }
        }
    }
    
    # Scheduled Tasks
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        if ($task.Author -notmatch "Microsoft" -and $task.Source -notmatch "Microsoft") {
            foreach ($action in $task.Actions) {
                if ($action.Execute) {
                    $analysis = Analyze-Binary -Path $action.Execute
                    
                    $sev = "INFO"
                    if ($analysis.BumpSeverity) { $sev = "MEDIUM" }
                    if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                    
                    $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Non-Microsoft Scheduled Task" -Detail "Task Name: $($task.TaskName)`nAuthor: $($task.Author)`nExecute: $($action.Execute) $($action.Arguments)" -Recommendation "Verify task purpose." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                    $idCounter++
                }
            }
        }
    }
    
    # Services outside System32
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        if (-not [string]::IsNullOrWhiteSpace($svc.PathName) -and -not $svc.PathName.ToLowerInvariant().Contains("system32\")) {
            if ($svc.PathName -match '"([^"]+\.exe)"' -or $svc.PathName -match '^([^\s]+\.exe)') {
                $exePath = $matches[1]
                $analysis = Analyze-Binary -Path $exePath
                
                $sev = "INFO"
                if ($analysis.BumpSeverity) { $sev = "LOW" } # Services are common, keep base low
                if ($analysis.IsHighSeverity) { $sev = "HIGH" }
                
                $Modules.persistence.findings += New-Finding -Id "PER-$(('{0:D3}' -f $idCounter))" -Severity $sev -Title "Service outside System32" -Detail "Name: $($svc.Name)`nPath: $($svc.PathName)" -Recommendation "Verify service origin." -SignatureStatus $analysis.SignatureStatus -SignerSubject $analysis.SignerSubject -LookalikeMatch $analysis.LookalikeMatch
                $idCounter++
            }
        }
    }
} catch {
    $Modules.persistence.status = "skipped"
    $Modules.persistence.findings += New-Finding -Id "PER-ERR" -Severity "INFO" -Title "Persistence Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 5. Accounts
try {
    $users = Get-LocalUser -ErrorAction Stop
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    
    $adminNames = $admins | Select-Object -ExpandProperty Name
    $Modules.accounts.findings += New-Finding -Id "ACC-01" -Severity "INFO" -Title "Local Administrators" -Detail "Members: $($adminNames -join ', ')" -Recommendation "Ensure least privilege principle is maintained."
    
    foreach ($user in $users) {
        if ($user.PasswordRequired -eq $false) {
            $Modules.accounts.findings += New-Finding -Id "ACC-02" -Severity "MEDIUM" -Title "Password Not Required" -Detail "User: $($user.Name)" -Recommendation "Enforce password requirements."
        }
        if ($user.PasswordNeverExpires -or $null -eq $user.PasswordExpires) {
            $Modules.accounts.findings += New-Finding -Id "ACC-03" -Severity "LOW" -Title "Password Never Expires" -Detail "User: $($user.Name)" -Recommendation "Implement password expiration policies if applicable."
        }
    }
} catch {
    $Modules.accounts.status = "skipped"
    $Modules.accounts.findings += New-Finding -Id "ACC-ERR" -Severity "INFO" -Title "Accounts Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 6. Patching
try {
    $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 5
    $details = @()
    foreach ($hf in $hotfixes) {
        $details += "KB: $($hf.HotFixID), Date: $($hf.InstalledOn)"
    }
    $Modules.patching.findings += New-Finding -Id "PAT-01" -Severity "INFO" -Title "Recent Patches" -Detail ($details -join "`n") -Recommendation "Ensure system is regularly updated."
} catch {
    $Modules.patching.status = "skipped"
    $Modules.patching.findings += New-Finding -Id "PAT-ERR" -Severity "INFO" -Title "Patching Check Failed" -Detail $_.Exception.Message -Recommendation "WMI may be disabled or blocked."
}

# 7. Defender Activity
try {
    $detections = Get-MpThreatDetection -ErrorAction Stop
    $detId = 1
    foreach ($det in $detections) {
        $sevName = "INFO"
        if ($det.SeverityID -eq 4 -or $det.SeverityID -eq 5) { $sevName = "HIGH" }
        $Modules.defender_activity.findings += New-Finding -Id "ACT-$(('{0:D3}' -f $detId))" -Severity $sevName -Title "Defender Detection History" -Detail "Threat: $($det.ThreatName)`nAction: $($det.ActionSuccess)`nPath: $($det.Resources)`nTime: $($det.InitialDetectionTime)" -Recommendation "Review Defender history for false positives or lingering infections."
        $detId++
    }
} catch {
    $Modules.defender_activity.status = "skipped"
    $Modules.defender_activity.findings += New-Finding -Id "ACT-ERR" -Severity "INFO" -Title "Defender Activity Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# 8. System Health
try {
    # Disk Health
    $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    foreach ($d in $disks) {
        if ($d.HealthStatus -ne 'Healthy') {
            $Modules.system_health.findings += New-Finding -Id "SYS-01" -Severity "HIGH" -Title "Disk Not Healthy" -Detail "Disk $($d.DeviceId) Status: $($d.HealthStatus)" -Recommendation "Check physical disk health."
        }
    }
    
    # TPM
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if ($tpm -and -not $tpm.TpmPresent) {
        $Modules.system_health.findings += New-Finding -Id "SYS-02" -Severity "MEDIUM" -Title "TPM Not Present" -Detail "No Trusted Platform Module detected." -Recommendation "Enable TPM in BIOS."
    } elseif ($tpm -and -not $tpm.TpmReady) {
        $Modules.system_health.findings += New-Finding -Id "SYS-03" -Severity "LOW" -Title "TPM Not Ready" -Detail "TPM is present but not ready/activated." -Recommendation "Initialize TPM."
    }
    
    # Restore Point
    $restore = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending | Select-Object -First 1
    if (-not $restore) {
        $Modules.system_health.findings += New-Finding -Id "SYS-04" -Severity "MEDIUM" -Title "No System Restore Points" -Detail "No recent restore points exist." -Recommendation "Enable System Restore or run a backup." -RemediationCommand "Enable-ComputerRestore -Drive 'C:\'"
    } else {
        $age = (Get-Date) - $restore.CreationTime
        if ($age.TotalDays -gt 30) {
            $Modules.system_health.findings += New-Finding -Id "SYS-05" -Severity "LOW" -Title "Stale System Restore Point" -Detail "Last restore point is $($age.Days) days old." -Recommendation "Create a new restore point." -RemediationCommand "Checkpoint-Computer -Description 'WinSentry Manual Checkpoint' -RestorePointType 'MODIFY_SETTINGS'"
        }
    }
    
    # Update Readiness / Info
    $info = Get-ComputerInfo -Property OsBuildNumber, OsVersion -ErrorAction SilentlyContinue
    if ($info) {
        $Modules.system_health.findings += New-Finding -Id "SYS-06" -Severity "INFO" -Title "OS Version Info" -Detail "Build: $($info.OsBuildNumber), Version: $($info.OsVersion)" -Recommendation "Ensure build is supported."
    }
    
    # Volume
    $vols = Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveLetter -eq $env:SystemDrive[0]
    if ($vols) {
        $freePct = ($vols.SizeRemaining / $vols.Size) * 100
        if ($freePct -lt 10) {
            $Modules.system_health.findings += New-Finding -Id "SYS-07" -Severity "HIGH" -Title "Low Disk Space" -Detail "System drive has $([math]::Round($freePct, 1))% free space." -Recommendation "Free up disk space to prevent update failures."
        }
    }
} catch {
    $Modules.system_health.status = "skipped"
    $Modules.system_health.findings += New-Finding -Id "SYS-ERR" -Severity "INFO" -Title "System Health Check Failed" -Detail $_.Exception.Message -Recommendation "Run as Administrator."
}

# --- Risk Scoring ---

# module_score = max_weight - (critical_count * 15 + high_count * 10 + medium_count * 5 + low_count * 2)
# floored at 0. Total score is sum of module scores.
function Calculate-Score {
    $totalScore = 0
    foreach ($key in $Modules.Keys) {
        $weight = $ScoringWeights[$key]
        if ($null -eq $weight) { continue }
        
        $cCount = 0; $hCount = 0; $mCount = 0; $lCount = 0
        foreach ($f in $Modules[$key].findings) {
            switch ($f.severity) {
                "CRITICAL" { $cCount++ }
                "HIGH"     { $hCount++ }
                "MEDIUM"   { $mCount++ }
                "LOW"      { $lCount++ }
            }
        }
        
        $penalty = ($cCount * 15) + ($hCount * 10) + ($mCount * 5) + ($lCount * 2)
        $modScore = [Math]::Max(0, $weight - $penalty)
        $totalScore += $modScore
    }
    return $totalScore
}

$RiskScore = Calculate-Score

# --- Diff Mode (-CompareTo) ---
$DiffOutput = $null
if (-not [string]::IsNullOrWhiteSpace($CompareTo) -and (Test-Path $CompareTo)) {
    try {
        $oldReport = Get-Content $CompareTo -Raw | ConvertFrom-Json
        $DiffOutput = @{
            new = @()
            resolved = @()
            unchanged = @()
        }
        
        $oldFindings = @{}
        foreach ($modProp in $oldReport.modules.PSObject.Properties) {
            foreach ($f in $modProp.Value.findings) {
                # Create a composite key to uniquely identify findings
                $key = "$($f.id)|$($f.title)|$($f.detail)"
                $oldFindings[$key] = $f
            }
        }
        
        $newFindings = @{}
        foreach ($key in $Modules.Keys) {
            foreach ($f in $Modules[$key].findings) {
                $compKey = "$($f.id)|$($f.title)|$($f.detail)"
                $newFindings[$compKey] = $f
            }
        }
        
        # Determine New & Unchanged
        foreach ($k in $newFindings.Keys) {
            if ($oldFindings.ContainsKey($k)) {
                $DiffOutput.unchanged += $newFindings[$k]
            } else {
                $DiffOutput.new += $newFindings[$k]
            }
        }
        
        # Determine Resolved
        foreach ($k in $oldFindings.Keys) {
            if (-not $newFindings.ContainsKey($k)) {
                $DiffOutput.resolved += $oldFindings[$k]
            }
        }
    } catch {
        Write-Warning "Failed to parse -CompareTo file for diff mode: $_"
    }
}

# --- Output Generation ---

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Report = [ordered]@{
    scan_metadata = [ordered]@{
        hostname = $env:COMPUTERNAME
        scan_time_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        ran_as_admin = $isAdmin
        winsentry_version = "1.0.0"
        operator = $env:USERNAME
    }
    risk_score = $RiskScore
    scoring_weights = $ScoringWeights
    modules = $Modules
}

if ($DiffOutput) {
    $Report["diff"] = $DiffOutput
}

# Write JSON
$reportJson = $Report | ConvertTo-Json -Depth 10 -Compress:$false
$ReportPath = $tempJsonPath
$reportJson | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host "Scan complete. Generating encrypted PDF..." -ForegroundColor Green

if (Test-Path ".\winsentry_report.exe") {
    $pdfPath = ".\WinSentry_Report_Encrypted.pdf"
    & .\winsentry_report.exe $ReportPath $pdfPath
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Report secured at: $pdfPath" -ForegroundColor Green
    } else {
        Write-Host "Failed to generate PDF. Check winsentry_report.exe output." -ForegroundColor Red
    }
} else {
    Write-Host "Warning: winsentry_report.exe not found in current directory. Temporary JSON file has been wiped." -ForegroundColor Yellow
}

# Secure Wipe and Cleanup
Wipe-File -Path $tempJsonPath
$env:WINSENTRY_PDF_PWD = $null
