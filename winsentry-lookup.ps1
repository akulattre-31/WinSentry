<#
.SYNOPSIS
Manual VirusTotal Hash Lookup Tool for WinSentry v1

.DESCRIPTION
This script is explicitly separate from WinSentry.ps1 to guarantee that the main scanner never makes network calls. 
This script calculates the SHA-256 hash of a specified file locally, prompts the user for confirmation, and queries the VirusTotal API.

It NEVER uploads the file itself, only the hash.
It requires a VirusTotal API key to be set in the VT_API_KEY environment variable.
Outputs directly to the console.

.PARAMETER Path
The absolute or relative path to the file to check.

.EXAMPLE
.\winsentry-lookup.ps1 -Path "C:\Users\Public\weird_folder\x.exe"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

# 1. Verify file exists
if (-not (Test-Path -Path $Path -PathType Leaf)) {
    Write-Error "File not found at path: $Path"
    exit 1
}

# 2. Verify API key
$apiKey = $env:VT_API_KEY
if ([string]::IsNullOrWhiteSpace($apiKey)) {
    Write-Error "VT_API_KEY environment variable is not set. Please set your VirusTotal API key before running this tool."
    exit 1
}

# 3. Compute Hash Locally
try {
    $fileHash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
} catch {
    Write-Error "Failed to calculate hash: $_"
    exit 1
}

Write-Host "File: $Path"
Write-Host "SHA-256 Hash: $fileHash"

# 4. Interactive Confirmation
$promptResult = Read-Host "Submit this hash to VirusTotal? Only the hash is sent, never the file. (y/N)"

if ($promptResult -notmatch "^y(es)?$") {
    Write-Host "Lookup cancelled by user. No network call made."
    exit 0
}

Write-Host "Querying VirusTotal API..."

# 5. Network Call
$apiUrl = "https://www.virustotal.com/api/v3/files/$fileHash"
$headers = @{
    "x-apikey" = $apiKey
}

try {
    # We must use Basic parsing or Invoke-RestMethod for simple API calls. 
    # The spec allows Invoke-RestMethod HERE (but never in WinSentry.ps1).
    $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -ErrorAction Stop
    
    $stats = $response.data.attributes.last_analysis_stats
    $malicious = $stats.malicious
    $suspicious = $stats.suspicious
    $undetected = $stats.undetected
    $total = $malicious + $suspicious + $undetected
    
    Write-Host ""
    Write-Host "=== VirusTotal Results ==="
    Write-Host "Detection Ratio: $malicious / $total"
    
    if ($response.data.attributes.first_submission_date) {
        $firstSeen = [datetime]::new(1970, 1, 1, 0, 0, 0, 0, [System.DateTimeKind]::Utc).AddSeconds($response.data.attributes.first_submission_date)
        Write-Host "First Seen (UTC): $firstSeen"
    }

    if ($malicious -gt 0 -or $suspicious -gt 0) {
        Write-Host ""
        Write-Host "Vendor Verdicts (Flagged):"
        $results = $response.data.attributes.last_analysis_results
        foreach ($vendor in $results.PSObject.Properties.Name) {
            $verdict = $results.$vendor
            if ($verdict.category -in @('malicious', 'suspicious')) {
                Write-Host "  - $vendor: $($verdict.result)"
            }
        }
    }
} catch {
    $errResp = $_.Exception.Response
    if ($errResp -ne $null) {
        $statusCode = $errResp.StatusCode
        if ($statusCode -eq 404) {
            Write-Host "Result: Hash is not known to VirusTotal (404 Not Found)."
            exit 0
        } elseif ($statusCode -eq 401) {
            Write-Error "Authentication failed. Please verify your VT_API_KEY."
        } elseif ($statusCode -eq 429) {
            Write-Error "Rate limit exceeded. The public VirusTotal API allows 4 requests per minute."
        } else {
            Write-Error "API query failed with HTTP status: $statusCode"
        }
    } else {
        Write-Error "Network error or API query failed: $_"
    }
}
