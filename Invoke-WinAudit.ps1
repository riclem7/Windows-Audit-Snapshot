param(
  #Where to store output folders (each run gets its own timestamp folder)
  [string]$OutputDir = ".\out",

  #How far back to look for failed logons in the Security log
  [int]$Hours = 24,

  #Added a OpenReport function
  [switch]$OpenReport

)

#Keep the script from crashing on minor permission/missing-command issues.
#We'll still try to capture as much as we can.
$ErrorActionPreference = "SilentlyContinue"

#Create a unique folder name like: 2026-02-11_130512
$stamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

#Final output path: .\out\<timestamp>\
$outPath = Join-Path $OutputDir $stamp

#Create the folder (Force = don't error if it exists)
New-Item -ItemType Directory -Force -Path $outPath | Out-Null

#Helper function:
#Runs a command safely. If it fails, returns a readable error string instead of stopping.
function Safe($sb) {
  try { & $sb } catch { "ERROR: $($_.Exception.Message)" }
}

#-----------------------------
#Collect baseline information
#-----------------------------

#OS info: name/version/build + last boot time
$os = Safe {
  Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, LastBootUpTime
}

#Local Administrators group members (who has admin on this machine)
$admins = Safe {
  Get-LocalGroupMember "Administrators" |
    Select-Object Name, ObjectClass
}

#Firewall profile status (Domain/Private/Public)
$fw = Safe {
  Get-NetFirewallProfile |
    Select-Object Name, Enabled
}

#Defender status (only works if Defender cmdlets exist)
#If this command isn't available (older Windows / policy), we print a message.
$def = Safe {
  if (Get-Command Get-MpComputerStatus -EA 0) {
    Get-MpComputerStatus |
      Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled, DefenderSignaturesOutOfDate
  } else {
    "Defender cmdlets not available"
  }
}

#Listening ports = services waiting for inbound connections
#OwningProcess = PID of the process that opened the port
$ports = Safe {
  Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort
}

#Failed logons in last X hours:
#Windows Security Event ID 4625 = failed logon attempt
#We limit to first 20 to keep report readable.
$failed = Safe {
  $start = (Get-Date).AddHours(-$Hours)
  Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=4625; StartTime=$start } |
    Select-Object TimeCreated, Id -First 20
}

#-----------------------------
#Package results into an object
#-----------------------------
#Ordered hash table keeps keys in a nice consistent order in the JSON.
$audit = [ordered]@{
  GeneratedAt = (Get-Date).ToString("o")       #ISO timestamp
  Computer    = $env:COMPUTERNAME              #machine name
  OS          = $os
  LocalAdmins = $admins
  Firewall    = $fw
  Defender    = $def
  ListenPorts = $ports
  FailedLogonsLastHours = $failed
}

#-----------------------------
#Output files
#-----------------------------

#1) JSON output for “structured data” (easy to diff/parse later)
($audit | ConvertTo-Json -Depth 5) |
  Out-File (Join-Path $outPath "audit.json") -Encoding UTF8

#2) TXT output for a human-readable report (easy to attach to a ticket/email)
@"
Windows Audit Snapshot
Generated: $($audit.GeneratedAt)
Computer:  $($audit.Computer)

OS:
$($os | Out-String)

Local Admins:
$($admins | Out-String)

Firewall Profiles:
$($fw | Out-String)

Defender:
$($def | Out-String)

Listening Ports (top):
$($ports | Select-Object -First 15 | Out-String)

Failed Logons (last $Hours hours, first 20):
$($failed | Out-String)
"@ | Out-File (Join-Path $outPath "report.txt") -Encoding UTF8

#Print where results were saved
Write-Host "Done. Output:" $outPath

#OpenReport function
if ($OpenReport) { notepad (Join-Path $outPath "report.txt") }
