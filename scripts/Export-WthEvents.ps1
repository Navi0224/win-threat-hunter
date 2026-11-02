<#
.SYNOPSIS
    Export recent Windows events to JSON lines for win-threat-hunter.

.DESCRIPTION
    Reads the Security, System, PowerShell Operational and Sysmon logs (any
    that exist), converts each event to one compact JSON object with NAMED
    EventData fields, and writes one object per line.

    Why not just "Get-WinEvent | ConvertTo-Json"? That output only has an
    unnamed "Properties" array, so rules cannot refer to fields such as
    TargetUserName or IpAddress. Converting via the event XML keeps the names.

    Run from an elevated (Administrator) PowerShell: the Security log needs it.
    Works on Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
    .\scripts\Export-WthEvents.ps1 -Hours 24 -OutFile my-logs\events.jsonl
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string]$OutFile = "my-logs\events.jsonl",
    [string[]]$LogName = @(
        'Security',
        'System',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Sysmon/Operational'
    ),
    [int]$MaxEventsPerLog = 50000
)

function ConvertTo-WthRecord {
    <# Turn one EventLogRecord into a compact JSON string. #>
    param([Parameter(Mandatory)] $Record)

    $xml  = [xml]$Record.ToXml()
    $data = [ordered]@{}
    $i = 0
    foreach ($d in $xml.Event.EventData.Data) {
        if ($d -is [string]) {
            # <Data> without a Name attribute comes back as a plain string
            $data["Data$i"] = $d
        } else {
            $name = if ($d.Name) { $d.Name } else { "Data$i" }
            $data[$name] = $d.'#text'
        }
        $i++
    }
    # Some events (e.g. 1102 "log cleared") use <UserData> instead of <EventData>
    if ($xml.Event.UserData) {
        foreach ($n in $xml.Event.UserData.FirstChild.ChildNodes) {
            $data[$n.LocalName] = $n.InnerText
        }
    }
    [pscustomobject]@{
        EventID     = $Record.Id
        TimeCreated = $Record.TimeCreated.ToUniversalTime().ToString('o')  # UTC avoids time-zone bugs
        Computer    = $Record.MachineName
        Channel     = $Record.LogName
        Provider    = $Record.ProviderName
        EventData   = $data
    } | ConvertTo-Json -Compress -Depth 4
}

$since = (Get-Date).AddHours(-$Hours)
$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

$lines = foreach ($log in $LogName) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since } `
                               -MaxEvents $MaxEventsPerLog -ErrorAction Stop
    } catch {
        # Log missing (e.g. Sysmon not installed), no events, or access denied
        Write-Warning "Skipping '$log': $($_.Exception.Message)"
        continue
    }
    foreach ($e in $events) { ConvertTo-WthRecord -Record $e }
}

$lines | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Wrote $(@($lines).Count) events to $OutFile"
