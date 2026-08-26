[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string[]]$Ports = @("7890", "7891", "7897", "1080", "10808", "20171")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$parsedPorts = @()
foreach ($portArgument in $Ports) {
    foreach ($portText in ($portArgument -split ',')) {
        $portText = $portText.Trim()
        if ($portText -notmatch '^\d+$') {
            throw "Ports must contain integers from 1 to 65535."
        }

        $port = [int]$portText
        if ($port -lt 1 -or $port -gt 65535) {
            throw "Ports must contain integers from 1 to 65535."
        }
        $parsedPorts += $port
    }
}
$parsedPorts = @($parsedPorts | Select-Object -Unique)

if ($parsedPorts.Count -eq 0) {
    throw "Ports must contain integers from 1 to 65535."
}

$processNames = @{}
Get-Process | ForEach-Object {
    $processNames[[int]$_.Id] = $_.ProcessName
}

$listeners = @(
    Get-NetTCPConnection -State Listen |
        Where-Object { $_.LocalPort -in $parsedPorts }
)

$rows = foreach ($listener in $listeners) {
    $processId = [int]$listener.OwningProcess
    $processName = "unavailable"
    if ($processNames.ContainsKey($processId)) {
        $processName = $processNames[$processId]
    }

    $scope = "lan-specific"
    if ($listener.LocalAddress -in @("127.0.0.1", "::1")) {
        $scope = "loopback"
    } elseif ($listener.LocalAddress -in @("0.0.0.0", "::")) {
        $scope = "wildcard"
    }

    [PSCustomObject]@{
        LocalAddress = $listener.LocalAddress
        LocalPort    = $listener.LocalPort
        ProcessId    = $processId
        Process      = $processName
        Scope        = $scope
    }
}

Write-Host "=== Candidate proxy listeners ==="
if (@($rows).Count -eq 0) {
    Write-Host "No listeners found on requested ports: $($parsedPorts -join ', ')"
} else {
    $rows | Sort-Object LocalPort, LocalAddress | Format-Table -AutoSize
}

$internetSettings = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$proxyServer = [string]$internetSettings.ProxyServer
$redactedProxyServer = $proxyServer -replace '(?i)(://)[^/@;]+@', '${1}[REDACTED]@'
$redactedProxyServer = $redactedProxyServer -replace '(?i)(^|[=;])[^=;@:/]+:[^=;@]+@', '${1}[REDACTED]@'

Write-Host ""
Write-Host "=== Windows proxy settings ==="
[PSCustomObject]@{
    ProxyEnabled = [bool]$internetSettings.ProxyEnable
    ProxyServer  = $redactedProxyServer
} | Format-List

Write-Host ""
Write-Host "=== WSL virtual adapters ==="
$wslAddresses = @(
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.InterfaceAlias -match 'WSL|vEthernet' } |
        Select-Object InterfaceAlias, IPAddress, PrefixLength
)
if ($wslAddresses.Count -eq 0) {
    Write-Host "No WSL or vEthernet IPv4 adapters found."
} else {
    $wslAddresses | Format-Table -AutoSize
}
