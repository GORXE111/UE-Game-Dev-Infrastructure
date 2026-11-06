#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProfileReport,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [ValidateRange(15, 180)] [int] $TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
$report = [ordered]@{ schemaVersion = 1; status = 'running'; scope = 'win64-loopback-listen'; phase = 'input'
    port = $null; sharedConfigSha256 = $null; checks = @(); cleanedUp = $false; error = $null }
$output = $null
$hostProcess = $null

function Stop-OwnedProcess([Diagnostics.Process] $Process) {
    if (-not $Process.HasExited) {
        $Process.Kill($true)
        if (-not $Process.WaitForExit(10000)) { throw 'A test game process did not exit.' }
    }
}

function Start-Sample([string] $RunName, [string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($game)
    $start.WorkingDirectory = $archive
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $userDir = [IO.Directory]::CreateDirectory((Join-Path $output "$RunName-user")).FullName
    $log = Join-Path $output "$RunName.log"
    foreach ($arg in ($Arguments + @('-NullRHI', '-NoSound', '-Unattended', "-UserDir=$userDir", "-abslog=$log"))) {
        $start.ArgumentList.Add($arg)
    }
    return [Diagnostics.Process]::Start($start)
}

try {
    if (-not $IsWindows) { throw 'The packaged loopback check requires Windows.' }
    $inputReport = Get-Content -LiteralPath $ProfileReport -Raw | ConvertFrom-Json
    $config = $inputReport.sharedConfigSha256
    if ($inputReport.status -cne 'project-profile-passed' -or $config -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Use a passing network-profile report containing the shared configuration identity.'
    }
    $archive = (Resolve-Path -LiteralPath $inputReport.archive).Path
    $game = (Resolve-Path -LiteralPath (Join-Path $archive 'ProfileSample/Binaries/Win64/ProfileSample.exe')).Path
    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem' -or (Test-Path -LiteralPath $requested) -or
        $requested.StartsWith($archive.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Choose a new output directory outside the packaged archive.'
    }
    $parent = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($requested))
    for ($directory = $parent; $directory; $directory = $directory.Parent) {
        if ($directory -isnot [IO.DirectoryInfo] -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Choose an existing output parent without filesystem links.'
        }
    }
    $output = (New-Item -Path $requested -ItemType Directory).FullName
    $report.sharedConfigSha256 = $config
    $report.phase = 'listen-host'
    $reservation = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    try { $port = $reservation.Client.LocalEndPoint.Port } finally { $reservation.Dispose() }
    $report.port = $port
    $hostProcess = Start-Sample 'host' @('/Engine/Maps/Entry?listen?game=/Script/ProfileSample.ProfileSessionMode',
        '-multihome=127.0.0.1', "-port=$port")
    $hostLog = Join-Path $output 'host.log'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $ready = $false
    while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds -and -not $hostProcess.HasExited) {
        if ((Test-Path -LiteralPath $hostLog) -and
            (Select-String -LiteralPath $hostLog -Quiet -SimpleMatch "UE_ADOPTION_SESSION_SERVER_READY shared=$config")) {
            $portLine = '^\s*UDP\s+127\.0\.0\.1:' + $port + '\s+\S+\s+' + $hostProcess.Id + '\s*$'
            $ready = [bool] (netstat.exe -ano -p udp | Select-String -Pattern $portLine -Quiet)
            if ($ready) { break }
        }
        Start-Sleep -Milliseconds 300
    }
    if (-not $ready) { throw 'The packaged host did not become ready on loopback. See host.log.' }
    $report.checks += 'listen-host-ready'

    $incompatible = $(if ($config[0] -eq '0') { '1' } else { '0' }) + $config.Substring(1)
    $checks = @(
        @{ Name = 'join'; Config = $config; Marker = "UE_ADOPTION_SESSION_CLIENT_CONNECTED shared=$config" },
        @{ Name = 'incompatible'; Config = $incompatible; Marker = 'UE_ADOPTION_SESSION_CLIENT_REJECTED' },
        @{ Name = 'reconnect'; Config = $config; Marker = "UE_ADOPTION_SESSION_CLIENT_CONNECTED shared=$config" }
    )
    foreach ($check in $checks) {
        $report.phase = $check.Name
        $client = Start-Sample $check.Name @("127.0.0.1:${port}?AdoptionConfigId=$($check.Config)", '-AdoptionSessionSmoke')
        try {
            if (-not $client.WaitForExit($TimeoutSeconds * 1000) -or $client.ExitCode -ne 0) {
                throw "Packaged client did not exit normally. See $($check.Name).log."
            }
        } finally {
            try { Stop-OwnedProcess $client } finally { $client.Dispose() }
        }
        $log = Join-Path $output "$($check.Name).log"
        if ($hostProcess.HasExited -or -not (Select-String -LiteralPath $log -SimpleMatch -Quiet $check.Marker)) {
            throw "Expected network marker absent. See $($check.Name).log."
        }
        $report.checks += $check.Name
    }
    $report.phase = 'complete'
    $report.status = 'loopback-session-passed'
} catch {
    $report.status = 'blocked'
    $report.error = $_.Exception.Message
} finally {
    if ($hostProcess) {
        try { Stop-OwnedProcess $hostProcess; $report.cleanedUp = $true }
        catch { $report.status = 'blocked'; $report.error = $_.Exception.Message }
        finally { $hostProcess.Dispose() }
    }
}

$result = $report | ConvertTo-Json -Depth 5
if ($output) { $result | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding utf8 }
$result
if ($report.status -ne 'loopback-session-passed') { exit 1 }
exit 0
