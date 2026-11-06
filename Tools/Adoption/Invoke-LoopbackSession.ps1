#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProfileReport,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [string] $DedicatedReport,
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

function Start-Sample([string] $Executable, [string] $ArchiveRoot, [string] $RunName, [string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($Executable)
    $start.WorkingDirectory = $ArchiveRoot
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
    $hostArchive = $archive
    $hostExecutable = $game
    $hostMap = '/Engine/Maps/Entry?listen?game=/Script/ProfileSample.ProfileSessionMode'
    $protectedRoots = @($archive)
    if ($DedicatedReport) {
        $dedicated = Get-Content -LiteralPath $DedicatedReport -Raw | ConvertFrom-Json
        if ($dedicated.status -cne 'server-profile-passed' -or $dedicated.sharedConfigSha256 -cne $config -or
            $dedicated.serverConfigManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $dedicated.executableSha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'Use a passing dedicated server report matching the client configuration identity.'
        }
        $hostArchive = (Resolve-Path -LiteralPath $dedicated.archive).Path
        $hostExecutable = (Resolve-Path -LiteralPath $dedicated.executable).Path
        $expectedExecutable = Join-Path $hostArchive 'ProfileSample/Binaries/Win64/ProfileSampleServer.exe'
        if ($hostExecutable -ine $expectedExecutable -or
            (Get-FileHash -LiteralPath $hostExecutable -Algorithm SHA256).Hash -ine $dedicated.executableSha256) {
            throw 'The packaged ProfileSampleServer.exe differs from its report.'
        }
        $serverConfig = (Resolve-Path -LiteralPath $dedicated.serverConfigDirectory).Path
        $serverManifest = Join-Path $serverConfig 'manifest.json'
        if ((Get-FileHash -LiteralPath $serverManifest -Algorithm SHA256).Hash -ine $dedicated.serverConfigManifestSha256) {
            throw 'The staged server manifest differs from its report.'
        }
        $protectedRoots += @($hostArchive, $serverConfig)
        $hostMap = '/Engine/Maps/Entry?game=/Script/ProfileSample.ProfileSessionMode'
        $report.scope = 'win64-loopback-dedicated'
    }
    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem' -or (Test-Path -LiteralPath $requested)) {
        throw 'Choose a new output directory outside the packaged archive.'
    }
    foreach ($protected in $protectedRoots) {
        if ($requested.StartsWith($protected.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Choose a new output directory outside the packaged archive and server configuration.'
        }
    }
    $parent = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($requested))
    for ($directory = $parent; $directory; $directory = $directory.Parent) {
        if ($directory -isnot [IO.DirectoryInfo] -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Choose an existing output parent without filesystem links.'
        }
    }
    $output = (New-Item -Path $requested -ItemType Directory).FullName
    $report.sharedConfigSha256 = $config
    $reservation = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    try { $port = $reservation.Client.LocalEndPoint.Port } finally { $reservation.Dispose() }
    $report.port = $port
    $hostArgs = @($hostMap, '-multihome=127.0.0.1', "-port=$port")
    if ($DedicatedReport) {
        $report.phase = 'reject-tampered-config'
        $tampered = [IO.Directory]::CreateDirectory((Join-Path $output 'TamperedServerConfig')).FullName
        $inputs = @(Get-ChildItem -LiteralPath $serverConfig -File -Filter '*.json')
        foreach ($file in $inputs) {
            if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Choose a server configuration without links.' }
            Copy-Item -LiteralPath $file.FullName -Destination $tampered
        }
        $enemy = Join-Path $tampered 'Enemies.json'
        $source = [IO.File]::ReadAllText($enemy)
        $budget = [regex]::new('("AiBudget"\s*:\s*)4\b')
        if ($budget.Matches($source).Count -ne 1) { throw 'Expected the sample Scout server-only value.' }
        [IO.File]::WriteAllText($enemy, $budget.Replace($source, '${1}5'), [Text.UTF8Encoding]::new($false))
        $pin = "-AdoptionServerManifestSha256=$($dedicated.serverConfigManifestSha256)"
        $rejected = Start-Sample $hostExecutable $hostArchive 'tampered-config' ($hostArgs + @(
            $pin, "-AdoptionServerConfigDir=$tampered", '-ForceLogFlush', '-NoCrashDialog'))
        try {
            if (-not $rejected.WaitForExit($TimeoutSeconds * 1000) -or $rejected.ExitCode -ne 1) {
                throw 'The dedicated process did not refuse the tampered server configuration.'
            }
        } finally {
            try { Stop-OwnedProcess $rejected } finally { $rejected.Dispose() }
        }
        $negativeLog = Get-Content -LiteralPath (Join-Path $output 'tampered-config.log') -Raw
        if (-not $negativeLog.Contains('UE_ADOPTION_SESSION_DEDICATED_CONFIG_REJECTED A listed JSON table is missing or differs from the pinned manifest') -or
            $negativeLog.Contains('UE_ADOPTION_SESSION_SERVER_READY')) {
            throw 'Expected a specific dedicated configuration rejection before readiness.'
        }
        $report.checks += 'tampered-server-config-rejected'
        $hostArgs += @($pin, "-AdoptionServerConfigDir=$serverConfig")
    }
    $report.phase = $(if ($DedicatedReport) { 'dedicated-host' } else { 'listen-host' })
    $hostProcess = Start-Sample $hostExecutable $hostArchive 'host' $hostArgs
    $hostLog = Join-Path $output 'host.log'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $ready = $false
    while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds -and -not $hostProcess.HasExited) {
        if ((Test-Path -LiteralPath $hostLog) -and
            (Select-String -LiteralPath $hostLog -Quiet -SimpleMatch "UE_ADOPTION_SESSION_SERVER_READY shared=$config") -and
            (-not $DedicatedReport -or (
                (Select-String -LiteralPath $hostLog -Quiet -SimpleMatch "UE_ADOPTION_SESSION_DEDICATED_CONFIG_READY shared=$config") -and
                (Select-String -LiteralPath $hostLog -Quiet -SimpleMatch 'UE_ADOPTION_SESSION_DEDICATED_CONFIG_CONTENT enemies=2 waves=2 waveAiBudget=26')))) {
            $portLine = '^\s*UDP\s+127\.0\.0\.1:' + $port + '\s+\S+\s+' + $hostProcess.Id + '\s*$'
            $ready = [bool] (netstat.exe -ano -p udp | Select-String -Pattern $portLine -Quiet)
            if ($ready) { break }
        }
        Start-Sleep -Milliseconds 300
    }
    if (-not $ready) { throw 'The packaged host did not become ready on loopback. See host.log.' }
    $report.checks += "$($report.phase)-ready"

    $incompatible = $(if ($config[0] -eq '0') { '1' } else { '0' }) + $config.Substring(1)
    $checks = @(
        @{ Name = 'join'; Config = $config; Marker = "UE_ADOPTION_SESSION_CLIENT_CONNECTED shared=$config" },
        @{ Name = 'incompatible'; Config = $incompatible; Marker = 'UE_ADOPTION_SESSION_CLIENT_REJECTED' },
        @{ Name = 'reconnect'; Config = $config; Marker = "UE_ADOPTION_SESSION_CLIENT_CONNECTED shared=$config" }
    )
    foreach ($check in $checks) {
        $report.phase = $check.Name
        $client = Start-Sample $game $archive $check.Name @("127.0.0.1:${port}?AdoptionConfigId=$($check.Config)", '-AdoptionSessionSmoke')
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
