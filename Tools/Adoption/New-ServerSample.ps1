#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProfileReport,
    [Parameter(Mandatory)] [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$report = [ordered]@{schemaVersion = 1; status = 'blocked'; error = $null}

function Copy-PlainFiles([string] $Source, [string] $Destination, [string] $Filter) {
    $directory = Get-Item -LiteralPath $Source
    if ($directory -isnot [IO.DirectoryInfo] -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a plain source directory: $Source"
    }
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($file in (Get-ChildItem -LiteralPath $Source -Filter $Filter -File)) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Cannot copy a linked sample file: $file" }
        Copy-Item -LiteralPath $file.FullName -Destination $Destination
    }
}

try {
    if (-not $IsWindows) { throw 'The source server sample requires Windows.' }
    $client = Get-Content -LiteralPath $ProfileReport -Raw | ConvertFrom-Json
    $shared = $client.sharedConfigSha256
    if ($client.status -cne 'project-profile-passed' -or $shared -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Use a passing network-profile client report.'
    }
    $root = (Resolve-Path -LiteralPath $client.outputDirectory).Path
    $project = Join-Path $root 'Project'
    $marker = Get-Content -LiteralPath (Join-Path $project 'Content/GeneratedConfig/shared-config.sha256') -Raw
    $manifestPath = (Resolve-Path -LiteralPath $client.serverConfigManifest).Path
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
    if ($marker.Trim() -cne $shared -or $manifest.compatibilitySha256 -cne $shared) {
        throw 'Client staged assets and server configuration have different shared identities.'
    }

    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem' -or (Test-Path -LiteralPath $requested) -or $requested -notmatch '^[ -~]+$' -or
        $requested.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Choose a new short output directory outside the client build.'
    }
    $parent = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($requested))
    for ($directory = $parent; $directory; $directory = $directory.Parent) {
        if ($directory -isnot [IO.DirectoryInfo] -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Choose an existing output parent without filesystem links.'
        }
    }
    $output = (New-Item -Path $requested -ItemType Directory).FullName
    $example = Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'Examples/ProjectProfile'
    $staged = Join-Path $output 'Project'
    Copy-PlainFiles (Join-Path $example 'ProfileSample') $staged 'ProfileSample.uproject'
    Copy-PlainFiles (Join-Path $example 'ProfileSample/Source') (Join-Path $staged 'Source') '*.cs'
    Copy-PlainFiles (Join-Path $example 'ProfileSample/Source/ProfileSample') (Join-Path $staged 'Source/ProfileSample') '*'
    Copy-Item -LiteralPath (Join-Path $example 'ServerTarget/ProfileSampleServer.Target.cs') -Destination (Join-Path $staged 'Source')
    Copy-PlainFiles (Join-Path $project 'Config') (Join-Path $staged 'Config') '*.ini'
    Copy-PlainFiles (Join-Path $project 'Content/Generated') (Join-Path $staged 'Content/Generated') '*.uasset'
    Copy-PlainFiles (Join-Path $project 'Content/GeneratedConfig') (Join-Path $staged 'Content/GeneratedConfig') 'shared-config.sha256'

    $server = [IO.Directory]::CreateDirectory((Join-Path $output 'ServerConfig')).FullName
    foreach ($name in $manifest.files.Keys) {
        if ($name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,62}\.json$') { throw 'Invalid server configuration filename.' }
        $file = Get-Item -LiteralPath (Join-Path (Split-Path $manifestPath) $name)
        if ($file -isnot [IO.FileInfo] -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $file.Length -ne $manifest.files[$name].size -or
            (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ine $manifest.files[$name].sha256) {
            throw "Server configuration differs from its manifest: $name"
        }
        Copy-Item -LiteralPath $file.FullName -Destination $server
    }
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $server 'manifest.json')
    $report.project = Join-Path $staged 'ProfileSample.uproject'
    $report.serverConfigDirectory = $server
    $report.sharedConfigSha256 = $shared
    $report.status = 'server-sample-prepared'
} catch {
    $report.error = $_.Exception.Message
}

$result = $report | ConvertTo-Json -Depth 4
if ($output) { $result | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding utf8 }
$result
if ($report.status -ne 'server-sample-prepared') { exit 1 }
exit 0
