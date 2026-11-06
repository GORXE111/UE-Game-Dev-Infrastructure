#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProfileReport,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [ValidateSet('baseline', 'candidate', 'fault')] [string] $Variant = 'baseline',
    [string] $QaCaDer
)

$ErrorActionPreference = 'Stop'
$output = $null
$report = [ordered]@{ schemaVersion = 1; status = 'blocked'; error = $null }

function Get-PlainItem([string] $Path, [bool] $Directory = $false) {
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a regular sample input at $Path."
    }
    return $item
}

function Copy-PlainTree([string] $Source, [string] $Destination) {
    $null = Get-PlainItem $Source $true
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($item in (Get-ChildItem -LiteralPath $Source -Force)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Cannot copy a linked sample input at $item." }
        $target = Join-Path $Destination $item.Name
        if ($item.PSIsContainer) { Copy-PlainTree $item.FullName $target }
        else { Copy-Item -LiteralPath $item.FullName -Destination $target }
    }
}

try {
    if (-not $IsWindows) { throw 'The Android profile sample requires a Windows UE build host.' }
    $Variant = $Variant.ToLowerInvariant()
    $clientReport = Get-PlainItem $ProfileReport
    $client = Get-Content -LiteralPath $clientReport.FullName -Raw | ConvertFrom-Json
    $shared = $client.sharedConfigSha256
    if ($client.schemaVersion -ne 1 -or $client.status -cne 'project-profile-passed' -or $client.gameExitCode -ne 0 -or
        $shared -cnotmatch '^[a-f0-9]{64}$' -or $client.configManifestSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Use a passing Win64 network profile report.'
    }
    $root = (Get-PlainItem $client.outputDirectory $true).FullName
    $project = (Get-PlainItem (Join-Path $root 'Project') $true).FullName
    $null = Get-PlainItem (Join-Path $project 'ProfileSample.uproject')
    $config = (Get-PlainItem (Join-Path $project 'Config') $true).FullName
    $content = (Get-PlainItem (Join-Path $project 'Content') $true).FullName
    $marker = Get-PlainItem (Join-Path $content 'GeneratedConfig/shared-config.sha256')
    $manifest = Get-PlainItem (Join-Path $root 'ConfigTables/client/manifest.json')
    $configIdentity = (Get-Content -LiteralPath $manifest.FullName -Raw | ConvertFrom-Json).compatibilitySha256
    if ((Get-Content -LiteralPath $marker.FullName -Raw).Trim() -cne $shared -or
        $configIdentity -cne $shared -or
        (Get-FileHash -LiteralPath $manifest.FullName -Algorithm SHA256).Hash -ine $client.configManifestSha256) {
        throw 'The staged configuration differs from the verified network profile report.'
    }
    foreach ($name in @('DT_Enemies.uasset', 'DT_GameplayTags.uasset', 'DT_Waves.uasset')) {
        if ((Get-PlainItem (Join-Path $content "Generated/$name")).Length -eq 0) { throw "Missing generated asset data for $name." }
    }
    $engineConfig = Get-PlainItem (Join-Path $config 'DefaultEngine.ini')
    $gameConfig = Get-PlainItem (Join-Path $config 'DefaultGame.ini')
    $section = '[/Script/AndroidRuntimeSettings.AndroidRuntimeSettings]'
    if (Select-String -LiteralPath $engineConfig.FullName -SimpleMatch -Quiet -Pattern $section) {
        throw 'The Win64 staging inputs already contain Android runtime settings.'
    }
    if (-not (Select-String -LiteralPath $gameConfig.FullName -SimpleMatch -Quiet -Pattern '+DirectoriesToAlwaysStageAsUFS=(Path="ReleaseProof")')) {
        throw 'The Win64 staging inputs do not stage the release proof marker.'
    }

    $qaCa = $null
    if ($QaCaDer) {
        $qaCa = Get-PlainItem $QaCaDer
        if ($qaCa.Length -le 0 -or $qaCa.Length -gt 16384) { throw 'Expected a bounded DER-encoded QA CA certificate.' }
        $certificateBytes = [IO.File]::ReadAllBytes($qaCa.FullName)
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateBytes)
        try {
            if ([Convert]::ToBase64String($certificate.RawData) -cne [Convert]::ToBase64String($certificateBytes) -or
                -not $certificate.Extensions['2.5.29.19'].CertificateAuthority) {
                throw 'Expected one DER-encoded QA CA certificate.'
            }
        } finally { $certificate.Dispose() }
    }

    $repo = Split-Path (Split-Path $PSScriptRoot)
    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem' -or (Test-Path -LiteralPath $requested) -or
        $requested -notmatch '^[A-Za-z]:\\[A-Za-z0-9 ._\\-]+$' -or $requested.Length -gt 100 -or
        $requested.StartsWith($root.TrimEnd('\\') + '\\', [StringComparison]::OrdinalIgnoreCase) -or
        $requested.StartsWith($repo.TrimEnd('\\') + '\\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Choose a new short ASCII output directory outside the client build and repository.'
    }
    $parent = Get-PlainItem ([IO.Path]::GetDirectoryName($requested)) $true
    for ($directory = $parent.Parent; $directory; $directory = $directory.Parent) {
        if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Choose an output parent without filesystem links.'
        }
    }

    $output = (New-Item -Path $requested -ItemType Directory).FullName
    $staged = Join-Path $output 'Project'
    $example = Join-Path $repo 'Examples/ProjectProfile/ProfileSample'
    Copy-PlainTree (Join-Path $example 'Source') (Join-Path $staged 'Source')
    Copy-PlainTree $config (Join-Path $staged 'Config')
    Copy-PlainTree $content (Join-Path $staged 'Content')

    $pluginName = 'SampleGameNativeUpdate'
    $plugin = Join-Path $repo "Project/SampleGame/Plugins/$pluginName"
    $stagedPlugin = Join-Path $staged "Plugins/$pluginName"
    Copy-PlainTree (Join-Path $plugin 'Source') (Join-Path $stagedPlugin 'Source')
    $pluginDescriptor = Get-PlainItem (Join-Path $plugin "$pluginName.uplugin")
    Copy-Item -LiteralPath $pluginDescriptor.FullName -Destination $stagedPlugin
    $sourceProject = Get-PlainItem (Join-Path $example 'ProfileSample.uproject')
    $descriptor = Get-Content -LiteralPath $sourceProject.FullName -Raw | ConvertFrom-Json -AsHashtable
    $descriptor['Plugins'] = @($descriptor['Plugins'] | Where-Object { $_ -and $_.Name -ine $pluginName }) +
        @([ordered]@{ Name = $pluginName; Enabled = $true })
    $stagedProject = Join-Path $staged 'ProfileSample.uproject'
    $descriptor | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $stagedProject -Encoding utf8

    @"
#pragma once

#define ADOPTION_RELEASE_NATIVE_MARKER TEXT("$Variant")
"@ | Set-Content -LiteralPath (Join-Path $staged 'Source/ProfileSample/ProfileReleaseVariant.h') -Encoding ascii
    $releaseProof = [IO.Directory]::CreateDirectory((Join-Path $staged 'Content/ReleaseProof')).FullName
    [ordered]@{ format = 1; nativeMarker = $Variant } | ConvertTo-Json -Compress |
        Set-Content -LiteralPath (Join-Path $releaseProof 'release-sample.json') -Encoding ascii

    $package = 'com.example.profilesample.adoption'
    $settings = @('', $section, "PackageName=$package", 'bBuildForArm64=True', 'bBuildForX8664=False',
        'bBuildForES31=True', 'bSupportsVulkan=False', 'bSupportsVulkanSM5=False', 'bPackageDataInsideApk=True',
        'bSupportAdMob=False', 'bShowLaunchImage=True', 'bUseExternalFilesDir=True', 'bEnableBundle=False')
    if ($qaCa) {
        $settings += 'bProfileSampleQaTls=True'
        $resources = Join-Path $staged 'Build/Android/res'
        $raw = [IO.Directory]::CreateDirectory((Join-Path $resources 'raw')).FullName
        $xml = [IO.Directory]::CreateDirectory((Join-Path $resources 'xml')).FullName
        [IO.File]::WriteAllBytes((Join-Path $raw 'profilesample_qa_ca.der'), $certificateBytes)
        @'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="false">10.0.2.2</domain>
        <trust-anchors><certificates src="@raw/profilesample_qa_ca" /></trust-anchors>
    </domain-config>
</network-security-config>
'@ | Set-Content -LiteralPath (Join-Path $xml 'profilesample_qa_network_security.xml') -Encoding utf8
    }
    # Win64 editor startup can add enabled AFS defaults. UE reads the Editor-named section when packaging.
    $afsSection = '/Script/AndroidFileServerEditor.AndroidFileServerRuntimeSettings'
    $stagedEngineConfig = Join-Path $staged 'Config/DefaultEngine.ini'
    $engineSettings = Get-Content -LiteralPath $stagedEngineConfig -Raw
    $afsPattern = '(?ms)^\[' + [regex]::Escape($afsSection) + '\][^\r\n]*(?:\r?\n|$).*?(?=^\[|\z)'
    $engineSettings = [regex]::Replace($engineSettings, $afsPattern, '').TrimEnd()
    $settings = @($engineSettings, '', "[$afsSection]", 'bEnablePlugin=False', 'bIncludeInShipping=False') + $settings
    Set-Content -LiteralPath $stagedEngineConfig -Value $settings -Encoding utf8

    $report.outputDirectory = $output
    $report.project = $stagedProject
    $report.variant = $Variant
    $report.packageName = $package
    $report.qaTlsEnabled = [bool] $qaCa
    $report.sharedConfigSha256 = $shared
    $report.status = 'android-sample-prepared'
} catch {
    $report.error = $_.Exception.Message
}

$result = $report | ConvertTo-Json -Depth 4
if ($output) { $result | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding utf8 }
$result
if ($report.status -ne 'android-sample-prepared') { exit 1 }
exit 0
