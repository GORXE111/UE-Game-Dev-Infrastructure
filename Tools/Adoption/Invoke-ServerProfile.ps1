#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Project,
    [Parameter(Mandatory)] [string] $EngineRoot,
    [Parameter(Mandatory)] [string] $ServerConfigDirectory,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [string] $Target,
    [string] $EditorTarget,
    [ValidatePattern('^/(Game|Engine)/[\w-]+(/[\w-]+)*$')] [string] $Map = '/Engine/Maps/Entry',
    [string] $PythonExecutable = 'python',
    [string] $ClangRoot,
    [ValidateRange(1, 8)] [int] $MaxParallelActions = 2,
    [switch] $SkipBuild,
    [switch] $SkipEditorBuild
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$report = [ordered]@{ schemaVersion = 1; status = 'running'; phase = 'input'; outputDirectory = $null; error = $null }
$output = $null
$previousLlvm = $env:LLVM_PATH

function Invoke-Logged([string] $Executable, [string] $Log, [string[]] $Arguments) {
    & $Executable @Arguments *> $Log
    if ($LASTEXITCODE -ne 0) { throw "$($report.phase) exited with code $LASTEXITCODE. See $Log." }
}

function Get-PhysicalPath([string] $Path) {
    $resolved = & $python -X utf8 -B -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' $Path
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve $Path." }
    return $resolved
}

function Test-InDirectory([string] $Path, [string] $Directory) {
    $base = $Directory.TrimEnd('\', '/')
    return ($Path -ieq $base -or $Path.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase))
}

function Get-PlainFile([string] $Path) {
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a regular file: $Path"
    }
    return $item
}

function Get-ServerExecutable {
    $binaries = Join-Path $projectDirectory 'Binaries/Win64'
    $receipt = (Get-PlainFile (Join-Path $binaries "$Target.target")).FullName
    $data = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    $launch = ([string] $data.Launch).Replace('\', '/')
    if ($data.TargetName -cne $Target -or $data.TargetType -cne 'Server' -or
        $data.Platform -cne 'Win64' -or $data.Configuration -cne 'Development' -or $data.Architecture -cne 'x64' -or
        $launch -cne ('$(ProjectDir)/Binaries/Win64/' + "$Target.exe")) {
        throw 'The staged project lacks a matching Win64 Development Server target receipt.'
    }
    $exe = Get-PlainFile (Join-Path $binaries "$Target.exe")
    if ($exe.Length -le 0) { throw 'The Server target executable is empty.' }
    $report.targetReceipt = $receipt
    return $exe.FullName
}

try {
    if (-not $IsWindows) { throw 'Dedicated profile packaging requires a Win64 UE host.' }
    $project = (Get-PlainFile (Resolve-Path -LiteralPath $Project).Path).FullName
    $projectName = [IO.Path]::GetFileNameWithoutExtension($project)
    if ([IO.Path]::GetExtension($project) -ine '.uproject' -or $projectName -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,127}$') {
        throw 'Choose a staged C++ .uproject with a valid project name.'
    }
    if (-not $Target) { $Target = "${projectName}Server" }
    if (-not $EditorTarget) { $EditorTarget = "${projectName}Editor" }
    if ($Target -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,127}$' -or $EditorTarget -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,127}$') {
        throw 'Choose valid UE Server and Editor target names.'
    }
    $report.target = $Target
    $report.map = $Map
    $projectDirectory = Split-Path $project
    $engine = (Resolve-Path -LiteralPath $EngineRoot).Path
    $python = (Get-Command -Name $PythonExecutable -CommandType Application | Select-Object -First 1).Source
    $projectPhysical = Get-PhysicalPath $projectDirectory
    $enginePhysical = Get-PhysicalPath $engine
    if (Test-InDirectory $projectPhysical $enginePhysical) { throw 'Use a staged project outside the UE engine directory.' }

    $configSource = Get-Item -LiteralPath (Resolve-Path -LiteralPath $ServerConfigDirectory).Path
    if (-not $configSource.PSIsContainer -or ($configSource.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Choose a server config directory with regular exported files.'
    }
    $configPhysical = Get-PhysicalPath $configSource.FullName
    if (Test-InDirectory $configPhysical $projectPhysical) { throw 'Keep the server config directory outside the staged project.' }

    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem') { throw 'Choose a local filesystem output path.' }
    $requested = Get-PhysicalPath $requested
    if (Test-Path -LiteralPath $requested) { throw 'Choose a new dedicated profile output directory.' }
    if ((Test-InDirectory $requested $projectPhysical) -or (Test-InDirectory $requested $enginePhysical) -or
        (Test-InDirectory $requested $configPhysical)) { throw 'Keep the output outside the staged project, engine and input config.' }
    if ($project -notmatch '^[ -~]+$' -or $requested -notmatch '^[ -~]+$' -or
        $project -match '[\\/]Programs[\\/]' -or $requested -match '[\\/]Programs[\\/]') {
        throw 'Choose short ASCII paths for the staged project and the new output, outside Programs directories.'
    }

    $build = Join-Path $engine 'Engine/Build/BatchFiles/Build.bat'
    $uat = Join-Path $engine 'Engine/Build/BatchFiles/RunUAT.bat'
    $editor = Join-Path $engine 'Engine/Binaries/Win64/UnrealEditor-Cmd.exe'
    $unrealPak = Join-Path $engine 'Engine/Binaries/Win64/UnrealPak.exe'
    foreach ($tool in @($build, $uat, $editor, $unrealPak)) { $null = Get-PlainFile $tool }
    $capability = & $python -X utf8 -B (Join-Path $PSScriptRoot 'server_capability.py') --engine $engine | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $capability.status -cnotin @('installed-ready', 'source-ready-to-plan')) {
        throw "Engine Server capability is blocked. $($capability.error)"
    }
    $report.engineCapability = $capability.status
    $ubt = @('-IgnoreJunk', '-NoEngineChanges', '-NoUBA', "-MaxParallelActions=$MaxParallelActions", '-NoDebugInfo', '-NoLinkerDebugInfo')
    if ($ClangRoot) {
        $env:LLVM_PATH = (Resolve-Path -LiteralPath $ClangRoot).Path
        $ubt += '-Compiler=Clang'
    }

    $report.phase = 'server-config'
    $manifestPath = (Get-PlainFile (Join-Path $configSource.FullName 'manifest.json')).FullName
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
    $sharedConfig = $manifest.compatibilitySha256
    if ($sharedConfig -cnotmatch '^[a-f0-9]{64}$' -or $manifest.sourceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $manifest.files -isnot [Collections.IDictionary] -or $manifest.files.Count -eq 0) {
        throw 'Expected a server config export with both configuration digests and file inventory.'
    }
    $marker = (Get-PlainFile (Join-Path $projectDirectory 'Content/GeneratedConfig/shared-config.sha256')).FullName
    if ((Get-Content -LiteralPath $marker -Raw).Trim() -cne $sharedConfig) {
        throw 'The staged shared-config marker differs from the server config manifest.'
    }

    $output = (New-Item -Path $requested -ItemType Directory).FullName
    $report.outputDirectory = $output
    $configSnapshot = (New-Item -Path (Join-Path $output 'ServerConfig') -ItemType Directory).FullName
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $manifest.files.GetEnumerator()) {
        $name = [string] $entry.Key
        $record = $entry.Value
        if ($name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,62}\.json$' -or $name -ieq 'manifest.json' -or -not $names.Add($name) -or
            $record -isnot [Collections.IDictionary] -or $record.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $record.size -isnot [long] -or $record.size -le 0) {
            throw "Invalid server config inventory entry: $name"
        }
        $source = Get-PlainFile (Join-Path $configSource.FullName $name)
        $snapshot = Join-Path $configSnapshot $name
        Copy-Item -LiteralPath $source.FullName -Destination $snapshot
        if ((Get-Item -LiteralPath $snapshot).Length -ne $record.size -or
            (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash.ToLowerInvariant() -cne $record.sha256) {
            throw "Server config file differs from the export manifest: $name"
        }
    }
    $snapshotManifest = Join-Path $configSnapshot 'manifest.json'
    Copy-Item -LiteralPath $manifestPath -Destination $snapshotManifest
    if ((Get-FileHash -LiteralPath $snapshotManifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifestHash) {
        throw 'Server config manifest changed during staging.'
    }
    $report.serverConfigDirectory = $configSnapshot
    $report.serverConfigManifestSha256 = $manifestHash
    $report.sharedConfigSha256 = $sharedConfig

    if ($SkipBuild) {
        $report.phase = 'server-target'
        $serverExecutable = Get-ServerExecutable
    }
    $report.phase = 'editor-build'
    if (-not $SkipEditorBuild) {
        Invoke-Logged $build (Join-Path $output 'editor-build.log') (@($EditorTarget, 'Win64', 'Development',
            "-Project=$project", '-NoHotReload') + $ubt)
    }
    $engineModules = Get-Content -LiteralPath (Join-Path $engine 'Engine/Binaries/Win64/UnrealEditor.modules') -Raw | ConvertFrom-Json
    $projectModules = Get-Content -LiteralPath (Join-Path $projectDirectory 'Binaries/Win64/UnrealEditor.modules') -Raw | ConvertFrom-Json
    if (-not $engineModules.BuildId -or $engineModules.BuildId -cne $projectModules.BuildId) {
        throw 'The staged Editor modules must match the selected engine BuildId.'
    }
    $report.editorBuildId = $engineModules.BuildId

    $report.phase = 'cook-and-package'
    $archiveRoot = Join-Path $output 'Archive'
    $stage = Join-Path $output 'Stage'
    $buildFlag = if ($SkipBuild) { '-skipbuild' } else { '-build' }
    Invoke-Logged $uat (Join-Path $output 'package.log') @('BuildCookRun', '-nocompileuat', '-nocompile', "-project=$project",
        '-noP4', '-platform=Win64', "-target=$Target", '-server', '-noclient', '-serverplatform=Win64', '-serverconfig=Development',
        $buildFlag, '-skipbuildeditor', '-cook', "-unrealexe=$editor", "-map=$Map", '-stage', '-pak', '-skipiostore', '-package', '-archive',
        "-stagingdirectory=$stage", "-archivedirectory=$archiveRoot", '-unattended', '-utf8output', ('-ubtargs=' + ($ubt -join ' ')))
    if (-not $SkipBuild) {
        $report.phase = 'server-target'
        $serverExecutable = Get-ServerExecutable
    }

    $report.phase = 'server-archive'
    $stagedExe = "$projectName/Binaries/Win64/$Target.exe"
    $payloads = @( @($archiveRoot, (Join-Path $archiveRoot 'WindowsServer')) | Where-Object {
        Test-Path -LiteralPath (Join-Path $_ $stagedExe) -PathType Leaf
    })
    if ($payloads.Count -ne 1) { throw 'Expected one Win64 dedicated Server archive with its inner executable.' }
    $payload = $payloads[0]
    $exe = (Get-PlainFile (Join-Path $payload $stagedExe)).FullName
    $archiveSha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $serverExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $archiveSha) {
        throw 'The archived executable differs from the Win64 Server target executable.'
    }
    $report.archive = $payload
    $report.executable = $exe
    $report.executableSha256 = $archiveSha

    $report.phase = 'cooked-asset-check'
    $paks = @(Get-ChildItem -LiteralPath (Join-Path $payload "$projectName/Content/Paks") -File -Filter '*.pak' | Sort-Object Name)
    if ($paks.Count -eq 0) { throw 'Expected at least one packaged Server PAK.' }
    $proof = @('-X', 'utf8', '-B', (Join-Path $PSScriptRoot 'verify_cooked_assets.py'), '--project-name', $projectName, '--map', $Map)
    $markerPaks = @()
    $markerEntry = '"../../../' + $projectName + '/Content/GeneratedConfig/shared-config.sha256" offset:'
    for ($i = 0; $i -lt $paks.Count; $i++) {
        $list = Join-Path $output "pak-$i.list.log"
        Invoke-Logged $unrealPak $list @($paks[$i].FullName, '-List', '-ExtractToMountPoint', '-ExcludeDeleted', '-stdout', '-UTF8Output')
        $proof += @('--inventory', $list)
        if (Select-String -LiteralPath $list -SimpleMatch -CaseSensitive -Quiet -Pattern $markerEntry) {
            $markerPaks += $paks[$i].FullName
        }
    }
    Invoke-Logged $python (Join-Path $output 'cooked-assets.json') $proof
    if ($markerPaks.Count -ne 1) { throw 'Expected the shared config marker in exactly one Server PAK.' }
    $extract = Join-Path $output 'PakProof'
    Invoke-Logged $unrealPak (Join-Path $output 'pak-marker.log') @($markerPaks[0], '-Extract', $extract,
        '-Filter=*GeneratedConfig/shared-config.sha256', '-stdout', '-UTF8Output')
    $markers = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter 'shared-config.sha256')
    if ($markers.Count -ne 1 -or (Get-Content -LiteralPath $markers[0].FullName -Raw).Trim() -cne $sharedConfig) {
        throw 'The shared config digest read from the Server PAK differs from the validated config export.'
    }
    $report.phase = 'complete'
    $report.status = 'server-profile-passed'
} catch {
    $report.status = 'blocked'
    $report.error = $_.Exception.Message
} finally {
    $env:LLVM_PATH = $previousLlvm
}

$result = $report | ConvertTo-Json -Depth 5
if ($output) { $result | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding utf8 }
$result
if ($report.status -ne 'server-profile-passed') { exit 1 }
exit 0
