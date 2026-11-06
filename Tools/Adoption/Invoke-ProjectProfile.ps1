#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Profile,
    [Parameter(Mandatory)] [string] $EngineRoot,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [string] $PythonExecutable = 'python',
    [string] $ClangRoot,
    [ValidateRange(1, 8)] [int] $MaxParallelActions = 2,
    [switch] $RequireBuildReceipt
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$report = [ordered]@{ schemaVersion = 1; status = 'running'; phase = 'input'; outputDirectory = $null; error = $null }
$toolsRoot = Split-Path $PSScriptRoot
$output = $null
$previousLlvm = $env:LLVM_PATH
$previousProfile = $env:UE_ADOPTION_NORMALIZED_PROFILE
$previousBundle = $env:UE_ADOPTION_CONFIG_BUNDLE
$previousPlan = $env:UE_ADOPTION_ASSET_PLAN
$previousAssetReport = $env:UE_ADOPTION_ASSET_REPORT

function Invoke-Logged([string] $Executable, [string] $Log, [string[]] $Arguments) {
    & $Executable @Arguments *> $Log
    if ($LASTEXITCODE -ne 0) { throw "$($report.phase) exited with code $LASTEXITCODE. See $Log." }
}

function Get-CleanCommit([string] $Directory) {
    $commit = & git -C $Directory rev-parse --verify HEAD
    if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') { throw 'Build receipt requires a Git commit.' }
    $changes = & git -C $Directory status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $changes) { throw 'Build receipt requires a clean project checkout.' }
    return $commit
}

try {
    if (-not $IsWindows) { throw 'Project profile packaging requires a Win64 UE host.' }
    $profilePath = (Resolve-Path -LiteralPath $Profile).Path
    $engine = (Resolve-Path -LiteralPath $EngineRoot).Path
    $python = (Get-Command -Name $PythonExecutable -CommandType Application | Select-Object -First 1).Source
    $json = & $python -X utf8 -B (Join-Path $PSScriptRoot 'project_profile.py') --profile $profilePath
    $profileExit = $LASTEXITCODE
    $settings = $json | ConvertFrom-Json
    if ($profileExit -ne 0 -or $settings.status -cne 'validated') { throw "Project profile failed validation. $($settings.error)" }
    $source = Split-Path $settings.project
    $projectName = [IO.Path]::GetFileNameWithoutExtension($settings.project)
    if ($RequireBuildReceipt) { $commit = Get-CleanCommit $source }
    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem') { throw 'Choose a local filesystem output path.' }
    $requested = & $python -X utf8 -B -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' $requested
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the profile output path.' }
    $sourcePrefix = $source.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (Test-Path -LiteralPath $requested) { throw 'Choose a new profile output directory.' }
    if ($requested.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $requested -notmatch '^[ -~]+$') { throw 'Choose a short ASCII output path outside the source project.' }

    $build = Join-Path $engine 'Engine/Build/BatchFiles/Build.bat'
    $uat = Join-Path $engine 'Engine/Build/BatchFiles/RunUAT.bat'
    $editor = Join-Path $engine 'Engine/Binaries/Win64/UnrealEditor-Cmd.exe'
    $unrealPak = Join-Path $engine 'Engine/Binaries/Win64/UnrealPak.exe'
    foreach ($file in @($build, $uat, $editor, $unrealPak)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing UE tool $file" }
    }
    $ubt = @('-NoUBA', "-MaxParallelActions=$MaxParallelActions", '-NoDebugInfo', '-NoLinkerDebugInfo')
    if ($ClangRoot) {
        $env:LLVM_PATH = (Resolve-Path -LiteralPath $ClangRoot).Path
        $ubt += '-Compiler=Clang'
    }

    $output = (New-Item -Path $requested -ItemType Directory).FullName
    $report.outputDirectory = $output
    $normalized = Join-Path $output 'normalized-profile.json'
    $json | Set-Content -LiteralPath $normalized -Encoding utf8
    $assetPlan = Join-Path $output 'asset-plan.json'
    Copy-Item -LiteralPath $settings.assetPlan -Destination $assetPlan
    $assets = (Get-Content -LiteralPath $assetPlan -Raw | ConvertFrom-Json).assets

    $report.phase = 'config-export'
    $bundle = Join-Path $output 'ConfigTables'
    Invoke-Logged $python (Join-Path $output 'config-export.log') @('-X', 'utf8', '-B',
        (Join-Path $toolsRoot 'ConfigTables/config_tables.py'), '--source', $settings.configSource, '--output', $bundle)
    $manifest = Join-Path $bundle 'manifest.json'
    $report.configManifestSha256 = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()

    $report.phase = 'stage-source'
    $staged = (New-Item -Path (Join-Path $output 'Project') -ItemType Directory).FullName
    $project = Join-Path $staged "$projectName.uproject"
    Copy-Item -LiteralPath $settings.project -Destination $project
    $copyLog = Join-Path $output 'stage-source.log'
    foreach ($name in @('Build', 'Config', 'Content', 'Plugins', 'Source')) {
        $directory = Join-Path $source $name
        if (Test-Path -LiteralPath $directory -PathType Container) {
            if ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Choose a real source directory for $name."
            }
            & robocopy.exe $directory (Join-Path $staged $name) /E /XJ /R:0 /W:0 /NFL /NDL /NP `
                /XD Intermediate Saved DerivedDataCache .git /XF .git *>> $copyLog
            if ($LASTEXITCODE -ge 8) { throw "Failed to stage source directory $name." }
            Add-Content -LiteralPath $copyLog -Value "Staged $name"
        }
    }
    $config = Join-Path $staged 'Config'
    [IO.Directory]::CreateDirectory($config) | Out-Null
    $packaging = @('', '[/Script/UnrealEd.ProjectPackagingSettings]', 'UsePakFile=True', 'bUseIoStore=False', 'bUseZenStore=False')
    foreach ($directory in ($settings.dataTables.asset | ForEach-Object { $_.Substring(0, $_.LastIndexOf('/')) } | Sort-Object -Unique)) {
        $packaging += ('+DirectoriesToAlwaysCook=(Path="' + $directory + '")')
    }
    Add-Content -LiteralPath (Join-Path $config 'DefaultGame.ini') -Value $packaging

    $report.phase = 'editor-build'
    Invoke-Logged $build (Join-Path $output 'editor-build.log') (@($settings.build.editorTarget, 'Win64', 'Development',
        "-Project=$project", '-NoHotReload') + $ubt)

    $commandlet = @('-run=PythonScript', '-EnablePlugins=PythonScriptPlugin', '-Unattended', '-NullRHI', '-NoSound',
        '-NoSplash', '-stdout', '-FullStdOutLogOutput')
    $env:UE_ADOPTION_NORMALIZED_PROFILE = $normalized
    $env:UE_ADOPTION_CONFIG_BUNDLE = $bundle
    $report.phase = 'table-import'
    $import = Join-Path $output 'import_profile_tables.py'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'import_profile_tables.py') -Destination $import
    $importLog = Join-Path $output 'table-import.log'
    Invoke-Logged $editor $importLog (@($project, "-script=$import") + $commandlet)
    if (-not (Select-String -LiteralPath $importLog -SimpleMatch -Quiet -Pattern "UE_ADOPTION_PROFILE_TABLES_IMPORTED count=$($settings.dataTables.Count)")) {
        throw "Expected all generated DataTables to be imported. See $importLog."
    }

    $report.phase = 'editor-asset-check'
    $checker = Join-Path $output 'check_ue_assets.py'
    Copy-Item -LiteralPath (Join-Path $toolsRoot 'AssetChecks/check_ue_assets.py') -Destination $checker
    $env:UE_ADOPTION_ASSET_PLAN = $assetPlan
    $env:UE_ADOPTION_ASSET_REPORT = Join-Path $output 'asset-report.json'
    Invoke-Logged $editor (Join-Path $output 'asset-check.log') (@($project, "-script=$checker") + $commandlet)
    if ((Get-Content -LiteralPath $env:UE_ADOPTION_ASSET_REPORT -Raw | ConvertFrom-Json).status -cne 'passed') {
        throw 'Declared editor assets did not pass. See asset-report.json.'
    }

    $report.phase = 'cook-and-package'
    $archive = Join-Path $output 'Archive'
    Invoke-Logged $uat (Join-Path $output 'package.log') @('BuildCookRun', "-project=$project", '-noP4', '-platform=Win64',
        "-target=$($settings.build.target)", '-clientconfig=Development', '-build', '-skipbuildeditor', '-cook',
        ('-map=' + ($settings.build.maps -join '+')), '-stage', '-pak', '-skipiostore', '-package', '-archive',
        "-archivedirectory=$archive", '-unattended', '-utf8output', ('-ubtargs=' + ($ubt -join ' ')))
    $payload = Join-Path $archive 'Windows'
    $report.archive = $payload

    $report.phase = 'cooked-asset-check'
    $pakDirectory = Join-Path $payload "$projectName/Content/Paks"
    $paks = @(Get-ChildItem -LiteralPath $pakDirectory -File -Filter '*.pak' | Sort-Object Name)
    if ($paks.Count -eq 0) { throw 'Expected at least one packaged PAK.' }
    $proof = @('-X', 'utf8', '-B', (Join-Path $PSScriptRoot 'verify_cooked_assets.py'), '--project-name', $projectName)
    for ($i = 0; $i -lt $paks.Count; $i++) {
        $list = Join-Path $output "pak-$i.list.log"
        Invoke-Logged $unrealPak $list @($paks[$i].FullName, '-List', '-ExtractToMountPoint', '-ExcludeDeleted', '-stdout', '-UTF8Output')
        $proof += @('--inventory', $list)
    }
    foreach ($map in $settings.build.maps) { $proof += @('--map', $map) }
    foreach ($asset in $assets) {
        if ($asset.class -ceq '/Script/Engine.World') { $proof += @('--map', $asset.path.Split('.')[0]) }
        else { $proof += @('--object', $asset.path) }
    }
    $cookedReport = Join-Path $output 'cooked-assets.json'
    Invoke-Logged $python $cookedReport $proof
    if ((Get-Content -LiteralPath $cookedReport -Raw | ConvertFrom-Json).status -cne 'passed') {
        throw 'Cooked asset checks did not pass. See cooked-assets.json.'
    }

    $report.phase = 'packaged-startup'
    $game = Join-Path $payload "$projectName/Binaries/Win64/$($settings.build.target).exe"
    $log = Join-Path $output 'packaged-game.log'
    $start = [Diagnostics.ProcessStartInfo]::new($game)
    $start.WorkingDirectory = $payload
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $runtimeUser = [IO.Directory]::CreateDirectory((Join-Path $output 'RuntimeUser')).FullName
    foreach ($arg in @($settings.startup.map, '-AdoptionProfileSmoke', '-NullRHI', '-Unattended', '-NoSound', "-abslog=$log", "-UserDir=$runtimeUser")) {
        $start.ArgumentList.Add($arg)
    }
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(120000)) {
            if (-not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
            throw 'Packaged startup timed out. See packaged-game.log.'
        }
        $report.gameExitCode = $process.ExitCode
    } finally {
        $process.Dispose()
    }
    if ($report.gameExitCode -ne 0 -or
        -not (Select-String -LiteralPath $log -SimpleMatch -CaseSensitive -Quiet -Pattern $settings.startup.readyMarker) -or
        -not (Select-String -LiteralPath $log -SimpleMatch -Quiet -Pattern 'LogExit: Exiting.')) {
        throw 'Expected project readiness and normal packaged exit. See packaged-game.log.'
    }
    if ($RequireBuildReceipt) {
        $report.phase = 'build-receipt'
        if ((Get-CleanCommit $source) -cne $commit) { throw 'The project commit changed during the build.' }
        $version = Get-Content -LiteralPath (Join-Path $engine 'Engine/Build/Build.version') -Raw | ConvertFrom-Json
        $modules = Get-Content -LiteralPath (Join-Path $engine 'Engine/Binaries/Win64/UnrealEditor.modules') -Raw | ConvertFrom-Json
        $toolchain = Get-Content -LiteralPath (Join-Path $output 'package.log') -Raw
        $sdkMatch = [regex]::Match($toolchain, 'and Windows (?<version>\d+(?:\.\d+){2,3}) SDK')
        $compilerMatch = [regex]::Match($toolchain, 'Using (?<name>Clang|Visual Studio \d{4}) (?<version>\d+(?:\.\d+)+) (?:compiler|toolchain)')
        if (-not $sdkMatch.Success -or -not $compilerMatch.Success) { throw 'Could not identify the actual UBT compiler and Windows SDK. See package.log.' }
        $metadata = [ordered]@{
            project = $projectName; target = $settings.build.target; platform = $settings.build.platform
            configuration = $settings.build.configuration; commit = $commit
            engine = @{version = "$($version.MajorVersion).$($version.MinorVersion).$($version.PatchVersion)"; buildId = $modules.BuildId}
            sdk = @{windows = $sdkMatch.Groups['version'].Value; compiler = $compilerMatch.Groups['name'].Value
                compilerVersion = $compilerMatch.Groups['version'].Value}
            configManifestSha256 = $report.configManifestSha256
            tests = @{'editor-assets' = 'passed'; 'cooked-assets' = 'passed'; 'packaged-startup' = 'passed'}
        }
        $metadataPath = Join-Path $output 'receipt-metadata.json'
        $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding utf8
        $receipt = Join-Path $output 'build-receipt.json'
        Invoke-Logged $python (Join-Path $output 'build-receipt.log') @('-X', 'utf8', '-B', (Join-Path $PSScriptRoot 'build_receipt.py'),
            'create', '--archive', $payload, '--metadata', $metadataPath, '--output', $receipt)
        $report.buildReceipt = $receipt
        $report.buildReceiptSha256 = (Get-FileHash -LiteralPath $receipt -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $report.phase = 'complete'
    $report.status = 'project-profile-passed'
} catch {
    $report.status = 'blocked'
    $report.error = $_.Exception.Message
} finally {
    $env:LLVM_PATH = $previousLlvm
    $env:UE_ADOPTION_NORMALIZED_PROFILE = $previousProfile
    $env:UE_ADOPTION_CONFIG_BUNDLE = $previousBundle
    $env:UE_ADOPTION_ASSET_PLAN = $previousPlan
    $env:UE_ADOPTION_ASSET_REPORT = $previousAssetReport
}

$result = $report | ConvertTo-Json -Depth 5
if ($output) { $result | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding utf8 }
$result
if ($report.status -ne 'project-profile-passed') { exit 1 }
exit 0
