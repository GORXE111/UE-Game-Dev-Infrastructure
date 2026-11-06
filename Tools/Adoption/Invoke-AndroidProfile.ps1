#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Project,
    [Parameter(Mandatory)] [string] $EngineRoot,
    [Parameter(Mandatory)] [string] $SdkRoot,
    [Parameter(Mandatory)] [string] $NdkRoot,
    [Parameter(Mandatory)] [string] $JavaHome,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [string] $EditorEngineRoot,
    [string] $ClangRoot,
    [string] $PythonExecutable = 'python',
    [ValidateRange(1, 8)] [int] $MaxParallelActions = 2,
    [switch] $SkipNativeBuild,
    [switch] $SkipEditorBuild
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$report = [ordered]@{schemaVersion=1; status='blocked'; phase='input'; error=$null}
$output = $null
$environment = @{}

function Invoke-Logged([string] $Tool, [string] $Log, [string[]] $Arguments) {
    & $Tool @Arguments *> $Log
    if ($LASTEXITCODE -ne 0) { throw "$($report.phase) exited $LASTEXITCODE. See $Log." }
}

function RequiredFile([string] $Path) {
    $file = Get-Item -LiteralPath $Path
    if ($file -isnot [IO.FileInfo] -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected an ordinary file at $Path."
    }
    return $file.FullName
}

function Get-SourceDigest {
    $source = Join-Path $directory 'Source'
    $records = @(Get-ChildItem -LiteralPath $source -File -Recurse | Sort-Object FullName | ForEach-Object {
        $file = RequiredFile $_.FullName
        [IO.Path]::GetRelativePath($source, $file).Replace('\','/') + ' ' + (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()
    })
    if ($records.Count -eq 0) { throw 'The staged sample has no native source.' }
    $bytes = [Text.Encoding]::UTF8.GetBytes($records -join "`n")
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

try {
    if (-not $IsWindows) { throw 'The Android sample builder requires the Windows UE tools.' }
    $uproject = RequiredFile $Project
    if ([IO.Path]::GetFileName($uproject) -cne 'ProfileSample.uproject') { throw 'Choose the staged ProfileSample project.' }
    $directory = Split-Path $uproject
    $engine = (Resolve-Path -LiteralPath $EngineRoot).Path
    $editorEngine = if ($EditorEngineRoot) { (Resolve-Path -LiteralPath $EditorEngineRoot).Path } else { $engine }
    $python = (Get-Command -Name $PythonExecutable -CommandType Application | Select-Object -First 1).Source
    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem' -or (Test-Path -LiteralPath $requested) -or
        $directory -notmatch '^[ -~]+$' -or $requested -notmatch '^[ -~]+$' -or
        $requested.StartsWith($directory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Use a new short ASCII output path outside the staged project.'
    }
    $marker = RequiredFile (Join-Path $directory 'Content/ReleaseProof/release-sample.json')
    $variant = (Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json).nativeMarker
    if ($variant -cnotin @('baseline','candidate','fault')) { throw 'Invalid Android sample variant.' }
    $null = RequiredFile (Join-Path $engine 'Engine/Build/Android/Java/src/com/epicgames/unreal/GameActivity.java.template')
    $build = RequiredFile (Join-Path $engine 'Engine/Build/BatchFiles/Build.bat')
    $editorBuild = RequiredFile (Join-Path $editorEngine 'Engine/Build/BatchFiles/Build.bat')
    $editor = RequiredFile (Join-Path $engine 'Engine/Binaries/Win64/UnrealEditor-Cmd.exe')
    $uat = RequiredFile (Join-Path $engine 'Engine/Build/BatchFiles/RunUAT.bat')
    $pakTool = RequiredFile (Join-Path $engine 'Engine/Binaries/Win64/UnrealPak.exe')
    $buildId = (Get-Content -LiteralPath (Join-Path $engine 'Engine/Binaries/Win64/UnrealEditor.modules') -Raw | ConvertFrom-Json).BuildId
    $editorBuildId = (Get-Content -LiteralPath (Join-Path $editorEngine 'Engine/Binaries/Win64/UnrealEditor.modules') -Raw | ConvertFrom-Json).BuildId
    if (-not $buildId -or $buildId -cne $editorBuildId) { throw 'The Android and Editor engines have different Build IDs.' }
    $ndk = (Resolve-Path -LiteralPath $NdkRoot).Path
    $sdk = (Resolve-Path -LiteralPath $SdkRoot).Path
    $java = (Resolve-Path -LiteralPath $JavaHome).Path
    $strip = RequiredFile (Join-Path $ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe')
    $null = RequiredFile (Join-Path $java 'bin/java.exe')
    $output = (New-Item -Path $requested -ItemType Directory).FullName
    $report.variant = $variant
    $report.project = $uproject
    $report.engineBuildId = $buildId
    $commit = & git -C $PSScriptRoot rev-parse --verify HEAD
    if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[a-f0-9]{40}$') { throw 'Expected the infrastructure Git commit.' }
    $report.sourceCommit = $commit
    $report.nativeSourceSha256 = Get-SourceDigest
    $report.ndk = $ndk
    $report.ndkSourcePropertiesSha256 = (Get-FileHash -LiteralPath (Join-Path $ndk 'source.properties')).Hash.ToLowerInvariant()
    $javaUser = (New-Item -Path (Join-Path $output 'AndroidUser') -ItemType Directory).FullName
    $values = @{
        ANDROID_HOME=$sdk; ANDROID_SDK_ROOT=$sdk; NDKROOT=$ndk; ANDROID_NDK_ROOT=$ndk
        JAVA_HOME=$java; ANDROID_USER_HOME=$javaUser
    }
    if ($ClangRoot) { $values.LLVM_PATH = (Resolve-Path -LiteralPath $ClangRoot).Path }
    foreach ($name in $values.Keys) {
        $environment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $values[$name], 'Process')
    }
    $common = @("-Project=$uproject", '-NoEngineChanges', '-NoUBA', "-MaxParallelActions=$MaxParallelActions", '-NoDebugInfo', '-NoLinkerDebugInfo')
    $report.phase = 'android-native'
    if (-not $SkipNativeBuild) {
        Invoke-Logged $build (Join-Path $output 'native-build.log') (@('ProfileSample', 'Android', 'Development',
            "-rootdirectory=$engine", "-remoteini=$directory", '-architecture=arm64', '-skipdeploy') + $common)
    }
    $native = RequiredFile (Join-Path $directory 'Binaries/Android/ProfileSample-arm64.so')
    $receipt = RequiredFile (Join-Path $directory 'Binaries/Android/ProfileSample.target')
    $target = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    if ($target.TargetName -cne 'ProfileSample' -or $target.Platform -cne 'Android' -or
        $target.TargetType -cne 'Game' -or $target.Configuration -cne 'Development' -or
        ($target.BuildProducts.Path -cnotcontains '$(ProjectDir)/Binaries/Android/ProfileSample-arm64.so')) {
        throw 'The native target receipt does not identify the Android Development game library.'
    }
    $nativeHash = (Get-FileHash -LiteralPath $native).Hash.ToLowerInvariant()
    $receiptHash = (Get-FileHash -LiteralPath $receipt).Hash.ToLowerInvariant()
    $derived = Join-Path $output 'derived-libUnreal.so'
    Invoke-Logged $strip (Join-Path $output 'native-strip.log') @('--strip-unneeded','-o',$derived,$native)
    $report.deliveryNativeSha256 = (Get-FileHash -LiteralPath $derived).Hash.ToLowerInvariant()

    $report.phase = 'editor-module'
    if (-not $SkipEditorBuild) {
        $editorArgs = @('ProfileSampleEditor', 'Win64', 'Development', '-NoHotReload', '-IgnoreJunk') + $common
        if ($ClangRoot) { $editorArgs += '-Compiler=Clang' }
        Invoke-Logged $editorBuild (Join-Path $output 'editor-build.log') $editorArgs
    }
    $modules = Get-Content -LiteralPath (Join-Path $directory 'Binaries/Win64/UnrealEditor.modules') -Raw | ConvertFrom-Json
    if ($modules.BuildId -cne $buildId -or -not $modules.Modules.ProfileSample) { throw 'The staged Editor module does not match the source engine.' }
    $report.phase = 'android-cook-and-package'
    $archive = Join-Path $output 'Archive'
    Invoke-Logged $uat (Join-Path $output 'package.log') @('BuildCookRun', '-nocompileuat', '-nocompile',
        "-project=$uproject", '-noP4', '-platform=Android', '-target=ProfileSample', '-clientconfig=Development',
        '-skipbuild', '-skipbuildeditor', "-unrealexe=$editor", '-cook', '-map=/Engine/Maps/Entry', '-cookflavor=ETC2',
        '-stage', '-pak', '-skipiostore', '-package', '-archive', "-archivedirectory=$archive", '-unattended', '-utf8output')
    $apks = @(Get-ChildItem -LiteralPath $archive -Recurse -File -Filter '*.apk')
    if ($apks.Count -ne 1) { throw 'Expected one archived Android APK.' }
    if ((Get-FileHash -LiteralPath $native).Hash.ToLowerInvariant() -cne $nativeHash -or
        (Get-FileHash -LiteralPath $receipt).Hash.ToLowerInvariant() -cne $receiptHash -or
        (Get-SourceDigest) -cne $report.nativeSourceSha256) {
        throw 'UAT changed the already-built Android target.'
    }
    $report.phase = 'cooked-paks'
    $paks = @(Get-ChildItem -LiteralPath (Join-Path $directory 'Saved/StagedBuilds/Android_ETC2/ProfileSample/Content/Paks') -File -Filter '*.pak' | Sort-Object Name)
    if ($paks.Count -eq 0) { throw 'Expected at least one staged ETC2 PAK.' }
    $pakRecords = @()
    $proof = @('-X','utf8','-B',(Join-Path $PSScriptRoot 'verify_cooked_assets.py'),'--project-name','ProfileSample','--map','/Engine/Maps/Entry')
    for ($i = 0; $i -lt $paks.Count; $i++) {
        $list = Join-Path $output "pak-$i.list.log"
        Invoke-Logged $pakTool $list @($paks[$i].FullName, '-List', '-ExtractToMountPoint', '-ExcludeDeleted', '-stdout', '-UTF8Output')
        $proof += @('--inventory', $list)
        $pakRecords += @{path=$paks[$i].Name; size=$paks[$i].Length; sha256=(Get-FileHash -LiteralPath $paks[$i].FullName).Hash.ToLowerInvariant()}
    }
    Invoke-Logged $python (Join-Path $output 'cooked-assets.json') $proof
    $report.stagePaks = $pakRecords
    $report.apk = $apks[0].FullName
    $report.apkSha256 = (Get-FileHash -LiteralPath $report.apk).Hash.ToLowerInvariant()
    $report.nativeSha256 = $nativeHash
    $report.targetReceiptSha256 = $receiptHash
    $report.phase = 'complete'
    $report.status = 'android-profile-packaged'
} catch {
    $report.error = $_.Exception.Message
} finally {
    foreach ($name in $environment.Keys) { [Environment]::SetEnvironmentVariable($name, $environment[$name], 'Process') }
}

$result = $report | ConvertTo-Json -Depth 7
if ($output) { $result | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding utf8 }
$result
if ($report.status -ne 'android-profile-packaged') { exit 1 }
