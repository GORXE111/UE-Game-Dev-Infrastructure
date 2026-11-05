param(
    [Parameter(Mandatory = $true)][string]$JavaHome,
    [Parameter(Mandatory = $true)][string]$AndroidJar,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$JsonJar
)
$ErrorActionPreference = 'Stop'
$pluginDirectory = Split-Path -Parent $PSScriptRoot
$javaSource = Join-Path $pluginDirectory 'Source/SampleGameNativeUpdate/Android/Java/com/example/samplegame/update'
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
& (Join-Path $JavaHome 'bin/javac.exe') -encoding UTF-8 -cp $AndroidJar -d $output `
    (Join-Path $javaSource 'NativeUpdatePolicy.java') (Join-Path $javaSource 'NativeUpdate.java') `
    (Join-Path $PSScriptRoot 'NativeUpdatePolicyTest.java')
if ($LASTEXITCODE -ne 0) { throw 'Android Java compile failed' }
& (Join-Path $JavaHome 'bin/java.exe') -cp $output com.example.samplegame.update.NativeUpdatePolicyTest
if ($LASTEXITCODE -ne 0) { throw 'Native update policy host test failed' }
if ($JsonJar) {
    $expectedJsonSha256 = '3ea61b2a06e31edf1c91134fe9106b0ebb16628be169f3db75bc7a2b06b45796'
    if ((Get-FileHash -LiteralPath $JsonJar -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedJsonSha256) {
        throw 'Host loader tests require the pinned org.json:json:20250517 JAR'
    }
    $hostOutput = Join-Path $output 'loader-host'
    New-Item -ItemType Directory -Path $hostOutput -Force | Out-Null
    $stubPaths = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'HostStubs') -Recurse -Filter '*.java' | ForEach-Object { $_.FullName })
    & (Join-Path $JavaHome 'bin/javac.exe') -encoding UTF-8 -cp $JsonJar -d $hostOutput @stubPaths `
        (Join-Path $javaSource 'NativeUpdatePolicy.java') (Join-Path $javaSource 'NativeUpdate.java') `
        (Join-Path $PSScriptRoot 'NativeUpdateLoaderTest.java') (Join-Path $PSScriptRoot 'NativeUpdateDownloadTest.java')
    if ($LASTEXITCODE -ne 0) { throw 'Loader host test compile failed' }
    & (Join-Path $JavaHome 'bin/java.exe') -cp "$hostOutput;$JsonJar" com.example.samplegame.update.NativeUpdateLoaderTest
    if ($LASTEXITCODE -ne 0) { throw 'Native update loader host test failed' }
    & (Join-Path $JavaHome 'bin/java.exe') -cp "$hostOutput;$JsonJar" com.example.samplegame.update.NativeUpdateDownloadTest
    if ($LASTEXITCODE -ne 0) { throw 'Native update download host test failed' }
}
