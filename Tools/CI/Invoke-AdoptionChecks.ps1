#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [string] $PythonExecutable = 'python'
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repository = Split-Path (Split-Path $PSScriptRoot)
$output = $null
$report = [ordered]@{
    schemaVersion = 1
    status = 'running'
    scope = 'offline-adoption-checks'
    unrealLaunched = $false
    androidRuntimeUsed = $false
    networkUsed = $false
    publicationExecuted = $false
    stages = [System.Collections.Generic.List[object]]::new()
    error = $null
}

function Invoke-Check([string] $Name, [string] $Executable, [string[]] $Arguments, [scriptblock] $Validate) {
    $logName = "$Name.log"
    $log = Join-Path $output $logName
    $stage = [ordered]@{ name = $Name; status = 'failed'; log = $logName }
    $report.stages.Add($stage)
    & $Executable @Arguments *> $log
    $stage.exitCode = $LASTEXITCODE
    if ($stage.exitCode -ne 0) { throw "$Name exited with code $($stage.exitCode). See $logName." }
    if ($Validate) { & $Validate $log }
    $stage.status = 'passed'
}

try {
    if (-not $IsWindows) { throw 'The adoption checks require a Windows worker.' }
    $provider = $null
    $drive = $null
    $requested = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem' -or (Test-Path -LiteralPath $requested)) {
        throw 'Choose a new local filesystem directory for adoption check output.'
    }
    $output = (New-Item -Path $requested -ItemType Directory).FullName

    $python = (Get-Command -Name $PythonExecutable -CommandType Application | Select-Object -First 1).Source
    $runtimeCheck = @'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Install Python 3.11 or newer on the worker.")
import cryptography
print(f"Python {sys.version.split()[0]}, cryptography {cryptography.__version__}")
'@
    Invoke-Check 'python-runtime' $python @('-X', 'utf8', '-B', '-c', $runtimeCheck)

    $configTools = Join-Path $repository 'Tools/ConfigTables'
    Invoke-Check 'config-tests' $python @('-X', 'utf8', '-B', '-m', 'unittest', 'discover', '-s', $configTools, '-p', 'test_config_tables.py', '-v') {
        param($Log)
        if (-not (Select-String -LiteralPath $Log -Pattern '^Ran [1-9][0-9]* tests? in ' -Quiet)) {
            throw 'No configuration table tests ran. See config-tests.log.'
        }
    }
    $configOutput = Join-Path $output 'ConfigTables'
    Invoke-Check 'config-export' $python @('-X', 'utf8', '-B', (Join-Path $configTools 'config_tables.py'),
        '--source', (Join-Path $repository 'Examples/ConfigTables'), '--output', $configOutput) {
        param($Log)
        $export = Get-Content -LiteralPath $Log -Raw | ConvertFrom-Json
        if ($export.status -cne 'config-exported' -or
            -not (Test-Path -LiteralPath (Join-Path $configOutput 'manifest.json') -PathType Leaf)) {
            throw 'The configuration exporter did not produce its manifest. See config-export.log.'
        }
    }

    $shell = Join-Path $PSHOME 'pwsh.exe'
    $project = Join-Path $output 'SampleGame'
    Invoke-Check 'project-scaffold' $shell @('-NoProfile', '-NonInteractive', '-File',
        (Join-Path $repository 'Tools/Scaffold/New-UEProject.ps1'), '-ProjectName', 'SampleGame', '-OutputDirectory', $project) {
        if (-not (Test-Path -LiteralPath (Join-Path $project 'SampleGame.uproject') -PathType Leaf)) {
            throw 'The scaffold exited successfully without producing SampleGame.uproject.'
        }
    }

    Invoke-Check 'release-demo' $python @('-X', 'utf8', '-B', (Join-Path $repository 'Tools/Release/ReleaseSets/demo_transaction.py')) {
        param($Log)
        $demo = Get-Content -LiteralPath $Log -Raw | ConvertFrom-Json
        if ($demo.status -cne 'passed' -or $demo.fixturePayloads -ne $true -or $demo.networkUsed -ne $false -or
            $demo.unrealLaunched -ne $false -or $demo.androidRuntimeUsed -ne $false) {
            throw 'The release demo did not report successful offline fixture checks.'
        }
    }
    $report.status = 'passed'
} catch {
    $report.status = 'failed'
    $report.error = $_.Exception.Message
}

$json = $report | ConvertTo-Json -Depth 6
if ($output) { Set-Content -LiteralPath (Join-Path $output 'report.json') -Value $json -Encoding utf8 }
$json
if ($report.status -ne 'passed') { exit 1 }
exit 0
