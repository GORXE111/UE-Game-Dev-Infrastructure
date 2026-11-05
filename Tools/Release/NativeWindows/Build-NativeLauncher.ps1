param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$PythonExecutable,
    [string]$PythonDependencies = ''
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output.Equals($repo, [StringComparison]::OrdinalIgnoreCase) -or $output.StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Native launcher build output must be outside the repository.'
}
if (Test-Path -LiteralPath $output) { throw 'Build output exists; use a fresh directory.' }
$previousPythonPath = $env:PYTHONPATH
try {
    if ($PythonDependencies) {
        $dependencyPath = (Resolve-Path -LiteralPath $PythonDependencies).Path
        $env:PYTHONPATH = $dependencyPath + [IO.Path]::PathSeparator + $previousPythonPath
    }
    & $PythonExecutable -c 'import PyInstaller; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey'
    if ($LASTEXITCODE -ne 0) { throw 'Release Python needs existing PyInstaller and cryptography dependencies; players need neither installed.' }
    New-Item -ItemType Directory -Path $output | Out-Null
    & $PythonExecutable -m PyInstaller --onedir --windowed --contents-directory _native_internal `
        --name SampleGameNativeLauncher --collect-all cryptography `
        --distpath (Join-Path $output 'dist') --workpath (Join-Path $output 'work') --specpath $output `
        (Join-Path $PSScriptRoot 'native_launcher.py')
    if ($LASTEXITCODE -ne 0) { throw "Native launcher build failed: $LASTEXITCODE" }
    Write-Output (Join-Path $output 'dist/SampleGameNativeLauncher')
} finally {
    $env:PYTHONPATH = $previousPythonPath
}
