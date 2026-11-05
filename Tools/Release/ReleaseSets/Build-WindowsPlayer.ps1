param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$PythonExecutable,
    [string]$PythonDependencies=''
)
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$output=[IO.Path]::GetFullPath($OutputDirectory)
if($output.Equals($repo,[StringComparison]::OrdinalIgnoreCase) -or $output.StartsWith($repo.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Player build output must be outside the repository.' }
if(Test-Path -LiteralPath $output) { throw 'Use a fresh player build directory.' }
$previousPath=$env:PYTHONPATH
try {
    if($PythonDependencies) { $env:PYTHONPATH=(Resolve-Path -LiteralPath $PythonDependencies).Path+[IO.Path]::PathSeparator+$previousPath }
    & $PythonExecutable -c 'import PyInstaller; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey'
    if($LASTEXITCODE -ne 0) { throw 'Existing release dependencies are required on the build machine.' }
    New-Item -ItemType Directory -Path $output | Out-Null
    & $PythonExecutable -m PyInstaller --onedir --windowed --contents-directory _release_internal `
        --name SampleGameReleasePlayer --collect-all cryptography `
        --distpath (Join-Path $output 'dist') --workpath (Join-Path $output 'work') --specpath $output `
        (Join-Path $PSScriptRoot 'windows_player.py')
    if($LASTEXITCODE -ne 0) { throw "Player build failed: $LASTEXITCODE" }
    Write-Output (Join-Path $output 'dist/SampleGameReleasePlayer')
} finally { $env:PYTHONPATH=$previousPath }
