[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Z][A-Za-z0-9]{2,63}$')]
    [string]$PluginName,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [ValidateSet('Runtime', 'Editor')]
    [string]$ModuleType = 'Runtime'
)

$ErrorActionPreference = 'Stop'
$templateRoot = Join-Path $PSScriptRoot 'Templates/UnrealPlugin'
$targetRoot = [IO.Path]::GetFullPath($OutputDirectory)

if (-not (Test-Path -LiteralPath $templateRoot -PathType Container)) {
    throw "Plugin templates are missing: $templateRoot"
}
if (Test-Path -LiteralPath $targetRoot) {
    $existing = Get-ChildItem -LiteralPath $targetRoot -Force
    if ($existing.Count -gt 0) {
        throw "Refusing to write into a non-empty directory: $targetRoot"
    }
} else {
    New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
}

$utf8 = [System.Text.UTF8Encoding]::new($false)
$templateFiles = Get-ChildItem -LiteralPath $templateRoot -Recurse -File
foreach ($template in $templateFiles) {
    $relative = [IO.Path]::GetRelativePath($templateRoot, $template.FullName)
    $relative = $relative.Replace('PLUGIN_NAME', $PluginName)
    if ($relative.EndsWith('.template', [StringComparison]::OrdinalIgnoreCase)) {
        $relative = $relative.Substring(0, $relative.Length - '.template'.Length)
    }
    $destination = Join-Path $targetRoot $relative
    $destinationParent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
    $content = [IO.File]::ReadAllText($template.FullName, [Text.Encoding]::UTF8)
    $content = $content.Replace('{{PLUGIN_NAME}}', $PluginName).Replace('{{PLUGIN_TYPE}}', $ModuleType)
    [IO.File]::WriteAllText($destination, $content, $utf8)
}

Write-Output "UE_PLUGIN_SCAFFOLDED $PluginName $targetRoot"
