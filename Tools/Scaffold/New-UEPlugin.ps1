#Requires -Version 7.0
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
. (Join-Path $PSScriptRoot 'Write-ScaffoldTree.ps1')
$targetRoot = Write-ScaffoldTree `
    -TemplateRoot (Join-Path $PSScriptRoot 'Templates/UnrealPlugin') `
    -OutputDirectory $OutputDirectory `
    -Names @{ PLUGIN_NAME = $PluginName } `
    -Tokens @{ PLUGIN_NAME = $PluginName; PLUGIN_TYPE = $ModuleType }
Write-Output "UE_PLUGIN_SCAFFOLDED $PluginName $targetRoot"
