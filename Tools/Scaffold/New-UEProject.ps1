#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Z][A-Za-z0-9]{2,31}$')]
    [string]$ProjectName,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [AllowEmptyString()]
    [string]$EngineAssociation = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Write-ScaffoldTree.ps1')
$targetRoot = Write-ScaffoldTree `
    -TemplateRoot (Join-Path $PSScriptRoot 'Templates/UnrealProject') `
    -OutputDirectory $OutputDirectory `
    -Names @{ PROJECT_NAME = $ProjectName } `
    -Tokens @{
        PROJECT_NAME = $ProjectName
        ENGINE_ASSOCIATION_JSON = (ConvertTo-Json -InputObject $EngineAssociation -Compress)
    }
Write-Output "UE_PROJECT_SCAFFOLDED $ProjectName $targetRoot"
