function Write-ScaffoldTree {
    param(
        [string]$TemplateRoot,
        [string]$OutputDirectory,
        [hashtable]$Names,
        [hashtable]$Tokens
    )

    $provider = $null
    $drive = $null
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') {
        throw 'The output directory must be a file system path.'
    }
    $target = [IO.Path]::TrimEndingDirectorySeparator($resolvedPath)
    if (Test-Path -LiteralPath $target) {
        throw "The output path already exists. Choose a new directory: $target"
    }

    $templates = @(Get-ChildItem -LiteralPath $TemplateRoot -Recurse -File -Filter '*.template')
    if ($templates.Count -eq 0) {
        throw "No scaffold templates found: $TemplateRoot"
    }

    $parent = [IO.Path]::GetDirectoryName($target)
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $staging = Join-Path $parent ('.ue-scaffold-' + [Guid]::NewGuid().ToString('N'))
    New-Item -Path $staging -ItemType Directory | Out-Null
    $utf8 = [Text.UTF8Encoding]::new($false, $true)

    try {
        foreach ($template in $templates) {
            $relative = [IO.Path]::GetRelativePath($TemplateRoot, $template.FullName)
            $relative = $relative.Substring(0, $relative.Length - '.template'.Length)
            foreach ($key in $Names.Keys) {
                $relative = $relative.Replace($key, $Names[$key])
            }
            $destination = Join-Path $staging $relative
            $content = [IO.File]::ReadAllText($template.FullName, $utf8)
            foreach ($key in $Tokens.Keys) {
                $content = $content.Replace('{{' + $key + '}}', $Tokens[$key])
            }
            if ($content -match '\{\{[A-Z0-9_]+\}\}') {
                throw "Unresolved placeholder in template: $relative"
            }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
            [IO.File]::WriteAllText($destination, $content, $utf8)
        }

        # A sibling rename publishes a complete tree and fails if another writer won the destination.
        [IO.Directory]::Move($staging, $target)
    } finally {
        if ([IO.Directory]::Exists($staging)) {
            $stageItem = Get-Item -LiteralPath $staging -Force
            if ($stageItem.FullName -eq $staging -and -not ($stageItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                Remove-Item -LiteralPath $staging -Recurse -Force
            }
        }
    }

    $target
}
