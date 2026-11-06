pipeline {
    agent { label 'windows' }

    options {
        disableConcurrentBuilds()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '15'))
    }

    parameters {
        booleanParam(name: 'RUN_PROJECT_PROFILE', defaultValue: false, description: 'Build, Cook and smoke-test a Win64 project on a UE worker')
        string(name: 'PROJECT_PROFILE', defaultValue: 'Examples/ProjectProfile/profile.json', description: 'Repository-relative path to a project profile JSON file')
    }

    stages {
        stage('Offline adoption checks') {
            steps {
                pwsh label: 'Validate config, scaffold and signed release demo', encoding: 'UTF-8', script: '''
                    $ErrorActionPreference = 'Stop'
                    if ($env:BUILD_NUMBER -notmatch '^[0-9]+$') { throw 'Expected a Jenkins build number.' }
                    $out = Join-Path $env:WORKSPACE ('ci-evidence/' + $env:BUILD_NUMBER)
                    $python = if ($env:UE_ADOPTION_PYTHON) { $env:UE_ADOPTION_PYTHON } else { 'python' }
                    & pwsh -NoProfile -NonInteractive -File ./Tools/CI/Invoke-AdoptionChecks.ps1 `
                        -OutputDirectory $out -PythonExecutable $python -RequireXlsx
                    exit $LASTEXITCODE
                '''
            }
        }
        stage('Win64 project profile') {
            when { expression { params.RUN_PROJECT_PROFILE } }
            steps {
                pwsh label: 'Import tables, check assets, Cook and launch', encoding: 'UTF-8', script: '''
                    $ErrorActionPreference = 'Stop'
                    $PSNativeCommandUseErrorActionPreference = $false
                    if ($env:BUILD_NUMBER -notmatch '^[0-9]+$') { throw 'Expected a Jenkins build number.' }
                    if (-not $env:UE_ADOPTION_ENGINE_ROOT) { throw 'Set UE_ADOPTION_ENGINE_ROOT on the Windows worker.' }
                    $python = if ($env:UE_ADOPTION_PYTHON) { $env:UE_ADOPTION_PYTHON } else { 'python' }
                    $selection = $env:PROJECT_PROFILE
                    if ([string]::IsNullOrWhiteSpace($selection) -or [IO.Path]::IsPathRooted($selection) -or
                        $selection.Contains(':') -or [IO.Path]::GetExtension($selection) -ine '.json') {
                        throw 'Set PROJECT_PROFILE to a repository-relative JSON path.'
                    }
                    $profile = & $python -X utf8 -B -c 'from pathlib import Path; import sys; root = Path(sys.argv[1]).resolve(strict=True); path = (root / sys.argv[2]).resolve(); print(path) if path.is_relative_to(root) else sys.exit("PROJECT_PROFILE resolves outside the workspace.")' $env:WORKSPACE $selection
                    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve PROJECT_PROFILE inside the workspace.' }

                    $evidence = Join-Path $env:WORKSPACE ('ci-evidence/' + $env:BUILD_NUMBER)
                    $out = Join-Path $evidence 'ProjectProfile'
                    $invoke = @('-Profile', $profile, '-EngineRoot', $env:UE_ADOPTION_ENGINE_ROOT,
                        '-OutputDirectory', $out, '-PythonExecutable', $python, '-RequireBuildReceipt')
                    if ($env:UE_ADOPTION_CLANG_ROOT) { $invoke += @('-ClangRoot', $env:UE_ADOPTION_CLANG_ROOT) }
                    & pwsh -NoProfile -NonInteractive -File ./Tools/Adoption/Invoke-ProjectProfile.ps1 @invoke *>&1 |
                        Tee-Object -LiteralPath (Join-Path $evidence 'ProjectProfile-invocation.log')
                    exit $LASTEXITCODE
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: "ci-evidence/${env.BUILD_NUMBER}/report.json,ci-evidence/${env.BUILD_NUMBER}/*.log,ci-evidence/${env.BUILD_NUMBER}/ConfigTables/*.json,ci-evidence/${env.BUILD_NUMBER}/ConfigTables/client/*.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/*.log,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/report.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/asset-report.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/cooked-assets.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/build-receipt.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/ConfigTables/manifest.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/ConfigTables/client/manifest.json",
                             allowEmptyArchive: true
        }
    }
}
