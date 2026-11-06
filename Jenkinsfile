pipeline {
    agent { label 'windows' }

    options {
        disableConcurrentBuilds()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '15'))
    }

    parameters {
        booleanParam(name: 'RUN_PROJECT_PROFILE', defaultValue: false, description: 'Build, Cook and smoke-test the Win64 example on a UE worker')
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
                    if (-not $env:UE_ADOPTION_ENGINE_ROOT) { throw 'Set UE_ADOPTION_ENGINE_ROOT on the Windows worker.' }
                    $out = Join-Path $env:WORKSPACE ('ci-evidence/' + $env:BUILD_NUMBER + '/ProjectProfile')
                    $python = if ($env:UE_ADOPTION_PYTHON) { $env:UE_ADOPTION_PYTHON } else { 'python' }
                    $invoke = @('-Profile', './Examples/ProjectProfile/profile.json', '-EngineRoot', $env:UE_ADOPTION_ENGINE_ROOT,
                        '-OutputDirectory', $out, '-PythonExecutable', $python)
                    if ($env:UE_ADOPTION_CLANG_ROOT) { $invoke += @('-ClangRoot', $env:UE_ADOPTION_CLANG_ROOT) }
                    & pwsh -NoProfile -NonInteractive -File ./Tools/Adoption/Invoke-ProjectProfile.ps1 @invoke
                    exit $LASTEXITCODE
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: "ci-evidence/${env.BUILD_NUMBER}/report.json,ci-evidence/${env.BUILD_NUMBER}/*.log,ci-evidence/${env.BUILD_NUMBER}/ConfigTables/*.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/*.log,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/report.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/asset-report.json,ci-evidence/${env.BUILD_NUMBER}/ProjectProfile/cooked-assets.json",
                             allowEmptyArchive: true
        }
    }
}
