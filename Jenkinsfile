pipeline {
    agent { label 'windows' }

    options {
        disableConcurrentBuilds()
        timeout(time: 15, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '15'))
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
                        -OutputDirectory $out -PythonExecutable $python
                    exit $LASTEXITCODE
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: "ci-evidence/${env.BUILD_NUMBER}/report.json,ci-evidence/${env.BUILD_NUMBER}/*.log,ci-evidence/${env.BUILD_NUMBER}/ConfigTables/*.json",
                             allowEmptyArchive: true
        }
    }
}
