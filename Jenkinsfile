// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pipeline {
    agent {
        docker {
            image 'your-registry/ai-deep-sast:latest'
            args '-v /model-cache:/root/.cache/llama.cpp'
        }
    }

    options {
        timestamps()
        timeout(time: 90, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    parameters {
        string(
            name: 'TARGET_PATH',
            defaultValue: '.',
            description: 'Target file or directory to scan'
        )
        choice(
            name: 'SEVERITY_THRESHOLD',
            choices: ['WARNING', 'INFO', 'ERROR'],
            description: 'Minimum severity to fail the build'
        )
        booleanParam(
            name: 'FORCE_AI_ANALYSIS',
            defaultValue: false,
            description: 'Force AI analysis even on scheduled scans'
        )
    }

    environment {
        SCANNER_OUTPUT_DIR = 'security-reports'
        SEMGREP_FINDINGS   = 'false'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "Source code checked out successfully."
            }
        }

        stage('Environment Validation') {
            steps {
                sh '''
                    echo "=== Environment Validation ==="
                    python3 --version
                    semgrep --version
                    llama-completion --version || echo "llama-completion version check returned non-zero (OK)"
                    echo "Environment ready."
                '''
            }
        }

        // ================================================
        // STAGE 1: Fast Semgrep Scan (Every Commit)
        // Runs in ~3-5 seconds
        // ================================================
        stage('Semgrep Scan') {
            steps {
                sh """
                    python3 aideepsast.py \
                        --target ${params.TARGET_PATH} \
                        --skip-llm \
                        --output-dir ${env.SCANNER_OUTPUT_DIR}-semgrep \
                        --severity-threshold ${params.SEVERITY_THRESHOLD} \
                        --log-level INFO \
                    || true
                """

                // Check if Semgrep found anything
                script {
                    def reportFile = "${env.SCANNER_OUTPUT_DIR}-semgrep/ai_deep_sast_report.json"
                    if (fileExists(reportFile)) {
                        def report = readJSON file: reportFile
                        def totalFindings = report.summary.total_findings
                        echo "Semgrep found ${totalFindings} finding(s)."

                        if (totalFindings > 0) {
                            env.SEMGREP_FINDINGS = 'true'
                            env.FINDING_COUNT = "${totalFindings}"

                            // Summarise findings by severity
                            def byError = report.summary.by_severity.ERROR ?: 0
                            def byWarning = report.summary.by_severity.WARNING ?: 0
                            def byInfo = report.summary.by_severity.INFO ?: 0
                            echo "Breakdown: ${byError} ERROR, ${byWarning} WARNING, ${byInfo} INFO"
                        } else {
                            echo "No findings detected. Skipping AI analysis."
                        }
                    } else {
                        echo "Semgrep report not found. Assuming no findings."
                    }
                }
            }
        }

        // ================================================
        // STAGE 2: AI Analysis (Only If Findings Exist)
        // Runs only when:
        //   - Semgrep found findings AND
        //   - This is a PR or manual trigger or FORCE_AI_ANALYSIS
        // ================================================
        stage('AI Security Analysis') {
            when {
                allOf {
                    // Findings must exist
                    expression { env.SEMGREP_FINDINGS == 'true' }
                    // Only run on PRs, manual triggers, or forced
                    anyOf {
                        changeRequest()
                        triggeredBy 'UserIdCause'
                        expression { params.FORCE_AI_ANALYSIS == true }
                    }
                }
            }
            steps {
                echo "Findings detected. Running AI-powered analysis on ${env.FINDING_COUNT} finding(s)..."
                echo "Estimated time: ~${env.FINDING_COUNT.toInteger() * 40} seconds"

                sh """
                    python3 aideepsast.py \
                        --target ${params.TARGET_PATH} \
                        --config config/scanner_config.yaml \
                        --output-dir ${env.SCANNER_OUTPUT_DIR} \
                        --severity-threshold ${params.SEVERITY_THRESHOLD} \
                        --log-level INFO \
                        --log-file ${env.SCANNER_OUTPUT_DIR}/scanner.log
                """
            }
        }

        // ================================================
        // STAGE 3: Quality Gate
        // Uses AI report if available, otherwise Semgrep report
        // ================================================
        stage('Quality Gate') {
            steps {
                script {
                    def reportDir = env.SCANNER_OUTPUT_DIR
                    def semgrepReportDir = "${env.SCANNER_OUTPUT_DIR}-semgrep"

                    // Determine which report to use
                    def finalReportDir = fileExists("${reportDir}/ai_deep_sast_report.json") ? reportDir : semgrepReportDir
                    echo "Using report from: ${finalReportDir}"

                    if (fileExists("${finalReportDir}/ai_deep_sast_report.json")) {
                        def report = readJSON file: "${finalReportDir}/ai_deep_sast_report.json"
                        def total = report.summary.total_findings
                        def errors = report.summary.by_severity.ERROR ?: 0
                        def warnings = report.summary.by_severity.WARNING ?: 0

                        echo "========================================"
                        echo "QUALITY GATE RESULTS"
                        echo "========================================"
                        echo "Total Findings: ${total}"
                        echo "Errors:         ${errors}"
                        echo "Warnings:       ${warnings}"
                        echo "Threshold:      ${params.SEVERITY_THRESHOLD}"
                        echo "AI Enhanced:    ${fileExists("${reportDir}/ai_deep_sast_report.json")}"
                        echo "========================================"

                        // Determine pass/fail based on threshold
                        def shouldFail = false
                        switch(params.SEVERITY_THRESHOLD) {
                            case 'ERROR':
                                shouldFail = errors > 0
                                break
                            case 'WARNING':
                                shouldFail = (errors + warnings) > 0
                                break
                            case 'INFO':
                                shouldFail = total > 0
                                break
                        }

                        if (shouldFail) {
                            currentBuild.result = 'FAILURE'
                            error("Quality gate FAILED: findings detected above ${params.SEVERITY_THRESHOLD} threshold.")
                        } else {
                            echo "Quality gate PASSED."
                        }
                    } else {
                        echo "No report found. Assuming clean scan."
                    }
                }
            }
        }
    }

    post {
        always {
            // Archive Semgrep-only reports
            archiveArtifacts(
                artifacts: "${env.SCANNER_OUTPUT_DIR}-semgrep/**",
                allowEmptyArchive: true,
                fingerprint: true
            )

            // Archive AI-enhanced reports (if they exist)
            archiveArtifacts(
                artifacts: "${env.SCANNER_OUTPUT_DIR}/**",
                allowEmptyArchive: true,
                fingerprint: true
            )

            // Publish JUnit results (prefer AI report, fallback to Semgrep)
            script {
                def aiJunit = "${env.SCANNER_OUTPUT_DIR}/sast_junit_report.xml"
                def semgrepJunit = "${env.SCANNER_OUTPUT_DIR}-semgrep/sast_junit_report.xml"
                def junitFile = fileExists(aiJunit) ? aiJunit : semgrepJunit

                junit(
                    testResults: junitFile,
                    allowEmptyResults: true
                )
            }

            // Publish HTML report (prefer AI report, fallback to Semgrep)
            script {
                def aiReport = env.SCANNER_OUTPUT_DIR
                def semgrepReport = "${env.SCANNER_OUTPUT_DIR}-semgrep"
                def reportDir = fileExists("${aiReport}/ai_deep_sast_report.md") ? aiReport : semgrepReport

                publishHTML(target: [
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: reportDir,
                    reportFiles: 'ai_deep_sast_report.md',
                    reportName: 'AI Deep SAST Report'
                ])
            }

            cleanWs()
        }

        success {
            echo '✅ Security scan passed. No critical findings.'
            // slackSend(channel: '#security', color: 'good',
            //     message: "✅ AI Deep SAST PASSED: ${env.JOB_NAME} #${env.BUILD_NUMBER}")
        }

        failure {
            echo '❌ Security scan failed. Findings detected.'
            // slackSend(channel: '#security', color: 'danger',
            //     message: "❌ AI Deep SAST FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER} — ${env.FINDING_COUNT ?: 'unknown'} finding(s)")
        }
    }
}