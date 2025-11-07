# CI/CD интеграция API Security Analyzer

Полное руководство по интеграции API Security Analyzer в ваши CI/CD и DevOps процессы.

## 📋 Содержание

- [Обзор](#обзор)
- [GitHub Actions](#github-actions)
- [GitLab CI/CD](#gitlab-cicd)
- [Jenkins](#jenkins)
- [Azure DevOps](#azure-devops)
- [Kubernetes](#kubernetes)
- [Docker Registry](#docker-registry)
- [Интеграция с системами уведомлений](#интеграция-с-системами-уведомлений)
- [Лучшие практики](#лучшие-практики)

## 🎯 Обзор

API Security Analyzer можно интегрировать в CI/CD pipeline для:

- **Автоматической проверки безопасности** при каждом изменении API спецификации
- **Регрессионного тестирования** безопасности при каждом деплое
- **Блокировки deployment** при обнаружении критичных уязвимостей
- **Генерации отчетов** для аудита и compliance

### Коды возврата (Exit Codes)

API Security Analyzer CLI возвращает следующие коды для интеграции в CI/CD:

| Код | Значение | Описание | Действие в CI/CD |
|-----|----------|----------|------------------|
| **0** | SUCCESS | ✅ Успешное выполнение, проблем не найдено или только низкой/средней серьезности | Продолжить pipeline |
| **3** | CRITICAL_ISSUES | ⚠️ Найдены критичные (CRITICAL) или высокой важности (HIGH) проблемы | Блокировать deployment |
| **1** | CONFIG_ERROR | ❌ Ошибка в параметрах командной строки или конфигурации | Исправить конфигурацию |
| **99** | UNEXPECTED_ERROR | 💥 Неожиданная ошибка выполнения (exception) | Проверить логи |

**Важно:** Код выхода `3` означает наличие проблем безопасности, требующих немедленного внимания. Рекомендуется блокировать deployment при получении этого кода.

**Пример обработки в bash:**
```bash
java -jar cli.jar -m full -u https://api.example.com specs/api.yaml
EXIT_CODE=$?

case $EXIT_CODE in
  0)
    echo "✅ Анализ пройден успешно - deployment разрешен"
    ;;
  3)
    echo "⚠️ БЛОКИРОВКА: Обнаружены критичные проблемы безопасности!"
    exit 1
    ;;
  1)
    echo "❌ Ошибка конфигурации - проверьте параметры"
    exit 1
    ;;
  99)
    echo "💥 Непредвиденная ошибка - проверьте логи"
    exit 1
    ;;
esac
```

Используйте эти коды для управления pipeline и автоматической блокировки небезопасных релизов.

## 🐙 GitHub Actions

### Базовая интеграция

Создайте `.github/workflows/api-security.yml`:

```yaml
name: API Security Analysis

on:
  push:
    branches: [ main, develop ]
    paths:
      - 'specs/**/*.yaml'
      - 'specs/**/*.yml'
      - 'specs/**/*.json'
  pull_request:
    branches: [ main ]
    paths:
      - 'specs/**'

jobs:
  api-security-scan:
    name: API Security Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up JDK 25
      uses: actions/setup-java@v4
      with:
        java-version: '25'
        distribution: 'temurin'
        cache: 'maven'

    - name: Build API Security Analyzer
      run: |
        git clone https://github.com/your-org/api-security-analyzer.git
        cd api-security-analyzer
        mvn clean package -Pskip-frontend -DskipTests
      working-directory: /tmp

    - name: Run Static Analysis
      id: static_analysis
      run: |
        java -jar /tmp/api-security-analyzer/cli/target/cli-1.0-SNAPSHOT.jar \
          -m static \
          -f json \
          -o static-report.json \
          specs/openapi.yaml
      continue-on-error: true

    - name: Run Active Security Testing
      id: active_testing
      if: github.event_name == 'push'
      run: |
        java -jar /tmp/api-security-analyzer/cli/target/cli-1.0-SNAPSHOT.jar \
          -m active \
          -u ${{ secrets.API_BASE_URL }} \
          -a "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
          -f json \
          -o active-report.json \
          --scan-intensity MEDIUM \
          specs/openapi.yaml
      continue-on-error: true

    - name: Upload Reports
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: security-reports
        path: |
          static-report.json
          active-report.json
        retention-days: 30

    - name: Check Exit Codes and Block on Critical Issues
      run: |
        # Проверяем exit code статического анализа
        STATIC_EXIT="${{ steps.static_analysis.outcome }}"
        ACTIVE_EXIT="${{ steps.active_testing.outcome }}"

        echo "Static analysis outcome: $STATIC_EXIT"
        echo "Active testing outcome: $ACTIVE_EXIT"

        # Анализируем результаты из JSON (дополнительная проверка)
        if [ -f static-report.json ]; then
          CRITICAL=$(jq '.summary.critical // 0' static-report.json)
          HIGH=$(jq '.summary.high // 0' static-report.json)
          echo "📊 Static: Critical=$CRITICAL, High=$HIGH"
        fi

        if [ -f active-report.json ]; then
          CRITICAL=$(jq '.summary.critical // 0' active-report.json)
          HIGH=$(jq '.summary.high // 0' active-report.json)
          echo "📊 Active: Critical=$CRITICAL, High=$HIGH"
        fi

        # Блокируем если анализатор вернул код 3 (critical issues)
        if [ "$STATIC_EXIT" = "failure" ] || [ "$ACTIVE_EXIT" = "failure" ]; then
          echo "::error::❌ DEPLOYMENT BLOCKED: Critical security issues found!"
          echo "::error::Review the security reports and fix issues before deploying"
          exit 1
        fi

        echo "✅ Security checks passed - deployment allowed"

    - name: Comment PR with Results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('static-report.json', 'utf8'));

          const summary = report.summary || {};
          const comment = `## 🔒 API Security Analysis Results

          **Mode:** ${report.mode || 'Static'}
          **Spec:** ${report.specTitle || 'N/A'}

          ### Summary
          - 🔴 Critical: ${summary.critical || 0}
          - 🟠 High: ${summary.high || 0}
          - 🟡 Medium: ${summary.medium || 0}
          - 🟢 Low: ${summary.low || 0}
          - ℹ️ Info: ${summary.info || 0}

          ${summary.critical > 0 ? '⚠️ **This PR introduces critical security issues!**' : '✅ No critical issues found.'}
          `;

          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

### Расширенная интеграция с Docker

```yaml
name: API Security Analysis (Docker)

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Запуск каждую ночь в 2:00 UTC
    - cron: '0 2 * * *'

jobs:
  build-and-scan:
    name: Build Docker Image and Scan API
    runs-on: ubuntu-latest

    steps:
    - name: Checkout
      uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Build CLI Docker Image
      run: |
        docker build -f Dockerfile.cli -t api-analyzer:cli .

    - name: Run Security Analysis
      run: |
        docker run -v $(pwd)/specs:/specs -v $(pwd)/reports:/reports \
          api-analyzer:cli -m full \
          -u ${{ secrets.API_BASE_URL }} \
          -a "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
          -f json \
          -o /reports/security-report.json \
          /specs/openapi.yaml

    - name: Upload Report
      uses: actions/upload-artifact@v4
      with:
        name: security-report
        path: reports/security-report.json

    - name: Fail on Critical Issues
      run: |
        CRITICAL=$(jq '.summary.critical // 0' reports/security-report.json)
        if [ "$CRITICAL" -gt 0 ]; then
          exit 1
        fi
```

### Интеграция с GitHub Security

```yaml
name: API Security to GitHub Security

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Еженедельно

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
    - uses: actions/checkout@v4

    - name: Run API Security Analysis
      run: |
        # ... сборка и запуск анализатора ...
        java -jar cli.jar -m full -u ${{ secrets.API_URL }} -f json -o report.json specs/api.yaml

    - name: Convert to SARIF
      run: |
        # Конвертация JSON отчета в SARIF формат для GitHub Security
        python3 scripts/json_to_sarif.py report.json sarif-report.sarif

    - name: Upload SARIF to GitHub Security
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: sarif-report.sarif
```

## 🦊 GitLab CI/CD

### Базовая интеграция

Создайте `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - test
  - security
  - deploy

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=$CI_PROJECT_DIR/.m2/repository"
  MAVEN_CLI_OPTS: "--batch-mode --errors --fail-at-end --show-version"

# Кэширование Maven зависимостей
.maven_cache:
  cache:
    key: ${CI_COMMIT_REF_SLUG}
    paths:
      - .m2/repository/

# Сборка анализатора
build:analyzer:
  stage: build
  image: maven:3.9-eclipse-temurin-25
  extends: .maven_cache
  script:
    - mvn $MAVEN_CLI_OPTS clean package -Pskip-frontend -DskipTests
  artifacts:
    paths:
      - cli/target/cli-*.jar
    expire_in: 1 hour

# Статический анализ (всегда выполняется)
static:analysis:
  stage: security
  image: eclipse-temurin:25-jdk
  dependencies:
    - build:analyzer
  script:
    - |
      set +e  # Не прерываем при ненулевом exit code
      java -jar cli/target/cli-1.0-SNAPSHOT.jar \
        -m static \
        -f json \
        -o static-report.json \
        specs/openapi.yaml
      EXIT_CODE=$?

      echo "Analysis exit code: $EXIT_CODE"

      # Код 3 = критичные проблемы, блокируем pipeline
      if [ $EXIT_CODE -eq 3 ]; then
        echo "❌ Critical security issues detected!"
        exit 1
      elif [ $EXIT_CODE -eq 0 ]; then
        echo "✅ No critical issues found"
        exit 0
      else
        echo "⚠️ Analysis error (code: $EXIT_CODE)"
        exit $EXIT_CODE
      fi
  artifacts:
    reports:
      junit: static-report.json
    paths:
      - static-report.json
    expire_in: 30 days
    when: always
  allow_failure: false

# Активное тестирование (только для staging)
active:analysis:
  stage: security
  image: eclipse-temurin:25-jdk
  dependencies:
    - build:analyzer
  only:
    - develop
    - staging
  script:
    - |
      set +e
      java -jar cli/target/cli-1.0-SNAPSHOT.jar \
        -m active \
        -u ${API_BASE_URL} \
        -a "Authorization: Bearer ${API_TOKEN}" \
        -f json \
        -o active-report.json \
        --scan-intensity MEDIUM \
        --max-parallel-scans 4 \
        specs/openapi.yaml
      EXIT_CODE=$?

      case $EXIT_CODE in
        0)
          echo "✅ Active testing passed"
          ;;
        3)
          echo "❌ Critical vulnerabilities found in active testing!"
          exit 1
          ;;
        *)
          echo "⚠️ Active testing error (code: $EXIT_CODE)"
          exit 1
          ;;
      esac
  artifacts:
    paths:
      - active-report.json
    expire_in: 30 days
    when: always
  allow_failure: false

# Полный анализ для production
full:analysis:
  stage: security
  image: eclipse-temurin:21-jdk
  dependencies:
    - build:analyzer
  only:
    - main
    - production
  script:
    - |
      java -jar cli/target/cli-1.0-SNAPSHOT.jar \
        -m full \
        -u ${API_BASE_URL} \
        -a "Authorization: Bearer ${API_TOKEN}" \
        -f pdf \
        -o security-report.pdf \
        --scan-intensity HIGH \
        specs/openapi.yaml
  artifacts:
    paths:
      - security-report.pdf
    expire_in: 90 days
  allow_failure: false

# Дополнительная проверка критичности (опционально)
check:vulnerabilities:
  stage: security
  image: alpine:latest
  dependencies:
    - static:analysis
  before_script:
    - apk add --no-cache jq
  script:
    - |
      # Дополнительная детальная проверка отчета
      if [ -f static-report.json ]; then
        CRITICAL=$(jq '.summary.critical // 0' static-report.json)
        HIGH=$(jq '.summary.high // 0' static-report.json)
        MEDIUM=$(jq '.summary.medium // 0' static-report.json)

        echo "📊 Security Summary:"
        echo "  Critical: $CRITICAL"
        echo "  High: $HIGH"
        echo "  Medium: $MEDIUM"

        # Устанавливаем пороги
        if [ "$CRITICAL" -gt 0 ]; then
          echo "❌ БЛОКИРОВКА: Найдено $CRITICAL критичных уязвимостей!"
          exit 1
        fi

        if [ "$HIGH" -gt 5 ]; then
          echo "⚠️ ПРЕДУПРЕЖДЕНИЕ: Найдено $HIGH проблем высокой важности (порог: 5)"
          # Можете настроить - блокировать или только предупредить
          # exit 1  # Раскомментируйте для блокировки
        fi

        echo "✅ Проверка безопасности пройдена"
      fi
  allow_failure: false
  # Этот job выполняется только если предыдущие не failed (т.к. exit code уже проверен)
```

### Docker интеграция

```yaml
# Дополнение к .gitlab-ci.yml

docker:build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker build -f Dockerfile.cli -t $CI_REGISTRY_IMAGE/analyzer:cli-$CI_COMMIT_SHORT_SHA .
    - docker build -f Dockerfile.webui -t $CI_REGISTRY_IMAGE/analyzer:webui-$CI_COMMIT_SHORT_SHA .
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker push $CI_REGISTRY_IMAGE/analyzer:cli-$CI_COMMIT_SHORT_SHA
    - docker push $CI_REGISTRY_IMAGE/analyzer:webui-$CI_COMMIT_SHORT_SHA
  only:
    - main

docker:scan:
  stage: security
  image: docker:24
  services:
    - docker:24-dind
  dependencies: []
  script:
    - |
      docker run --rm \
        -v $(pwd)/specs:/specs \
        -v $(pwd)/reports:/reports \
        $CI_REGISTRY_IMAGE/analyzer:cli-$CI_COMMIT_SHORT_SHA \
        -m full \
        -u ${API_BASE_URL} \
        -f json \
        -o /reports/report.json \
        /specs/openapi.yaml
  artifacts:
    paths:
      - reports/
  only:
    - main
```

## 🔧 Jenkins

### Declarative Pipeline

Создайте `Jenkinsfile`:

```groovy
pipeline {
    agent any

    environment {
        API_BASE_URL = credentials('api-base-url')
        API_TOKEN = credentials('api-token')
        JAVA_HOME = tool 'JDK-25'
        MAVEN_HOME = tool 'Maven-3.9'
        PATH = "${JAVA_HOME}/bin:${MAVEN_HOME}/bin:${env.PATH}"
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 1, unit: 'HOURS')
        timestamps()
    }

    triggers {
        // Запуск при изменении спецификаций
        pollSCM('H/15 * * * *')
        // Ежедневный запуск в 2:00
        cron('0 2 * * *')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Analyzer') {
            steps {
                sh '''
                    mvn clean package -Pskip-frontend -DskipTests \
                        -Dmaven.repo.local=${WORKSPACE}/.m2/repository
                '''
            }
        }

        stage('Static Analysis') {
            steps {
                script {
                    def exitCode = sh(
                        script: '''
                            java -jar cli/target/cli-1.0-SNAPSHOT.jar \
                                -m static \
                                -f json \
                                -o static-report.json \
                                specs/openapi.yaml
                        ''',
                        returnStatus: true
                    )

                    echo "Exit code: ${exitCode}"

                    switch(exitCode) {
                        case 0:
                            echo '✅ Static analysis passed'
                            break
                        case 3:
                            error('❌ DEPLOYMENT BLOCKED: Critical security issues found!')
                            break
                        case 1:
                            error('❌ Configuration error in analyzer')
                            break
                        case 99:
                            error('💥 Unexpected error in analyzer')
                            break
                        default:
                            error("Unknown exit code: ${exitCode}")
                    }
                }
            }
        }

        stage('Active Testing') {
            when {
                anyOf {
                    branch 'develop'
                    branch 'staging'
                    branch 'main'
                }
            }
            steps {
                script {
                    def intensity = env.BRANCH_NAME == 'main' ? 'HIGH' : 'MEDIUM'

                    sh """
                        java -jar cli/target/cli-1.0-SNAPSHOT.jar \
                            -m active \
                            -u ${API_BASE_URL} \
                            -a "Authorization: Bearer ${API_TOKEN}" \
                            -f json \
                            -o active-report.json \
                            --scan-intensity ${intensity} \
                            --max-parallel-scans 4 \
                            specs/openapi.yaml
                    """
                }
            }
        }

        stage('Generate Reports') {
            steps {
                sh '''
                    java -jar cli/target/cli-1.0-SNAPSHOT.jar \
                        -m full \
                        -u ${API_BASE_URL} \
                        -a "Authorization: Bearer ${API_TOKEN}" \
                        -f pdf \
                        -o security-report-${BUILD_NUMBER}.pdf \
                        specs/openapi.yaml
                '''
            }
        }

        stage('Analyze Results') {
            steps {
                script {
                    def report = readJSON file: 'static-report.json'
                    def critical = report.summary?.critical ?: 0
                    def high = report.summary?.high ?: 0

                    echo "Security Summary:"
                    echo "  Critical: ${critical}"
                    echo "  High: ${high}"

                    // Установка статуса сборки
                    if (critical > 0) {
                        currentBuild.result = 'FAILURE'
                        error("Found ${critical} critical vulnerabilities!")
                    } else if (high > 5) {
                        currentBuild.result = 'UNSTABLE'
                        echo "Warning: Found ${high} high severity issues"
                    }
                }
            }
        }
    }

    post {
        always {
            // Архивирование отчетов
            archiveArtifacts artifacts: '*-report*.json,*-report*.pdf',
                            fingerprint: true,
                            allowEmptyArchive: true

            // Очистка workspace
            cleanWs(deleteDirs: true,
                   patterns: [[pattern: '.m2/repository', type: 'EXCLUDE']])
        }

        success {
            echo '✅ Security analysis completed successfully'
        }

        failure {
            echo '❌ Security analysis failed - review the reports'

            // Отправка уведомления (настройте под вашу систему)
            // emailext subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
            //          body: "Check console output at ${env.BUILD_URL}",
            //          to: "${env.SECURITY_TEAM_EMAIL}"
        }

        unstable {
            echo '⚠️ Security issues found - review required'
        }
    }
}
```

### Scripted Pipeline с Docker

```groovy
node {
    def analyzer

    stage('Checkout') {
        checkout scm
    }

    stage('Build Docker Image') {
        analyzer = docker.build("api-analyzer:cli", "-f Dockerfile.cli .")
    }

    stage('Run Analysis') {
        analyzer.inside("-v ${workspace}/specs:/specs -v ${workspace}/reports:/reports") {
            sh """
                java -jar /app/cli.jar \
                    -m full \
                    -u ${env.API_BASE_URL} \
                    -a "Authorization: Bearer ${env.API_TOKEN}" \
                    -f json \
                    -o /reports/report.json \
                    /specs/openapi.yaml
            """
        }
    }

    stage('Process Results') {
        def report = readJSON file: 'reports/report.json'
        if (report.summary.critical > 0) {
            error("Critical vulnerabilities found!")
        }
    }
}
```

## ☁️ Azure DevOps

Создайте `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - specs/**

pr:
  branches:
    include:
      - main
  paths:
    include:
      - specs/**

schedules:
- cron: "0 2 * * *"
  displayName: Nightly security scan
  branches:
    include:
    - main
  always: true

pool:
  vmImage: 'ubuntu-latest'

variables:
  MAVEN_CACHE_FOLDER: $(Pipeline.Workspace)/.m2/repository
  MAVEN_OPTS: '-Dmaven.repo.local=$(MAVEN_CACHE_FOLDER)'
  buildConfiguration: 'Release'

stages:
- stage: Build
  displayName: 'Build Analyzer'
  jobs:
  - job: BuildJob
    displayName: 'Build'
    steps:
    - task: JavaToolInstaller@0
      inputs:
        versionSpec: '21'
        jdkArchitectureOption: 'x64'
        jdkSourceOption: 'PreInstalled'
      displayName: 'Install JDK 21'

    - task: Cache@2
      inputs:
        key: 'maven | "$(Agent.OS)" | **/pom.xml'
        restoreKeys: |
          maven | "$(Agent.OS)"
          maven
        path: $(MAVEN_CACHE_FOLDER)
      displayName: 'Cache Maven packages'

    - task: Maven@3
      inputs:
        mavenPomFile: 'pom.xml'
        goals: 'clean package'
        options: '-Pskip-frontend -DskipTests'
        publishJUnitResults: false
        javaHomeOption: 'JDKVersion'
        jdkVersionOption: '1.21'
        mavenVersionOption: 'Default'
      displayName: 'Maven Build'

    - task: CopyFiles@2
      inputs:
        contents: 'cli/target/*.jar'
        targetFolder: '$(Build.ArtifactStagingDirectory)'
      displayName: 'Copy artifacts'

    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: '$(Build.ArtifactStagingDirectory)'
        artifactName: 'analyzer'
      displayName: 'Publish artifacts'

- stage: SecurityScan
  displayName: 'Security Analysis'
  dependsOn: Build
  jobs:
  - job: StaticAnalysis
    displayName: 'Static Analysis'
    steps:
    - task: DownloadBuildArtifacts@0
      inputs:
        buildType: 'current'
        downloadType: 'single'
        artifactName: 'analyzer'
        downloadPath: '$(System.ArtifactsDirectory)'

    - script: |
        java -jar $(System.ArtifactsDirectory)/analyzer/cli/target/cli-1.0-SNAPSHOT.jar \
          -m static \
          -f json \
          -o $(Build.ArtifactStagingDirectory)/static-report.json \
          specs/openapi.yaml
      displayName: 'Run Static Analysis'

    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: '$(Build.ArtifactStagingDirectory)/static-report.json'
        artifactName: 'static-report'
      displayName: 'Publish Static Report'
      condition: always()

  - job: ActiveTesting
    displayName: 'Active Security Testing'
    condition: and(succeeded(), in(variables['Build.SourceBranch'], 'refs/heads/main', 'refs/heads/develop'))
    steps:
    - task: DownloadBuildArtifacts@0
      inputs:
        buildType: 'current'
        downloadType: 'single'
        artifactName: 'analyzer'
        downloadPath: '$(System.ArtifactsDirectory)'

    - script: |
        java -jar $(System.ArtifactsDirectory)/analyzer/cli/target/cli-1.0-SNAPSHOT.jar \
          -m active \
          -u $(ApiBaseUrl) \
          -a "Authorization: Bearer $(ApiToken)" \
          -f json \
          -o $(Build.ArtifactStagingDirectory)/active-report.json \
          --scan-intensity MEDIUM \
          specs/openapi.yaml
      displayName: 'Run Active Testing'
      env:
        ApiBaseUrl: $(API_BASE_URL)
        ApiToken: $(API_TOKEN)

    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: '$(Build.ArtifactStagingDirectory)/active-report.json'
        artifactName: 'active-report'
      displayName: 'Publish Active Report'
      condition: always()

- stage: CheckResults
  displayName: 'Check Security Results'
  dependsOn: SecurityScan
  jobs:
  - job: AnalyzeResults
    displayName: 'Analyze Security Results'
    steps:
    - task: DownloadBuildArtifacts@0
      inputs:
        buildType: 'current'
        downloadType: 'single'
        artifactName: 'static-report'
        downloadPath: '$(System.ArtifactsDirectory)'

    - bash: |
        CRITICAL=$(jq '.summary.critical // 0' $(System.ArtifactsDirectory)/static-report/static-report.json)
        HIGH=$(jq '.summary.high // 0' $(System.ArtifactsDirectory)/static-report/static-report.json)

        echo "Critical issues: $CRITICAL"
        echo "High severity issues: $HIGH"

        if [ "$CRITICAL" -gt 0 ]; then
          echo "##vso[task.logissue type=error]Found $CRITICAL critical vulnerabilities!"
          echo "##vso[task.complete result=Failed;]"
          exit 1
        fi

        if [ "$HIGH" -gt 5 ]; then
          echo "##vso[task.logissue type=warning]Found $HIGH high severity issues (threshold: 5)"
        fi

        echo "##[section]Security check passed"
      displayName: 'Check for vulnerabilities'
```

## ☸️ Kubernetes

### CronJob для периодического сканирования

Создайте `k8s/api-security-cronjob.yaml`:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: api-security-scan
  namespace: security
spec:
  # Запуск каждый день в 02:00
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        metadata:
          labels:
            app: api-security-analyzer
        spec:
          restartPolicy: Never
          containers:
          - name: analyzer
            image: your-registry/api-security-analyzer:cli-latest
            imagePullPolicy: Always
            command:
            - /bin/bash
            - -c
            - |
              echo "Starting API security analysis..."
              java -jar /app/cli.jar \
                -m full \
                -u ${API_BASE_URL} \
                -a "Authorization: Bearer ${API_TOKEN}" \
                -f json \
                -o /reports/security-report-$(date +%Y%m%d).json \
                --scan-intensity HIGH \
                /specs/openapi.yaml

              CRITICAL=$(jq '.summary.critical // 0' /reports/security-report-*.json)
              if [ "$CRITICAL" -gt 0 ]; then
                echo "CRITICAL: Found $CRITICAL critical vulnerabilities!"
                exit 1
              fi
            env:
            - name: API_BASE_URL
              valueFrom:
                secretKeyRef:
                  name: api-credentials
                  key: base-url
            - name: API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: api-credentials
                  key: token
            - name: JAVA_OPTS
              value: "-Xms512m -Xmx2g"
            volumeMounts:
            - name: specs
              mountPath: /specs
              readOnly: true
            - name: reports
              mountPath: /reports
            resources:
              requests:
                memory: "1Gi"
                cpu: "500m"
              limits:
                memory: "4Gi"
                cpu: "2000m"
          volumes:
          - name: specs
            configMap:
              name: api-specifications
          - name: reports
            persistentVolumeClaim:
              claimName: security-reports-pvc
```

### Job для ad-hoc сканирования

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: api-security-scan-adhoc
  namespace: security
spec:
  ttlSecondsAfterFinished: 86400  # 24 часа
  template:
    metadata:
      labels:
        app: api-security-analyzer
        scan-type: adhoc
    spec:
      restartPolicy: Never
      containers:
      - name: analyzer
        image: your-registry/api-security-analyzer:cli-latest
        args:
        - "-m"
        - "active"
        - "-u"
        - "$(API_BASE_URL)"
        - "-a"
        - "Authorization: Bearer $(API_TOKEN)"
        - "-f"
        - "pdf"
        - "-o"
        - "/reports/adhoc-report.pdf"
        - "/specs/openapi.yaml"
        env:
        - name: API_BASE_URL
          value: "https://api.example.com"
        - name: API_TOKEN
          valueFrom:
            secretKeyRef:
              name: api-credentials
              key: token
        volumeMounts:
        - name: specs
          mountPath: /specs
        - name: reports
          mountPath: /reports
      volumes:
      - name: specs
        configMap:
          name: api-specifications
      - name: reports
        emptyDir: {}
```

### Helm Chart пример

```yaml
# values.yaml
analyzer:
  image:
    repository: your-registry/api-security-analyzer
    tag: cli-latest
    pullPolicy: Always

  schedule: "0 2 * * *"

  config:
    mode: full
    intensity: HIGH
    format: json

  resources:
    requests:
      memory: 1Gi
      cpu: 500m
    limits:
      memory: 4Gi
      cpu: 2000m

  secrets:
    apiBaseUrl: ""
    apiToken: ""

persistence:
  enabled: true
  size: 10Gi
  storageClass: ""
```

## 🐳 Docker Registry

### Публикация образов в registry

```bash
# Сборка и тегирование
docker build -f Dockerfile.cli -t your-registry.com/api-analyzer:cli-latest .
docker build -f Dockerfile.cli -t your-registry.com/api-analyzer:cli-1.0.0 .

docker build -f Dockerfile.webui -t your-registry.com/api-analyzer:webui-latest .
docker build -f Dockerfile.webui -t your-registry.com/api-analyzer:webui-1.0.0 .

# Публикация
docker push your-registry.com/api-analyzer:cli-latest
docker push your-registry.com/api-analyzer:cli-1.0.0
docker push your-registry.com/api-analyzer:webui-latest
docker push your-registry.com/api-analyzer:webui-1.0.0
```

### GitLab Container Registry

```yaml
# .gitlab-ci.yml
docker:publish:
  stage: publish
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -f Dockerfile.cli -t $CI_REGISTRY_IMAGE/analyzer:cli-$CI_COMMIT_TAG .
    - docker build -f Dockerfile.webui -t $CI_REGISTRY_IMAGE/analyzer:webui-$CI_COMMIT_TAG .
    - docker push $CI_REGISTRY_IMAGE/analyzer:cli-$CI_COMMIT_TAG
    - docker push $CI_REGISTRY_IMAGE/analyzer:webui-$CI_COMMIT_TAG
  only:
    - tags
```

## 📢 Интеграция с системами уведомлений

### Slack

```bash
#!/bin/bash
# send-slack-notification.sh

REPORT_FILE="$1"
CRITICAL=$(jq '.summary.critical // 0' "$REPORT_FILE")
HIGH=$(jq '.summary.high // 0' "$REPORT_FILE")
SPEC=$(jq -r '.specTitle' "$REPORT_FILE")

COLOR="good"
if [ "$CRITICAL" -gt 0 ]; then
  COLOR="danger"
elif [ "$HIGH" -gt 0 ]; then
  COLOR="warning"
fi

curl -X POST $SLACK_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{
    "attachments": [{
      "color": "'"$COLOR"'",
      "title": "🔒 API Security Analysis: '"$SPEC"'",
      "fields": [
        {"title": "Critical", "value": "'"$CRITICAL"'", "short": true},
        {"title": "High", "value": "'"$HIGH"'", "short": true}
      ],
      "footer": "API Security Analyzer",
      "ts": '$(date +%s)'
    }]
  }'
```

### Microsoft Teams

```bash
#!/bin/bash
# send-teams-notification.sh

REPORT_FILE="$1"
CRITICAL=$(jq '.summary.critical // 0' "$REPORT_FILE")
HIGH=$(jq '.summary.high // 0' "$REPORT_FILE")

curl -H 'Content-Type: application/json' -d '{
  "@type": "MessageCard",
  "@context": "https://schema.org/extensions",
  "summary": "API Security Analysis Results",
  "themeColor": "'$([ "$CRITICAL" -gt 0 ] && echo "FF0000" || echo "00FF00")'",
  "title": "🔒 API Security Analysis",
  "sections": [{
    "facts": [
      {"name": "Critical Issues", "value": "'"$CRITICAL"'"},
      {"name": "High Severity Issues", "value": "'"$HIGH"'"}
    ]
  }]
}' $TEAMS_WEBHOOK_URL
```

## 🎯 Лучшие практики

### 1. Staged Rollout

```yaml
# Пример для GitHub Actions
strategy:
  matrix:
    environment: [dev, staging, production]
    intensity: [MEDIUM, MEDIUM, HIGH]

steps:
  - name: Run scan for ${{ matrix.environment }}
    run: |
      java -jar cli.jar -m full \
        -u ${{ secrets[format('{0}_API_URL', matrix.environment)] }} \
        --scan-intensity ${{ matrix.intensity }} \
        specs/api.yaml
```

### 2. Пороги для блокировки

```bash
# Настройка порогов
CRITICAL_THRESHOLD=0
HIGH_THRESHOLD=5
MEDIUM_THRESHOLD=20

CRITICAL=$(jq '.summary.critical // 0' report.json)
HIGH=$(jq '.summary.high // 0' report.json)
MEDIUM=$(jq '.summary.medium // 0' report.json)

if [ "$CRITICAL" -gt "$CRITICAL_THRESHOLD" ]; then
  echo "❌ BLOCKED: $CRITICAL critical issues (threshold: $CRITICAL_THRESHOLD)"
  exit 1
fi

if [ "$HIGH" -gt "$HIGH_THRESHOLD" ]; then
  echo "⚠️ WARNING: $HIGH high issues (threshold: $HIGH_THRESHOLD)"
  exit 1
fi

if [ "$MEDIUM" -gt "$MEDIUM_THRESHOLD" ]; then
  echo "ℹ️ INFO: $MEDIUM medium issues (threshold: $MEDIUM_THRESHOLD)"
fi
```

### 3. Кэширование зависимостей

Всегда используйте кэширование для Maven/Docker слоев:

```yaml
# GitHub Actions
- uses: actions/cache@v4
  with:
    path: ~/.m2/repository
    key: ${{ runner.os }}-maven-${{ hashFiles('**/pom.xml') }}
    restore-keys: ${{ runner.os }}-maven-
```

### 4. Параллельное выполнение

```yaml
# GitLab CI - параллельные задачи
static:analysis:
  parallel:
    matrix:
      - SPEC: [api-v1.yaml, api-v2.yaml, admin-api.yaml]
  script:
    - java -jar cli.jar -m static specs/${SPEC}
```

### 5. Сохранение истории отчетов

```bash
# Сохранение с версионированием
REPORT_NAME="security-report-${CI_COMMIT_SHORT_SHA}-$(date +%Y%m%d-%H%M%S).json"
java -jar cli.jar -m full -f json -o "$REPORT_NAME" specs/api.yaml

# Загрузка в S3/MinIO
aws s3 cp "$REPORT_NAME" "s3://security-reports/$CI_PROJECT_NAME/"
```

---

**Примечание:** Адаптируйте примеры под вашу инфраструктуру и требования безопасности. Храните секреты (токены, URL) в защищенных хранилищах (GitHub Secrets, GitLab CI/CD Variables, Jenkins Credentials, Azure Key Vault и т.д.).
