# API Security Analyzer

[![Java](https://img.shields.io/badge/Java-25-orange.svg)](https://www.oracle.com/java/)
[![Maven](https://img.shields.io/badge/Maven-3.9+-blue.svg)](https://maven.apache.org/)
![License](https://img.shields.io/github/license/Dream-Wood/api-security-analyzer-hack)


Комплексный инструмент для автоматизированного анализа безопасности API, поддерживающий OpenAPI и AsyncAPI спецификации. Предоставляет возможности статического анализа, активного тестирования на уязвимости и валидации контрактов с поддержкой GOST TLS.

## 📋 Содержание

- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
- [Использование](#использование)
- [Docker](#docker)
- [CI/CD интеграция](#cicd-интеграция)
- [Модули проекта](#модули-проекта)
- [Плагины сканеров](#плагины-сканеров)
- [Документация](#документация)
- [Требования](#требования)

## 🎯 Возможности

### Статический анализ
- 🔍 Анализ OpenAPI и AsyncAPI спецификаций
- 🛡️ Обнаружение проблем безопасности в спецификации
- ⚠️ Валидация схем аутентификации и авторизации
- 🔒 Проверка использования HTTPS
- 📝 Анализ схем валидации данных

### Активное тестирование
- 🚨 **SQL Injection** - обнаружение SQL инъекций
- 🔓 **BOLA/IDOR** - тестирование Broken Object Level Authorization
- 🔐 **BFLA** - тестирование Broken Function Level Authorization
- 💉 **XSS** - обнаружение Cross-Site Scripting
- 🌐 **SSRF** - обнаружение Server-Side Request Forgery
- 📂 **Path Traversal** - обнаружение обхода директорий
- 🔑 **Broken Authentication** - тестирование обхода аутентификации
- 🧬 **XXE** - обнаружение XML External Entity
- 💰 **Mass Assignment** - обнаружение массового присваивания
- 🔧 **Security Misconfiguration** - обнаружение ошибок конфигурации
- 📊 **Business Logic** - тестирование бизнес-логики
- 🔐 **Cryptographic Failures** - обнаружение проблем криптографии

### Валидация контрактов
- ✅ Проверка соответствия реализации спецификации
- 📊 Валидация кодов статуса и схем ответов
- 🔢 Проверка обязательных полей и типов данных
- 🎲 Fuzzing входных данных

### Дополнительные возможности
- 🔐 **Поддержка ГОСТ криптографии** через CryptoPro JCSP
- 📈 **Веб-интерфейс** с визуализацией в реальном времени
- 📊 **Множество форматов отчетов**: Console, JSON, PDF
- 🔌 **Плагинная архитектура** для добавления новых сканеров
- ⚡ **Параллельное сканирование** для высокой производительности
- 🎚️ **Настраиваемая интенсивность** сканирования (LOW, MEDIUM, HIGH, AGGRESSIVE)

## 🏗️ Архитектура

API Security Analyzer построен на модульной архитектуре:

```
api-security-analyzer/
├── core/              # Ядро анализа (парсинг, валидация, HTTP клиенты)
├── report/            # Генерация отчетов (Console, JSON, PDF)
├── cli/               # Интерфейс командной строки
├── webui/             # Веб-интерфейс (Spring Boot + React)
└── plugins/           # Плагины сканеров уязвимостей
    ├── scanner-bola/
    ├── scanner-bfla/
    ├── scanner-injection/
    ├── scanner-sqlinjection/
    ├── scanner-ssrf/
    ├── scanner-traversal/
    ├── scanner-xxe/
    ├── scanner-brokenauth/
    ├── scanner-crypto/
    ├── scanner-misconfiguration/
    ├── scanner-businessflow/
    ├── scanner-resource/
    ├── scanner-inventory/
    ├── scanner-infodisclosure/
    ├── scanner-bopla/
    └── scanner-unsafeapi/
```

### Принципы архитектуры

- **Модульность**: Каждый модуль имеет четкую ответственность
- **Расширяемость**: Плагинная система для добавления новых сканеров
- **Производительность**: Параллельное выполнение тестов
- **Гибкость**: Поддержка различных режимов анализа и форматов отчетов

## 🚀 Быстрый старт

### CLI режим

```bash
# Сборка проекта
mvn clean package

# Статический анализ спецификации
java -jar cli/target/cli-1.0-SNAPSHOT.jar openapi.yaml

# Полный анализ с активным тестированием
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
  -u https://api.example.com \
  openapi.yaml

# С аутентификацией
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m active \
  -u https://api.example.com \
  -a "Authorization: Bearer YOUR_TOKEN" \
  openapi.yaml
```

### Web UI режим

```bash
# Запуск веб-интерфейса
java -jar webui/target/webui-1.0-SNAPSHOT.jar

# Откройте браузер
http://localhost:8080
```

### Docker

```bash
# CLI версия
docker build -f Dockerfile.cli -t api-security-analyzer:cli .
docker run -v $(pwd):/specs api-security-analyzer:cli /specs/openapi.yaml

# Web UI версия
docker build -f Dockerfile.webui -t api-security-analyzer:webui .
docker run -p 8080:8080 api-security-analyzer:webui

# Или используйте docker-compose
docker-compose up
```

## 📦 Установка

### Требования

- **Java**: JDK 25 или выше
- **Maven**: 3.9+ для сборки
- **Node.js**: 18+ (только для WebUI модуля)
- **Docker** (опционально): Для контейнеризации

### Сборка из исходников

```bash
# Клонирование репозитория
git clone https://github.com/your-org/api-security-analyzer.git
cd api-security-analyzer

# Полная сборка (все модули включая WebUI)
mvn clean package

# Сборка без WebUI (быстрее)
mvn clean package -Pskip-frontend

# Сборка только CLI модулей
mvn clean package -pl core,report,cli -am
```

### Артефакты сборки

После сборки вы получите:

- `cli/target/cli-1.0-SNAPSHOT.jar` - CLI приложение
- `webui/target/webui-1.0-SNAPSHOT.jar` - Web UI приложение

## 💻 Использование

### Режимы анализа

#### 1. Статический анализ (по умолчанию)
Анализирует только спецификацию без выполнения запросов:

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar openapi.yaml
```

**Проверяет:**
- Отсутствие схем безопасности
- Использование HTTP вместо HTTPS
- Проблемы валидации данных
- Отсутствие rate limiting

#### 2. Активное тестирование
Выполняет реальные запросы для поиска уязвимостей:

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m active \
  -u https://api.example.com \
  openapi.yaml
```

**Тестирует:**
- SQL Injection, XSS, SSRF
- BOLA/IDOR, BFLA
- Path Traversal, XXE
- Authentication/Authorization bypass
- И многое другое...

#### 3. Валидация контракта
Проверяет соответствие реализации спецификации:

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m contract \
  -u https://api.example.com \
  openapi.yaml
```

#### 4. Полный анализ
Выполняет все типы анализа:

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
  -u https://api.example.com \
  openapi.yaml
```

### Коды возврата (Exit Codes)

Анализатор возвращает следующие коды для интеграции в CI/CD:

- **0** - ✅ Успешное выполнение, проблем не найдено или только низкой/средней серьезности
- **3** - ⚠️ Найдены критичные (CRITICAL) или высокой важности (HIGH) проблемы
- **1** - ❌ Ошибка в параметрах командной строки или конфигурации
- **99** - 💥 Неожиданная ошибка выполнения (exception)

**Использование в скриптах:**
```bash
java -jar cli.jar -m full -u https://api.example.com specs/api.yaml
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ Анализ пройден успешно"
elif [ $EXIT_CODE -eq 3 ]; then
  echo "⚠️ Найдены критичные проблемы безопасности!"
  exit 1  # Блокируем deployment
elif [ $EXIT_CODE -eq 1 ]; then
  echo "❌ Ошибка конфигурации"
  exit 1
else
  echo "💥 Непредвиденная ошибка"
  exit 1
fi
```

### Опции CLI

```
Использование: api-security-analyzer [OPTIONS] <spec-path>

Опции:
  -m, --mode <mode>              Режим анализа: static, active, combined, contract, full
                                 (по умолчанию: static)

  -u, --base-url <url>           Базовый URL для активного тестирования

  -a, --auth-header <header>     Заголовок аутентификации (Authorization: Bearer token)

  -c, --crypto-protocol <proto>  Криптографический протокол: standard, gost
                                 (по умолчанию: standard)

  -f, --format <format>          Формат отчета: console, json, pdf
                                 (по умолчанию: console)

  -o, --output <file>            Выходной файл для отчета

  -v, --verbose                  Подробный вывод

  --no-color                     Отключить цветной вывод

  --no-verify-ssl                Отключить проверку SSL сертификатов

  --no-auto-auth                 Отключить автоматическую аутентификацию

  --max-parallel-scans <n>       Максимальное количество параллельных сканов
                                 (по умолчанию: 4)

  --request-delay <ms>           Задержка между запросами в миллисекундах
                                 (по умолчанию: 0)

  --scan-intensity <level>       Интенсивность сканирования: LOW, MEDIUM, HIGH, AGGRESSIVE
                                 (по умолчанию: MEDIUM)

Опции ГОСТ криптографии:
  --gost-pfx-path <path>         Путь к PFX сертификату
  --gost-pfx-password <pass>     Пароль PFX сертификата
  --gost-pfx-resource            Загрузить PFX из classpath
```

### Примеры использования

#### Пример 1: Базовый статический анализ

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar petstore.yaml
```

#### Пример 2: Активное тестирование с аутентификацией

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m active \
  -u https://petstore.swagger.io/v2 \
  -a "api_key: special-key" \
  petstore.yaml
```

#### Пример 3: Полный анализ с сохранением в JSON

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
  -u https://api.example.com \
  -f json \
  -o report.json \
  openapi.yaml
```

#### Пример 4: Анализ с ГОСТ криптографией

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m active \
  -u https://api.example.ru \
  -c gost \
  --gost-pfx-path /path/to/cert.pfx \
  --gost-pfx-password "password" \
  openapi.yaml
```

#### Пример 5: Настройка производительности

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m active \
  -u https://api.example.com \
  --max-parallel-scans 8 \
  --request-delay 500 \
  --scan-intensity HIGH \
  openapi.yaml
```

#### Пример 6: Генерация PDF отчета

```bash
java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
  -u https://api.example.com \
  -f pdf \
  -o security-report.pdf \
  openapi.yaml
```

### Использование Web UI

1. **Запустите приложение:**
```bash
java -jar webui/target/webui-1.0-SNAPSHOT.jar
```

2. **Откройте браузер:** `http://localhost:8080`

3. **Настройте анализ:**
   - Загрузите спецификацию или укажите URL/путь к файлу
   - Выберите режим анализа
   - Выберите сканеры для запуска
   - Настройте параметры (URL, аутентификация, SSL и т.д.)

4. **Запустите и мониторьте:**
   - Нажмите "Запустить анализ"
   - Наблюдайте за логами в реальном времени
   - Просматривайте результаты по мере их появления

5. **Экспортируйте результаты:**
   - Скачайте отчет в нужном формате (PDF, JSON)

## 🐳 Docker

### Образы Docker

Проект предоставляет два варианта Docker образов:

#### 1. CLI образ (минимальный размер)

```bash
# Сборка
docker build -f Dockerfile.cli -t api-security-analyzer:cli .

# Запуск статического анализа
docker run -v $(pwd)/specs:/specs \
  api-security-analyzer:cli /specs/openapi.yaml

# Запуск активного тестирования
docker run -v $(pwd)/specs:/specs \
  api-security-analyzer:cli -m active \
  -u https://api.example.com \
  /specs/openapi.yaml

# С сохранением отчета
docker run -v $(pwd)/specs:/specs \
  -v $(pwd)/reports:/reports \
  api-security-analyzer:cli -m full \
  -u https://api.example.com \
  -f json \
  -o /reports/report.json \
  /specs/openapi.yaml
```

#### 2. Web UI образ

```bash
# Сборка
docker build -f Dockerfile.webui -t api-security-analyzer:webui .

# Запуск
docker run -p 8080:8080 api-security-analyzer:webui

# С кастомным портом
docker run -p 9090:8080 api-security-analyzer:webui

# Откройте браузер
http://localhost:8080
```

### Docker Compose

Для удобного управления несколькими сервисами используйте docker-compose:

```bash
# Запуск всех сервисов
docker-compose up

# Запуск в фоновом режиме
docker-compose up -d

# Просмотр логов
docker-compose logs -f

# Остановка
docker-compose down

# Пересборка образов
docker-compose build
```

`docker-compose.yml` предоставляет:
- Web UI на порту 8080
- CLI сервис для запуска анализа
- Общий volume для спецификаций и отчетов

### Кастомизация Docker образов

#### Изменение порта Web UI

Отредактируйте `docker-compose.yml`:
```yaml
services:
  webui:
    ports:
      - "9090:8080"  # Внешний порт:Внутренний порт
```

#### Монтирование сертификатов GOST

```bash
docker run -v $(pwd)/certs:/certs \
  api-security-analyzer:cli -m active \
  -u https://api.example.ru \
  -c gost \
  --gost-pfx-path /certs/cert.pfx \
  --gost-pfx-password "password" \
  /specs/openapi.yaml
```

## 🔄 CI/CD интеграция

### GitHub Actions

Создайте `.github/workflows/api-security.yml`:

```yaml
name: API Security Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up JDK 25
      uses: actions/setup-java@v4
      with:
        java-version: '25'
        distribution: 'temurin'

    - name: Build analyzer
      run: mvn clean package -Pskip-frontend -DskipTests
      working-directory: ./api-security-analyzer

    - name: Run API security analysis
      run: |
        java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
          -u ${{ secrets.API_BASE_URL }} \
          -a "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
          -f json \
          -o security-report.json \
          specs/openapi.yaml
      working-directory: ./api-security-analyzer

    - name: Upload security report
      uses: actions/upload-artifact@v4
      with:
        name: security-report
        path: ./api-security-analyzer/security-report.json

    - name: Check exit code for critical issues
      run: |
        # Анализатор уже вернул код 3 если найдены критичные проблемы
        # Дополнительно можем проверить JSON отчет
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 3 ]; then
          echo "❌ Критичные уязвимости обнаружены!"
          CRITICAL=$(jq '.summary.critical // 0' security-report.json)
          HIGH=$(jq '.summary.high // 0' security-report.json)
          echo "Critical: $CRITICAL, High: $HIGH"
          exit 1
        fi
      working-directory: ./api-security-analyzer
```

### GitLab CI/CD

Создайте `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - test
  - security

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=$CI_PROJECT_DIR/.m2/repository"

build:
  stage: build
  image: maven:3.9-eclipse-temurin-21
  script:
    - mvn clean package -Pskip-frontend -DskipTests
  artifacts:
    paths:
      - cli/target/cli-*.jar
    expire_in: 1 hour
  cache:
    paths:
      - .m2/repository

api-security-scan:
  stage: security
  image: eclipse-temurin:21-jdk
  dependencies:
    - build
  script:
    - |
      java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
        -u ${API_BASE_URL} \
        -a "Authorization: Bearer ${API_TOKEN}" \
        -f json \
        -o security-report.json \
        specs/openapi.yaml
  artifacts:
    reports:
      junit: security-report.json
    paths:
      - security-report.json
    expire_in: 30 days
  allow_failure: false
```

### Jenkins Pipeline

Создайте `Jenkinsfile`:

```groovy
pipeline {
    agent any

    environment {
        API_BASE_URL = credentials('api-base-url')
        API_TOKEN = credentials('api-token')
    }

    stages {
        stage('Build') {
            steps {
                sh 'mvn clean package -Pskip-frontend -DskipTests'
            }
        }

        stage('API Security Scan') {
            steps {
                sh '''
                    java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
                        -u ${API_BASE_URL} \
                        -a "Authorization: Bearer ${API_TOKEN}" \
                        -f json \
                        -o security-report.json \
                        specs/openapi.yaml
                '''
            }
        }

        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: 'security-report.json', fingerprint: true

                script {
                    def report = readJSON file: 'security-report.json'
                    def critical = report.summary.critical ?: 0

                    if (critical > 0) {
                        error("Found ${critical} critical vulnerabilities!")
                    }
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
```

### Azure DevOps

Создайте `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  MAVEN_CACHE_FOLDER: $(Pipeline.Workspace)/.m2/repository
  MAVEN_OPTS: '-Dmaven.repo.local=$(MAVEN_CACHE_FOLDER)'

steps:
- task: JavaToolInstaller@0
  inputs:
    versionSpec: '21'
    jdkArchitectureOption: 'x64'
    jdkSourceOption: 'PreInstalled'

- task: Cache@2
  inputs:
    key: 'maven | "$(Agent.OS)" | **/pom.xml'
    restoreKeys: |
      maven | "$(Agent.OS)"
      maven
    path: $(MAVEN_CACHE_FOLDER)
  displayName: Cache Maven packages

- task: Maven@3
  inputs:
    mavenPomFile: 'pom.xml'
    goals: 'clean package'
    options: '-Pskip-frontend -DskipTests'
  displayName: 'Build project'

- script: |
    java -jar cli/target/cli-1.0-SNAPSHOT.jar -m full \
      -u $(API_BASE_URL) \
      -a "Authorization: Bearer $(API_TOKEN)" \
      -f json \
      -o $(Build.ArtifactStagingDirectory)/security-report.json \
      specs/openapi.yaml
  displayName: 'Run API Security Analysis'
  env:
    API_BASE_URL: $(ApiBaseUrl)
    API_TOKEN: $(ApiToken)

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)/security-report.json'
    artifactName: 'security-report'
  displayName: 'Publish Security Report'

- script: |
    CRITICAL_COUNT=$(jq '.summary.critical // 0' $(Build.ArtifactStagingDirectory)/security-report.json)
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
      echo "##vso[task.logissue type=error]Found $CRITICAL_COUNT critical vulnerabilities!"
      exit 1
    fi
  displayName: 'Check for critical vulnerabilities'
```

### Интеграция с Kubernetes

Для запуска анализа в Kubernetes кластере создайте Job:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: api-security-scan
spec:
  template:
    spec:
      containers:
      - name: analyzer
        image: api-security-analyzer:cli
        command:
        - java
        - -jar
        - /app/cli.jar
        - -m
        - full
        - -u
        - "https://api.example.com"
        - -f
        - json
        - -o
        - /reports/security-report.json
        - /specs/openapi.yaml
        env:
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
      restartPolicy: Never
      volumes:
      - name: specs
        configMap:
          name: api-specs
      - name: reports
        persistentVolumeClaim:
          claimName: reports-pvc
  backoffLimit: 3
```

## 📚 Модули проекта

### [Core](core/README.md)
Ядро анализатора безопасности API. Содержит:
- Движок активного анализа
- HTTP клиенты (Standard TLS, GOST)
- Парсеры спецификаций (OpenAPI, AsyncAPI)
- Статические валидаторы безопасности
- Плагинная система сканеров

**Ключевые классы:**
- `ActiveAnalysisEngine` - движок активного анализа
- `HttpClientFactory` - фабрика HTTP клиентов
- `OpenApiLoader` - загрузчик OpenAPI спецификаций
- `SecurityValidator` - валидатор безопасности

### [Report](report/README.md)
Модуль генерации отчетов. Поддерживает:
- Console (с ANSI цветами)
- JSON (структурированный формат)
- PDF (подробные отчеты с графиками)

**Ключевые классы:**
- `ReporterFactory` - фабрика создания репортеров
- `AnalysisReport` - модель отчета
- `ConsoleReporter`, `JsonReporter`, `PdfReporter`

### [CLI](cli/README.md)
Интерфейс командной строки. Предоставляет:
- Парсинг аргументов командной строки (picocli)
- Управление аутентификацией
- Координацию выполнения анализа
- Форматирование вывода

**Ключевые классы:**
- `ApiSecurityAnalyzerCli` - точка входа CLI
- `UnifiedAnalyzer` - координатор анализа
- `AuthenticationManager` - управление аутентификацией
- `HttpClientHelper` - помощник для создания HTTP клиентов

### [WebUI](webui/README.md)
Веб-интерфейс. Включает:
- Spring Boot 4 backend
- React + TypeScript frontend
- WebSocket для real-time логов
- Визуализация результатов
- Экспорт в различные форматы

**Ключевые компоненты:**
- `AnalysisController` - REST API контроллер
- `AnalysisService` - бизнес-логика
- `AnalysisWebSocketHandler` - WebSocket обработчик
- React компоненты (ConfigurationPanel, LogsPanel, ResultsPanel)

### [Plugins](plugins/)
Плагины сканеров уязвимостей. Каждый плагин - отдельный Maven модуль:
- `scanner-bola` - Broken Object Level Authorization
- `scanner-bfla` - Broken Function Level Authorization
- `scanner-injection` - Generic Injection
- `scanner-sqlinjection` - SQL Injection
- `scanner-ssrf` - Server-Side Request Forgery
- `scanner-traversal` - Path Traversal
- `scanner-xxe` - XML External Entity
- `scanner-brokenauth` - Broken Authentication
- `scanner-crypto` - Cryptographic Failures
- `scanner-misconfiguration` - Security Misconfiguration
- `scanner-businessflow` - Business Logic Vulnerabilities
- `scanner-resource` - Unrestricted Resource Consumption
- `scanner-inventory` - Improper Inventory Management
- `scanner-infodisclosure` - Information Disclosure
- `scanner-bopla` - Broken Object Property Level Authorization
- `scanner-unsafeapi` - Unsafe Consumption of APIs

## 🔌 Плагины сканеров

API Security Analyzer использует плагинную архитектуру через Java ServiceLoader. Все сканеры автоматически обнаруживаются и загружаются при запуске.

### Создание собственного сканера

1. **Создайте новый Maven модуль** в директории `plugins/`:

```xml
<project>
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.apisecurity</groupId>
        <artifactId>plugins</artifactId>
        <version>1.0-SNAPSHOT</version>
    </parent>

    <artifactId>scanner-custom</artifactId>
    <name>Custom Scanner Plugin</name>

    <dependencies>
        <dependency>
            <groupId>com.apisecurity</groupId>
            <artifactId>core</artifactId>
            <version>1.0-SNAPSHOT</version>
        </dependency>
    </dependencies>
</project>
```

2. **Реализуйте интерфейс VulnerabilityScanner:**

```java
package scanners;

import active.scanner.AbstractScanner;
import active.scanner.ScanResult;
import active.model.*;

public class CustomScanner extends AbstractScanner {

    @Override
    public String getId() {
        return "custom-scanner";
    }

    @Override
    public String getName() {
        return "Custom Vulnerability Scanner";
    }

    @Override
    public String getDescription() {
        return "Проверяет кастомные уязвимости";
    }

    @Override
    public List<VulnerabilityReport.VulnerabilityType> getDetectedVulnerabilities() {
        return List.of(VulnerabilityReport.VulnerabilityType.OTHER);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Определите, когда применять сканер
        return true;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint,
                                     HttpClient httpClient,
                                     ScanContext context) {
        // Реализация логики сканирования
        // ...
        return ScanResult.clean();
    }
}
```

3. **Зарегистрируйте через ServiceLoader:**

Создайте `src/main/resources/META-INF/services/active.scanner.VulnerabilityScanner`:
```
scanners.CustomScanner
```

4. **Добавьте в parent POM** (`plugins/pom.xml`):
```xml
<modules>
    <!-- ... -->
    <module>scanner-custom</module>
</modules>
```

5. **Пересоберите проект:**
```bash
mvn clean package
```

Сканер автоматически будет обнаружен и загружен!

## 📖 Документация

### Детальная документация модулей
- [Core Module](core/README.md) - Архитектура ядра, API, примеры расширения
- [Report Module](report/README.md) - Форматы отчетов, кастомизация
- [CLI Module](cli/README.md) - Все опции CLI, примеры использования
- [WebUI Module](webui/README.md) - API документация, разработка

### Дополнительные руководства
- [CICD_INTEGRATION.md](docs/CICD_INTEGRATION.md) - Полное руководство по CI/CD
- [DOCKER_GUIDE.md](docs/DOCKER_GUIDE.md) - Подробное руководство по Docker

### API документация
- Javadoc доступен после сборки: `mvn javadoc:aggregate`
- Откройте `target/site/apidocs/index.html`

## 🛠️ Требования

### Системные требования (приблизительные...)

- **Java**: JDK 25 (проект использует последнюю версию Java)
- **Maven**: 3.9+ для сборки проекта
- **Память**: Минимум 2GB RAM, рекомендуется 4GB для полного анализа
- **Дисковое пространство**: ~500MB для сборки, ~100MB для runtime

### Опциональные зависимости

- **Node.js**: 18+ (только для разработки WebUI модуля)
- **Docker**: 20.10+ (для контейнеризации, образы используют Alpine Linux)
- **CryptoPro JCSP**: Для поддержки ГОСТ криптографии

### Зависимости Java библиотек

Основные библиотеки:
- **Java**: 25 (использует современные возможности включая pattern matching, records, sealed classes)
- **Swagger Parser**: 2.1.24 - парсинг OpenAPI спецификаций
- **Spring Boot**: 4.0.0-RC1 (только WebUI, полная поддержка Java 25)
- **PicoCLI**: 4.7.7 - CLI парсинг
- **iText**: 5.5.13.4 - PDF генерация
- **Jackson**: 2.18+ - JSON обработка

Полный список зависимостей см. в `pom.xml` файлах модулей.

## 🔧 Разработка

### Настройка окружения разработки

```bash
# Клонирование репозитория
git clone https://github.com/your-org/api-security-analyzer.git
cd api-security-analyzer

# Импортировать в IntelliJ IDEA или Eclipse как Maven проект

# Сборка без запуска тестов
mvn clean install -DskipTests

# Запуск тестов
mvn test

# Запуск конкретного модуля
mvn spring-boot:run -pl webui
```


### Запуск в режиме разработки

**Backend (WebUI):**
```bash
cd webui
mvn spring-boot:run
```

**Frontend (WebUI):**
```bash
cd webui/src/main/frontend
npm install
npm run dev
```

**CLI:**
```bash
cd cli
mvn exec:java -Dexec.args="-m static ../../examples/petstore.yaml"
```

---

**Сделано с ❤️ командой devnull**
