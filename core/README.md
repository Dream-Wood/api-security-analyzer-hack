# Core Module / Модуль Core

Ядро анализатора безопасности API - фундаментальная библиотека, содержащая все основные компоненты для статического и активного анализа API спецификаций.

## 📋 Содержание

- [Обзор](#обзор)
- [Архитектура](#архитектура)
- [Основные компоненты](#основные-компоненты)
- [Структура пакетов](#структура-пакетов)
- [Использование](#использование)
- [Расширение функциональности](#расширение-функциональности)

## 🎯 Обзор

Модуль `core` предоставляет:
- 🔍 **Активный анализ безопасности** - динамическое тестирование API с реальными HTTP-запросами
- 🛡️ **Статическая валидация** - проверка спецификаций на соответствие стандартам безопасности
- 📝 **Парсинг спецификаций** - загрузка и нормализация OpenAPI и AsyncAPI
- 🔐 **Поддержка криптографии ГОСТ** - интеграция с CryptoPro JCSP
- 🔌 **Плагинная архитектура** - расширяемая система сканеров уязвимостей

## 🏗️ Архитектура

```
core/
├── active/              # Активный анализ безопасности
│   ├── scanner/         # Сканеры уязвимостей (плагины)
│   ├── http/            # HTTP клиенты (TLS, GOST)
│   ├── auth/            # Аутентификация
│   ├── validator/       # Валидация контрактов
│   └── model/           # Модели данных активного анализа
├── validator/           # Статические валидаторы
├── parser/              # Парсеры спецификаций
├── model/               # Общие модели данных
└── util/                # Утилиты
```

## 🔧 Основные компоненты

### 1. Движок активного анализа

**`ActiveAnalysisEngine`** - главный оркестратор активного анализа безопасности.

**Возможности:**
- ✅ Автоматическое обнаружение сканеров через ServiceLoader
- ✅ Параллельное сканирование эндпоинтов
- ✅ Поддержка стандартного TLS и ГОСТ криптографии
- ✅ Настраиваемая интенсивность сканирования (LOW, MEDIUM, HIGH, AGGRESSIVE)
- ✅ Отслеживание прогресса в реальном времени
- ✅ Гибкая конфигурация задержек между запросами

**Пример использования:**
```java
// Создание конфигурации
AnalysisConfig config = AnalysisConfig.builder()
    .cryptoProtocol(HttpClient.CryptoProtocol.STANDARD_TLS)
    .verifySsl(true)
    .maxParallelScans(4)
    .scanIntensity("MEDIUM")
    .progressListener(new MyProgressListener())
    .build();

// Инициализация движка
ActiveAnalysisEngine engine = new ActiveAnalysisEngine(config);

// Сканирование эндпоинтов
List<ApiEndpoint> endpoints = extractFromSpec(openAPI);
ScanContext context = new ScanContext(baseUrl);
AnalysisReport report = engine.scanEndpoints(endpoints, context);

// Получение результатов
System.out.println("Найдено уязвимостей: " + report.getTotalVulnerabilityCount());
System.out.println("Уязвимых эндпоинтов: " + report.getVulnerableEndpointCount());

// Освобождение ресурсов
engine.shutdown();
```

### 2. HTTP клиенты

**`HttpClient`** - интерфейс для HTTP клиентов с поддержкой различных криптографических протоколов.

**Реализации:**

#### StandardHttpClient
Стандартный HTTP клиент с поддержкой TLS/SSL:
```java
HttpClientConfig config = HttpClientConfig.builder()
    .cryptoProtocol(HttpClient.CryptoProtocol.STANDARD_TLS)
    .connectTimeout(Duration.ofSeconds(30))
    .readTimeout(Duration.ofSeconds(30))
    .followRedirects(true)
    .verifySsl(true)
    .build();

HttpClient client = HttpClientFactory.createClient(config);
```

#### CryptoProHttpClient
HTTP клиент с поддержкой российской криптографии ГОСТ:
```java
HttpClientConfig config = HttpClientConfig.builder()
    .cryptoProtocol(HttpClient.CryptoProtocol.CRYPTOPRO_JCSP)
    .addCustomSetting("pfxPath", "/path/to/certificate.pfx")
    .addCustomSetting("pfxPassword", "password")
    .build();

HttpClient client = HttpClientFactory.createClient(config);
```

**Поддерживаемые хранилища ключей:**
- 📁 **PFX** - PKCS#12 файлы (`.pfx`, `.p12`)
- 🔐 **JCP** - CryptoPro Java CSP хранилище
- 🏪 **Cacerts** - системное Java хранилище

### 3. Сканеры уязвимостей

**`VulnerabilityScanner`** - интерфейс плагина для сканеров уязвимостей.

**Архитектура:**
- 🔌 Плагинная система через Java ServiceLoader
- 🎯 Каждый сканер фокусируется на конкретном типе уязвимости
- ⚙️ Независимая конфигурация для каждого сканера
- 📊 Поддержка различных уровней интенсивности

**Создание собственного сканера:**

1. Создайте класс, реализующий интерфейс `VulnerabilityScanner`:
```java
package com.example.scanners;

public class MyCustomScanner extends AbstractScanner {

    @Override
    public String getId() {
        return "my-custom-scanner";
    }

    @Override
    public String getName() {
        return "My Custom Scanner";
    }

    @Override
    public String getDescription() {
        return "Проверяет кастомную уязвимость";
    }

    @Override
    public List<VulnerabilityReport.VulnerabilityType> getDetectedVulnerabilities() {
        return List.of(VulnerabilityReport.VulnerabilityType.OTHER);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Определите, когда применять сканер
        return endpoint.getMethod().equals("POST");
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        // Реализация логики сканирования
        TestRequest request = buildTestRequest(endpoint, context);
        TestResponse response = httpClient.execute(request);

        // Анализ ответа и создание отчета
        if (isVulnerable(response)) {
            VulnerabilityReport vuln = createVulnerabilityReport(endpoint, request, response);
            return ScanResult.withVulnerabilities(List.of(vuln));
        }

        return ScanResult.clean();
    }
}
```

2. Зарегистрируйте сканер через ServiceLoader:

Создайте файл `META-INF/services/active.scanner.VulnerabilityScanner`:
```
com.example.scanners.MyCustomScanner
```

### 4. Валидаторы безопасности

**`SecurityValidator`** - статический валидатор для проверки проблем безопасности в спецификациях.

**Проверяемые аспекты:**
- 🔐 Наличие и корректность схем аутентификации
- 🔒 Использование HTTPS вместо HTTP
- ⚠️ Небезопасные методы аутентификации (Basic Auth)
- 🔑 API ключи в query параметрах
- 🛡️ Защита критичных операций (POST, PUT, DELETE)
- 🚨 Потенциальные IDOR уязвимости

**Пример использования:**
```java
OpenAPI openAPI = new OpenAPIV3Parser().read("api-spec.yaml");
SecurityValidator validator = new SecurityValidator(openAPI);
List<ValidationFinding> findings = validator.validate();

// Группировка по критичности
Map<Severity, Long> bySeverity = findings.stream()
    .collect(Collectors.groupingBy(
        ValidationFinding::getSeverity,
        Collectors.counting()
    ));

System.out.println("Критичных: " + bySeverity.get(Severity.HIGH));
System.out.println("Средних: " + bySeverity.get(Severity.MEDIUM));
```

### 5. Парсеры спецификаций

**`OpenApiLoader`** - загрузчик OpenAPI спецификаций с улучшенной обработкой ошибок.

**Возможности:**
- 📂 Загрузка из локальных файлов и URL
- 🔗 Полное разрешение ссылок ($ref)
- ✅ Детальная валидация
- 📊 Информативные сообщения об ошибках

**Пример:**
```java
OpenApiLoader loader = new OpenApiLoader();
OpenApiLoader.LoadResult result = loader.load("api-spec.yaml");

if (result.isSuccessful()) {
    OpenAPI openAPI = result.getOpenAPI();
    System.out.println("Загружено операций: " + openAPI.getPaths().size());
} else {
    System.err.println("Ошибки загрузки:");
    result.getMessages().forEach(System.err::println);
}
```

## 📦 Структура пакетов

### active.* - Активный анализ

| Пакет | Описание |
|-------|----------|
| `active` | Главный движок анализа, конфигурация |
| `active.scanner` | Интерфейсы и базовые классы сканеров |
| `active.http` | HTTP клиенты и конфигурация |
| `active.http.ssl` | SSL/TLS и GOST криптография |
| `active.http.ssl.store` | Хранилища ключей (PFX, JCP, cacerts) |
| `active.auth` | Аутентификация и учетные данные |
| `active.validator` | Валидация контрактов и фаззинг |
| `active.model` | Модели данных (эндпоинты, запросы, отчеты) |

### validator.* - Статическая валидация

| Пакет | Описание |
|-------|----------|
| `validator` | Валидаторы безопасности и контрактов |

### parser.* - Парсеры

| Пакет | Описание |
|-------|----------|
| `parser` | Загрузка и нормализация спецификаций |

### model.* - Модели данных

| Пакет | Описание |
|-------|----------|
| `model` | Общие модели (операции, результаты валидации) |

### util.* - Утилиты

| Пакет | Описание |
|-------|----------|
| `util` | Вспомогательные функции валидации |

## 🚀 Использование

### Полный пример анализа

```java
import active.ActiveAnalysisEngine;
import active.scanner.ScanContext;
import parser.OpenApiLoader;
import validator.SecurityValidator;

// 1. Загрузка спецификации
OpenApiLoader loader = new OpenApiLoader();
OpenApiLoader.LoadResult loadResult = loader.load("openapi.yaml");

if (!loadResult.isSuccessful()) {
    System.err.println("Ошибка загрузки спецификации");
    return;
}

OpenAPI spec = loadResult.getOpenAPI();

// 2. Статическая валидация
SecurityValidator staticValidator = new SecurityValidator(spec);
List<ValidationFinding> staticFindings = staticValidator.validate();
System.out.println("Статических проблем: " + staticFindings.size());

// 3. Активный анализ
AnalysisConfig config = AnalysisConfig.builder()
    .cryptoProtocol(HttpClient.CryptoProtocol.STANDARD_TLS)
    .scanIntensity("MEDIUM")
    .maxParallelScans(4)
    .build();

ActiveAnalysisEngine engine = new ActiveAnalysisEngine(config);

// Извлечение эндпоинтов из спецификации
List<ApiEndpoint> endpoints = extractEndpoints(spec, "https://api.example.com");

// Сканирование
ScanContext context = new ScanContext("https://api.example.com");
AnalysisReport report = engine.scanEndpoints(endpoints, context);

// 4. Анализ результатов
System.out.println("\n=== Результаты активного анализа ===");
System.out.println("Просканировано эндпоинтов: " + report.getEndpointCount());
System.out.println("Найдено уязвимостей: " + report.getTotalVulnerabilityCount());

// Группировка по типу уязвимости
Map<VulnerabilityReport.VulnerabilityType, Long> byType =
    report.getVulnerabilityCountByType();
byType.forEach((type, count) ->
    System.out.println("  " + type + ": " + count)
);

// Группировка по критичности
Map<Severity, Long> bySeverity = report.getVulnerabilityCountBySeverity();
System.out.println("\nПо критичности:");
bySeverity.forEach((severity, count) ->
    System.out.println("  " + severity + ": " + count)
);

// 5. Освобождение ресурсов
engine.shutdown();
```

## 🔌 Расширение функциональности

### Создание нового сканера уязвимостей

1. **Создайте класс сканера:**
```java
package com.example.scanners;

import active.scanner.AbstractScanner;
import active.scanner.ScanResult;
import active.model.*;

public class CustomInjectionScanner extends AbstractScanner {

    public CustomInjectionScanner() {
        super(ScannerConfig.builder()
            .enabled(true)
            .maxTestsPerEndpoint(5)
            .timeoutSeconds(30)
            .build());
    }

    @Override
    public String getId() {
        return "custom-injection";
    }

    @Override
    public String getName() {
        return "Custom Injection Scanner";
    }

    @Override
    public String getDescription() {
        return "Обнаруживает кастомные инъекции";
    }

    @Override
    public List<VulnerabilityReport.VulnerabilityType> getDetectedVulnerabilities() {
        return List.of(VulnerabilityReport.VulnerabilityType.INJECTION);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Применять к эндпоинтам с параметрами
        return endpoint.hasParameters();
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint,
                                     HttpClient httpClient,
                                     ScanContext context) {
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Список тестовых пейлоадов
        List<String> payloads = List.of(
            "'; DROP TABLE users--",
            "<script>alert('xss')</script>",
            "../../../etc/passwd"
        );

        for (String payload : payloads) {
            TestRequest request = buildRequestWithPayload(endpoint, payload, context);
            TestResponse response = httpClient.execute(request);

            if (detectVulnerability(response, payload)) {
                VulnerabilityReport vuln = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.INJECTION)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint.getPath())
                    .method(endpoint.getMethod())
                    .details("Обнаружена уязвимость инъекции с пейлоадом: " + payload)
                    .evidence(response.getBody())
                    .request(request)
                    .response(response)
                    .build();

                vulnerabilities.add(vuln);
            }
        }

        return vulnerabilities.isEmpty()
            ? ScanResult.clean()
            : ScanResult.withVulnerabilities(vulnerabilities);
    }

    private boolean detectVulnerability(TestResponse response, String payload) {
        // Логика определения уязвимости
        return response.getStatusCode() == 500
            || response.getBody().contains(payload);
    }
}
```

2. **Зарегистрируйте через ServiceLoader:**

Создайте файл `src/main/resources/META-INF/services/active.scanner.VulnerabilityScanner`:
```
com.example.scanners.CustomInjectionScanner
```

3. **Сканер автоматически загрузится** при инициализации `ActiveAnalysisEngine`.

### Создание кастомного HTTP клиента

```java
public class MyCustomHttpClient implements HttpClient {

    @Override
    public TestResponse execute(TestRequest request) {
        // Ваша реализация
        return new TestResponse(200, "OK", headers, body);
    }

    @Override
    public CryptoProtocol getCryptoProtocol() {
        return CryptoProtocol.CUSTOM;
    }

    @Override
    public boolean supports(String url) {
        return url.startsWith("https://");
    }

    @Override
    public void close() {
        // Освобождение ресурсов
    }
}
```

### Создание кастомного валидатора

```java
public class MyCustomValidator implements ContractValidator {

    private final OpenAPI openAPI;

    public MyCustomValidator(OpenAPI openAPI) {
        this.openAPI = openAPI;
    }

    @Override
    public List<ValidationFinding> validate() {
        List<ValidationFinding> findings = new ArrayList<>();

        // Ваша логика валидации
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();

            // Проверка...
            if (hasIssue(pathItem)) {
                findings.add(ValidationFinding.builder()
                    .severity(Severity.MEDIUM)
                    .category(FindingCategory.SECURITY)
                    .type("CUSTOM_ISSUE")
                    .path(path)
                    .details("Обнаружена проблема")
                    .recommendation("Рекомендация по исправлению")
                    .build());
            }
        }

        return findings;
    }
}
```

