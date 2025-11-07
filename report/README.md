# Модуль Report

Модуль для генерации отчетов о результатах анализа безопасности API в различных форматах.

## Описание

Модуль `report` предоставляет унифицированную систему для создания отчетов о результатах анализа безопасности API. Поддерживает множество форматов вывода и интегрируется с различными типами анализа: статическим, активным и валидацией контракта.

## Архитектура

### Основные компоненты

```
report/
├── Reporter                 - Интерфейс генератора отчетов
├── ReporterFactory         - Фабрика для создания репортеров
├── AnalysisReport          - Унифицированный отчет о результатах
├── ReportFormat            - Enum поддерживаемых форматов
├── ConsoleReporter         - Генератор для консольного вывода с цветами
├── JsonReporter            - Генератор JSON-отчетов
└── PdfReporter             - Генератор подробных PDF-отчетов
```

### Поддерживаемые форматы

1. **CONSOLE** - Консольный вывод с ANSI цветами
   - Интерактивный вывод для терминала
   - Цветовое кодирование по severity
   - Структурированное представление
   - Возможность отключить цвета

2. **JSON** - Структурированный JSON формат
   - Для интеграции с CI/CD
   - Программная обработка результатов
   - Агрегация и визуализация
   - Pretty-print с отступами

3. **PDF** - Подробные PDF-отчеты
   - Профессиональная презентация
   - Графики и диаграммы
   - База знаний об уязвимостях
   - Кликабельное оглавление

## Использование

### Базовое использование

```java
// Создание репортера через фабрику
Reporter reporter = ReporterFactory.createReporter(ReportFormat.CONSOLE, true);

// Генерация отчета
try (PrintWriter writer = new PrintWriter(System.out)) {
    reporter.generate(analysisReport, writer);
}
```

### Консольный отчет

```java
// С цветами (по умолчанию)
Reporter consoleReporter = new ConsoleReporter(true);
consoleReporter.generate(report, new PrintWriter(System.out));

// Без цветов (для перенаправления в файл)
Reporter plainReporter = new ConsoleReporter(false);
try (PrintWriter writer = new PrintWriter(new FileWriter("report.txt"))) {
    plainReporter.generate(report, writer);
}
```

### JSON отчет

```java
Reporter jsonReporter = new JsonReporter();
try (PrintWriter writer = new PrintWriter(new FileWriter("report.json"))) {
    jsonReporter.generate(report, writer);
}
```

### PDF отчет

```java
PdfReporter pdfReporter = new PdfReporter();
try (OutputStream out = new FileOutputStream("report.pdf")) {
    pdfReporter.generateToOutputStream(report, out);
}
```

## Структура AnalysisReport

Класс `AnalysisReport` объединяет результаты всех типов анализа:

```java
AnalysisReport report = AnalysisReport.builder()
    .specLocation("petstore.yaml")
    .specTitle("Petstore API")
    .startTime(Instant.now())
    .mode(AnalysisMode.FULL)
    .staticResult(staticResult)
    .activeResult(activeResult)
    .contractResult(contractResult)
    .endTime(Instant.now())
    .build();
```

### Режимы анализа (AnalysisMode)

- `STATIC_ONLY` - Только статический анализ спецификации
- `ACTIVE_ONLY` - Только активное тестирование безопасности
- `COMBINED` - Статический + активный анализ
- `CONTRACT` - Проверка соответствия контракту
- `FULL` - Полный анализ (все типы)

### Результаты анализа

#### StaticAnalysisResult
Содержит результаты статического анализа:
- Сообщения о парсинге спецификации
- Список найденных проблем (ValidationFinding)
- Сообщение об ошибке (если есть)

#### ActiveAnalysisResult
Содержит результаты активного тестирования:
- Отчет от движка активного анализа
- Список найденных уязвимостей
- Статистика по endpoint'ам
- Сообщение об ошибке (если есть)

#### ContractAnalysisResult
Содержит результаты валидации контракта:
- Отчет о расхождениях
- Статистика по критичным проблемам
- Настройки fuzzing
- Сообщение об ошибке (если есть)

## Форматы вывода

### Консольный формат

Консольный отчет использует ANSI escape-коды для цветового выделения:

```
============================================================
API Security Analyzer
============================================================

Analyzing: Petstore API
Mode: FULL
Duration: 1m 23s

Static Analysis Results
------------------------------------------------------------
Found 5 issues

By Severity:
  🔴 CRITICAL: 1
  🟠 HIGH: 2
  🟡 MEDIUM: 2

[CRITICAL]

🔴 Missing authentication on sensitive endpoint
  Location: GET /admin/users
  Details: Endpoint exposes sensitive data without authentication
  Recommendation: Add security scheme requirement
  ID: SEC-001
```

### JSON формат

JSON отчет содержит полную структурированную информацию:

```json
{
  "specTitle": "Petstore API",
  "specLocation": "petstore.yaml",
  "startTime": "2024-01-15T10:30:00Z",
  "endTime": "2024-01-15T10:31:23Z",
  "durationSeconds": 83,
  "mode": "FULL",
  "staticAnalysis": {
    "parsingMessages": [],
    "findings": [
      {
        "id": "SEC-001",
        "type": "Missing authentication",
        "severity": "CRITICAL",
        "category": "SECURITY",
        "path": "/admin/users",
        "method": "GET",
        "details": "Endpoint exposes sensitive data without authentication",
        "recommendation": "Add security scheme requirement",
        "metadata": {}
      }
    ],
    "findingsCount": 5,
    "findingsBySeverity": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 2
    }
  },
  "activeAnalysis": {
    "endpointsScanned": 15,
    "vulnerableEndpoints": 3,
    "totalVulnerabilities": 7,
    "vulnerabilitiesBySeverity": {
      "CRITICAL": 2,
      "HIGH": 3,
      "MEDIUM": 2
    },
    "vulnerabilitiesByType": {
      "SQL_INJECTION": 2,
      "XSS": 1,
      "BOLA": 4
    }
  },
  "summary": {
    "totalIssues": 12,
    "staticIssues": 5,
    "activeVulnerabilities": 7
  }
}
```

### PDF формат

PDF отчет включает:

1. **Титульная страница**
   - Название спецификации
   - Дата и время анализа
   - Режим анализа
   - Краткая статистика

2. **Оглавление**
   - Кликабельные ссылки на разделы
   - Номера страниц

3. **Статический анализ**
   - Круговая диаграмма по severity
   - Группировка по endpoint'ам
   - Детали каждой проблемы

4. **Активное тестирование**
   - Круговая диаграмма по severity
   - Столбчатая диаграмма по типам
   - Ссылки на базу знаний
   - Детали уязвимостей

5. **Валидация контракта**
   - Круговая диаграмма по severity
   - Группировка расхождений
   - Детали каждого расхождения

6. **База знаний**
   - Подробное описание уязвимостей
   - Список затронутых endpoint'ов
   - Примеры воспроизведения
   - Рекомендации по устранению

## Интеграция с CLI

Модуль `report` интегрируется с CLI через класс `ApiSecurityAnalyzerCli`:

```java
// В CLI
Reporter reporter = ReporterFactory.createReporter(reportFormat, !noColor);

if (outputFile != null) {
    try (PrintWriter fileWriter = new PrintWriter(new FileWriter(outputFile))) {
        reporter.generate(report, fileWriter);
    }
} else {
    reporter.generate(report, out);
}
```

## Расширение функциональности

### Добавление нового формата

1. Создайте класс, реализующий интерфейс `Reporter`:

```java
public final class MyCustomReporter implements Reporter {

    @Override
    public void generate(AnalysisReport report, PrintWriter writer) throws IOException {
        // Ваша логика генерации отчета
    }

    @Override
    public ReportFormat getFormat() {
        return ReportFormat.CUSTOM; // Добавьте в enum
    }
}
```

2. Добавьте новый формат в `ReportFormat`:

```java
public enum ReportFormat {
    // ...
    CUSTOM("My custom format");
}
```

3. Добавьте создание в `ReporterFactory`:

```java
public static Reporter createReporter(ReportFormat format, boolean useColors) {
    return switch (format) {
        // ...
        case CUSTOM -> new MyCustomReporter();
    };
}
```

## Лучшие практики

### Выбор формата отчета

- **CONSOLE** - для интерактивной работы и быстрой проверки результатов
- **JSON** - для интеграции с CI/CD и автоматической обработки
- **PDF** - для документирования, презентаций и архивирования

### Обработка ошибок

Всегда проверяйте наличие ошибок в результатах:

```java
if (report.hasStaticResults() && !report.getStaticResult().hasError()) {
    // Обработка результатов статического анализа
}

if (report.hasActiveResults() && report.getActiveResult().hasError()) {
    System.err.println("Active analysis failed: " +
        report.getActiveResult().getErrorMessage());
}
```

### Производительность

- Консольный репортер самый быстрый
- JSON репортер средней скорости
- PDF репортер самый медленный (из-за создания графиков)

### Конфигурация цветов

```java
// Включить цвета для интерактивного терминала
Reporter reporter = new ConsoleReporter(true);

// Отключить цвета для перенаправления в файл или CI/CD
Reporter plainReporter = new ConsoleReporter(false);
```

## Примеры использования

### Пример 1: Простой консольный отчет

```java
UnifiedAnalyzer analyzer = new UnifiedAnalyzer(config);
AnalysisReport report = analyzer.analyze("spec.yaml");

Reporter reporter = ReporterFactory.createReporter(ReportFormat.CONSOLE);
reporter.generate(report, new PrintWriter(System.out, true));
```

### Пример 2: JSON отчет в файл

```java
Reporter jsonReporter = ReporterFactory.createReporter(ReportFormat.JSON);
try (PrintWriter writer = new PrintWriter(new FileWriter("analysis-report.json"))) {
    jsonReporter.generate(report, writer);
}
```

### Пример 3: PDF отчет с обработкой ошибок

```java
PdfReporter pdfReporter = new PdfReporter();
try (OutputStream out = new FileOutputStream("security-report.pdf")) {
    pdfReporter.generateToOutputStream(report, out);
    System.out.println("PDF report generated successfully");
} catch (IOException e) {
    System.err.println("Failed to generate PDF: " + e.getMessage());
}
```

### Пример 4: Условный выбор формата

```java
String formatStr = System.getProperty("report.format", "console");
ReportFormat format = switch (formatStr.toLowerCase()) {
    case "json" -> ReportFormat.JSON;
    case "pdf" -> ReportFormat.PDF;
    default -> ReportFormat.CONSOLE;
};

Reporter reporter = ReporterFactory.createReporter(format);
reporter.generate(report, new PrintWriter(System.out));
```

## Тестирование

Для тестирования репортеров рекомендуется:

1. Создать тестовый `AnalysisReport` с фиктивными данными
2. Проверить корректность форматирования
3. Для PDF проверить создание файла и его размер
4. Для JSON проверить корректность десериализации

```java
@Test
void testConsoleReporter() throws IOException {
    AnalysisReport report = createTestReport();
    Reporter reporter = new ConsoleReporter(false); // Без цветов для тестов

    StringWriter stringWriter = new StringWriter();
    reporter.generate(report, new PrintWriter(stringWriter));

    String output = stringWriter.toString();
    assertTrue(output.contains("API Security Analyzer"));
    assertTrue(output.contains("Total issues found:"));
}
```