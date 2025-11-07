# CLI модуль API Security Analyzer

## Обзор

CLI модуль предоставляет интерфейс командной строки для комплексного анализа безопасности OpenAPI и AsyncAPI спецификаций. Модуль поддерживает как статический анализ спецификаций, так и активное тестирование реальных API на уязвимости безопасности.

## Архитектура

### Основные компоненты

#### 1. `ApiSecurityAnalyzerCli`
Главная точка входа приложения. Обрабатывает аргументы командной строки с помощью библиотеки picocli.

**Основные опции:**
- `-m, --mode` - режим анализа (static, active, both, contract, full)
- `-u, --base-url` - базовый URL для активного тестирования
- `-a, --auth-header` - заголовок аутентификации
- `-c, --crypto-protocol` - криптографический протокол (standard, gost)
- `-f, --format` - формат вывода (console, json)
- `-v, --verbose` - подробный вывод

#### 2. `UnifiedAnalyzer`
Координирует выполнение различных типов анализа. Основной оркестратор для:
- Статического анализа спецификаций
- Активного тестирования безопасности
- Валидации контрактов API
- Обработки OpenAPI и AsyncAPI спецификаций

**Режимы работы:**
- `STATIC_ONLY` - только статический анализ
- `ACTIVE_ONLY` - только активное тестирование
- `COMBINED` - статический + активный анализ
- `CONTRACT` - проверка соответствия контракту
- `FULL` - полный анализ (все типы тестов)

#### 3. `AuthenticationManager`
Управляет аутентификацией и созданием тестовых пользователей.

**Возможности:**
- Автоматическая аутентификация через registration/login endpoints
- Поддержка пользовательских заголовков аутентификации
- Создание тестовых пользователей для BOLA тестирования
- Аутентификация с использованием client credentials flow

#### 4. `HttpClientHelper`
Вспомогательный класс для создания HTTP клиентов с единообразной конфигурацией.

**Поддерживаемые протоколы:**
- Standard TLS (стандартная криптография)
- GOST TLS (CryptoPro JCSP для российской криптографии)

#### 5. `SpecAnalyzer`
Загрузка и валидация OpenAPI спецификаций.

**Функции:**
- Парсинг YAML/JSON спецификаций
- Статическая валидация структуры
- Обработка ошибок парсинга
- Сбор сообщений валидации

#### 6. `ResultFormatter`
Форматирование результатов анализа для консольного вывода.

**Возможности:**
- Цветной ANSI вывод
- Группировка по уровням критичности
- Детальная информация о каждой проблеме
- Сводная статистика

#### 7. `AnalysisProgressListener`
Интерфейс для отслеживания прогресса анализа.

**Методы:**
- `onLog()` - логирование сообщений
- `onPhaseChange()` - смена фазы анализа
- `onStepComplete()` - завершение шага

## Примеры использования

### 1. Базовый статический анализ

```bash
java -jar api-security-analyzer.jar spec.yaml
```

### 2. Активное тестирование

```bash
java -jar api-security-analyzer.jar -m active -u https://api.example.com spec.yaml
```

### 3. Полный анализ с аутентификацией

```bash
java -jar api-security-analyzer.jar -m full \
  -u https://api.example.com \
  -a "Authorization: Bearer token123" \
  spec.yaml
```

### 4. Анализ с GOST криптографией

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  -c gost \
  --gost-pfx-path cert.pfx \
  --gost-pfx-password password \
  spec.yaml
```

### 5. Контрактная валидация без фаззинга

```bash
java -jar api-security-analyzer.jar -m contract \
  -u https://api.example.com \
  --no-fuzzing \
  spec.yaml
```

### 6. Сохранение результатов в JSON

```bash
java -jar api-security-analyzer.jar -m full \
  -u https://api.example.com \
  -f json \
  -o report.json \
  spec.yaml
```

### 7. Отключение автоматической аутентификации

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  --no-auto-auth \
  spec.yaml
```

### 8. Настройка параллельности и задержек

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  --max-parallel-scans 2 \
  --request-delay 500 \
  spec.yaml
```

## Режимы анализа

### Static (статический)
Анализирует только спецификацию без выполнения запросов к API.

**Проверки:**
- Отсутствие схем безопасности
- Использование HTTP вместо HTTPS
- Отсутствие rate limiting
- Проблемы валидации данных
- Использование устаревших методов

### Active (активный)
Выполняет реальные запросы к API для поиска уязвимостей.

**Сканеры:**
- SQL Injection
- XSS (Cross-Site Scripting)
- Authentication bypass
- Authorization bypass (BOLA/IDOR)
- Mass assignment
- Server-Side Request Forgery (SSRF)
- Path traversal

### Contract (контрактный)
Проверяет соответствие реализации API контракту в спецификации.

**Проверки:**
- Соответствие кодов статуса
- Соответствие схем ответов
- Проверка обязательных полей
- Проверка типов данных
- Fuzzing входных данных (опционально)

### Full (полный)
Выполняет все типы анализа: статический, активный и контрактный.

## Поддержка ГОСТ криптографии

Модуль поддерживает российские криптографические стандарты ГОСТ через библиотеку CryptoPro JCSP.

### Требования

1. Установленный CryptoPro CSP
2. PFX сертификат с закрытым ключом
3. Настроенные провайдеры безопасности

### Использование

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  -c gost \
  --gost-pfx-path /path/to/cert.pfx \
  --gost-pfx-password "certificate_password" \
  spec.yaml
```

### Загрузка из classpath

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  -c gost \
  --gost-pfx-path certs/cert.pfx \
  --gost-pfx-password "password" \
  --gost-pfx-resource \
  spec.yaml
```

## Аутентификация

### Автоматическая аутентификация

По умолчанию анализатор пытается автоматически аутентифицироваться через:
1. Поиск `/register` или `/signup` endpoints
2. Создание нового пользователя
3. Получение токена доступа

### Ручная аутентификация

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  -a "Authorization: Bearer your_token_here" \
  spec.yaml
```

### Тестовые пользователи для BOLA

Анализатор автоматически создает дополнительных пользователей для тестирования BOLA уязвимостей:

```bash
# Создание тестовых пользователей включено по умолчанию
java -jar api-security-analyzer.jar -m active -u https://api.example.com spec.yaml

# Отключение создания тестовых пользователей
java -jar api-security-analyzer.jar -m active -u https://api.example.com --no-test-users spec.yaml
```

## Оптимизация производительности

### Параллельное выполнение

```bash
# Увеличить количество параллельных сканов (по умолчанию: 4)
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  --max-parallel-scans 8 \
  spec.yaml
```

### Задержка между запросами

```bash
# Добавить задержку 1000ms между запросами для снижения нагрузки
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  --request-delay 1000 \
  spec.yaml
```

### Отключение фаззинга

```bash
# Ускорить контрактную валидацию отключением фаззинга
java -jar api-security-analyzer.jar -m contract \
  -u https://api.example.com \
  --no-fuzzing \
  spec.yaml
```

## Обработка ошибок

### Коды возврата

- `0` - успешное выполнение, проблем не найдено
- `3` - найдены критические или высокой важности проблемы
- `1` - ошибка в параметрах или конфигурации
- `99` - неожиданная ошибка выполнения

### SSL сертификаты

```bash
# Отключить проверку SSL (только для тестирования!)
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  --no-verify-ssl \
  spec.yaml
```

## Расширение функциональности

### Добавление новых сканеров

Сканеры регистрируются автоматически через механизм ServiceLoader. Для добавления нового сканера:

1. Реализуйте интерфейс `SecurityScanner`
2. Создайте файл `META-INF/services/active.scanner.SecurityScanner`
3. Добавьте полное имя класса вашего сканера в файл

### Пользовательские форматы отчетов

Форматы отчетов создаются через `ReporterFactory`. Для добавления нового формата:

1. Реализуйте интерфейс `Reporter`
2. Добавьте создание в `ReporterFactory.createReporter()`

## Интеграция с CI/CD

### GitHub Actions

```yaml
- name: API Security Analysis
  run: |
    java -jar api-security-analyzer.jar -m full \
      -u ${{ secrets.API_BASE_URL }} \
      -f json \
      -o security-report.json \
      openapi.yaml

    # Проверка exit code
    if [ $? -eq 3 ]; then
      echo "Critical security issues found!"
      exit 1
    fi
```

### GitLab CI

```yaml
api_security_test:
  script:
    - java -jar api-security-analyzer.jar -m full -u $API_URL -f json -o report.json spec.yaml
  artifacts:
    reports:
      junit: report.json
  allow_failure: false
```

## Разработка и отладка

### Подробный вывод

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  -v \
  spec.yaml
```

### Отладка аутентификации

```bash
# Используйте verbose для просмотра процесса аутентификации
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  -v \
  spec.yaml
```

## Устранение неполадок

### Проблема: Не удается найти endpoints для тестирования

**Решение:** Убедитесь, что спецификация содержит определения paths:

```bash
# Проверьте спецификацию статическим анализом
java -jar api-security-analyzer.jar -m static spec.yaml
```

### Проблема: Автоматическая аутентификация не работает

**Решение:** Проверьте наличие registration/login endpoints или используйте ручную аутентификацию:

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  -a "Authorization: Bearer token" \
  spec.yaml
```

### Проблема: GOST соединение не устанавливается

**Решения:**
1. Проверьте установку CryptoPro CSP
2. Убедитесь, что PFX файл содержит закрытый ключ
3. Проверьте правильность пароля
4. Убедитесь, что сервер поддерживает GOST

## Лучшие практики

### 1. Начните со статического анализа

```bash
# Сначала проверьте спецификацию
java -jar api-security-analyzer.jar spec.yaml
```

### 2. Используйте staging окружение

Не запускайте активное тестирование на production без разрешения.

### 3. Настройте задержки для production-like тестирования

```bash
java -jar api-security-analyzer.jar -m active \
  -u https://api.example.com \
  --request-delay 1000 \
  --max-parallel-scans 2 \
  spec.yaml
```

### 4. Сохраняйте отчеты

```bash
java -jar api-security-analyzer.jar -m full \
  -u https://api.example.com \
  -f json \
  -o "report-$(date +%Y%m%d).json" \
  spec.yaml
```

### 5. Интегрируйте в CI/CD pipeline

Автоматизируйте проверки безопасности при каждом изменении спецификации или кода.

## Архитектурные улучшения (версия 1.0+)

### Рефакторинг от legacy кода

В текущей версии были проведены следующие улучшения:

1. **Создан `HttpClientHelper`** - устранено дублирование кода создания HTTP клиентов
2. **Создан `AuthenticationManager`** - выделена логика аутентификации в отдельный класс
3. **Упрощен `UnifiedAnalyzer`** - уменьшен размер с 983 до ~650 строк
4. **Улучшена документация** - добавлены подробные Javadoc комментарии на русском языке
5. **Соблюдение SOLID** - разделение ответственности между классами

### Детали рефакторинга

#### До рефакторинга:
- `UnifiedAnalyzer`: 983 строки, множественная ответственность
- Дублирование кода создания HTTP клиентов в 3 местах
- Смешанная логика аутентификации внутри анализа
- Метод `performActiveAnalysis`: 240+ строк

#### После рефакторинга:
- `UnifiedAnalyzer`: ~650 строк, фокус на оркестрации
- `HttpClientHelper`: централизованное создание клиентов
- `AuthenticationManager`: выделенная логика аутентификации
- Улучшенная читаемость и поддерживаемость кода

### Будущие улучшения

- [ ] Поддержка дополнительных форматов вывода (HTML, PDF)
- [ ] Расширенная конфигурация через файлы
- [ ] Поддержка профилей сканирования
- [ ] Интеграция с базами данных уязвимостей

## Структура пакета

```
cli/src/main/java/cli/
├── ApiSecurityAnalyzerCli.java     # Точка входа CLI
├── UnifiedAnalyzer.java            # Главный оркестратор анализа
├── AuthenticationManager.java      # Менеджер аутентификации
├── HttpClientHelper.java           # Вспомогательный класс для HTTP клиентов
├── SpecAnalyzer.java               # Анализатор спецификаций
├── ResultFormatter.java            # Форматирование результатов
└── AnalysisProgressListener.java  # Интерфейс слушателя прогресса
```

## Зависимости

CLI модуль использует:
- **picocli 4.7.7** - парсинг аргументов командной строки
- **core module** - парсеры, валидаторы, движок активного анализа
- **report module** - инфраструктура отчетности

## Лицензия

API Security Analyzer - внутренний инструмент разработки.

## Контакты

Для вопросов и предложений обращайтесь к команде API Security Analyzer Team.

## Дополнительная документация

- [README.md](README.md) - Оригинальная документация на английском
- [../CLI_USAGE.md](../CLI_USAGE.md) - Полное руководство по использованию CLI
- [../ACTIVE_ANALYSIS_README.md](../ACTIVE_ANALYSIS_README.md) - Детали активного тестирования
- [../README.md](../README.md) - Обзор всего проекта
