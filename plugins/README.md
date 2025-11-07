# Scanner Plugins

Эта директория содержит плагины-сканеры для API Security Analyzer.

## О плагинах

API Security Analyzer использует плагинную архитектуру на основе Java ServiceLoader для динамической загрузки сканеров уязвимостей.

**Важно:** CLI версия уже включает все плагины внутри JAR файла (fat JAR), поэтому **отдельные плагины не требуются** для обычного использования.

## Когда использовать отдельные плагины

Отдельные плагины полезны в следующих случаях:

1. **Разработка собственных сканеров** - Вы можете заменить или добавить свои плагины
2. **Выборочное использование** - Запускать только определенные сканеры
3. **Обновление плагинов** - Обновлять отдельные сканеры без пересборки всего приложения
4. **Тестирование** - Тестировать новые версии плагинов

## Список плагинов

| Плагин | Описание | OWASP API Top 10 |
|--------|----------|------------------|
| `scanner-bola` | Broken Object Level Authorization | API1:2023 |
| `scanner-bfla` | Broken Function Level Authorization | API5:2023 |
| `scanner-sqlinjection` | SQL Injection | API8:2023 |
| `scanner-injection` | Command/LDAP/NoSQL Injection | API8:2023 |
| `scanner-xxe` | XML External Entity | API8:2023 |
| `scanner-ssrf` | Server-Side Request Forgery | API7:2023 |
| `scanner-traversal` | Path Traversal | API8:2023 |
| `scanner-brokenauth` | Broken Authentication | API2:2023 |
| `scanner-crypto` | Weak Cryptography | API2:2023 |
| `scanner-misconfiguration` | Security Misconfiguration | API8:2023 |
| `scanner-businessflow` | Business Logic Flaws | API10:2023 |
| `scanner-resource` | Unrestricted Resource Consumption | API4:2023 |
| `scanner-inventory` | Improper Inventory Management | API9:2023 |
| `scanner-infodisclosure` | Information Disclosure | - |
| `scanner-bopla` | Broken Object Property Level Auth | API3:2023 |
| `scanner-unsafeapi` | Unsafe API Consumption | API10:2023 |

## Как использовать отдельные плагины

### Вариант 1: С classpath

```bash
java -cp "api-security-analyzer-cli-1.0.0.jar:plugins/*" \
  cli.ApiSecurityAnalyzerCli \
  -m active \
  -u https://api.example.com \
  openapi.yaml
```

### Вариант 2: С директорией плагинов (если поддерживается)

```bash
java -jar api-security-analyzer-cli-1.0.0.jar \
  --plugins-dir ./plugins \
  -m active \
  -u https://api.example.com \
  openapi.yaml
```

### Вариант 3: Выборочная загрузка

Скопируйте только нужные плагины в отдельную директорию:

```bash
mkdir my-plugins
cp plugins/scanner-sqlinjection-1.0-SNAPSHOT.jar my-plugins/
cp plugins/scanner-xxe-1.0-SNAPSHOT.jar my-plugins/

java -cp "api-security-analyzer-cli-1.0.0.jar:my-plugins/*" \
  cli.ApiSecurityAnalyzerCli \
  -m active \
  -u https://api.example.com \
  openapi.yaml
```

## Создание собственного плагина

### 1. Создайте Maven модуль

```xml
<project>
    <parent>
        <groupId>com.apisecurity</groupId>
        <artifactId>plugins</artifactId>
        <version>1.0-SNAPSHOT</version>
    </parent>

    <artifactId>scanner-custom</artifactId>
    <name>Custom Scanner Plugin</name>
</project>
```

### 2. Реализуйте VulnerabilityScanner

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
        return "Detects custom vulnerabilities";
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
        return ScanResult.clean();
    }
}
```

### 3. Зарегистрируйте через ServiceLoader

Создайте файл `src/main/resources/META-INF/services/active.scanner.VulnerabilityScanner`:

```
scanners.CustomScanner
```

### 4. Соберите плагин

```bash
mvn clean package
```

JAR файл появится в `target/scanner-custom-1.0-SNAPSHOT.jar`

### 5. Используйте свой плагин

```bash
cp target/scanner-custom-1.0-SNAPSHOT.jar /path/to/release/plugins/

java -cp "api-security-analyzer-cli-1.0.0.jar:plugins/*" \
  cli.ApiSecurityAnalyzerCli \
  -m active \
  -u https://api.example.com \
  openapi.yaml
```

## Зависимости плагинов

Каждый плагин зависит от `core` модуля со scope `provided`, что означает:
- При разработке: зависимость доступна для компиляции
- При выполнении: зависимость должна быть в classpath (предоставляется CLI JAR)

## Структура плагина

```
scanner-custom/
├── pom.xml
└── src/
    └── main/
        ├── java/
        │   └── scanners/
        │       └── CustomScanner.java
        └── resources/
            └── META-INF/
                └── services/
                    └── active.scanner.VulnerabilityScanner
```

## Отладка плагинов

Для проверки загрузки плагинов используйте verbose режим:

```bash
java -verbose:class -jar api-security-analyzer-cli-1.0.0.jar \
  -m active \
  -u https://api.example.com \
  openapi.yaml
```

Это покажет, какие классы и плагины загружаются.

## Производительность

Рекомендации по производительности плагинов:

1. **Кэширование** - Кэшируйте результаты тяжелых операций
2. **Timeout** - Устанавливайте таймауты для HTTP запросов
3. **Параллелизм** - Используйте встроенный механизм параллельного выполнения
4. **Ограничение запросов** - Уважайте настройки `--request-delay` и `--max-parallel-scans`

## Безопасность плагинов

При создании и использовании плагинов:

1. **Проверяйте источник** - Используйте только доверенные плагины
2. **Проверяйте код** - Просматривайте исходный код плагинов перед использованием
3. **Изолируйте** - Рассмотрите использование Security Manager для изоляции плагинов
4. **Обновляйте** - Регулярно обновляйте плагины до последних версий

## Поддержка

- Документация: https://github.com/your-org/api-security-analyzer
- Issues: https://github.com/your-org/api-security-analyzer/issues
- Примеры плагинов: См. существующие плагины в `plugins/` директории проекта

---

**Примечание:** Большинству пользователей **не нужно** использовать отдельные плагины, так как они уже включены в CLI JAR файл.
