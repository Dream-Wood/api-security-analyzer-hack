# Локализация / Localization

## 🌍 Обзор / Overview

Система локализации API Security Analyzer поддерживает многоязычность во всех модулях проекта:
- **Core модуль**: Java ResourceBundle для backend локализации
- **CLI**: Параметр `--lang` для выбора языка
- **WebUI**: React i18next для frontend локализации
- **Plugins**: Индивидуальные .properties файлы для каждого сканера

**Поддерживаемые языки:**
- 🇬🇧 English (en)
- 🇷🇺 Русский (ru)

---

## 📁 Структура файлов / File Structure

### Core модуль

```
core/src/main/
├── java/com/apisecurity/analyzer/core/i18n/
│   ├── LocaleManager.java          # Управление текущей локалью
│   ├── MessageService.java         # Сервис для core сообщений
│   ├── PluginMessageService.java   # Сервис для сообщений плагинов
│   ├── I18nKeys.java              # Константы ключей сообщений
│   ├── VulnerabilityTypeLocalizer.java  # Локализация типов уязвимостей
│   └── SeverityLocalizer.java     # Локализация уровней критичности
└── resources/
    ├── messages.properties         # Fallback (по умолчанию английский)
    ├── messages_en.properties      # Английские сообщения
    └── messages_ru.properties      # Русские сообщения
```

### Plugins (пример для BOLA сканера) - Hot Swappable!

**⚠️ ВАЖНО:** Каждый плагин содержит свою собственную локализацию в своем JAR файле!

```
plugins/scanner-bola/
└── src/main/resources/
    ├── bola.properties             # Fallback (ОБЯЗАТЕЛЬНО!)
    ├── bola_en.properties          # Английская локализация
    └── bola_ru.properties          # Русская локализация
```

### WebUI

```
webui/src/main/frontend/src/
├── i18n/
│   ├── config.ts                  # Конфигурация i18next
│   └── locales/
│       ├── en.json               # Английские переводы
│       └── ru.json               # Русские переводы
└── components/
    └── LanguageSwitcher.tsx      # Компонент переключения языка
```

---

## 🚀 Использование / Usage

### CLI

```bash
# Использование русского языка
api-security-analyzer --lang ru spec.yaml

# Использование английского языка
api-security-analyzer --lang en spec.yaml

# Короткая форма
api-security-analyzer -l ru spec.yaml
```

---

## 🔌 Добавление локализации в новый сканер

### Пример для нового сканера XYZ

1. **Создайте файлы локализации:**

```
plugins/scanner-xyz/src/main/resources/
├── xyz.properties
├── xyz_en.properties
└── xyz_ru.properties
```

2. **Добавьте ключи в xyz_en.properties:**

```properties
# Scanner metadata
scanner.name=XYZ Scanner
scanner.description=Detects XYZ vulnerabilities

# Vulnerability messages
vuln.xyz.title=XYZ Vulnerability Found
vuln.xyz.description=This endpoint is vulnerable to XYZ attack...
vuln.xyz.recommendation=To fix this vulnerability, implement...
```

3. **Добавьте переводы в xyz_ru.properties:**

```properties
# Метаданные сканера
scanner.name=Сканер XYZ
scanner.description=Обнаруживает уязвимости XYZ

# Сообщения об уязвимостях
vuln.xyz.title=Обнаружена уязвимость XYZ
vuln.xyz.description=Этот эндпоинт уязвим к атаке XYZ...
vuln.xyz.recommendation=Для устранения этой уязвимости реализуйте...
```

4. **Используйте в коде сканера:**

```java
public class XyzScanner implements VulnerabilityScanner {
    @Override
    public String getName() {
        return MessageService.getMessage("xyz", "scanner.name");
    }

    @Override
    public String getDescription() {
        return MessageService.getMessage("xyz", "scanner.description");
    }

    private VulnerabilityReport createReport() {
        String title = MessageService.getMessage("xyz", "vuln.xyz.title");
        String description = MessageService.getMessage("xyz", "vuln.xyz.description");
        String recommendation = MessageService.getMessage("xyz", "vuln.xyz.recommendation");

        return VulnerabilityReport.builder()
            .title(title)
            .description(description)
            .addRecommendation(recommendation)
            .build();
    }
}
```