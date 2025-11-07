# API Security Analyzer - Модуль WebUI

Веб-интерфейс для API Security Analyzer. Предоставляет интерактивный способ настройки, запуска и мониторинга анализа безопасности с логами в реальном времени и визуализацией результатов.

## Возможности

- **Интерактивная настройка**: Удобная форма для настройки параметров анализа
- **Выбор сканеров**: Выбор конкретных сканеров для запуска через интерфейс (недоступно в CLI)
- **Логи в реальном времени**: Мониторинг прогресса анализа через WebSocket
- **Визуальные результаты**: Просмотр находок, организованных по степени серьезности и категории
- **Множественные режимы анализа**: Поддержка статического, активного, валидации контракта и полного анализа
- **Загрузка файлов**: Загрузка спецификаций API через веб-интерфейс
- **Экспорт отчетов**: Скачивание отчетов в форматах PDF, JSON, YAML, HTML, Markdown
- **Определение типа спецификации**: Автоматическое определение OpenAPI vs AsyncAPI
- **Тестирование множественных пользователей**: Поддержка BOLA/BFLA тестирования с несколькими учетными записями
- **Современный UI**: Построен на React, TypeScript и современных веб-стандартах

## Архитектура

Модуль WebUI состоит из двух основных частей:

### Backend (Spring Boot 4)

**Основные компоненты:**
- `webui.ApiSecurityAnalyzerWebUI` - Главное Spring Boot приложение
  - Настройка ObjectMapper для JSON сериализации
  - Конфигурация CORS для безопасного доступа

**Контроллеры:**
- `webui.controller.AnalysisController` - REST API для операций анализа
  - Запуск/остановка анализа
  - Получение статуса, логов и отчетов
  - Загрузка файлов спецификаций
  - Скачивание отчетов в различных форматах
  - Определение типа спецификации

- `webui.controller.ScannerController` - REST API для информации о сканерах
  - Получение списка доступных сканеров с категориями

**Сервисы:**
- `webui.service.AnalysisService` - Бизнес-логика выполнения анализа
  - Управление сессиями анализа
  - Интеграция с ядром анализа
  - Graceful shutdown ExecutorService
  - Преобразование учетных данных

**WebSocket:**
- `webui.websocket.AnalysisWebSocketHandler` - Обработчик WebSocket для реальновременных обновлений
  - Подписка/отписка на сессии анализа
  - Рассылка обновлений прогресса

**Конфигурация:**
- `webui.config.WebSocketConfig` - Настройка WebSocket endpoints

**Модели данных:**
- `webui.model.AnalysisRequest` - Запрос на анализ
- `webui.model.AnalysisResponse` - Ответ от сервера
- `webui.model.ScannerInfo` - Информация о сканере
- `webui.model.UserCredentials` - Учетные данные для множественных пользователей

### Frontend (React + TypeScript)

- Построен на Vite для быстрой разработки и оптимизированной продакшен сборки
- TypeScript для типобезопасности
- Компоненты:
  - `ConfigurationPanel` - Левая панель с настройками анализа
  - `LogsPanel` - Отображение логов в реальном времени
  - `ResultsPanel` - Вкладки с результатами (Сводка, Статический, Активный, Контракт)

## Сборка

### Сборка Backend и Frontend вместе
```bash
# Из корня проекта
mvn clean package

# Или сборка только модуля webui
cd webui
mvn clean package
```

### Отдельная сборка Frontend (Разработка)
```bash
cd webui/src/main/frontend
npm install
npm run build
```

### Пропуск сборки Frontend (Опциональный профиль)
```bash
mvn clean package -Pskip-frontend
```

## Запуск

### Production режим (Встроенный Frontend)
```bash
# После сборки через Maven
java -jar webui/target/webui-1.0-SNAPSHOT.jar

# Доступ по адресу http://localhost:8080
```

### Режим разработки (Hot Reload)

**Терминал 1 - Backend:**
```bash
cd webui
mvn spring-boot:run
```

**Терминал 2 - Frontend:**
```bash
cd webui/src/main/frontend
npm run dev

# Frontend dev сервер запускается на http://localhost:3000
# Проксирует API запросы на http://localhost:8080
```

## Конфигурация

### Конфигурация Backend

Редактируйте `webui/src/main/resources/application.properties`:

```properties
# Порт сервера
server.port=8080

# Уровни логирования
logging.level.webui=INFO
logging.level.active=INFO

# Лимиты загрузки файлов
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB
```

### Конфигурация CORS

По умолчанию разрешены localhost источники для разработки:
- `http://localhost:3000`
- `http://localhost:8080`
- `http://127.0.0.1:3000`
- `http://127.0.0.1:8080`

**Для production** настройте конкретные разрешенные источники в `ApiSecurityAnalyzerWebUI.corsConfigurer()`.

### Конфигурация Frontend

Редактируйте `webui/src/main/frontend/vite.config.ts` для настройки прокси в режиме разработки.

## API Endpoints

### Управление сканерами
- `GET /api/scanners` - Получить все доступные сканеры

### Операции анализа
- `POST /api/analysis/start` - Запустить новый анализ
- `GET /api/analysis/{sessionId}` - Получить полную информацию о сессии
- `GET /api/analysis/{sessionId}/status` - Получить статус анализа
- `GET /api/analysis/{sessionId}/logs` - Получить логи анализа
- `GET /api/analysis/{sessionId}/report` - Получить отчет анализа
- `POST /api/analysis/{sessionId}/cancel` - Отменить анализ
- `GET /api/analysis/{sessionId}/download?format={format}` - Скачать отчет (форматы: PDF, JSON)
- `POST /api/analysis/upload-file` - Загрузить файл спецификации
- `GET /api/analysis/detect-spec-type?path={path}` - Определить тип спецификации

### WebSocket
- `ws://localhost:8080/ws/analysis` - WebSocket endpoint для реальновременных обновлений
  - Отправьте `{"action": "subscribe", "sessionId": "..."}` для подписки
  - Отправьте `{"action": "unsubscribe", "sessionId": "..."}` для отписки

## Использование

1. **Запустите приложение**:
   ```bash
   java -jar webui/target/webui-1.0-SNAPSHOT.jar
   ```

2. **Откройте браузер**: Перейдите на `http://localhost:8080`

3. **Настройте анализ**:
   - Введите путь или URL OpenAPI/AsyncAPI спецификации, либо загрузите файл
   - Выберите режим анализа (Статический, Активный, Комбинированный, Контракт, Полный)
   - Выберите сканеры для запуска (отметьте нужные)
   - Настройте дополнительные параметры:
     - SSL верификация
     - Аутентификация (заголовки, токены)
     - Криптографический протокол (Standard/GOST)
     - Интенсивность сканирования (Low/Medium/High/Aggressive)
     - Задержка между запросами
     - Тестовые пользователи для BOLA/BFLA тестирования

4. **Запустите анализ**:
   - Нажмите "Запустить анализ"
   - Мониторьте логи в реальном времени в панели логов
   - Просматривайте результаты по мере их появления

5. **Просмотрите результаты**:
   - Вкладка "Сводка" показывает обзорную статистику
   - Вкладка "Статический" показывает находки в спецификации
   - Вкладка "Активный" показывает обнаруженные уязвимости
   - Вкладка "Контракт" показывает результаты валидации
   - Скачайте отчет в нужном формате


## Поддержка Docker

Модуль WebUI может быть исключен из Docker образов используя профиль `skip-frontend`:

```dockerfile
# Сборка без WebUI
RUN mvn clean package -Pskip-frontend -DskipTests

# Или сборка только определенных модулей
RUN mvn clean package -pl core,report,cli -am -DskipTests
```

## Технологический стек

### Backend
- **Spring Boot 4.0.0-RC1** - Полная поддержка Java 25
- **Spring Web MVC** - REST API
- **Spring WebSocket** - Реальновременные обновления
- **Jackson** - JSON сериализация с поддержкой Java 8+ типов
- **SLF4J + Logback** - Логирование
- **Maven** - Управление сборкой

### Frontend
- **React 18.3** - UI библиотека
- **TypeScript 5.5** - Типобезопасность
- **Vite 5.3** - Инструмент сборки
- **Axios** - HTTP клиент
- **WebSocket API** - Реальновременные обновления
- **CSS Modules** - Стилизация компонентов


## Разработка

### Добавление новых функций

**Backend:**
1. Добавьте методы контроллера в `webui.controller`
2. Реализуйте бизнес-логику в `webui.service`
3. Определите модели данных в `webui.model`
4. Обновите документацию на русском языке

**Frontend:**
1. Создайте компоненты в `src/components`
2. Определите типы в `src/types`
3. Добавьте методы API в `src/services/api.ts`


## Решение проблем

### Сборка Frontend не удалась
```bash
# Очистите node_modules и переустановите
cd webui/src/main/frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

### Порт уже используется
Измените порт в `application.properties`:
```properties
server.port=8081
```

Также обновите конфигурацию CORS и WebSocket для нового порта.

### Проблемы с подключением к API
Проверьте, что backend запущен на ожидаемом порту. Frontend проксирует запросы на `http://localhost:8080` по умолчанию (режим разработки).

### WebSocket не подключается
- Убедитесь, что источник разрешен в WebSocketConfig
- Проверьте, что используете правильный протокол (ws:// или wss://)
- Проверьте консоль браузера на наличие ошибок CORS

## Реализованные функции

- ✅ WebSocket поддержка для потоковой передачи логов в реальном времени
- ✅ Экспорт отчетов в PDF/JSON
- ✅ Загрузка файлов спецификаций
- ✅ Определение типа спецификации (OpenAPI/AsyncAPI)
- ✅ Поддержка множественных пользователей для BOLA/BFLA тестирования
- ✅ Детальный прогресс анализа (фаза, эндпоинт, сканер)
- ✅ Настройка интенсивности сканирования