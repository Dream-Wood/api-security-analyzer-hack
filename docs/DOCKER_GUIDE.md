# Docker руководство API Security Analyzer

Полное руководство по использованию Docker с API Security Analyzer.

## 📋 Содержание

- [Обзор](#обзор)
- [Образы Docker](#образы-docker)
- [Быстрый старт](#быстрый-старт)
- [CLI образ](#cli-образ)
- [WebUI образ](#webui-образ)
- [Docker Compose](#docker-compose)
- [Продвинутое использование](#продвинутое-использование)
- [Безопасность](#безопасность)
- [Troubleshooting](#troubleshooting)

## 🎯 Обзор

API Security Analyzer предоставляет два Docker образа:

1. **CLI образ** (`Dockerfile.cli`) - Минимальный образ для командной строки (~400MB)
2. **WebUI образ** (`Dockerfile.webui`) - Полный образ с веб-интерфейсом (~600MB)

Оба образа используют многоступенчатую сборку для оптимизации размера.

## 🐳 Образы Docker

### Архитектура образов

```
CLI Image:
├── Base: eclipse-temurin:25-jre-alpine
├── User: analyzer (non-root)
├── App: /app/cli.jar
├── Plugins: /app/plugins/*.jar
└── Volumes: /specs, /reports, /certs

WebUI Image:
├── Base: eclipse-temurin:25-jre-alpine
├── User: analyzer (non-root)
├── App: /app/webui.jar
├── Frontend: Встроен в static ресурсы
├── Plugins: /app/plugins/*.jar
└── Volumes: /uploads, /reports, /certs
```

## 🚀 Быстрый старт

### Сборка образов

```bash
# Клонирование репозитория
git clone https://github.com/your-org/api-security-analyzer.git
cd api-security-analyzer

# Сборка CLI образа
docker build -f Dockerfile.cli -t api-security-analyzer:cli .

# Сборка WebUI образа
docker build -f Dockerfile.webui -t api-security-analyzer:webui .
```

### Первый запуск

```bash
# CLI - статический анализ
docker run -v $(pwd)/examples:/specs \
  api-security-analyzer:cli /specs/petstore.yaml

# WebUI - запуск веб-интерфейса
docker run -p 8080:8080 api-security-analyzer:webui

# Откройте браузер: http://localhost:8080
```

## 💻 CLI образ

### Базовое использование

#### Статический анализ

```bash
docker run --rm \
  -v $(pwd)/specs:/specs:ro \
  api-security-analyzer:cli \
  -m static \
  /specs/openapi.yaml
```

#### Активное тестирование

```bash
docker run --rm \
  -v $(pwd)/specs:/specs:ro \
  -v $(pwd)/reports:/reports \
  api-security-analyzer:cli \
  -m active \
  -u https://api.example.com \
  -f json \
  -o /reports/report.json \
  /specs/openapi.yaml
```

#### Полный анализ с аутентификацией

```bash
docker run --rm \
  -v $(pwd)/specs:/specs:ro \
  -v $(pwd)/reports:/reports \
  -e API_TOKEN="your-token-here" \
  api-security-analyzer:cli \
  -m full \
  -u https://api.example.com \
  -a "Authorization: Bearer $API_TOKEN" \
  -f pdf \
  -o /reports/security-report.pdf \
  --scan-intensity HIGH \
  /specs/openapi.yaml
```

### Продвинутые опции

#### С GOST криптографией

```bash
docker run --rm \
  -v $(pwd)/specs:/specs:ro \
  -v $(pwd)/certs:/certs:ro \
  -v $(pwd)/reports:/reports \
  api-security-analyzer:cli \
  -m active \
  -u https://api.example.ru \
  -c gost \
  --gost-pfx-path /certs/cert.pfx \
  --gost-pfx-password "password" \
  -o /reports/report.json \
  /specs/openapi.yaml
```

#### Настройка производительности

```bash
docker run --rm \
  -v $(pwd)/specs:/specs:ro \
  -v $(pwd)/reports:/reports \
  -e JAVA_OPTS="-Xms1g -Xmx4g" \
  --cpus="2.0" \
  --memory="4g" \
  api-security-analyzer:cli \
  -m active \
  -u https://api.example.com \
  --max-parallel-scans 8 \
  --request-delay 100 \
  /specs/openapi.yaml
```

#### Анализ нескольких спецификаций

```bash
# Используйте bash цикл
for spec in specs/*.yaml; do
  docker run --rm \
    -v $(pwd)/specs:/specs:ro \
    -v $(pwd)/reports:/reports \
    api-security-analyzer:cli \
    -m static \
    -f json \
    -o /reports/$(basename $spec .yaml)-report.json \
    /specs/$(basename $spec)
done
```

#### С переменными окружения

```bash
# Создайте .env файл
cat > .env <<EOF
API_BASE_URL=https://api.example.com
API_TOKEN=your-token-here
SCAN_INTENSITY=MEDIUM
EOF

# Запуск с env файлом
docker run --rm \
  --env-file .env \
  -v $(pwd)/specs:/specs:ro \
  -v $(pwd)/reports:/reports \
  api-security-analyzer:cli \
  -m active \
  -u $API_BASE_URL \
  -a "Authorization: Bearer $API_TOKEN" \
  --scan-intensity $SCAN_INTENSITY \
  /specs/openapi.yaml
```

### Интеграция в скрипты

```bash
#!/bin/bash
# analyze-api.sh - Скрипт для автоматизации анализа

set -e

SPEC_FILE="${1:-specs/openapi.yaml}"
OUTPUT_DIR="reports/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "🔍 Analyzing: $SPEC_FILE"

# Запуск анализа
docker run --rm \
  -v "$(pwd)/specs:/specs:ro" \
  -v "$(pwd)/$OUTPUT_DIR:/reports" \
  api-security-analyzer:cli \
  -m full \
  -u "${API_BASE_URL}" \
  -a "Authorization: Bearer ${API_TOKEN}" \
  -f json \
  -o /reports/report.json \
  "/specs/$(basename $SPEC_FILE)"

# Проверка результатов
CRITICAL=$(jq '.summary.critical // 0' "$OUTPUT_DIR/report.json")
echo "📊 Critical issues found: $CRITICAL"

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ Analysis failed - critical issues found!"
  exit 1
fi

echo "✅ Analysis completed successfully"
```

## 🌐 WebUI образ

### Базовое использование

#### Запуск веб-интерфейса

```bash
docker run -d \
  --name api-analyzer-webui \
  -p 8080:8080 \
  -v $(pwd)/uploads:/uploads \
  -v $(pwd)/reports:/reports \
  api-security-analyzer:webui

# Доступ: http://localhost:8080
```

#### С кастомным портом

```bash
docker run -d \
  --name api-analyzer-webui \
  -p 9090:8080 \
  -e SERVER_PORT=8080 \
  api-security-analyzer:webui

# Доступ: http://localhost:9090
```

#### С постоянным хранилищем

```bash
# Создание volumes
docker volume create analyzer-uploads
docker volume create analyzer-reports

# Запуск с volumes
docker run -d \
  --name api-analyzer-webui \
  -p 8080:8080 \
  -v analyzer-uploads:/uploads \
  -v analyzer-reports:/reports \
  api-security-analyzer:webui
```

### Продвинутые настройки

#### Настройка JVM параметров

```bash
docker run -d \
  --name api-analyzer-webui \
  -p 8080:8080 \
  -e JAVA_OPTS="-Xms1g -Xmx8g -XX:+UseG1GC" \
  --memory="8g" \
  --cpus="4.0" \
  api-security-analyzer:webui
```

#### С кастомной конфигурацией

```bash
# Создайте кастомный application.properties
cat > application.properties <<EOF
server.port=8080
logging.level.root=DEBUG
spring.servlet.multipart.max-file-size=100MB
EOF

docker run -d \
  --name api-analyzer-webui \
  -p 8080:8080 \
  -v $(pwd)/application.properties:/app/config/application.properties:ro \
  api-security-analyzer:webui
```

#### Reverse Proxy (Nginx)

```nginx
# nginx.conf
upstream analyzer {
    server localhost:8080;
}

server {
    listen 80;
    server_name analyzer.example.com;

    location / {
        proxy_pass http://analyzer;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://analyzer;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

```bash
# Запуск с Nginx
docker run -d --name analyzer api-security-analyzer:webui
docker run -d --name nginx \
  --link analyzer \
  -p 80:80 \
  -v $(pwd)/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine
```

#### С SSL/TLS

```bash
docker run -d \
  --name api-analyzer-webui \
  -p 8443:8443 \
  -e SERVER_PORT=8443 \
  -e SERVER_SSL_ENABLED=true \
  -v $(pwd)/certs/keystore.p12:/app/keystore.p12:ro \
  -e SERVER_SSL_KEY_STORE=/app/keystore.p12 \
  -e SERVER_SSL_KEY_STORE_PASSWORD=changeit \
  api-security-analyzer:webui
```

## 🔧 Docker Compose

### Базовая конфигурация

```yaml
version: '3.8'

services:
  analyzer-webui:
    image: api-security-analyzer:webui
    ports:
      - "8080:8080"
    environment:
      - JAVA_OPTS=-Xms512m -Xmx4g
    volumes:
      - ./uploads:/uploads
      - ./reports:/reports
      - ./specs:/specs:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### С базой данных (для хранения истории)

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: analyzer
      POSTGRES_USER: analyzer
      POSTGRES_PASSWORD: changeit
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U analyzer"]
      interval: 10s
      timeout: 5s
      retries: 5

  analyzer-webui:
    image: api-security-analyzer:webui
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8080:8080"
    environment:
      - SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/analyzer
      - SPRING_DATASOURCE_USERNAME=analyzer
      - SPRING_DATASOURCE_PASSWORD=changeit
    volumes:
      - ./uploads:/uploads
      - ./reports:/reports

volumes:
  postgres-data:
```

### Полный стек с мониторингом

```yaml
version: '3.8'

services:
  analyzer-webui:
    image: api-security-analyzer:webui
    ports:
      - "8080:8080"
    environment:
      - JAVA_OPTS=-Xms1g -Xmx4g
      - MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=*
    volumes:
      - ./uploads:/uploads
      - ./reports:/reports
    networks:
      - analyzer-network
    labels:
      - "prometheus.scrape=true"
      - "prometheus.port=8080"
      - "prometheus.path=/actuator/prometheus"

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    networks:
      - analyzer-network
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - analyzer-network
    depends_on:
      - prometheus

networks:
  analyzer-network:

volumes:
  prometheus-data:
  grafana-data:
```

## 🔐 Безопасность

### Non-root пользователь

Оба образа используют non-root пользователя `analyzer` (UID 1000):

```dockerfile
RUN addgroup -g 1000 analyzer && \
    adduser -D -u 1000 -G analyzer analyzer
USER analyzer
```

### Сканирование образов на уязвимости

```bash
# Используйте Trivy
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image api-security-analyzer:cli

# Используйте Snyk
snyk container test api-security-analyzer:cli
```

### Лучшие практики

1. **Не храните секреты в образах**
```bash
# ❌ Плохо
docker build --build-arg API_TOKEN=secret .

# ✅ Хорошо
docker run -e API_TOKEN=secret image
```

2. **Используйте secrets для чувствительных данных**
```bash
echo "my-secret-token" | docker secret create api_token -
docker service create \
  --secret api_token \
  api-security-analyzer:cli
```

3. **Ограничьте ресурсы**
```bash
docker run \
  --memory="2g" \
  --memory-swap="2g" \
  --cpus="1.0" \
  --pids-limit=100 \
  api-security-analyzer:cli
```

4. **Используйте read-only файловую систему**
```bash
docker run --read-only \
  --tmpfs /tmp \
  -v $(pwd)/specs:/specs:ro \
  -v $(pwd)/reports:/reports \
  api-security-analyzer:cli
```

## 🔧 Продвинутое использование

### Multi-platform сборка

```bash
# Создание buildx builder
docker buildx create --name multiarch --use

# Сборка для multiple платформ
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile.cli \
  -t your-registry/api-analyzer:cli-latest \
  --push \
  .
```

### Оптимизация размера образа

```bash
# Использование dive для анализа слоев
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  wagoodman/dive:latest api-security-analyzer:cli

# Squash слоев (экспериментально)
docker build --squash -f Dockerfile.cli -t api-analyzer:cli-squashed .
```

### Кэширование для ускорения сборки

```bash
# Используйте BuildKit кэш
export DOCKER_BUILDKIT=1

docker build \
  --cache-from api-security-analyzer:cli-latest \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  -f Dockerfile.cli \
  -t api-security-analyzer:cli-latest \
  .
```

### Интеграция с CI/CD

См. [CICD_INTEGRATION.md](CICD_INTEGRATION.md) для детальных примеров.

## 🐛 Troubleshooting

### Коды возврата CLI

CLI анализатор возвращает следующие exit codes:

- **0** - ✅ Успех, нет критичных проблем
- **3** - ⚠️ Найдены критичные/высокой важности проблемы
- **1** - ❌ Ошибка конфигурации
- **99** - 💥 Непредвиденная ошибка

Используйте эти коды для проверки результатов:

```bash
docker run -v $(pwd)/specs:/specs api-security-analyzer:cli /specs/api.yaml
EXIT_CODE=$?

if [ $EXIT_CODE -eq 3 ]; then
  echo "Критичные уязвимости найдены!"
  exit 1
fi
```

### Проблема: Контейнер не запускается

```bash
# Проверка логов
docker logs api-analyzer-webui

# Интерактивный режим для отладки
docker run -it --entrypoint /bin/bash api-security-analyzer:cli
```

### Проблема: Permission denied при записи отчетов

```bash
# Проверьте права на директории
ls -la reports/

# Измените владельца (UID 1000 = analyzer user)
sudo chown -R 1000:1000 reports/

# Или используйте tmpfs
docker run -v tmpfs:/reports:uid=1000 ...
```

### Проблема: Out of memory

```bash
# Увеличьте лимит памяти
docker run --memory="8g" ...

# Настройте JVM heap
docker run -e JAVA_OPTS="-Xms2g -Xmx6g" ...
```

### Проблема: WebSocket соединение не работает

```bash
# Проверьте, что порт проброшен
docker port api-analyzer-webui

# Проверьте CORS настройки
docker logs api-analyzer-webui | grep CORS

# Используйте правильный URL для WebSocket
ws://localhost:8080/ws/analysis  # не wss:// для локального тестирования
```

### Проблема: Медленная сборка

```bash
# Используйте .dockerignore
# Убедитесь, что target/ и node_modules/ исключены

# Проверьте размер контекста сборки
docker build --no-cache --progress=plain -f Dockerfile.cli . 2>&1 | grep "transferring context"

# Используйте многоступенчатую сборку с кэшированием
# (уже реализовано в Dockerfile.cli и Dockerfile.webui)
```

### Отладка сетевых проблем

```bash
# Войдите в контейнер
docker exec -it api-analyzer-webui /bin/sh

# Проверьте сетевое соединение
apk add --no-cache curl
curl -v https://api.example.com

# Проверьте DNS
nslookup api.example.com

# Проверьте сертификаты
openssl s_client -connect api.example.com:443
```

## 📊 Мониторинг

### Health checks

```bash
# CLI образ
docker run --health-cmd="ps aux | grep -q '[j]ava' || exit 1" ...

# WebUI образ
docker run --health-cmd="curl -f http://localhost:8080/actuator/health || exit 1" ...
```

### Метрики и логи

```bash
# Просмотр логов в реальном времени
docker logs -f api-analyzer-webui

# Экспорт метрик (WebUI)
curl http://localhost:8080/actuator/metrics

# Использование cAdvisor
docker run -d \
  --name=cadvisor \
  -p 8081:8080 \
  -v /:/rootfs:ro \
  -v /var/run:/var/run:ro \
  -v /sys:/sys:ro \
  -v /var/lib/docker/:/var/lib/docker:ro \
  gcr.io/cadvisor/cadvisor:latest
```

## 🔄 Обновление образов

```bash
# Pull последней версии
docker pull api-security-analyzer:cli-latest
docker pull api-security-analyzer:webui-latest

# Остановка и удаление старого контейнера
docker stop api-analyzer-webui
docker rm api-analyzer-webui

# Запуск нового контейнера
docker run -d --name api-analyzer-webui api-security-analyzer:webui-latest

# Или используйте docker-compose
docker-compose pull
docker-compose up -d
```

## 📚 Дополнительные ресурсы

- [Официальная документация Docker](https://docs.docker.com/)
- [Best practices для Dockerfile](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Docker security](https://docs.docker.com/engine/security/)
- [CI/CD интеграция](CICD_INTEGRATION.md)

---

**Примечание:** Примеры в этом руководстве используют `$(pwd)` для Linux/macOS. Для Windows PowerShell используйте `${PWD}`, для Windows CMD используйте `%cd%`.
