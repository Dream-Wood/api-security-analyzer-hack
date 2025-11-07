#!/bin/bash
set -e

echo "============================================"
echo "API Security Analyzer - Web UI"
echo "============================================"
echo ""
echo "Starting application..."
echo "Server will be available at http://0.0.0.0:${SERVER_PORT}"
echo ""

# Запуск Spring Boot приложения
exec java $JAVA_OPTS \
    -Dspring.config.location=/app/config/application.properties \
    -Dscanner.plugin.dir=/app/plugins \
    -jar /app/webui.jar "$@"
