#!/bin/bash
set -e

# Функция помощи
usage() {
    echo "API Security Analyzer - CLI"
    echo ""
    echo "Usage: docker run [docker-options] api-security-analyzer:cli [analyzer-options] <spec-path>"
    echo ""
    echo "Examples:"
    echo "  # Static analysis"
    echo "  docker run -v \$(pwd)/specs:/specs api-security-analyzer:cli /specs/openapi.yaml"
    echo ""
    echo "  # Active testing"
    echo "  docker run -v \$(pwd)/specs:/specs api-security-analyzer:cli -m active -u https://api.example.com /specs/openapi.yaml"
    echo ""
    echo "  # Full analysis with report"
    echo "  docker run -v \$(pwd)/specs:/specs -v \$(pwd)/reports:/reports \\"
    echo "    api-security-analyzer:cli -m full -u https://api.example.com -f json -o /reports/report.json /specs/openapi.yaml"
    echo ""
}

# Проверка аргументов
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
    exit 0
fi

# Запуск анализатора
exec java $JAVA_OPTS -Dscanner.plugin.dir=/app/plugins -jar /app/cli.jar "$@"
