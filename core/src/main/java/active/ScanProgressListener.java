package active;

/**
 * Слушатель прогресса операций активного сканирования.
 * Предоставляет детальную информацию о ходе сканирования, включая эндпоинты и сканеры.
 */
public interface ScanProgressListener {

    /**
     * Вызывается при изменении фазы сканирования.
     *
     * @param phase текущая фаза (например, "authentication", "scanning", "analyzing")
     * @param totalEndpoints общее количество эндпоинтов для сканирования
     * @param totalScanners количество сканеров, которые будут запущены
     */
    void onScanStart(String phase, int totalEndpoints, int totalScanners);

    /**
     * Вызывается при начале сканирования конкретного эндпоинта.
     *
     * @param endpointIndex текущий индекс эндпоинта (начиная с 0)
     * @param totalEndpoints общее количество эндпоинтов
     * @param endpoint сканируемый эндпоинт
     */
    void onEndpointStart(int endpointIndex, int totalEndpoints, String endpoint);

    /**
     * Вызывается при запуске сканера на эндпоинте.
     *
     * @param scannerName имя сканера
     * @param scannerIndex текущий индекс сканера (начиная с 0)
     * @param totalScanners общее количество сканеров для этого эндпоинта
     */
    void onScannerStart(String scannerName, int scannerIndex, int totalScanners);

    /**
     * Вызывается при завершении работы сканера на эндпоинте.
     *
     * @param scannerName имя сканера
     * @param vulnerabilityCount количество найденных уязвимостей
     */
    void onScannerComplete(String scannerName, int vulnerabilityCount);

    /**
     * Вызывается при завершении сканирования эндпоинта.
     *
     * @param endpointIndex текущий индекс эндпоинта
     * @param totalEndpoints общее количество эндпоинтов
     * @param totalVulnerabilities общее количество найденных уязвимостей на данный момент
     */
    void onEndpointComplete(int endpointIndex, int totalEndpoints, int totalVulnerabilities);

    /**
     * Вызывается при завершении всего сканирования.
     *
     * @param totalVulnerabilities общее количество найденных уязвимостей
     * @param durationSeconds общая продолжительность сканирования в секундах
     */
    void onScanComplete(int totalVulnerabilities, long durationSeconds);

    /**
     * Пустая реализация без операций.
     */
    static ScanProgressListener noOp() {
        return new ScanProgressListener() {
            @Override
            public void onScanStart(String phase, int totalEndpoints, int totalScanners) {}

            @Override
            public void onEndpointStart(int endpointIndex, int totalEndpoints, String endpoint) {}

            @Override
            public void onScannerStart(String scannerName, int scannerIndex, int totalScanners) {}

            @Override
            public void onScannerComplete(String scannerName, int vulnerabilityCount) {}

            @Override
            public void onEndpointComplete(int endpointIndex, int totalEndpoints, int totalVulnerabilities) {}

            @Override
            public void onScanComplete(int totalVulnerabilities, long durationSeconds) {}
        };
    }
}
