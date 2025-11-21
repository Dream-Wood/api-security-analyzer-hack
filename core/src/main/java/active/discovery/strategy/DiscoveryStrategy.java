package active.discovery.strategy;

import active.discovery.ResponseAnalyzer;
import active.discovery.WordlistManager;
import active.discovery.model.DiscoveryConfig;
import active.discovery.model.DiscoveryResult;
import active.discovery.model.PathNode;
import active.http.HttpClient;
import active.model.AnalysisProgressListener;

import java.util.List;

/**
 * Интерфейс стратегии обнаружения незадокументированных эндпоинтов.
 * Определяет контракт для различных алгоритмов обхода дерева путей.
 */
public interface DiscoveryStrategy {

    /**
     * Выполняет поиск незадокументированных эндпоинтов.
     *
     * @param root корневой узел дерева путей из спецификации
     * @param baseUrl базовый URL API
     * @param httpClient HTTP клиент для запросов
     * @param wordlistManager менеджер словарей
     * @param responseAnalyzer анализатор ответов
     * @param config конфигурация discovery
     * @param progressListener слушатель прогресса
     * @return список обнаруженных незадокументированных эндпоинтов
     */
    List<DiscoveryResult> discover(
        PathNode root,
        String baseUrl,
        HttpClient httpClient,
        WordlistManager wordlistManager,
        ResponseAnalyzer responseAnalyzer,
        DiscoveryConfig config,
        AnalysisProgressListener progressListener
    );

    /**
     * Возвращает имя стратегии.
     */
    String getName();

    /**
     * Возвращает описание стратегии.
     */
    String getDescription();
}
