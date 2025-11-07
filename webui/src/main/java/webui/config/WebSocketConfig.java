package webui.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import webui.websocket.AnalysisWebSocketHandler;

/**
 * Конфигурация WebSocket для обновлений анализа в реальном времени.
 */
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final AnalysisWebSocketHandler analysisWebSocketHandler;

    public WebSocketConfig(AnalysisWebSocketHandler analysisWebSocketHandler) {
        this.analysisWebSocketHandler = analysisWebSocketHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(analysisWebSocketHandler, "/ws/analysis")
                .setAllowedOrigins(
                    "http://localhost:3000",
                    "http://localhost:8080",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:8080"
                );
    }
}
