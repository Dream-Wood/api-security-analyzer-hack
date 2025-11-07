package webui.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Обработчик WebSocket для обновлений анализа в реальном времени.
 */
@Component
public class AnalysisWebSocketHandler extends TextWebSocketHandler {
    private static final Logger logger = LoggerFactory.getLogger(AnalysisWebSocketHandler.class);

    // Map of sessionId -> Set of WebSocket sessions subscribed to it
    private final Map<String, CopyOnWriteArraySet<WebSocketSession>> sessionSubscriptions = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;

    public AnalysisWebSocketHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        logger.info("WebSocket connection established: {}", session.getId());
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        try {
            String payload = message.getPayload();
            Map<String, String> data = objectMapper.readValue(payload, Map.class);

            String action = data.get("action");
            String analysisSessionId = data.get("sessionId");

            if ("subscribe".equals(action) && analysisSessionId != null) {
                subscribe(session, analysisSessionId);
                logger.info("WebSocket {} subscribed to analysis session {}", session.getId(), analysisSessionId);
            } else if ("unsubscribe".equals(action) && analysisSessionId != null) {
                unsubscribe(session, analysisSessionId);
                logger.info("WebSocket {} unsubscribed from analysis session {}", session.getId(), analysisSessionId);
            }
        } catch (Exception e) {
            logger.error("Error handling WebSocket message", e);
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        // Remove session from all subscriptions
        sessionSubscriptions.values().forEach(set -> set.remove(session));
        logger.info("WebSocket connection closed: {}", session.getId());
    }

    /**
     * Подписка WebSocket соединения на обновления конкретной сессии анализа.
     */
    private void subscribe(WebSocketSession wsSession, String analysisSessionId) {
        sessionSubscriptions.computeIfAbsent(analysisSessionId, k -> new CopyOnWriteArraySet<>())
                .add(wsSession);
    }

    /**
     * Отписка WebSocket соединения от обновлений конкретной сессии анализа.
     */
    private void unsubscribe(WebSocketSession wsSession, String analysisSessionId) {
        CopyOnWriteArraySet<WebSocketSession> sessions = sessionSubscriptions.get(analysisSessionId);
        if (sessions != null) {
            sessions.remove(wsSession);
            if (sessions.isEmpty()) {
                sessionSubscriptions.remove(analysisSessionId);
            }
        }
    }

    /**
     * Рассылка обновления всем подписчикам конкретной сессии анализа.
     */
    public void broadcastUpdate(String analysisSessionId, Map<String, Object> update) {
        CopyOnWriteArraySet<WebSocketSession> sessions = sessionSubscriptions.get(analysisSessionId);
        if (sessions == null || sessions.isEmpty()) {
            return;
        }

        try {
            String json = objectMapper.writeValueAsString(update);
            TextMessage message = new TextMessage(json);

            for (WebSocketSession session : sessions) {
                if (session.isOpen()) {
                    try {
                        // Synchronize on session to prevent concurrent writes
                        synchronized (session) {
                            session.sendMessage(message);
                        }
                    } catch (IOException e) {
                        logger.error("Error sending WebSocket message to session {}", session.getId(), e);
                        sessions.remove(session);
                    } catch (IllegalStateException e) {
                        // Session is in invalid state for writing, skip it
                        logger.warn("WebSocket session {} is in invalid state, skipping update", session.getId());
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error broadcasting update for analysis session {}", analysisSessionId, e);
        }
    }
}
