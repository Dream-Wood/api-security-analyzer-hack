package active.protocol;

/**
 * Base exception for protocol-related errors during AsyncAPI active analysis.
 * This exception is thrown when communication with async protocols (Kafka, MQTT, WebSocket, etc.) fails.
 */
public class ProtocolException extends Exception {

    private final String protocol;
    private final ErrorType errorType;

    public enum ErrorType {
        CONNECTION_FAILED,
        AUTHENTICATION_FAILED,
        TIMEOUT,
        INVALID_MESSAGE,
        SUBSCRIPTION_FAILED,
        PUBLISH_FAILED,
        PROTOCOL_ERROR,
        UNKNOWN
    }

    public ProtocolException(String message) {
        super(message);
        this.protocol = null;
        this.errorType = ErrorType.UNKNOWN;
    }

    public ProtocolException(String message, Throwable cause) {
        super(message, cause);
        this.protocol = null;
        this.errorType = ErrorType.UNKNOWN;
    }

    public ProtocolException(String protocol, ErrorType errorType, String message) {
        super(String.format("[%s] %s: %s", protocol, errorType, message));
        this.protocol = protocol;
        this.errorType = errorType;
    }

    public ProtocolException(String protocol, ErrorType errorType, String message, Throwable cause) {
        super(String.format("[%s] %s: %s", protocol, errorType, message), cause);
        this.protocol = protocol;
        this.errorType = errorType;
    }

    public String getProtocol() {
        return protocol;
    }

    public ErrorType getErrorType() {
        return errorType;
    }
}
