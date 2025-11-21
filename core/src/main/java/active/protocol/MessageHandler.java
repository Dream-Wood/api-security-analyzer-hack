package active.protocol;

/**
 * Callback interface for handling messages received from async protocols.
 * Used primarily for subscribe operations where messages arrive asynchronously.
 */
@FunctionalInterface
public interface MessageHandler {

    /**
     * Handle a received message.
     *
     * @param message the received message
     */
    void onMessage(ProtocolMessage message);

    /**
     * Handle an error during message reception.
     * Default implementation does nothing.
     *
     * @param error the error that occurred
     */
    default void onError(Throwable error) {
        // Default: do nothing
    }

    /**
     * Called when the subscription is completed or closed.
     * Default implementation does nothing.
     */
    default void onComplete() {
        // Default: do nothing
    }
}
