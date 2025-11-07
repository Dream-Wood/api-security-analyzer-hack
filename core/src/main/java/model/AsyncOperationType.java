package model;

/**
 * Represents the type of AsyncAPI operation.
 */
public enum AsyncOperationType {
    /**
     * Publish operation - sends messages to a channel.
     */
    PUBLISH("publish"),

    /**
     * Subscribe operation - receives messages from a channel.
     */
    SUBSCRIBE("subscribe");

    private final String value;

    AsyncOperationType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static AsyncOperationType fromString(String value) {
        for (AsyncOperationType type : values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown AsyncOperationType: " + value);
    }
}
