package active.discovery.model;

import java.util.*;

/**
 * Словарь для перебора сегментов путей.
 * Содержит список слов и метаданные о применении.
 */
public final class Wordlist {
    private final String id;
    private final String name;
    private final List<String> words;
    private final WordlistType type;
    private final int priority;
    private final List<Integer> positions;
    private final Map<String, Object> metadata;

    private Wordlist(Builder builder) {
        this.id = Objects.requireNonNull(builder.id, "id cannot be null");
        this.name = builder.name != null ? builder.name : id;
        this.words = Collections.unmodifiableList(new ArrayList<>(builder.words));
        this.type = builder.type != null ? builder.type : WordlistType.PATH_SEGMENT;
        this.priority = builder.priority;
        this.positions = builder.positions != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.positions))
            : Collections.emptyList();
        this.metadata = builder.metadata != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.metadata))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public List<String> getWords() {
        return words;
    }

    public WordlistType getType() {
        return type;
    }

    public int getPriority() {
        return priority;
    }

    public List<Integer> getPositions() {
        return positions;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * Проверяет, применим ли словарь для данной позиции в пути.
     *
     * @param position позиция в пути (0-based)
     * @return true если применим
     */
    public boolean isApplicableForPosition(int position) {
        return positions.isEmpty() || positions.contains(position);
    }

    @Override
    public String toString() {
        return "Wordlist{" +
               "id='" + id + '\'' +
               ", name='" + name + '\'' +
               ", words=" + words.size() +
               ", type=" + type +
               ", priority=" + priority +
               '}';
    }

    /**
     * Тип словаря.
     */
    public enum WordlistType {
        /** Сегменты пути (api, v1, users) */
        PATH_SEGMENT,

        /** Параметры запроса */
        QUERY_PARAM,

        /** ID ресурсов */
        RESOURCE_ID,

        /** Комбинированные паттерны */
        PATTERN
    }

    public static class Builder {
        private String id;
        private String name;
        private List<String> words = new ArrayList<>();
        private WordlistType type;
        private int priority = 50; // default medium priority
        private List<Integer> positions;
        private Map<String, Object> metadata;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder words(List<String> words) {
            this.words = new ArrayList<>(words);
            return this;
        }

        public Builder addWord(String word) {
            this.words.add(word);
            return this;
        }

        public Builder type(WordlistType type) {
            this.type = type;
            return this;
        }

        public Builder priority(int priority) {
            this.priority = priority;
            return this;
        }

        public Builder positions(List<Integer> positions) {
            this.positions = new ArrayList<>(positions);
            return this;
        }

        public Builder addPosition(int position) {
            if (this.positions == null) {
                this.positions = new ArrayList<>();
            }
            this.positions.add(position);
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = new HashMap<>(metadata);
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.put(key, value);
            return this;
        }

        public Wordlist build() {
            return new Wordlist(this);
        }
    }
}
