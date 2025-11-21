package active.discovery;

import active.discovery.model.Wordlist;
import active.discovery.model.Wordlist.WordlistType;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Менеджер для загрузки и управления словарями из внешних файлов.
 * Загружает словари из директории рядом с исполняемым файлом.
 *
 * <p>Формат файлов словарей:
 * <ul>
 *   <li>Простой текстовый файл: одно слово на строку</li>
 *   <li>Пустые строки игнорируются</li>
 *   <li>Строки начинающиеся с # - комментарии</li>
 * </ul>
 *
 * <p>Пример структуры:
 * <pre>
 * wordlists/
 * ├── versions.txt
 * ├── controllers.txt
 * ├── actions.txt
 * └── common-endpoints.txt
 * </pre>
 */
public final class WordlistManager {
    private static final Logger logger = Logger.getLogger(WordlistManager.class.getName());

    private final Path wordlistDirectory;
    private final Map<String, Wordlist> wordlists;
    private final Map<String, WordlistMetadata> metadata;

    public WordlistManager(String wordlistDirectoryPath) {
        this.wordlistDirectory = Paths.get(wordlistDirectoryPath);
        this.wordlists = new ConcurrentHashMap<>();
        this.metadata = new ConcurrentHashMap<>();

        ensureWordlistDirectory();
    }

    /**
     * Создает директорию для словарей если она не существует.
     */
    private void ensureWordlistDirectory() {
        if (!Files.exists(wordlistDirectory)) {
            try {
                Files.createDirectories(wordlistDirectory);
                logger.info("Created wordlist directory: " + wordlistDirectory);

                // Create default wordlists if directory was just created
                createDefaultWordlists();
            } catch (IOException e) {
                logger.warning("Failed to create wordlist directory: " + e.getMessage());
            }
        }
    }

    /**
     * Создает стандартные словари при первом запуске.
     */
    private void createDefaultWordlists() {
        try {
            // versions.txt
            createWordlistFile("versions.txt", List.of(
                "# API версии",
                "v1", "v2", "v3", "v4", "v5",
                "api", "rest", "graphql",
                "internal", "public", "private",
                "beta", "alpha", "dev", "staging"
            ));

            // controllers.txt
            createWordlistFile("controllers.txt", List.of(
                "# Популярные контроллеры/ресурсы",
                "users", "user", "accounts", "account",
                "auth", "authentication", "login", "logout",
                "admin", "administrator", "management",
                "profile", "settings", "config", "configuration",
                "orders", "order", "products", "product", "items", "item",
                "files", "file", "uploads", "upload", "download", "downloads",
                "internal", "debug", "test", "health", "metrics", "status",
                "dashboard", "reports", "analytics"
            ));

            // actions.txt
            createWordlistFile("actions.txt", List.of(
                "# Действия/операции",
                "create", "update", "delete", "remove",
                "list", "get", "search", "find", "query",
                "activate", "deactivate", "enable", "disable",
                "reset", "verify", "confirm", "validate",
                "import", "export", "sync", "refresh"
            ));

            // common-endpoints.txt
            createWordlistFile("common-endpoints.txt", List.of(
                "# Общие эндпоинты",
                "health", "healthcheck", "ping", "status",
                "version", "info", "about",
                "metrics", "stats", "statistics",
                "admin", "console", "dashboard",
                "debug", "test", "swagger", "docs",
                "graphql", "graphiql"
            ));

            logger.info("Created default wordlists in " + wordlistDirectory);
        } catch (IOException e) {
            logger.warning("Failed to create default wordlists: " + e.getMessage());
        }
    }

    /**
     * Создает файл словаря с содержимым.
     */
    private void createWordlistFile(String filename, List<String> lines) throws IOException {
        Path filePath = wordlistDirectory.resolve(filename);
        if (!Files.exists(filePath)) {
            Files.write(filePath, lines, StandardOpenOption.CREATE_NEW);
        }
    }

    /**
     * Загружает все словари из директории.
     *
     * @return количество загруженных словарей
     */
    public int loadAllWordlists() {
        try {
            if (!Files.exists(wordlistDirectory)) {
                logger.warning("Wordlist directory does not exist: " + wordlistDirectory);
                return 0;
            }

            List<Path> wordlistFiles = Files.list(wordlistDirectory)
                .filter(path -> path.toString().endsWith(".txt"))
                .toList();

            int loaded = 0;
            for (Path file : wordlistFiles) {
                try {
                    loadWordlist(file);
                    loaded++;
                } catch (IOException e) {
                    logger.warning("Failed to load wordlist " + file.getFileName() + ": " + e.getMessage());
                }
            }

            logger.info("Loaded " + loaded + " wordlist(s) from " + wordlistDirectory);
            return loaded;
        } catch (IOException e) {
            logger.severe("Failed to list wordlist directory: " + e.getMessage());
            return 0;
        }
    }

    /**
     * Загружает отдельный словарь из файла.
     *
     * @param filePath путь к файлу словаря
     * @return загруженный словарь
     * @throws IOException при ошибке чтения файла
     */
    public Wordlist loadWordlist(Path filePath) throws IOException {
        String filename = filePath.getFileName().toString();
        String id = filename.replace(".txt", "");

        List<String> words = Files.readAllLines(filePath).stream()
            .map(String::trim)
            .filter(line -> !line.isEmpty() && !line.startsWith("#"))
            .collect(Collectors.toList());

        // Parse metadata from filename or use defaults
        WordlistMetadata meta = parseMetadataFromFilename(filename);

        Wordlist.Builder builder = Wordlist.builder()
            .id(id)
            .name(meta.name)
            .words(words)
            .type(meta.type)
            .priority(meta.priority);

        if (meta.positions != null && !meta.positions.isEmpty()) {
            builder.positions(meta.positions);
        }

        Wordlist wordlist = builder.build();
        wordlists.put(id, wordlist);
        metadata.put(id, meta);

        logger.fine("Loaded wordlist '" + id + "' with " + words.size() + " words");
        return wordlist;
    }

    /**
     * Извлекает метаданные из имени файла.
     * Формат: name.txt или name_priority_positions.txt
     * Например: controllers_high_1-2-3.txt
     */
    private WordlistMetadata parseMetadataFromFilename(String filename) {
        String baseName = filename.replace(".txt", "");
        String[] parts = baseName.split("_");

        WordlistMetadata meta = new WordlistMetadata();
        meta.name = parts[0].replace("-", " ");
        meta.type = inferTypeFromName(parts[0]);
        meta.priority = 50; // default

        if (parts.length > 1) {
            // Parse priority if exists
            if (parts[1].matches("\\d+")) {
                meta.priority = Integer.parseInt(parts[1]);
            } else if ("high".equalsIgnoreCase(parts[1])) {
                meta.priority = 80;
            } else if ("low".equalsIgnoreCase(parts[1])) {
                meta.priority = 20;
            }
        }

        if (parts.length > 2) {
            // Parse positions: "1-2-3" -> [1, 2, 3]
            String[] posStr = parts[2].split("-");
            meta.positions = Arrays.stream(posStr)
                .map(Integer::parseInt)
                .collect(Collectors.toList());
        }

        return meta;
    }

    /**
     * Определяет тип словаря по его имени.
     */
    private WordlistType inferTypeFromName(String name) {
        return switch (name.toLowerCase()) {
            case "versions", "version" -> WordlistType.PATH_SEGMENT;
            case "controllers", "controller", "resources", "resource" -> WordlistType.PATH_SEGMENT;
            case "actions", "action", "operations", "operation" -> WordlistType.PATH_SEGMENT;
            case "params", "parameters", "query" -> WordlistType.QUERY_PARAM;
            case "ids", "identifiers" -> WordlistType.RESOURCE_ID;
            default -> WordlistType.PATH_SEGMENT;
        };
    }

    /**
     * Получает словарь по ID.
     */
    public Optional<Wordlist> getWordlist(String id) {
        return Optional.ofNullable(wordlists.get(id));
    }

    /**
     * Получает все загруженные словари.
     */
    public List<Wordlist> getAllWordlists() {
        return new ArrayList<>(wordlists.values());
    }

    /**
     * Получает словари отсортированные по приоритету (от высокого к низкому).
     */
    public List<Wordlist> getWordlistsByPriority() {
        return wordlists.values().stream()
            .sorted(Comparator.comparingInt(Wordlist::getPriority).reversed())
            .collect(Collectors.toList());
    }

    /**
     * Получает словари применимые для данной позиции в пути.
     *
     * @param position позиция в пути (0-based)
     * @return список применимых словарей
     */
    public List<Wordlist> getWordlistsForPosition(int position) {
        return wordlists.values().stream()
            .filter(wl -> wl.isApplicableForPosition(position))
            .sorted(Comparator.comparingInt(Wordlist::getPriority).reversed())
            .collect(Collectors.toList());
    }

    /**
     * Проверяет существование директории словарей.
     */
    public boolean isWordlistDirectoryExists() {
        return Files.exists(wordlistDirectory);
    }

    /**
     * Получает путь к директории словарей.
     */
    public Path getWordlistDirectory() {
        return wordlistDirectory;
    }

    /**
     * Получает количество загруженных словарей.
     */
    public int getWordlistCount() {
        return wordlists.size();
    }

    /**
     * Перезагружает все словари.
     */
    public void reloadWordlists() {
        wordlists.clear();
        metadata.clear();
        loadAllWordlists();
    }

    /**
     * Внутренний класс для метаданных словаря.
     */
    private static class WordlistMetadata {
        String name;
        WordlistType type;
        int priority;
        List<Integer> positions;
    }
}
