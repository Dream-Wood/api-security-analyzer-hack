package webui.util;

import active.model.VulnerabilityReport;
import active.scanner.ScanResult;
import com.apisecurity.analyzer.core.i18n.LocaleManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Утилита для локализации всего AnalysisReport.
 * Рекурсивно проходит по структуре отчета и локализует все VulnerabilityReport объекты.
 */
public class ReportLocalizer {
    private static final Logger logger = LoggerFactory.getLogger(ReportLocalizer.class);
    private static final ObjectMapper objectMapper;

    static {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    private ReportLocalizer() {
        // Utility class
    }

    /**
     * Локализовать отчет представленный как Map или любой объект.
     * Рекурсивно находит все VulnerabilityReport объекты и заменяет их локализованными версиями.
     *
     * @param report оригинальный отчет (Map, AnalysisReport или другой объект)
     * @return локализованная копия отчета как Map
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> localizeReport(Object report) {
        if (report == null) {
            return Collections.emptyMap();
        }

        // Если это уже Map, обрабатываем напрямую
        if (report instanceof Map) {
            return localizeMap((Map<String, Object>) report);
        }

        // Иначе конвертируем объект в Map через Jackson
        try {
            Map<String, Object> reportMap = objectMapper.convertValue(report, Map.class);
            return localizeMap(reportMap);
        } catch (Exception e) {
            logger.error("Failed to convert report to Map: {}", e.getMessage(), e);
            return Collections.emptyMap();
        }
    }

    /**
     * Локализовать Map-представление отчета.
     */
    private static Map<String, Object> localizeMap(Map<String, Object> reportMap) {
        Map<String, Object> localized = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : reportMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Рекурсивно обрабатываем вложенные структуры
            if (value instanceof Map) {
                localized.put(key, localizeReport(value));
            } else if (value instanceof List) {
                localized.put(key, localizeList((List<?>) value));
            } else {
                localized.put(key, value);
            }
        }

        return localized;
    }

    /**
     * Локализовать список объектов.
     */
    @SuppressWarnings("unchecked")
    private static List<Object> localizeList(List<?> list) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }

        return list.stream()
            .map(item -> {
                if (item instanceof Map) {
                    Map<String, Object> itemMap = (Map<String, Object>) item;

                    // Проверяем является ли это VulnerabilityReport
                    // (имеет поля type, title, description)
                    if (isVulnerabilityReport(itemMap)) {
                        return localizeVulnerability(itemMap);
                    }

                    // Рекурсивно обрабатываем вложенные Maps
                    return localizeReport(item);
                } else if (item instanceof List) {
                    return localizeList((List<?>) item);
                } else {
                    return item;
                }
            })
            .collect(Collectors.toList());
    }

    /**
     * Проверить является ли Map представлением VulnerabilityReport.
     */
    private static boolean isVulnerabilityReport(Map<String, Object> map) {
        return map.containsKey("type") &&
               map.containsKey("severity") &&
               map.containsKey("title") &&
               map.containsKey("description");
    }

    /**
     * Локализовать VulnerabilityReport представленный как Map.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> localizeVulnerability(Map<String, Object> vuln) {
        Map<String, Object> localized = new LinkedHashMap<>(vuln);

        try {
            String type = (String) vuln.get("type");
            if (type != null) {
                String typeKey = "vulnerability." + type.toLowerCase() + ".";

                // Локализуем title
                String titleKey = typeKey + "title";
                String localizedTitle = com.apisecurity.analyzer.core.i18n.MessageService.getMessage(
                    "vulnerabilities", titleKey
                );
                if (!localizedTitle.equals(titleKey)) {
                    localized.put("title", localizedTitle);
                }

                // Локализуем description
                String descKey = typeKey + "description";
                String localizedDesc = com.apisecurity.analyzer.core.i18n.MessageService.getMessage(
                    "vulnerabilities", descKey
                );
                if (!localizedDesc.equals(descKey)) {
                    localized.put("description", localizedDesc);
                }

                // Локализуем recommendations
                List<String> localizedRecs = new ArrayList<>();
                for (int i = 1; i <= 10; i++) {
                    String recKey = typeKey + "recommendation" + i;
                    String localizedRec = com.apisecurity.analyzer.core.i18n.MessageService.getMessage(
                        "vulnerabilities", recKey
                    );

                    // Если ключ не найден, прекращаем
                    if (localizedRec.equals(recKey)) {
                        break;
                    }

                    localizedRecs.add(localizedRec);
                }

                if (!localizedRecs.isEmpty()) {
                    localized.put("recommendations", localizedRecs);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to localize vulnerability: {}", e.getMessage());
        }

        return localized;
    }
}
