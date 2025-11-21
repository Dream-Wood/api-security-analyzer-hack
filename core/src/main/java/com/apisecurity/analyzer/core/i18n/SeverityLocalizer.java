package com.apisecurity.analyzer.core.i18n;

import model.Severity;

/**
 * Localizer for Severity enum.
 * Provides localized display names for severity levels.
 */
public class SeverityLocalizer {

    private SeverityLocalizer() {
        // Utility class
    }

    /**
     * Get localized display name for a severity level.
     *
     * @param severity the severity level
     * @return the localized display name
     */
    public static String getLocalizedName(Severity severity) {
        if (severity == null) {
            return "";
        }

        String key = "severity." + severity.name().toLowerCase();
        String localized = MessageService.getMessage(key);

        // Fallback to the original name if translation not found
        return localized.equals(key) ? severity.name() : localized;
    }
}
