package com.apisecurity.analyzer.core.i18n;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Manages the current locale for the application.
 * Thread-safe singleton for global locale management.
 */
public class LocaleManager {
    private static final AtomicReference<Locale> currentLocale = new AtomicReference<>(getDefaultLocale());

    // Supported locales
    public static final Locale LOCALE_EN = Locale.ENGLISH;
    public static final Locale LOCALE_RU = new Locale("ru");

    private LocaleManager() {
        // Private constructor to prevent instantiation
    }

    /**
     * Get the default locale based on system settings.
     * Falls back to English if the system locale is not supported.
     */
    private static Locale getDefaultLocale() {
        Locale systemLocale = Locale.getDefault();
        String language = systemLocale.getLanguage();

        return switch (language) {
            case "ru" -> LOCALE_RU;
            case "en" -> LOCALE_EN;
            default -> LOCALE_EN; // Default to English
        };
    }

    /**
     * Get the current locale.
     */
    public static Locale getCurrentLocale() {
        return currentLocale.get();
    }

    /**
     * Set the current locale.
     *
     * @param locale the locale to set
     */
    public static void setCurrentLocale(Locale locale) {
        if (locale == null) {
            throw new IllegalArgumentException("Locale cannot be null");
        }
        currentLocale.set(locale);
    }

    /**
     * Set the current locale by language code.
     *
     * @param languageCode the language code (e.g., "en", "ru")
     */
    public static void setCurrentLocale(String languageCode) {
        if (languageCode == null || languageCode.isBlank()) {
            throw new IllegalArgumentException("Language code cannot be null or blank");
        }

        Locale locale = switch (languageCode.toLowerCase()) {
            case "en", "english" -> LOCALE_EN;
            case "ru", "russian" -> LOCALE_RU;
            default -> throw new IllegalArgumentException("Unsupported language: " + languageCode);
        };

        setCurrentLocale(locale);
    }

    /**
     * Reset to the default locale.
     */
    public static void resetToDefault() {
        currentLocale.set(getDefaultLocale());
    }

    /**
     * Check if a language is supported.
     *
     * @param languageCode the language code to check
     * @return true if supported, false otherwise
     */
    public static boolean isSupported(String languageCode) {
        if (languageCode == null || languageCode.isBlank()) {
            return false;
        }

        String lower = languageCode.toLowerCase();
        return lower.equals("en") || lower.equals("english") ||
               lower.equals("ru") || lower.equals("russian");
    }
}
