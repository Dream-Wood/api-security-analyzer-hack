package com.apisecurity.analyzer.core.i18n;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for retrieving localized messages from resource bundles.
 * Supports parameterized messages and fallback to keys when translations are missing.
 */
public class MessageService {

    private static final ConcurrentHashMap<String, ResourceBundleCache> bundleCache = new ConcurrentHashMap<>();

    /**
     * Get a localized message from the default bundle.
     *
     * @param key the message key
     * @return the localized message, or the key itself if not found
     */
    public static String getMessage(String key) {
        return getMessage("messages", key);
    }

    /**
     * Get a localized message with parameters from the default bundle.
     *
     * @param key the message key
     * @param params the parameters to format into the message
     * @return the localized and formatted message
     */
    public static String getMessage(String key, Object... params) {
        return getMessage("messages", key, params);
    }

    /**
     * Get a localized message from a specific bundle.
     *
     * @param bundleName the name of the resource bundle
     * @param key the message key
     * @return the localized message, or the key itself if not found
     */
    public static String getMessage(String bundleName, String key) {
        if (key == null || key.isBlank()) {
            return "";
        }

        try {
            ResourceBundle bundle = getBundle(bundleName);
            String message = bundle.getString(key);
            return message != null ? message : key;
        } catch (MissingResourceException e) {
            // Return the key itself if the resource is not found
            return key;
        }
    }

    /**
     * Get a localized message with parameters from a specific bundle.
     *
     * @param bundleName the name of the resource bundle
     * @param key the message key
     * @param params the parameters to format into the message
     * @return the localized and formatted message
     */
    public static String getMessage(String bundleName, String key, Object... params) {
        String message = getMessage(bundleName, key);

        if (params == null || params.length == 0) {
            return message;
        }

        try {
            MessageFormat formatter = new MessageFormat(message, LocaleManager.getCurrentLocale());
            return formatter.format(params);
        } catch (IllegalArgumentException e) {
            // If formatting fails, return the unformatted message
            return message;
        }
    }

    /**
     * Get a resource bundle for the current locale.
     * Uses caching to improve performance.
     *
     * @param bundleName the name of the resource bundle
     * @return the resource bundle
     */
    private static ResourceBundle getBundle(String bundleName) {
        Locale currentLocale = LocaleManager.getCurrentLocale();
        String cacheKey = bundleName + "_" + currentLocale.getLanguage();

        ResourceBundleCache cache = bundleCache.computeIfAbsent(cacheKey, k -> new ResourceBundleCache());

        // Check if we need to reload due to locale change
        if (!currentLocale.equals(cache.locale)) {
            cache.bundle = ResourceBundle.getBundle(bundleName, currentLocale);
            cache.locale = currentLocale;
        }

        return cache.bundle;
    }

    /**
     * Clear the bundle cache.
     * Useful when switching locales or reloading resources.
     */
    public static void clearCache() {
        bundleCache.clear();
    }

    /**
     * Check if a message key exists in the default bundle.
     *
     * @param key the message key
     * @return true if the key exists, false otherwise
     */
    public static boolean hasMessage(String key) {
        return hasMessage("messages", key);
    }

    /**
     * Check if a message key exists in a specific bundle.
     *
     * @param bundleName the name of the resource bundle
     * @param key the message key
     * @return true if the key exists, false otherwise
     */
    public static boolean hasMessage(String bundleName, String key) {
        if (key == null || key.isBlank()) {
            return false;
        }

        try {
            ResourceBundle bundle = getBundle(bundleName);
            return bundle.containsKey(key);
        } catch (MissingResourceException e) {
            return false;
        }
    }

    /**
     * Inner class for caching resource bundles with their locales.
     */
    private static class ResourceBundleCache {
        ResourceBundle bundle;
        Locale locale;
    }
}
