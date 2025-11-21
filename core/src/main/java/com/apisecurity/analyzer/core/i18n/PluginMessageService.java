package com.apisecurity.analyzer.core.i18n;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for retrieving localized messages from plugin-specific resource bundles.
 * Each plugin can have its own localization files in its JAR.
 *
 * Plugins should include .properties files in their resources:
 * - {plugin-name}.properties (fallback)
 * - {plugin-name}_en.properties (English)
 * - {plugin-name}_ru.properties (Russian)
 *
 * Example for BOLA scanner plugin:
 * - bola.properties
 * - bola_en.properties
 * - bola_ru.properties
 */
public class PluginMessageService {

    private static final ConcurrentHashMap<String, ResourceBundleCache> pluginBundleCache = new ConcurrentHashMap<>();

    /**
     * Get a localized message from a plugin's resource bundle.
     *
     * @param pluginBundleName the name of the plugin's resource bundle (e.g., "bola" for BOLA scanner)
     * @param key the message key
     * @return the localized message, or the key itself if not found
     */
    public static String getMessage(String pluginBundleName, String key) {
        if (key == null || key.isBlank()) {
            return "";
        }

        try {
            ResourceBundle bundle = getPluginBundle(pluginBundleName);
            String message = bundle.getString(key);
            return message != null ? message : key;
        } catch (MissingResourceException e) {
            // Return the key itself if the resource is not found
            return key;
        }
    }

    /**
     * Get a localized message from a plugin's resource bundle using a specific ClassLoader.
     * This is useful when loading resources from plugin JARs.
     *
     * @param pluginBundleName the name of the plugin's resource bundle (e.g., "bola" for BOLA scanner)
     * @param key the message key
     * @param classLoader the ClassLoader to use for loading the resource bundle
     * @return the localized message, or the key itself if not found
     */
    public static String getMessage(String pluginBundleName, String key, ClassLoader classLoader) {
        if (key == null || key.isBlank()) {
            return "";
        }

        try {
            ResourceBundle bundle = getPluginBundle(pluginBundleName, classLoader);
            String message = bundle.getString(key);
            return message != null ? message : key;
        } catch (MissingResourceException e) {
            // Return the key itself if the resource is not found
            return key;
        }
    }

    /**
     * Get a localized message with parameters from a plugin's resource bundle.
     *
     * @param pluginBundleName the name of the plugin's resource bundle
     * @param key the message key
     * @param params the parameters to format into the message
     * @return the localized and formatted message
     */
    public static String getMessage(String pluginBundleName, String key, Object... params) {
        String message = getMessage(pluginBundleName, key);

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
     * Get a plugin-specific resource bundle for the current locale.
     * Uses caching to improve performance.
     *
     * The bundle is loaded from the plugin's ClassLoader, allowing hot-swappable plugins
     * to provide their own localization without modifying the core module.
     *
     * @param bundleName the name of the plugin's resource bundle
     * @return the resource bundle
     */
    private static ResourceBundle getPluginBundle(String bundleName) {
        Locale currentLocale = LocaleManager.getCurrentLocale();
        String cacheKey = bundleName + "_" + currentLocale.getLanguage();

        ResourceBundleCache cache = pluginBundleCache.computeIfAbsent(cacheKey, k -> new ResourceBundleCache());

        // Check if we need to reload due to locale change
        if (!currentLocale.equals(cache.locale)) {
            // Load from the current thread's context ClassLoader to support plugin isolation
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            cache.bundle = ResourceBundle.getBundle(bundleName, currentLocale, classLoader);
            cache.locale = currentLocale;
        }

        return cache.bundle;
    }

    /**
     * Get a plugin-specific resource bundle for the current locale using a specific ClassLoader.
     * Uses caching to improve performance.
     *
     * @param bundleName the name of the plugin's resource bundle
     * @param classLoader the ClassLoader to use for loading the resource bundle
     * @return the resource bundle
     */
    private static ResourceBundle getPluginBundle(String bundleName, ClassLoader classLoader) {
        Locale currentLocale = LocaleManager.getCurrentLocale();
        String cacheKey = bundleName + "_" + currentLocale.getLanguage() + "_" + classLoader.hashCode();

        ResourceBundleCache cache = pluginBundleCache.computeIfAbsent(cacheKey, k -> new ResourceBundleCache());

        // Check if we need to reload due to locale change
        if (!currentLocale.equals(cache.locale) || cache.bundle == null) {
            cache.bundle = ResourceBundle.getBundle(bundleName, currentLocale, classLoader);
            cache.locale = currentLocale;
        }

        return cache.bundle;
    }

    /**
     * Clear the plugin bundle cache.
     * Useful when switching locales or reloading plugins.
     */
    public static void clearCache() {
        pluginBundleCache.clear();
    }

    /**
     * Clear cache for a specific plugin.
     * Useful when a plugin is hot-swapped.
     *
     * @param pluginBundleName the name of the plugin's resource bundle
     */
    public static void clearPluginCache(String pluginBundleName) {
        pluginBundleCache.keySet().removeIf(key -> key.startsWith(pluginBundleName + "_"));
    }

    /**
     * Check if a message key exists in a plugin's bundle.
     *
     * @param pluginBundleName the name of the plugin's resource bundle
     * @param key the message key
     * @return true if the key exists, false otherwise
     */
    public static boolean hasMessage(String pluginBundleName, String key) {
        if (key == null || key.isBlank()) {
            return false;
        }

        try {
            ResourceBundle bundle = getPluginBundle(pluginBundleName);
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
