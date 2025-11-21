import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import en from './locales/en.json';
import ru from './locales/ru.json';

// Initialize i18next
i18n
  .use(LanguageDetector) // Detect user language
  .use(initReactI18next) // Pass i18n instance to react-i18next
  .init({
    resources: {
      en: {
        translation: en,
      },
      ru: {
        translation: ru,
      },
    },
    fallbackLng: 'en',
    debug: false,

    // Support for language codes like 'en-US', 'ru-RU'
    load: 'languageOnly', // Use 'en' instead of 'en-US'

    interpolation: {
      escapeValue: false, // React already escapes values
    },

    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],

      // Convert 'ru-RU' to 'ru' automatically
      lookupLocalStorage: 'i18nextLng',
      lookupSessionStorage: 'i18nextLng',
    },

    // Supported languages
    supportedLngs: ['en', 'ru'],

    // Fallback to 'en' if language not found
    nonExplicitSupportedLngs: true,
  });

export default i18n;
