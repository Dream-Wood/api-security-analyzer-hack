import React from 'react';
import { useTranslation } from 'react-i18next';

const LanguageSwitcher: React.FC = () => {
  const { i18n, t } = useTranslation();

  // Normalize language code (e.g., "ru-RU" -> "ru")
  const getCurrentLanguage = () => {
    const lang = i18n.language || 'en';
    return lang.split('-')[0]; // Get first part (ru-RU -> ru)
  };

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  const currentLang = getCurrentLanguage();

  return (
    <div className="language-switcher">
      <label htmlFor="language-select">{t('header.language')}: </label>
      <select
        id="language-select"
        value={currentLang}
        onChange={(e) => changeLanguage(e.target.value)}
        className="language-select"
      >
        <option value="en">English</option>
        <option value="ru">Русский</option>
      </select>
    </div>
  );
};

export default LanguageSwitcher;
