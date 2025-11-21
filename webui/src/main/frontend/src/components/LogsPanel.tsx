import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LogEntry } from '../types';
import './LogsPanel.css';

interface LogsPanelProps {
  logs: LogEntry[];
  autoScroll?: boolean;
  autoCollapse?: boolean; // Auto-collapse when results are available
}

export const LogsPanel: React.FC<LogsPanelProps> = ({ logs, autoScroll = true, autoCollapse = false }) => {
  const { t } = useTranslation();
  const logsEndRef = useRef<HTMLDivElement>(null);
  const [isCollapsed, setIsCollapsed] = useState(false);

  // Auto-collapse when autoCollapse prop is true
  useEffect(() => {
    if (autoCollapse && !isCollapsed) {
      setIsCollapsed(true);
    }
  }, [autoCollapse]);

  useEffect(() => {
    if (autoScroll && logsEndRef.current && !isCollapsed) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll, isCollapsed]);

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour12: false });
  };

  const getLogLevelClass = (level: string): string => {
    return `log-level-${level.toLowerCase()}`;
  };

  return (
    <div className={`logs-panel ${isCollapsed ? 'collapsed' : ''}`}>
      <div className="logs-header" onClick={() => setIsCollapsed(!isCollapsed)}>
        <div className="logs-header-left">
          <h3>{t('logs.title')}</h3>
          <span className="logs-count">{logs.length} {t('logs.entries')}</span>
        </div>
        <button
          className="collapse-button"
          type="button"
          title={isCollapsed ? t('logs.expandLogs') : t('logs.collapseLogs')}
        >
          {isCollapsed ? '▼' : '▲'}
        </button>
      </div>
      {!isCollapsed && (
        <div className="logs-content">
          {logs.length === 0 ? (
            <div className="logs-empty">{t('logs.noLogs')}</div>
          ) : (
            logs.map((log, index) => (
              <div key={index} className={`log-entry ${getLogLevelClass(log.level)}`}>
                <span className="log-timestamp">{formatTimestamp(log.timestamp)}</span>
                <span className="log-level">{log.level}</span>
                <span className="log-message">{log.message}</span>
              </div>
            ))
          )}
          <div ref={logsEndRef} />
        </div>
      )}
    </div>
  );
};
