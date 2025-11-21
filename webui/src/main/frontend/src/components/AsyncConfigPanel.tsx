import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../services/api';
import type { AsyncApiInfo, AsyncAnalysisRequest, ScanIntensity, ProtocolProperty } from '../types';
import './ConfigurationPanel.css';

interface AsyncConfigPanelProps {
  onStartAnalysis: (request: AsyncAnalysisRequest) => void;
  onSpecTypeDetected: (type: 'openapi' | 'asyncapi' | 'unknown') => void;
  onSpecLocationChange: (location: string) => void;
  specLocation: string;
  isAnalyzing: boolean;
}

export const AsyncConfigPanel: React.FC<AsyncConfigPanelProps> = ({
  onStartAnalysis,
  onSpecTypeDetected,
  onSpecLocationChange,
  specLocation,
  isAnalyzing
}) => {
  const { t } = useTranslation();

  // Form state - specLocation is now controlled by parent
  const [mode, setMode] = useState<'static' | 'active' | 'both'>('static');
  const [asyncApiInfo, setAsyncApiInfo] = useState<AsyncApiInfo | null>(null);
  const [selectedServer, setSelectedServer] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Spec type display (like ConfigurationPanel)
  const [specTypeMessage, setSpecTypeMessage] = useState<string>('');

  // Track last detected path to avoid re-detection of same spec
  const [lastDetectedPath, setLastDetectedPath] = useState<string>('');

  // Credentials (username, password, apiKey, etc.)
  const [credentials, setCredentials] = useState<ProtocolProperty[]>([]);

  // Protocol properties (protocol-specific configs)
  const [protocolProperties, setProtocolProperties] = useState<ProtocolProperty[]>([]);

  // SSL properties
  const [sslProperties, setSslProperties] = useState<ProtocolProperty[]>([]);
  const [enableSsl, setEnableSsl] = useState(false);

  // Scanner selection
  const [selectedScanners, setSelectedScanners] = useState<Set<string>>(new Set());

  // Scan settings
  const [scanIntensity, setScanIntensity] = useState<ScanIntensity>('medium');
  const [maxParallelScans, setMaxParallelScans] = useState<number>(4);
  const [requestDelayMs, setRequestDelayMs] = useState<number | ''>('');

  // Server ping status
  const [serverPingStatus, setServerPingStatus] = useState<Record<string, {
    loading: boolean;
    available?: boolean;
    latencyMs?: number;
    statusCode?: number;
    error?: string;
  }>>({});

  // Auto-detect spec type when specLocation changes (with debounce for URLs)
  useEffect(() => {
    // Skip if same path was already detected or if loading
    if (!specLocation || specLocation === lastDetectedPath || loading) {
      return;
    }

    // Reset state when specLocation changes to a new value
    if (specLocation !== lastDetectedPath && asyncApiInfo) {
      setAsyncApiInfo(null);
      setSpecTypeMessage('');
    }

    // For URLs, use debounce; for file paths from parent, detect immediately
    const isUrl = specLocation.startsWith('http://') || specLocation.startsWith('https://');
    const delay = isUrl ? 500 : 0;

    const timer = setTimeout(() => {
      detectAndLoadSpec(specLocation);
    }, delay);

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [specLocation]);

  // Detect spec type and load appropriate info
  const detectAndLoadSpec = async (path: string) => {
    if (!path || path.trim() === '') {
      setAsyncApiInfo(null);
      setSpecTypeMessage('');
      onSpecTypeDetected('unknown');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // First, detect spec type
      const typeResult = await api.detectSpecType(path);

      // Track this path as detected
      setLastDetectedPath(path);

      if (typeResult.type === 'openapi') {
        // Switch back to OpenAPI panel
        setSpecTypeMessage('');
        onSpecTypeDetected('openapi');
        setLoading(false);
        return;
      } else if (typeResult.type === 'asyncapi') {
        // Load AsyncAPI info
        const info = await api.getAsyncApiInfo(path);
        setAsyncApiInfo(info);
        onSpecTypeDetected('asyncapi');

        // Set spec type message with version info
        const versionInfo = typeResult.version ? ` ${typeResult.version}` : '';
        const displayName = typeResult.displayName || 'AsyncAPI';
        setSpecTypeMessage(`${displayName}${versionInfo} ${t('configuration.asyncAPIDetected')}`);

        // Auto-select first server if available
        if (info.servers.length > 0) {
          setSelectedServer(info.servers[0].name);
        }

        // Enable all scanners by default
        setSelectedScanners(new Set(info.asyncScanners
          .filter(s => s.enabledByDefault)
          .map(s => s.id)));

        // Ping all servers to show availability
        pingAllServers(info);
      } else {
        setError(typeResult.error || 'Unknown specification type');
        setAsyncApiInfo(null);
        setSpecTypeMessage('');
        onSpecTypeDetected('unknown');
      }
    } catch (err: any) {
      console.error('Error detecting/loading spec:', err);
      setError(err.response?.data?.message || 'Failed to load specification');
      setAsyncApiInfo(null);
      setSpecTypeMessage('');
      onSpecTypeDetected('unknown');
    } finally {
      setLoading(false);
    }
  };

  // Ping all servers when asyncApiInfo changes
  const pingAllServers = async (info: AsyncApiInfo) => {
    if (!info.servers || info.servers.length === 0) {
      return;
    }

    // Mark all as loading
    const loadingStatus: Record<string, any> = {};
    info.servers.forEach(server => {
      loadingStatus[server.name] = { loading: true };
    });
    setServerPingStatus(loadingStatus);

    // Ping each server
    for (const server of info.servers) {
      // Build full URL for ping
      let pingUrl = server.url;
      // Add protocol if missing
      if (!pingUrl.startsWith('http://') && !pingUrl.startsWith('https://')) {
        // For AMQP, Kafka, etc., we can't ping directly - use HTTP health endpoint if available
        // or just mark as unable to ping
        if (['kafka', 'amqp', 'mqtt', 'nats', 'redis', 'jms'].includes(server.protocol.toLowerCase())) {
          setServerPingStatus(prev => ({
            ...prev,
            [server.name]: {
              loading: false,
              available: undefined,
              error: `${server.protocol.toUpperCase()} - use broker tools to check`
            }
          }));
          continue;
        }
        // For WebSocket, convert ws:// to http://
        if (server.protocol.toLowerCase() === 'ws') {
          pingUrl = 'http://' + server.url;
        } else if (server.protocol.toLowerCase() === 'wss') {
          pingUrl = 'https://' + server.url;
        } else {
          pingUrl = 'http://' + server.url;
        }
      }

      try {
        const result = await api.pingServer(pingUrl);
        setServerPingStatus(prev => ({
          ...prev,
          [server.name]: {
            loading: false,
            available: result.available,
            latencyMs: result.latencyMs,
            statusCode: result.statusCode,
            error: result.error
          }
        }));
      } catch (err: any) {
        setServerPingStatus(prev => ({
          ...prev,
          [server.name]: {
            loading: false,
            available: false,
            error: err.message || 'Failed to ping'
          }
        }));
      }
    }
  };

  // Helper functions (same as ConfigurationPanel)
  const needsScanner = (analysisMode: string): boolean => {
    return analysisMode !== 'static';
  };

  const needsActiveSettings = (analysisMode: string): boolean => {
    return analysisMode !== 'static';
  };

  const handleFileUpload = async () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.yaml,.yml,.json';
    input.onchange = async (e) => {
      const target = e.target as HTMLInputElement;
      if (target.files && target.files[0]) {
        const file = target.files[0];

        try {
          const result = await api.uploadFile(file);

          if (result.error) {
            alert(`${t('configuration.uploadError')}: ${result.error}`);
            return;
          }

          onSpecLocationChange(result.path);
          detectAndLoadSpec(result.path);
        } catch (err) {
          console.error('Upload error:', err);
          alert(t('configuration.uploadErrorRetry'));
        }
      }
    };
    input.click();
  };

  // Credentials management
  const handleAddCredential = () => {
    setCredentials([...credentials, { key: '', value: '' }]);
  };

  const handleRemoveCredential = (index: number) => {
    setCredentials(credentials.filter((_, i) => i !== index));
  };

  const handleUpdateCredential = (index: number, field: 'key' | 'value', value: string) => {
    const updated = [...credentials];
    updated[index][field] = value;
    setCredentials(updated);
  };

  // Protocol properties management
  const handleAddProperty = () => {
    setProtocolProperties([...protocolProperties, { key: '', value: '' }]);
  };

  const handleRemoveProperty = (index: number) => {
    setProtocolProperties(protocolProperties.filter((_, i) => i !== index));
  };

  const handleUpdateProperty = (index: number, field: 'key' | 'value', value: string) => {
    const updated = [...protocolProperties];
    updated[index][field] = value;
    setProtocolProperties(updated);
  };

  // SSL properties management
  const handleAddSslProperty = () => {
    setSslProperties([...sslProperties, { key: '', value: '' }]);
  };

  const handleRemoveSslProperty = (index: number) => {
    setSslProperties(sslProperties.filter((_, i) => i !== index));
  };

  const handleUpdateSslProperty = (index: number, field: 'key' | 'value', value: string) => {
    const updated = [...sslProperties];
    updated[index][field] = value;
    setSslProperties(updated);
  };

  const handleScannerToggle = (scannerId: string) => {
    setSelectedScanners(prev => {
      const next = new Set(prev);
      if (next.has(scannerId)) {
        next.delete(scannerId);
      } else {
        next.add(scannerId);
      }
      return next;
    });
  };

  const handleSelectAllScanners = () => {
    if (asyncApiInfo) {
      setSelectedScanners(new Set(asyncApiInfo.asyncScanners.map(s => s.id)));
    }
  };

  const handleDeselectAllScanners = () => {
    setSelectedScanners(new Set());
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    // For static mode, server selection is optional
    if (mode !== 'static' && !selectedServer) {
      alert(t('asyncapi.selectServerRequired') || 'Please select a server');
      return;
    }

    // Convert arrays to objects
    const credentialsObj: Record<string, string> = {};
    credentials.forEach(c => {
      if (c.key && c.value) {
        credentialsObj[c.key] = c.value;
      }
    });

    const propertiesObj: Record<string, string> = {};
    protocolProperties.forEach(p => {
      if (p.key && p.value) {
        propertiesObj[p.key] = p.value;
      }
    });

    const sslPropertiesObj: Record<string, string> = {};
    sslProperties.forEach(p => {
      if (p.key && p.value) {
        sslPropertiesObj[p.key] = p.value;
      }
    });

    const request: AsyncAnalysisRequest = {
      specLocation,
      mode,
      selectedServer: selectedServer || (asyncApiInfo?.servers[0]?.name || ''),
      credentials: credentialsObj,
      protocolProperties: propertiesObj,
      sslProperties: sslPropertiesObj,
      enableSsl,
      scanIntensity: needsActiveSettings(mode) ? scanIntensity : undefined,
      maxParallelScans,
      requestDelayMs: needsActiveSettings(mode) && requestDelayMs !== '' ? requestDelayMs : undefined,
      enabledScanners: needsScanner(mode) ? Array.from(selectedScanners) : undefined
    };

    onStartAnalysis(request);
  };

  const selectedServerInfo = asyncApiInfo?.servers.find(s => s.name === selectedServer);
  const scanners = asyncApiInfo?.asyncScanners || [];

  return (
    <div className="configuration-panel">
      <h2>{t('configuration.title')}</h2>

      <form onSubmit={handleSubmit}>
        {/* Basic Configuration */}
        <div className="config-section">
          <h3>{t('configuration.basicSettings')}</h3>

          <div className="form-group">
            <label>{t('configuration.specFileLabel')} *</label>
            <div className="input-with-button">
              <input
                type="text"
                value={specLocation}
                onChange={(e) => {
                  onSpecLocationChange(e.target.value);
                }}
                onBlur={() => detectAndLoadSpec(specLocation)}
                placeholder={t('configuration.specFilePlaceholder')}
                required
                disabled={isAnalyzing}
              />
              <button
                type="button"
                className="file-picker-button"
                onClick={handleFileUpload}
                disabled={isAnalyzing}
                title={t('configuration.uploadButton')}
              >
                ⬆️
              </button>
            </div>
            <small>
              {t('configuration.specFileHint')}
            </small>
            {specTypeMessage && (
              <div style={{
                padding: '8px 12px',
                backgroundColor: '#d1fae5',
                color: '#065f46',
                borderRadius: '4px',
                fontSize: '0.875rem',
                marginTop: '8px',
                border: '1px solid #6ee7b7'
              }}>
                ✓ {specTypeMessage}
              </div>
            )}
            {/* Protocol badges */}
            {asyncApiInfo && asyncApiInfo.availableProtocols && asyncApiInfo.availableProtocols.length > 0 && (
              <div style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: '8px',
                marginTop: '12px',
                padding: '12px',
                backgroundColor: '#f8fafc',
                borderRadius: '8px',
                border: '1px solid #e2e8f0'
              }}>
                <span style={{ fontSize: '0.8rem', color: '#64748b', marginRight: '4px', alignSelf: 'center' }}>
                  {t('asyncapi.availableProtocols') || 'Protocols:'}
                </span>
                {asyncApiInfo.availableProtocols.map(protocol => {
                  const protocolColors: Record<string, { bg: string; text: string; border: string }> = {
                    kafka: { bg: '#fef3c7', text: '#92400e', border: '#fbbf24' },
                    mqtt: { bg: '#f3e8ff', text: '#6b21a8', border: '#c084fc' },
                    amqp: { bg: '#dbeafe', text: '#1e40af', border: '#60a5fa' },
                    ws: { bg: '#d1fae5', text: '#065f46', border: '#34d399' },
                    wss: { bg: '#d1fae5', text: '#065f46', border: '#34d399' },
                    nats: { bg: '#fee2e2', text: '#991b1b', border: '#f87171' },
                    redis: { bg: '#fce7f3', text: '#9d174d', border: '#f472b6' },
                    http: { bg: '#e0e7ff', text: '#3730a3', border: '#818cf8' },
                    https: { bg: '#e0e7ff', text: '#3730a3', border: '#818cf8' },
                    jms: { bg: '#fed7aa', text: '#c2410c', border: '#fb923c' },
                    stomp: { bg: '#fef08a', text: '#854d0e', border: '#facc15' }
                  };
                  const colors = protocolColors[protocol.toLowerCase()] || { bg: '#f1f5f9', text: '#475569', border: '#94a3b8' };
                  return (
                    <span
                      key={protocol}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        padding: '4px 12px',
                        backgroundColor: colors.bg,
                        color: colors.text,
                        border: `1px solid ${colors.border}`,
                        borderRadius: '20px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        letterSpacing: '0.5px'
                      }}
                    >
                      {protocol}
                    </span>
                  );
                })}
              </div>
            )}
            {error && (
              <div style={{
                padding: '8px 12px',
                backgroundColor: '#fee2e2',
                color: '#991b1b',
                borderRadius: '4px',
                fontSize: '0.875rem',
                marginTop: '8px',
                border: '1px solid #fca5a5'
              }}>
                ❌ {error}
              </div>
            )}
          </div>

          {/* Server selection - only for active modes */}
          {asyncApiInfo && asyncApiInfo.servers.length > 0 && (
            <div className="form-group">
              <label>{t('asyncapi.selectServer')} {needsActiveSettings(mode) && '*'}</label>
              <div className="input-with-status">
                <select
                  value={selectedServer}
                  onChange={(e) => setSelectedServer(e.target.value)}
                  disabled={isAnalyzing}
                  required={needsActiveSettings(mode)}
                  style={{ flex: 1 }}
                >
                  {asyncApiInfo.servers.map(server => {
                    const pingStatus = serverPingStatus[server.name];
                    const statusIndicator = pingStatus?.loading
                      ? '⏳'
                      : pingStatus?.available === true
                        ? `✅ ${pingStatus.latencyMs}ms`
                        : pingStatus?.available === false
                          ? '❌'
                          : pingStatus?.error
                            ? '⚠️'
                            : '';
                    return (
                      <option key={server.name} value={server.name}>
                        {statusIndicator} {server.name} ({server.protocol}://{server.url})
                      </option>
                    );
                  })}
                </select>
                {/* Ping status indicator for selected server */}
                {selectedServer && serverPingStatus[selectedServer] && (
                  <>
                    {serverPingStatus[selectedServer].loading && (
                      <span className="ping-status loading">⏳</span>
                    )}
                    {!serverPingStatus[selectedServer].loading && serverPingStatus[selectedServer].available === true && (
                      <span className="ping-status available" title={`Server available - ${serverPingStatus[selectedServer].latencyMs}ms`}>
                        ✅ {serverPingStatus[selectedServer].latencyMs}ms
                      </span>
                    )}
                    {!serverPingStatus[selectedServer].loading && serverPingStatus[selectedServer].available === false && (
                      <span className="ping-status unavailable" title={serverPingStatus[selectedServer].error || 'Server unavailable'}>
                        ❌
                      </span>
                    )}
                    {!serverPingStatus[selectedServer].loading && serverPingStatus[selectedServer].available === undefined && serverPingStatus[selectedServer].error && (
                      <span className="ping-status" style={{ backgroundColor: '#fef3c7', color: '#92400e', border: '1px solid #fbbf24' }} title={serverPingStatus[selectedServer].error}>
                        ⚠️
                      </span>
                    )}
                  </>
                )}
              </div>
              {selectedServerInfo && (
                <small>
                  Protocol: {selectedServerInfo.protocol} {selectedServerInfo.protocolVersion}
                  {selectedServerInfo.description && ` - ${selectedServerInfo.description}`}
                </small>
              )}
              {/* Show ping error message if server is unavailable */}
              {selectedServer && serverPingStatus[selectedServer]?.available === false && serverPingStatus[selectedServer]?.error && (
                <div style={{
                  padding: '6px 10px',
                  backgroundColor: '#fee2e2',
                  color: '#991b1b',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                  marginTop: '4px',
                  border: '1px solid #fca5a5'
                }}>
                  ⚠️ {serverPingStatus[selectedServer].error}
                </div>
              )}
              {/* Show warning for non-HTTP protocols */}
              {selectedServer && serverPingStatus[selectedServer]?.available === undefined && serverPingStatus[selectedServer]?.error && (
                <div style={{
                  padding: '6px 10px',
                  backgroundColor: '#fef3c7',
                  color: '#92400e',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                  marginTop: '4px',
                  border: '1px solid #fbbf24'
                }}>
                  ℹ️ {serverPingStatus[selectedServer].error}
                </div>
              )}
            </div>
          )}

          {/* Analysis mode */}
          {asyncApiInfo && (
            <div className="form-group">
              <label>{t('configuration.mode')} *</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as 'static' | 'active' | 'both')}
                disabled={isAnalyzing}
                required
              >
                <option value="static">{t('configuration.modeStatic')}</option>
                <option value="active">{t('configuration.modeActive')}</option>
                <option value="both">{t('configuration.modeBoth')}</option>
              </select>
            </div>
          )}
        </div>

        {/* Advanced Configuration - only for active modes */}
        {asyncApiInfo && needsActiveSettings(mode) && (
          <div className="config-section">
            <h3>{t('configuration.advancedSettings')}</h3>

            {/* Credentials */}
            <div className="form-group">
              <label>{t('asyncapi.credentials')}</label>
              <div style={{ marginTop: '8px' }}>
                {credentials.map((cred, index) => (
                  <div key={index} style={{
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                    padding: '12px',
                    marginBottom: '12px',
                    backgroundColor: '#f9fafb'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <strong style={{ fontSize: '0.875rem', color: '#374151' }}>{t('configuration.testUserNumber', { number: index + 1 })}</strong>
                      <button
                        type="button"
                        onClick={() => handleRemoveCredential(index)}
                        disabled={isAnalyzing}
                        style={{
                          padding: '4px 8px',
                          fontSize: '0.75rem',
                          backgroundColor: '#ef4444',
                          color: 'white',
                          border: 'none',
                          borderRadius: '4px',
                          cursor: 'pointer'
                        }}
                      >
                        {t('configuration.removeUser')}
                      </button>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                      <input
                        type="text"
                        placeholder="Key (e.g., username, apiKey)"
                        value={cred.key}
                        onChange={(e) => handleUpdateCredential(index, 'key', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="password"
                        placeholder="Value"
                        value={cred.value}
                        onChange={(e) => handleUpdateCredential(index, 'value', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={handleAddCredential}
                  disabled={isAnalyzing}
                  className="secondary"
                  style={{ width: '100%', marginTop: '8px' }}
                >
                  {t('asyncapi.addCredential')}
                </button>
                <small style={{ display: 'block', marginTop: '8px' }}>
                  {t('asyncapi.credentialsHint')}
                </small>
              </div>
            </div>

            {/* Protocol Properties */}
            <div className="form-group">
              <label>{t('asyncapi.protocolProperties')}</label>
              <div style={{ marginTop: '8px' }}>
                {protocolProperties.map((prop, index) => (
                  <div key={index} style={{
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                    padding: '12px',
                    marginBottom: '12px',
                    backgroundColor: '#f9fafb'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <strong style={{ fontSize: '0.875rem', color: '#374151' }}>Property #{index + 1}</strong>
                      <button
                        type="button"
                        onClick={() => handleRemoveProperty(index)}
                        disabled={isAnalyzing}
                        style={{
                          padding: '4px 8px',
                          fontSize: '0.75rem',
                          backgroundColor: '#ef4444',
                          color: 'white',
                          border: 'none',
                          borderRadius: '4px',
                          cursor: 'pointer'
                        }}
                      >
                        {t('configuration.removeUser')}
                      </button>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                      <input
                        type="text"
                        placeholder="Key"
                        value={prop.key}
                        onChange={(e) => handleUpdateProperty(index, 'key', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="text"
                        placeholder="Value"
                        value={prop.value}
                        onChange={(e) => handleUpdateProperty(index, 'value', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={handleAddProperty}
                  disabled={isAnalyzing}
                  className="secondary"
                  style={{ width: '100%', marginTop: '8px' }}
                >
                  {t('asyncapi.addProperty')}
                </button>
                <small style={{ display: 'block', marginTop: '8px' }}>
                  {selectedServerInfo?.protocol === 'kafka' &&
                    'Kafka: sasl.mechanism, sasl.username, sasl.password, consumer.group.id'}
                  {selectedServerInfo?.protocol === 'mqtt' &&
                    'MQTT: clientId, qos, cleanSession'}
                  {selectedServerInfo?.protocol === 'ws' &&
                    'WebSocket: Authorization, X-API-Key'}
                </small>
              </div>
            </div>

            {/* SSL Configuration */}
            <div className="checkbox-group">
              <input
                type="checkbox"
                id="enableSsl"
                checked={enableSsl}
                onChange={(e) => setEnableSsl(e.target.checked)}
                disabled={isAnalyzing}
              />
              <label htmlFor="enableSsl">{t('asyncapi.enableSsl')}</label>
            </div>

            {enableSsl && (
              <div className="form-group">
                <label>{t('asyncapi.sslSettings')}</label>
                <div style={{ marginTop: '8px' }}>
                  {sslProperties.map((prop, index) => (
                    <div key={index} style={{
                      border: '1px solid #e5e7eb',
                      borderRadius: '8px',
                      padding: '12px',
                      marginBottom: '12px',
                      backgroundColor: '#f9fafb'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <strong style={{ fontSize: '0.875rem', color: '#374151' }}>SSL Property #{index + 1}</strong>
                        <button
                          type="button"
                          onClick={() => handleRemoveSslProperty(index)}
                          disabled={isAnalyzing}
                          style={{
                            padding: '4px 8px',
                            fontSize: '0.75rem',
                            backgroundColor: '#ef4444',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer'
                          }}
                        >
                          {t('configuration.removeUser')}
                        </button>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                        <input
                          type="text"
                          placeholder="Key"
                          value={prop.key}
                          onChange={(e) => handleUpdateSslProperty(index, 'key', e.target.value)}
                          disabled={isAnalyzing}
                          style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                        />
                        <input
                          type="text"
                          placeholder="Value (path or password)"
                          value={prop.value}
                          onChange={(e) => handleUpdateSslProperty(index, 'value', e.target.value)}
                          disabled={isAnalyzing}
                          style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                        />
                      </div>
                    </div>
                  ))}
                  <button
                    type="button"
                    onClick={handleAddSslProperty}
                    disabled={isAnalyzing}
                    className="secondary"
                    style={{ width: '100%', marginTop: '8px' }}
                  >
                    {t('asyncapi.addSslProperty')}
                  </button>
                  <small style={{ display: 'block', marginTop: '8px' }}>
                    Common: ssl.truststore.location, ssl.truststore.password, ssl.keystore.location
                  </small>
                </div>
              </div>
            )}

            <div className="form-group">
              <label>{t('configuration.parallelScans')}</label>
              <input
                type="number"
                value={maxParallelScans}
                onChange={(e) => setMaxParallelScans(parseInt(e.target.value) || 4)}
                min="1"
                max="16"
                disabled={isAnalyzing}
              />
            </div>
          </div>
        )}

        {/* Active Scan Settings - only for active modes */}
        {asyncApiInfo && needsActiveSettings(mode) && (
          <div className="config-section">
            <h3>{t('configuration.activeScanSettings')}</h3>

            <div className="form-group">
              <label>{t('configuration.scanIntensity')}</label>
              <select
                value={scanIntensity}
                onChange={(e) => setScanIntensity(e.target.value as ScanIntensity)}
                disabled={isAnalyzing}
              >
                <option value="low">{t('configuration.scanIntensityLow')}</option>
                <option value="medium">{t('configuration.scanIntensityMedium')}</option>
                <option value="high">{t('configuration.scanIntensityHigh')}</option>
                <option value="aggressive">{t('configuration.scanIntensityAggressive')}</option>
              </select>
              <small>{t('configuration.scanIntensityHint')}</small>
            </div>

            <div className="form-group">
              <label>{t('configuration.requestDelay')}</label>
              <input
                type="number"
                value={requestDelayMs}
                onChange={(e) => setRequestDelayMs(e.target.value === '' ? '' : parseInt(e.target.value))}
                placeholder={t('configuration.requestDelayPlaceholder')}
                min="0"
                max="10000"
                disabled={isAnalyzing}
              />
              <small>{t('configuration.requestDelayHint')}</small>
            </div>
          </div>
        )}

        {/* Scanner Selection */}
        {asyncApiInfo && scanners.length > 0 && (
          <div className="config-section">
            <div className="scanner-header">
              <h3>{t('configuration.scannersCount', { selected: selectedScanners.size, total: scanners.length })}</h3>
              <div className="scanner-actions">
                <button
                  type="button"
                  onClick={handleSelectAllScanners}
                  disabled={isAnalyzing || !needsScanner(mode)}
                  className="secondary small"
                >
                  {t('configuration.selectAll')}
                </button>
                <button
                  type="button"
                  onClick={handleDeselectAllScanners}
                  disabled={isAnalyzing || !needsScanner(mode)}
                  className="secondary small"
                >
                  {t('configuration.deselectAll')}
                </button>
              </div>
            </div>

            {!needsScanner(mode) && (
              <div className="scanner-disabled-notice">
                <p>{t('configuration.scannersDisabledNotice', { mode })}</p>
              </div>
            )}

            <div className={`scanner-list ${!needsScanner(mode) ? 'disabled' : ''}`}>
              {scanners.map(scanner => (
                <div key={scanner.id} className="scanner-item">
                  <div className="checkbox-group">
                    <input
                      type="checkbox"
                      id={scanner.id}
                      checked={selectedScanners.has(scanner.id)}
                      onChange={() => handleScannerToggle(scanner.id)}
                      disabled={isAnalyzing || !needsScanner(mode)}
                    />
                    <label htmlFor={scanner.id}>
                      <strong>{scanner.name}</strong>
                      <small>{scanner.description}</small>
                      <small style={{ color: '#6b7280', fontSize: '0.75rem' }}>
                        Protocols: {scanner.supportedProtocols.join(', ') || 'all'}
                      </small>
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Submit Button - same structure as ConfigurationPanel */}
        <div className="submit-button-container">
          <button
            type="submit"
            disabled={
              isAnalyzing ||
              !asyncApiInfo ||
              loading ||
              (needsScanner(mode) && selectedScanners.size === 0)
            }
            className="submit-button"
          >
            {isAnalyzing ? t('configuration.analyzing') : t('configuration.startAnalysis')}
          </button>
          {needsScanner(mode) && selectedScanners.size === 0 && (
            <small className="validation-error">{t('configuration.validationError', { mode })}</small>
          )}
        </div>
      </form>
    </div>
  );
};
