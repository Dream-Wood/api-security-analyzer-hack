import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../services/api';
import type { ScannerInfo, AnalysisRequest, AnalysisMode, CryptoProtocol, ScanIntensity, UserCredentials } from '../types';
import './ConfigurationPanel.css';

interface ConfigurationPanelProps {
  onStartAnalysis: (request: AnalysisRequest) => void;
  onSpecTypeDetected: (type: 'openapi' | 'asyncapi' | 'unknown') => void;
  onSpecLocationChange: (location: string) => void;
  specLocation: string;
  isAnalyzing: boolean;
}

export const ConfigurationPanel: React.FC<ConfigurationPanelProps> = ({
  onStartAnalysis,
  onSpecTypeDetected,
  onSpecLocationChange,
  specLocation,
  isAnalyzing
}) => {
  const { t, i18n } = useTranslation();
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form state - specLocation is now controlled by parent
  const [mode, setMode] = useState<AnalysisMode>('static');
  const [baseUrl, setBaseUrl] = useState('');
  const [authHeader, setAuthHeader] = useState('');
  const [cryptoProtocol, setCryptoProtocol] = useState<CryptoProtocol>('standard');
  const [verifySsl, setVerifySsl] = useState(true);
  const [verbose, setVerbose] = useState(false);
  const [noFuzzing, setNoFuzzing] = useState(false);
  const [autoAuth, setAutoAuth] = useState(true);
  const [createTestUsers, setCreateTestUsers] = useState(true);
  const [maxParallelScans, setMaxParallelScans] = useState<number>(4);
  const [selectedScanners, setSelectedScanners] = useState<Set<string>>(new Set());

  // Scan intensity configuration
  const [scanIntensity, setScanIntensity] = useState<ScanIntensity>('medium');
  const [requestDelayMs, setRequestDelayMs] = useState<number | ''>('');

  // Test users configuration
  const [testUsers, setTestUsers] = useState<UserCredentials[]>([]);

  // GOST TLS state
  const [gostPfxPath, setGostPfxPath] = useState('');
  const [gostPfxPassword, setGostPfxPassword] = useState('');
  const [showGostPassword, setShowGostPassword] = useState(false);
  const [serverIp, setServerIp] = useState('');
  const [sniHostname, setSniHostname] = useState('');

  // Discovery configuration
  const [discoveryStrategy, setDiscoveryStrategy] = useState<'none' | 'top-down' | 'bottom-up' | 'hybrid'>('none');
  const [discoveryMaxDepth, setDiscoveryMaxDepth] = useState<number>(5);
  const [discoveryMaxRequests, setDiscoveryMaxRequests] = useState<number>(1000);
  const [discoveryFastCancel, setDiscoveryFastCancel] = useState<boolean>(false);

  // Spec type detection
  const [specType, setSpecType] = useState<'unknown' | 'openapi' | 'asyncapi'>('unknown');
  const [specTypeMessage, setSpecTypeMessage] = useState<string>('');
  const [specTypeLoading, setSpecTypeLoading] = useState(false);
  const [specTypeError, setSpecTypeError] = useState<string | null>(null);

  // Server ping status
  const [baseUrlPing, setBaseUrlPing] = useState<{
    loading: boolean;
    available?: boolean;
    latencyMs?: number;
    statusCode?: number;
    error?: string;
  }>({ loading: false });

  useEffect(() => {
    loadScanners();
  }, []);

  // Auto-detect spec type when specLocation changes (for URLs)
  useEffect(() => {
    // Only auto-detect for URLs (http/https) to avoid unnecessary API calls while typing file paths
    if (specLocation && (specLocation.startsWith('http://') || specLocation.startsWith('https://'))) {
      const timer = setTimeout(() => {
        detectSpecType(specLocation);
      }, 500); // Debounce for 500ms
      return () => clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [specLocation]);

  // Reload scanners when language changes
  useEffect(() => {
    const handleLanguageChange = () => {
      loadScanners();
    };

    i18n.on('languageChanged', handleLanguageChange);

    return () => {
      i18n.off('languageChanged', handleLanguageChange);
    };
  }, [i18n]);

  const loadScanners = async () => {
    try {
      const data = await api.getScanners();
      setScanners(data);
      // Enable all scanners by default
      setSelectedScanners(new Set(data.map(s => s.id)));
      setLoading(false);
    } catch (err) {
      setError(t('messages.error'));
      setLoading(false);
    }
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

  const handleSelectAll = () => {
    setSelectedScanners(new Set(scanners.map(s => s.id)));
  };

  const handleDeselectAll = () => {
    setSelectedScanners(new Set());
  };

  const handleFileUpload = async (
    callback: (path: string) => void,
    acceptTypes: string = '.yaml,.yml,.json',
    shouldDetectSpecType: boolean = true
  ) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = acceptTypes;
    input.onchange = async (e) => {
      const target = e.target as HTMLInputElement;
      if (target.files && target.files[0]) {
        const file = target.files[0];

        try {
          // Upload file to server
          const result = await api.uploadFile(file);

          if (result.error) {
            alert(`${t('configuration.uploadError')}: ${result.error}`);
            return;
          }

          // Set the uploaded file path
          callback(result.path);

          // Also update parent's specLocation
          onSpecLocationChange(result.path);

          // Detect spec type only for specification files
          if (shouldDetectSpecType) {
            detectSpecType(result.path);
          }

          console.log(`File uploaded: ${result.filename} (${result.size} bytes) -> ${result.path}`);
        } catch (err) {
          console.error('Upload error:', err);
          alert(t('configuration.uploadErrorRetry'));
        }
      }
    };
    input.click();
  };

  const detectSpecType = async (path: string) => {
    if (!path || path.trim() === '') {
      setSpecType('unknown');
      setSpecTypeMessage('');
      setSpecTypeError(null);
      onSpecTypeDetected('unknown');
      return;
    }

    try {
      setSpecTypeLoading(true);
      setSpecTypeError(null);

      const result = await api.detectSpecType(path);
      setSpecType(result.type);
      onSpecTypeDetected(result.type);

      if (result.type === 'asyncapi') {
        setSpecTypeMessage(`${result.displayName || 'AsyncAPI'} ${t('configuration.asyncAPIDetected')}`);
        // Будет использован AsyncConfigPanel автоматически
      } else if (result.type === 'openapi') {
        setSpecTypeMessage(`${result.displayName || 'OpenAPI'} ${result.version || ''} ${t('configuration.openAPIDetected')}`);
      } else {
        setSpecTypeMessage('');
        if (result.error) {
          setSpecTypeError(result.error);
        }
      }
    } catch (err: any) {
      console.error('Failed to detect spec type:', err);
      setSpecType('unknown');
      setSpecTypeMessage('');
      setSpecTypeError(err.response?.data?.message || err.message || 'Failed to detect specification type');
      onSpecTypeDetected('unknown');
    } finally {
      setSpecTypeLoading(false);
    }
  };

  const pingBaseUrl = async (url: string) => {
    if (!url || url.trim() === '') {
      setBaseUrlPing({ loading: false });
      return;
    }

    // Only ping if URL starts with http:// or https://
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      setBaseUrlPing({ loading: false, error: 'URL must start with http:// or https://' });
      return;
    }

    try {
      setBaseUrlPing({ loading: true });
      const result = await api.pingServer(url);
      setBaseUrlPing({
        loading: false,
        available: result.available,
        latencyMs: result.latencyMs,
        statusCode: result.statusCode,
        error: result.error
      });
    } catch (err: any) {
      setBaseUrlPing({
        loading: false,
        available: false,
        error: err.message || 'Failed to ping server'
      });
    }
  };

  const needsScanner = (analysisMode: AnalysisMode): boolean => {
    return analysisMode !== 'static' && analysisMode !== 'contract';
  };

  const needsActiveSettings = (analysisMode: AnalysisMode): boolean => {
    return analysisMode !== 'static';
  };

  const handleAddTestUser = () => {
    setTestUsers([...testUsers, { username: '', password: '', role: 'user' }]);
  };

  const handleRemoveTestUser = (index: number) => {
    setTestUsers(testUsers.filter((_, i) => i !== index));
  };

  const handleUpdateTestUser = (index: number, field: keyof UserCredentials, value: string) => {
    const updated = [...testUsers];
    updated[index] = { ...updated[index], [field]: value };
    setTestUsers(updated);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const request: AnalysisRequest = {
      specLocation,
      mode,
      baseUrl: baseUrl || undefined,
      authHeader: authHeader || undefined,
      cryptoProtocol,
      verifySsl,
      gostPfxPath: gostPfxPath || undefined,
      gostPfxPassword: gostPfxPassword || undefined,
      gostPfxResource: false,
      serverIp: serverIp || undefined,
      sniHostname: sniHostname || undefined,
      verbose,
      noFuzzing,
      autoAuth,
      createTestUsers,
      maxParallelScans,
      enabledScanners: Array.from(selectedScanners),
      scanIntensity: needsActiveSettings(mode) ? scanIntensity : undefined,
      requestDelayMs: needsActiveSettings(mode) && requestDelayMs !== '' ? requestDelayMs : undefined,
      testUsers: needsActiveSettings(mode) && testUsers.length > 0 ? testUsers : undefined,
      // Discovery options
      enableDiscovery: needsActiveSettings(mode) && discoveryStrategy !== 'none',
      discoveryStrategy: needsActiveSettings(mode) ? discoveryStrategy : 'none',
      discoveryMaxDepth: needsActiveSettings(mode) && discoveryStrategy !== 'none' ? discoveryMaxDepth : undefined,
      discoveryMaxRequests: needsActiveSettings(mode) && discoveryStrategy !== 'none' ? discoveryMaxRequests : undefined,
      discoveryFastCancel: needsActiveSettings(mode) && discoveryStrategy !== 'none' ? discoveryFastCancel : false,
      wordlistDir: needsActiveSettings(mode) && discoveryStrategy !== 'none' ? './wordlists' : undefined
    };

    onStartAnalysis(request);
  };

  const groupedScanners = scanners.reduce((acc, scanner) => {
    const category = scanner.category;
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(scanner);
    return acc;
  }, {} as Record<string, ScannerInfo[]>);

  // Translate category names
  const translateCategory = (category: string): string => {
    const categoryMap: Record<string, string> = {
      'Authentication & Authorization': t('configuration.categoryAuth'),
      'Injection Attacks': t('configuration.categoryInjection'),
      'Cryptography': t('configuration.categoryCrypto'),
      'Configuration & Deployment': t('configuration.categoryConfig'),
      'Information Disclosure': t('configuration.categoryInfo'),
      'Business Logic': t('configuration.categoryBusiness'),
      'Other': t('configuration.categoryOther')
    };
    return categoryMap[category] || category;
  };

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
                onBlur={() => detectSpecType(specLocation)}
                placeholder={t('configuration.specFilePlaceholder')}
                required
                disabled={isAnalyzing}
              />
              <button
                type="button"
                className="file-picker-button"
                onClick={() => handleFileUpload(onSpecLocationChange)}
                disabled={isAnalyzing}
                title={t('configuration.uploadButton')}
              >
                ⬆️
              </button>
            </div>
            <small>
              {t('configuration.specFileHint')}
            </small>
            {specTypeLoading && (
              <div style={{
                padding: '8px 12px',
                backgroundColor: '#f3f4f6',
                color: '#374151',
                borderRadius: '4px',
                fontSize: '0.875rem',
                marginTop: '8px',
                border: '1px solid #d1d5db'
              }}>
                ⏳ {t('configuration.detectingSpecType') || 'Detecting specification type...'}
              </div>
            )}
            {!specTypeLoading && specTypeMessage && (
              <div style={{
                padding: '8px 12px',
                backgroundColor: specType === 'asyncapi' ? '#fef3c7' : '#dbeafe',
                color: specType === 'asyncapi' ? '#92400e' : '#1e3a8a',
                borderRadius: '4px',
                fontSize: '0.875rem',
                marginTop: '8px',
                border: `1px solid ${specType === 'asyncapi' ? '#fbbf24' : '#60a5fa'}`
              }}>
                {specType === 'asyncapi' && '⚠️ '}{specTypeMessage}
              </div>
            )}
            {!specTypeLoading && specTypeError && (
              <div style={{
                padding: '8px 12px',
                backgroundColor: '#fee2e2',
                color: '#991b1b',
                borderRadius: '4px',
                fontSize: '0.875rem',
                marginTop: '8px',
                border: '1px solid #fca5a5'
              }}>
                ❌ {specTypeError}
              </div>
            )}
          </div>

          <div className="form-group">
            <label>{t('configuration.mode')} *</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as AnalysisMode)}
              disabled={isAnalyzing || specType === 'asyncapi'}
            >
              <option value="static">{t('configuration.modeStatic')}</option>
              <option value="active" disabled={specType === 'asyncapi'}>
                {t('configuration.modeActive')}{specType === 'asyncapi' ? ` (${t('configuration.modeNotAvailableAsyncAPI')})` : ''}
              </option>
              <option value="both" disabled={specType === 'asyncapi'}>
                {t('configuration.modeBoth')}{specType === 'asyncapi' ? ` (${t('configuration.modeNotAvailableAsyncAPI')})` : ''}
              </option>
              <option value="contract" disabled={specType === 'asyncapi'}>
                {t('configuration.modeContract')}{specType === 'asyncapi' ? ` (${t('configuration.modeNotAvailableAsyncAPI')})` : ''}
              </option>
              <option value="full" disabled={specType === 'asyncapi'}>
                {t('configuration.modeFull')}{specType === 'asyncapi' ? ` (${t('configuration.modeNotAvailableAsyncAPI')})` : ''}
              </option>
            </select>
            {specType === 'asyncapi' && (
              <small style={{ color: '#92400e', fontStyle: 'italic' }}>
                {t('configuration.asyncAPIOnlyStatic')}
              </small>
            )}
          </div>

          {mode !== 'static' && (
            <div className="form-group">
              <label>{t('configuration.baseUrl')}</label>
              <div className="input-with-status">
                <input
                  type="text"
                  value={baseUrl}
                  onChange={(e) => {
                    setBaseUrl(e.target.value);
                    // Reset ping status when URL changes
                    setBaseUrlPing({ loading: false });
                  }}
                  onBlur={() => pingBaseUrl(baseUrl)}
                  placeholder={t('configuration.baseUrlPlaceholder')}
                  disabled={isAnalyzing}
                  style={{ flex: 1 }}
                />
                {baseUrlPing.loading && (
                  <span className="ping-status loading" title={t('configuration.checkingServer') || 'Checking server...'}>
                    ⏳
                  </span>
                )}
                {!baseUrlPing.loading && baseUrlPing.available === true && (
                  <span className="ping-status available" title={`${t('configuration.serverAvailable') || 'Server available'} - ${baseUrlPing.latencyMs}ms`}>
                    ✅ {baseUrlPing.latencyMs}ms
                  </span>
                )}
                {!baseUrlPing.loading && baseUrlPing.available === false && baseUrlPing.error && (
                  <span className="ping-status unavailable" title={baseUrlPing.error}>
                    ❌
                  </span>
                )}
              </div>
              <small>{t('configuration.baseUrlHint')}</small>
              {!baseUrlPing.loading && baseUrlPing.available === false && baseUrlPing.error && (
                <div style={{
                  padding: '6px 10px',
                  backgroundColor: '#fee2e2',
                  color: '#991b1b',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                  marginTop: '4px',
                  border: '1px solid #fca5a5'
                }}>
                  ⚠️ {baseUrlPing.error}
                </div>
              )}
            </div>
          )}

          <div className="form-group">
            <label>{t('configuration.authHeader')}</label>
            <input
              type="text"
              value={authHeader}
              onChange={(e) => setAuthHeader(e.target.value)}
              placeholder={t('configuration.authHeaderPlaceholder')}
              disabled={isAnalyzing}
            />
            <small>{t('configuration.authHeaderHint')}</small>
          </div>
        </div>

        {/* Advanced Configuration */}
        <div className="config-section">
          <h3>{t('configuration.advancedSettings')}</h3>

          <div className="form-group">
            <label>{t('configuration.cryptoProtocol')}</label>
            <select
              value={cryptoProtocol}
              onChange={(e) => setCryptoProtocol(e.target.value as CryptoProtocol)}
              disabled={isAnalyzing}
            >
              <option value="standard">{t('configuration.cryptoStandard')}</option>
              <option value="gost">{t('configuration.cryptoGost')}</option>
            </select>
          </div>

          {cryptoProtocol === 'gost' && (
            <>
              <div className="form-group">
                <label>{t('configuration.gostCertificate')}</label>
                <div className="input-with-button">
                  <input
                    type="text"
                    value={gostPfxPath}
                    onChange={(e) => setGostPfxPath(e.target.value)}
                    placeholder={t('configuration.gostCertificatePlaceholder')}
                    disabled={isAnalyzing}
                  />
                  <button
                    type="button"
                    className="file-picker-button"
                    onClick={() => handleFileUpload(setGostPfxPath, '.pfx,.p12', false)}
                    disabled={isAnalyzing}
                    title={t('configuration.gostCertificateUpload')}
                  >
                    ⬆️
                  </button>
                </div>
                <small>
                  {t('configuration.gostCertificateHint')}
                </small>
              </div>

              <div className="form-group">
                <label>{t('configuration.pfxPassword')}</label>
                <div className="input-with-button">
                  <input
                    type={showGostPassword ? 'text' : 'password'}
                    value={gostPfxPassword}
                    onChange={(e) => setGostPfxPassword(e.target.value)}
                    placeholder={t('configuration.pfxPasswordPlaceholder')}
                    disabled={isAnalyzing}
                  />
                  <button
                    type="button"
                    className="file-picker-button"
                    onClick={() => setShowGostPassword(!showGostPassword)}
                    disabled={isAnalyzing}
                    title={showGostPassword ? t('configuration.hidePassword') : t('configuration.showPassword')}
                  >
                    {showGostPassword ? '🙈' : '👁️'}
                  </button>
                </div>
                <small>{t('configuration.pfxPasswordHint')}</small>
              </div>

              <div className="form-group">
                <label>{t('configuration.serverIp')}</label>
                <input
                  type="text"
                  value={serverIp}
                  onChange={(e) => setServerIp(e.target.value)}
                  placeholder={t('configuration.serverIpPlaceholder')}
                  disabled={isAnalyzing}
                />
                <small>{t('configuration.serverIpHint')}</small>
              </div>

              <div className="form-group">
                <label>{t('configuration.sniHostname')}</label>
                <input
                  type="text"
                  value={sniHostname}
                  onChange={(e) => setSniHostname(e.target.value)}
                  placeholder={t('configuration.sniHostnamePlaceholder')}
                  disabled={isAnalyzing}
                />
                <small>{t('configuration.sniHostnameHint')}</small>
              </div>
            </>
          )}

          <div className="form-group">
            <label>{t('configuration.parallelScans')}</label>
            <input
              type="number"
              value={maxParallelScans}
              onChange={(e) => setMaxParallelScans(parseInt(e.target.value))}
              min="1"
              max="16"
              disabled={isAnalyzing}
            />
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="verifySsl"
              checked={verifySsl}
              onChange={(e) => setVerifySsl(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="verifySsl">{t('configuration.verifySsl')}</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="verbose"
              checked={verbose}
              onChange={(e) => setVerbose(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="verbose">{t('configuration.verboseLogging')}</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="autoAuth"
              checked={autoAuth}
              onChange={(e) => setAutoAuth(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="autoAuth">{t('configuration.autoAuth')}</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="createTestUsers"
              checked={createTestUsers}
              onChange={(e) => setCreateTestUsers(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="createTestUsers">{t('configuration.createTestUsers')}</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="noFuzzing"
              checked={noFuzzing}
              onChange={(e) => setNoFuzzing(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="noFuzzing">{t('configuration.disableFuzzing')}</label>
          </div>
        </div>

        {/* Active Scan Settings */}
        {needsActiveSettings(mode) && (
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

            <div className="form-group">
              <label>{t('configuration.testUsers')}</label>
              <div style={{ marginTop: '8px' }}>
                {testUsers.map((user, index) => (
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
                        onClick={() => handleRemoveTestUser(index)}
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
                        placeholder={t('configuration.usernamePlaceholder')}
                        value={user.username || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'username', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="password"
                        placeholder={t('configuration.passwordPlaceholder')}
                        value={user.password || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'password', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="text"
                        placeholder={t('configuration.clientIdPlaceholder')}
                        value={user.clientId || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'clientId', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="password"
                        placeholder={t('configuration.clientSecretPlaceholder')}
                        value={user.clientSecret || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'clientSecret', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="text"
                        placeholder={t('configuration.tokenPlaceholder')}
                        value={user.token || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'token', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px', gridColumn: 'span 2' }}
                      />
                      <input
                        type="text"
                        placeholder={t('configuration.rolePlaceholder')}
                        value={user.role || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'role', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={handleAddTestUser}
                  disabled={isAnalyzing}
                  className="secondary"
                  style={{ width: '100%', marginTop: '8px' }}
                >
                  {t('configuration.addTestUser')}
                </button>
                <small style={{ display: 'block', marginTop: '8px' }}>
                  {t('configuration.testUsersHint')}
                </small>
              </div>
            </div>
          </div>
        )}

        {/* Endpoint Discovery */}
        {needsActiveSettings(mode) && (
          <div className="config-section">
            <h3>{t('configuration.endpointDiscovery')}</h3>
            <p className="section-description">
              {t('configuration.endpointDiscoveryDescription')}
            </p>

            <div className="form-group">
              <label>{t('configuration.discoveryStrategy')}</label>
              <select
                value={discoveryStrategy}
                onChange={(e) => setDiscoveryStrategy(e.target.value as 'none' | 'top-down' | 'bottom-up' | 'hybrid')}
                disabled={isAnalyzing}
              >
                <option value="none">{t('configuration.discoveryStrategyNone')}</option>
                <option value="top-down">{t('configuration.discoveryStrategyTopDown')}</option>
                <option value="bottom-up">{t('configuration.discoveryStrategyBottomUp')}</option>
                <option value="hybrid">{t('configuration.discoveryStrategyHybrid')}</option>
              </select>
              <small>
                {discoveryStrategy === 'none' && t('configuration.discoveryStrategyHintNone')}
                {discoveryStrategy === 'top-down' && t('configuration.discoveryStrategyHintTopDown')}
                {discoveryStrategy === 'bottom-up' && t('configuration.discoveryStrategyHintBottomUp')}
                {discoveryStrategy === 'hybrid' && t('configuration.discoveryStrategyHintHybrid')}
              </small>
            </div>

            {discoveryStrategy !== 'none' && (
              <>
                <div className="form-group">
                  <label>{t('configuration.discoveryMaxDepth')}</label>
                  <input
                    type="number"
                    value={discoveryMaxDepth}
                    onChange={(e) => setDiscoveryMaxDepth(parseInt(e.target.value) || 5)}
                    min="1"
                    max="10"
                    disabled={isAnalyzing}
                  />
                  <small>{t('configuration.discoveryMaxDepthHint')}</small>
                </div>

                <div className="form-group">
                  <label>{t('configuration.discoveryMaxRequests')}</label>
                  <input
                    type="number"
                    value={discoveryMaxRequests}
                    onChange={(e) => {
                      const value = parseInt(e.target.value);
                      setDiscoveryMaxRequests(isNaN(value) ? 0 : Math.max(0, value));
                    }}
                    min="0"
                    max="100000"
                    step="100"
                    disabled={isAnalyzing}
                  />
                  <small>{t('configuration.discoveryMaxRequestsHint')}</small>
                </div>

                <div className="form-group">
                  <label>
                    <input
                      type="checkbox"
                      checked={discoveryFastCancel}
                      onChange={(e) => setDiscoveryFastCancel(e.target.checked)}
                      disabled={isAnalyzing}
                    />
                    <span style={{ marginLeft: '8px' }}>{t('configuration.discoveryFastCancel')}</span>
                  </label>
                  <small>{t('configuration.discoveryFastCancelHint')}</small>
                </div>

                <div style={{
                  backgroundColor: '#fef3c7',
                  border: '1px solid #fbbf24',
                  borderRadius: '6px',
                  padding: '12px',
                  marginTop: '12px'
                }}>
                  <p style={{ margin: 0, fontSize: '0.875rem', color: '#92400e' }}>
                    {t('configuration.discoveryNote')}
                  </p>
                </div>
              </>
            )}
          </div>
        )}

        {/* Scanner Selection */}
        <div className="config-section">
          <div className="scanner-header">
            <h3>{t('configuration.scannersCount', { selected: selectedScanners.size, total: scanners.length })}</h3>
            <div className="scanner-actions">
              <button
                type="button"
                onClick={handleSelectAll}
                disabled={isAnalyzing || !needsScanner(mode)}
                className="secondary small"
              >
                {t('configuration.selectAll')}
              </button>
              <button
                type="button"
                onClick={handleDeselectAll}
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

          {loading ? (
            <p>{t('configuration.loadingScanners')}</p>
          ) : error ? (
            <p className="error">{error}</p>
          ) : (
            <div className={`scanner-list ${!needsScanner(mode) ? 'disabled' : ''}`}>
              {Object.entries(groupedScanners).map(([category, categoryScanner]) => (
                <div key={category} className="scanner-category">
                  <h4>{translateCategory(category)}</h4>
                  {categoryScanner.map(scanner => (
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
                        </label>
                      </div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Submit Button */}
        <div className="submit-button-container">
          <button
            type="submit"
            disabled={
              isAnalyzing ||
              !specLocation ||
              (needsScanner(mode) && selectedScanners.size === 0 && discoveryStrategy === 'none')
            }
            className="submit-button"
          >
            {isAnalyzing ? t('configuration.analyzing') : t('configuration.startAnalysis')}
          </button>
          {needsScanner(mode) && selectedScanners.size === 0 && discoveryStrategy === 'none' && (
            <small className="validation-error">{t('configuration.validationError', { mode })}</small>
          )}
        </div>
      </form>
    </div>
  );
};
