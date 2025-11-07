import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type { ScannerInfo, AnalysisRequest, AnalysisMode, CryptoProtocol, ScanIntensity, UserCredentials } from '../types';
import './ConfigurationPanel.css';

interface ConfigurationPanelProps {
  onStartAnalysis: (request: AnalysisRequest) => void;
  isAnalyzing: boolean;
}

export const ConfigurationPanel: React.FC<ConfigurationPanelProps> = ({
  onStartAnalysis,
  isAnalyzing
}) => {
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [specLocation, setSpecLocation] = useState('');
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

  // Spec type detection
  const [specType, setSpecType] = useState<'unknown' | 'openapi' | 'asyncapi'>('unknown');
  const [specTypeMessage, setSpecTypeMessage] = useState<string>('');

  useEffect(() => {
    loadScanners();
  }, []);

  const loadScanners = async () => {
    try {
      const data = await api.getScanners();
      setScanners(data);
      // Enable all scanners by default
      setSelectedScanners(new Set(data.map(s => s.id)));
      setLoading(false);
    } catch (err) {
      setError('Failed to load scanners');
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
            alert(`Failed to upload file: ${result.error}`);
            return;
          }

          // Set the uploaded file path
          callback(result.path);

          // Detect spec type only for specification files
          if (shouldDetectSpecType) {
            detectSpecType(result.path);
          }

          console.log(`File uploaded: ${result.filename} (${result.size} bytes) -> ${result.path}`);
        } catch (err) {
          console.error('Upload error:', err);
          alert('Failed to upload file. Please try again.');
        }
      }
    };
    input.click();
  };

  const detectSpecType = async (path: string) => {
    if (!path || path.trim() === '') {
      setSpecType('unknown');
      setSpecTypeMessage('');
      return;
    }

    try {
      const result = await api.detectSpecType(path);
      setSpecType(result.type);

      if (result.type === 'asyncapi') {
        setSpecTypeMessage(`${result.displayName || 'AsyncAPI'} detected - only static analysis is available`);
        // Force static mode for AsyncAPI
        if (mode !== 'static') {
          setMode('static');
        }
      } else if (result.type === 'openapi') {
        setSpecTypeMessage(`${result.displayName || 'OpenAPI'} ${result.version || ''} detected`);
      } else {
        setSpecTypeMessage('');
      }
    } catch (err) {
      console.error('Failed to detect spec type:', err);
      setSpecType('unknown');
      setSpecTypeMessage('');
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
      verbose,
      noFuzzing,
      autoAuth,
      createTestUsers,
      maxParallelScans,
      enabledScanners: Array.from(selectedScanners),
      scanIntensity: needsActiveSettings(mode) ? scanIntensity : undefined,
      requestDelayMs: needsActiveSettings(mode) && requestDelayMs !== '' ? requestDelayMs : undefined,
      testUsers: needsActiveSettings(mode) && testUsers.length > 0 ? testUsers : undefined
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

  return (
    <div className="configuration-panel">
      <h2>Configuration</h2>

      <form onSubmit={handleSubmit}>
        {/* Basic Configuration */}
        <div className="config-section">
          <h3>Basic Settings</h3>

          <div className="form-group">
            <label>OpenAPI/AsyncAPI Specification *</label>
            <div className="input-with-button">
              <input
                type="text"
                value={specLocation}
                onChange={(e) => {
                  setSpecLocation(e.target.value);
                }}
                onBlur={() => detectSpecType(specLocation)}
                placeholder="Enter path/URL or click ⬆️ to upload file"
                required
                disabled={isAnalyzing}
              />
              <button
                type="button"
                className="file-picker-button"
                onClick={() => handleFileUpload(setSpecLocation)}
                disabled={isAnalyzing}
                title="Upload file to server"
              >
                ⬆️
              </button>
            </div>
            <small>
              Enter full path (absolute or relative from project root) or URL, or click ⬆️ to upload a file from your computer
            </small>
            {specTypeMessage && (
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
          </div>

          <div className="form-group">
            <label>Analysis Mode *</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as AnalysisMode)}
              disabled={isAnalyzing || specType === 'asyncapi'}
            >
              <option value="static">Static Only</option>
              <option value="active" disabled={specType === 'asyncapi'}>
                Active Only{specType === 'asyncapi' ? ' (Not available for AsyncAPI)' : ''}
              </option>
              <option value="both" disabled={specType === 'asyncapi'}>
                Combined{specType === 'asyncapi' ? ' (Not available for AsyncAPI)' : ''}
              </option>
              <option value="contract" disabled={specType === 'asyncapi'}>
                Contract{specType === 'asyncapi' ? ' (Not available for AsyncAPI)' : ''}
              </option>
              <option value="full" disabled={specType === 'asyncapi'}>
                Full{specType === 'asyncapi' ? ' (Not available for AsyncAPI)' : ''}
              </option>
            </select>
            {specType === 'asyncapi' && (
              <small style={{ color: '#92400e', fontStyle: 'italic' }}>
                AsyncAPI only supports static analysis
              </small>
            )}
          </div>

          {mode !== 'static' && (
            <div className="form-group">
              <label>Base URL</label>
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://api.example.com"
                disabled={isAnalyzing}
              />
              <small>Base URL for active analysis (overrides servers from spec)</small>
            </div>
          )}

          <div className="form-group">
            <label>Authentication Header</label>
            <input
              type="text"
              value={authHeader}
              onChange={(e) => setAuthHeader(e.target.value)}
              placeholder="Authorization: Bearer token"
              disabled={isAnalyzing}
            />
            <small>Format: 'Header: Value'</small>
          </div>
        </div>

        {/* Advanced Configuration */}
        <div className="config-section">
          <h3>Advanced Settings</h3>

          <div className="form-group">
            <label>Crypto Protocol</label>
            <select
              value={cryptoProtocol}
              onChange={(e) => setCryptoProtocol(e.target.value as CryptoProtocol)}
              disabled={isAnalyzing}
            >
              <option value="standard">Standard TLS</option>
              <option value="gost">GOST (CryptoPro)</option>
            </select>
          </div>

          {cryptoProtocol === 'gost' && (
            <>
              <div className="form-group">
                <label>GOST Certificate (PFX)</label>
                <div className="input-with-button">
                  <input
                    type="text"
                    value={gostPfxPath}
                    onChange={(e) => setGostPfxPath(e.target.value)}
                    placeholder="Enter path or click ⬆️ to upload certificate"
                    disabled={isAnalyzing}
                  />
                  <button
                    type="button"
                    className="file-picker-button"
                    onClick={() => handleFileUpload(setGostPfxPath, '.pfx,.p12', false)}
                    disabled={isAnalyzing}
                    title="Upload certificate to server"
                  >
                    ⬆️
                  </button>
                </div>
                <small>
                  Enter full path (absolute or relative from project root), or click ⬆️ to upload certificate from your computer
                </small>
              </div>

              <div className="form-group">
                <label>PFX Password</label>
                <div className="input-with-button">
                  <input
                    type={showGostPassword ? 'text' : 'password'}
                    value={gostPfxPassword}
                    onChange={(e) => setGostPfxPassword(e.target.value)}
                    placeholder="Certificate password"
                    disabled={isAnalyzing}
                  />
                  <button
                    type="button"
                    className="file-picker-button"
                    onClick={() => setShowGostPassword(!showGostPassword)}
                    disabled={isAnalyzing}
                    title={showGostPassword ? 'Hide password' : 'Show password'}
                  >
                    {showGostPassword ? '🙈' : '👁️'}
                  </button>
                </div>
                <small>Password for the PFX certificate</small>
              </div>
            </>
          )}

          <div className="form-group">
            <label>Max Parallel Scans</label>
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
            <label htmlFor="verifySsl">Verify SSL Certificates</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="verbose"
              checked={verbose}
              onChange={(e) => setVerbose(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="verbose">Verbose Logging</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="autoAuth"
              checked={autoAuth}
              onChange={(e) => setAutoAuth(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="autoAuth">Auto Authentication</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="createTestUsers"
              checked={createTestUsers}
              onChange={(e) => setCreateTestUsers(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="createTestUsers">Create Test Users (BOLA)</label>
          </div>

          <div className="checkbox-group">
            <input
              type="checkbox"
              id="noFuzzing"
              checked={noFuzzing}
              onChange={(e) => setNoFuzzing(e.target.checked)}
              disabled={isAnalyzing}
            />
            <label htmlFor="noFuzzing">Disable Fuzzing</label>
          </div>
        </div>

        {/* Active Scan Settings */}
        {needsActiveSettings(mode) && (
          <div className="config-section">
            <h3>Active Scan Settings</h3>

            <div className="form-group">
              <label>Scan Intensity</label>
              <select
                value={scanIntensity}
                onChange={(e) => setScanIntensity(e.target.value as ScanIntensity)}
                disabled={isAnalyzing}
              >
                <option value="low">Low (500ms delay) - Production Safe</option>
                <option value="medium">Medium (200ms delay) - Default</option>
                <option value="high">High (100ms delay) - Testing</option>
                <option value="aggressive">Aggressive (50ms delay) - Dev Only ⚠️</option>
              </select>
              <small>Controls request rate to avoid overwhelming the target API</small>
            </div>

            <div className="form-group">
              <label>Custom Request Delay (ms)</label>
              <input
                type="number"
                value={requestDelayMs}
                onChange={(e) => setRequestDelayMs(e.target.value === '' ? '' : parseInt(e.target.value))}
                placeholder="Leave empty to use intensity default"
                min="0"
                max="10000"
                disabled={isAnalyzing}
              />
              <small>Override intensity default (optional)</small>
            </div>

            <div className="form-group">
              <label>Test Users for BOLA/Privilege Testing</label>
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
                      <strong style={{ fontSize: '0.875rem', color: '#374151' }}>User #{index + 1}</strong>
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
                        Remove
                      </button>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                      <input
                        type="text"
                        placeholder="Username"
                        value={user.username || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'username', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="password"
                        placeholder="Password"
                        value={user.password || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'password', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="text"
                        placeholder="Client ID (optional)"
                        value={user.clientId || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'clientId', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="password"
                        placeholder="Client Secret (optional)"
                        value={user.clientSecret || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'clientSecret', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px' }}
                      />
                      <input
                        type="text"
                        placeholder="Token (optional)"
                        value={user.token || ''}
                        onChange={(e) => handleUpdateTestUser(index, 'token', e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontSize: '0.875rem', padding: '6px 8px', gridColumn: 'span 2' }}
                      />
                      <input
                        type="text"
                        placeholder="Role (e.g., user, admin)"
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
                  + Add Test User
                </button>
                <small style={{ display: 'block', marginTop: '8px' }}>
                  Multiple users enable horizontal privilege escalation testing (BOLA)
                </small>
              </div>
            </div>
          </div>
        )}

        {/* Scanner Selection */}
        <div className="config-section">
          <div className="scanner-header">
            <h3>Scanners ({selectedScanners.size}/{scanners.length})</h3>
            <div className="scanner-actions">
              <button
                type="button"
                onClick={handleSelectAll}
                disabled={isAnalyzing || !needsScanner(mode)}
                className="secondary small"
              >
                Select All
              </button>
              <button
                type="button"
                onClick={handleDeselectAll}
                disabled={isAnalyzing || !needsScanner(mode)}
                className="secondary small"
              >
                Deselect All
              </button>
            </div>
          </div>

          {!needsScanner(mode) && (
            <div className="scanner-disabled-notice">
              <p>Scanners are not used in {mode} mode</p>
            </div>
          )}

          {loading ? (
            <p>Loading scanners...</p>
          ) : error ? (
            <p className="error">{error}</p>
          ) : (
            <div className={`scanner-list ${!needsScanner(mode) ? 'disabled' : ''}`}>
              {Object.entries(groupedScanners).map(([category, categoryScanner]) => (
                <div key={category} className="scanner-category">
                  <h4>{category}</h4>
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
              (needsScanner(mode) && selectedScanners.size === 0)
            }
            className="submit-button"
          >
            {isAnalyzing ? 'Analyzing...' : 'Start Analysis'}
          </button>
          {needsScanner(mode) && selectedScanners.size === 0 && (
            <small className="validation-error">Please select at least one scanner for {mode} mode</small>
          )}
        </div>
      </form>
    </div>
  );
};
