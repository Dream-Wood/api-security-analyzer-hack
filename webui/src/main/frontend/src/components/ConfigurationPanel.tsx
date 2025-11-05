import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type { ScannerInfo, AnalysisRequest, AnalysisMode, CryptoProtocol } from '../types';
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

  // GOST TLS state
  const [gostPfxPath, setGostPfxPath] = useState('');
  const [gostPfxPassword, setGostPfxPassword] = useState('');
  const [showGostPassword, setShowGostPassword] = useState(false);

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

  const handleFileSelect = (callback: (path: string) => void) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = (e) => {
      const target = e.target as HTMLInputElement;
      if (target.files && target.files[0]) {
        // In browser environment, we can only get the filename, not the full path
        // User will need to manually edit to provide the full server-side path if needed
        const file = target.files[0];
        // Try to use webkitRelativePath or name as fallback
        const filePath = (file as any).webkitRelativePath || file.name;
        callback(filePath);
      }
    };
    input.click();
  };

  const needsScanner = (analysisMode: AnalysisMode): boolean => {
    return analysisMode !== 'static' && analysisMode !== 'contract';
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
      enabledScanners: Array.from(selectedScanners)
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
            <label>OpenAPI Specification *</label>
            <div className="input-with-button">
              <input
                type="text"
                value={specLocation}
                onChange={(e) => setSpecLocation(e.target.value)}
                placeholder="Path or URL to OpenAPI spec"
                required
                disabled={isAnalyzing}
              />
              <button
                type="button"
                className="file-picker-button"
                onClick={() => handleFileSelect(setSpecLocation)}
                disabled={isAnalyzing}
                title="Browse for file"
              >
                📁
              </button>
            </div>
            <small>Path to OpenAPI specification file (YAML/JSON) or URL</small>
          </div>

          <div className="form-group">
            <label>Analysis Mode *</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as AnalysisMode)}
              disabled={isAnalyzing}
            >
              <option value="static">Static Only</option>
              <option value="active">Active Only</option>
              <option value="both">Combined (Static + Active)</option>
              <option value="contract">Contract Validation</option>
              <option value="full">Full (All)</option>
            </select>
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
                    placeholder="Path to PFX certificate"
                    disabled={isAnalyzing}
                  />
                  <button
                    type="button"
                    className="file-picker-button"
                    onClick={() => handleFileSelect(setGostPfxPath)}
                    disabled={isAnalyzing}
                    title="Browse for certificate"
                  >
                    📁
                  </button>
                </div>
                <small>Path to GOST PFX certificate file</small>
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
