import React, { useState, useEffect } from 'react';
import { ConfigurationPanel } from './components/ConfigurationPanel';
import { LogsPanel } from './components/LogsPanel';
import { ResultsPanel } from './components/ResultsPanel';
import { api } from './services/api';
import type { AnalysisRequest, LogEntry } from './types';
import './styles/App.css';

export const App: React.FC = () => {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [status, setStatus] = useState<string>('idle');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Poll for status and logs
  useEffect(() => {
    if (!sessionId) return;

    const interval = setInterval(async () => {
      try {
        // Get status
        const statusData = await api.getStatus(sessionId);
        setStatus(statusData.status);

        // Get logs
        const logsData = await api.getLogs(sessionId);
        setLogs(logsData);

        // If completed, get report
        if (statusData.status === 'completed') {
          const reportData = await api.getReport(sessionId);
          setReport(reportData);
          clearInterval(interval);
        }

        // If failed or cancelled, stop polling
        if (statusData.status === 'failed' || statusData.status === 'cancelled') {
          clearInterval(interval);
        }
      } catch (err) {
        console.error('Error polling status:', err);
        setError('Failed to fetch analysis status');
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [sessionId]);

  const handleStartAnalysis = async (request: AnalysisRequest) => {
    try {
      setError(null);
      setLogs([]);
      setReport(null);
      setStatus('pending');

      const response = await api.startAnalysis(request);
      setSessionId(response.sessionId);
      setStatus('running');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to start analysis');
      setStatus('idle');
    }
  };

  const handleCancelAnalysis = async () => {
    if (sessionId) {
      try {
        await api.cancelAnalysis(sessionId);
        setStatus('cancelled');
      } catch (err) {
        console.error('Error cancelling analysis:', err);
      }
    }
  };

  const isAnalyzing = status === 'running' || status === 'pending';

  return (
    <div className="app">
      <div className="main-container">
        {/* Left Sidebar - Configuration */}
        <div className="sidebar">
          <ConfigurationPanel
            onStartAnalysis={handleStartAnalysis}
            isAnalyzing={isAnalyzing}
          />
        </div>

        {/* Right Content - Logs and Results */}
        <div className="content">
          <div className="header">
            <h1>API Security Analyzer</h1>
            <p>Comprehensive security analysis for OpenAPI specifications</p>
            {sessionId && (
              <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <span style={{ opacity: 0.9, fontSize: '0.875rem' }}>
                  Session: {sessionId.substring(0, 8)}...
                </span>
                {isAnalyzing && (
                  <button
                    onClick={handleCancelAnalysis}
                    className="danger"
                    style={{ padding: '4px 12px', fontSize: '0.875rem' }}
                  >
                    Cancel
                  </button>
                )}
              </div>
            )}
          </div>

          {error && (
            <div style={{ padding: '16px', margin: '16px', backgroundColor: '#fee2e2', color: '#991b1b', borderRadius: '8px' }}>
              {error}
            </div>
          )}

          <div className="content-area">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: '100%' }}>
              {/* Logs Panel - auto-collapses when results are available */}
              <div style={{ flex: report ? '0 0 auto' : '0 0 300px', minHeight: report ? 'auto' : '300px' }}>
                <LogsPanel logs={logs} autoCollapse={!!report} />
              </div>

              {/* Results Panel */}
              <div style={{ flex: '1', minHeight: '400px' }}>
                <ResultsPanel report={report} status={status} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
