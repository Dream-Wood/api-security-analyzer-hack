import React, { useState, useEffect, useCallback } from 'react';
import { ConfigurationPanel } from './components/ConfigurationPanel';
import { LogsPanel } from './components/LogsPanel';
import { ProgressBar } from './components/ProgressBar';
import { ResultsPanel } from './components/ResultsPanel';
import { api } from './services/api';
import { wsService } from './services/websocket';
import type { AnalysisRequest, LogEntry, AnalysisSession } from './types';
import './styles/App.css';

const SESSION_STORAGE_KEY = 'api-security-analyzer-session-id';

export const App: React.FC = () => {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [status, setStatus] = useState<string>('idle');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [totalSteps, setTotalSteps] = useState<number>(0);
  const [progressPercentage, setProgressPercentage] = useState<number>(0);
  const [estimatedTimeRemaining, setEstimatedTimeRemaining] = useState<number>(0);
  const [currentPhase, setCurrentPhase] = useState<string>('');
  const [currentEndpoint, setCurrentEndpoint] = useState<string>('');
  const [currentScanner, setCurrentScanner] = useState<string>('');
  const [totalVulnerabilitiesFound, setTotalVulnerabilitiesFound] = useState<number>(0);
  const [isRestoredSession, setIsRestoredSession] = useState<boolean>(false);

  // WebSocket connection and updates
  useEffect(() => {
    // Connect to WebSocket on component mount
    wsService.connect();

    return () => {
      // Disconnect on component unmount
      wsService.disconnect();
    };
  }, []);

  // Restore session from localStorage on page load
  useEffect(() => {
    const storedSessionId = localStorage.getItem(SESSION_STORAGE_KEY);

    if (storedSessionId) {
      console.log('Found stored session ID:', storedSessionId);

      // Try to restore the session
      api.getSession(storedSessionId)
        .then(session => {
          // Only restore if session is still active
          if (session.status === 'running' || session.status === 'pending') {
            console.log('Restoring active session:', storedSessionId);
            setSessionId(storedSessionId);
            setIsRestoredSession(true);
            // State will be updated by WebSocket or the subscription effect
          } else if (session.status === 'completed' || session.status === 'failed' || session.status === 'cancelled') {
            console.log('Session already finished, showing results:', storedSessionId);
            setSessionId(storedSessionId);
            setIsRestoredSession(true);
            // Load the final state
            handleWebSocketMessage(session);
          }
        })
        .catch(err => {
          console.error('Failed to restore session:', err);
          // Session not found or error, clear stored ID
          localStorage.removeItem(SESSION_STORAGE_KEY);
        });
    }
  }, []); // Run only once on mount

  // Handle WebSocket messages
  const handleWebSocketMessage = useCallback((session: AnalysisSession) => {
    setStatus(session.status);
    setLogs(session.logs);
    setCurrentStep(session.currentStep);
    setTotalSteps(session.totalSteps);
    setProgressPercentage(session.progressPercentage);
    setEstimatedTimeRemaining(session.estimatedTimeRemaining);
    setCurrentPhase(session.currentPhase);
    setCurrentEndpoint(session.currentEndpoint || '');
    setCurrentScanner(session.currentScanner || '');
    setTotalVulnerabilitiesFound(session.totalVulnerabilitiesFound || 0);

    // If completed, set report
    if (session.status === 'completed' && session.report) {
      setReport(session.report);
    }

    // Clear localStorage when session is finished (completed, failed, or cancelled)
    if (session.status === 'completed' || session.status === 'failed' || session.status === 'cancelled') {
      localStorage.removeItem(SESSION_STORAGE_KEY);
      console.log('Session finished, cleared from localStorage');
    }
  }, []);

  // Subscribe to WebSocket updates when sessionId changes
  useEffect(() => {
    if (!sessionId) return;

    // Subscribe to session updates
    wsService.subscribe(sessionId);
    wsService.onMessage(handleWebSocketMessage);

    // Fetch initial session state
    api.getSession(sessionId).then(session => {
      handleWebSocketMessage(session);
    }).catch(err => {
      console.error('Error fetching initial session:', err);
      setError('Failed to fetch analysis status');
    });

    return () => {
      // Unsubscribe when session changes or component unmounts
      if (sessionId) {
        wsService.unsubscribe(sessionId);
      }
      wsService.offMessage(handleWebSocketMessage);
    };
  }, [sessionId, handleWebSocketMessage]);

  const handleStartAnalysis = async (request: AnalysisRequest) => {
    try {
      setError(null);
      setLogs([]);
      setReport(null);
      setStatus('pending');
      setIsRestoredSession(false);

      const response = await api.startAnalysis(request);
      setSessionId(response.sessionId);
      setStatus('running');

      // Save session ID to localStorage for persistence across page reloads
      localStorage.setItem(SESSION_STORAGE_KEY, response.sessionId);
      console.log('Session ID saved to localStorage:', response.sessionId);
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
        // Clear localStorage when manually cancelled
        localStorage.removeItem(SESSION_STORAGE_KEY);
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
            <p>Comprehensive security analysis for OpenAPI and AsyncAPI specifications</p>
            {sessionId && (
              <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
                <span style={{ opacity: 0.9, fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  Session: {sessionId.substring(0, 8)}...
                  {isRestoredSession && (
                    <span
                      style={{
                        backgroundColor: '#dbeafe',
                        color: '#1e40af',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}
                      title="Session restored after page reload"
                    >
                      <span style={{ fontSize: '0.875rem' }}>🔄</span>
                      Restored
                    </span>
                  )}
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
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
              height: '100%',
              // Add padding-bottom when progress bar is shown to prevent content overlap
              paddingBottom: (sessionId && (status === 'running' || status === 'pending')) ? '160px' : '0'
            }}>
              {/* Logs Panel - stretches to fill available space */}
              <div style={{ flex: report ? '0 0 auto' : '1', minHeight: report ? 'auto' : '300px', overflow: 'auto' }}>
                <LogsPanel logs={logs} autoCollapse={!!report} />
              </div>

              {/* Results Panel */}
              <div style={{ flex: '1', minHeight: '400px' }}>
                <ResultsPanel report={report} status={status} sessionId={sessionId} />
              </div>
            </div>

            {/* Progress Bar - fixed at bottom when analysis is running */}
            {sessionId && (status === 'running' || status === 'pending') && (
              <div style={{
                position: 'fixed',
                bottom: 0,
                left: '450px', // Offset by sidebar width (450px)
                right: 0,
                backgroundColor: '#ffffff',
                borderTop: '2px solid #e5e7eb',
                boxShadow: '0 -4px 6px -1px rgba(0, 0, 0, 0.1), 0 -2px 4px -1px rgba(0, 0, 0, 0.06)',
                zIndex: 1000,
                padding: '16px',
              }}>
                <ProgressBar
                  currentStep={currentStep}
                  totalSteps={totalSteps}
                  progressPercentage={progressPercentage}
                  estimatedTimeRemaining={estimatedTimeRemaining}
                  currentPhase={currentPhase}
                  status={status}
                  currentEndpoint={currentEndpoint}
                  currentScanner={currentScanner}
                  totalVulnerabilitiesFound={totalVulnerabilitiesFound}
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
