import React from 'react';
import { useTranslation } from 'react-i18next';
import './ProgressBar.css';

interface ProgressBarProps {
  currentStep: number;
  totalSteps: number;
  progressPercentage: number;
  estimatedTimeRemaining: number;
  currentPhase: string;
  status: string;
  currentEndpoint?: string;
  currentScanner?: string;
  totalVulnerabilitiesFound?: number;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  currentStep,
  totalSteps,
  progressPercentage,
  estimatedTimeRemaining,
  currentPhase,
  status,
  currentEndpoint,
  currentScanner,
  totalVulnerabilitiesFound,
}) => {
  const { t } = useTranslation();

  const formatTime = (milliseconds: number): string => {
    if (milliseconds === 0 || !isFinite(milliseconds)) return '--:--';

    const seconds = Math.floor(milliseconds / 1000);
    if (seconds < 60) {
      return `${seconds}s`;
    } else if (seconds < 3600) {
      const mins = Math.floor(seconds / 60);
      const secs = seconds % 60;
      return `${mins}m ${secs}s`;
    } else {
      const hours = Math.floor(seconds / 3600);
      const mins = Math.floor((seconds % 3600) / 60);
      return `${hours}h ${mins}m`;
    }
  };

  const formatPhase = (phase: string): string => {
    if (!phase) return t('analysis.phaseInitializing');

    const phaseMap: Record<string, string> = {
      'initialization': t('analysis.phaseInitializing'),
      'parsing': t('analysis.phaseParsing'),
      'static-analysis': t('analysis.phaseStaticAnalysis'),
      'active-analysis': t('analysis.phaseActiveAnalysis'),
      'authentication': t('analysis.phaseAuthentication'),
      'contract-validation': t('analysis.phaseContractValidation'),
      'endpoint-discovery': t('analysis.phaseEndpointDiscovery'),
      'scanning': t('analysis.phaseScanning'),
      'analyzing': t('analysis.phaseAnalyzing')
    };

    return phaseMap[phase] || phase.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const isRunning = status === 'running';
  const isCompleted = status === 'completed';
  const isFailed = status === 'failed';

  return (
    <div className="progress-bar-container">
      <div className="progress-bar-header">
        <div className="progress-info">
          <span className="progress-phase">{formatPhase(currentPhase)}</span>
          <span className="progress-steps">
            {totalSteps > 0 ? `${currentStep}/${totalSteps}` : '--/--'}
          </span>
          {totalVulnerabilitiesFound !== undefined && totalVulnerabilitiesFound > 0 && (
            <span className="progress-vulns">
              🔍 {totalVulnerabilitiesFound} {t('analysis.vulns')}{totalVulnerabilitiesFound !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div className="progress-details">
          <span className="progress-percentage">
            {progressPercentage.toFixed(1)}%
          </span>
          {isRunning && estimatedTimeRemaining > 0 && (
            <span className="progress-eta">
              {t('analysis.eta')}: {formatTime(estimatedTimeRemaining)}
            </span>
          )}
        </div>
      </div>

      {isRunning && (currentEndpoint || currentScanner) && (
        <div className="progress-details-line">
          {currentEndpoint && (
            <span className="progress-detail-item">
              <strong>{t('analysis.endpoint')}:</strong> {currentEndpoint}
            </span>
          )}
          {currentScanner && (
            <span className="progress-detail-item">
              <strong>{t('analysis.scanner')}:</strong> {currentScanner}
            </span>
          )}
        </div>
      )}

      <div className="progress-bar-track">
        <div
          className={`progress-bar-fill ${isCompleted ? 'completed' : ''} ${isFailed ? 'failed' : ''}`}
          style={{ width: `${Math.min(100, progressPercentage)}%` }}
        >
          {isRunning && (
            <div className="progress-bar-animation" />
          )}
        </div>
      </div>
    </div>
  );
};
