import React, { useState } from 'react';
import { api } from '../services/api';
import { VulnerabilityChart } from './VulnerabilityChart';
import './ResultsPanel.css';

interface ResultsPanelProps {
  report: any;
  status: string;
  sessionId: string | null;
}

interface EndpointVulnerabilities {
  method: string;
  path: string;
  vulnerabilities: any[];
  severityCounts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
}

// Severity order for sorting
const SEVERITY_ORDER: Record<string, number> = {
  'CRITICAL': 0,
  'HIGH': 1,
  'MEDIUM': 2,
  'LOW': 3,
  'INFO': 4
};

/**
 * Sort vulnerabilities/findings by severity (Critical > High > Medium > Low > Info)
 */
const sortBySeverity = <T extends { severity?: string }>(items: T[]): T[] => {
  return [...items].sort((a, b) => {
    const severityA = (a.severity || 'INFO').toUpperCase();
    const severityB = (b.severity || 'INFO').toUpperCase();
    const orderA = SEVERITY_ORDER[severityA] ?? 999;
    const orderB = SEVERITY_ORDER[severityB] ?? 999;
    return orderA - orderB;
  });
};

export const ResultsPanel: React.FC<ResultsPanelProps> = ({ report, status, sessionId }) => {
  const [activeTab, setActiveTab] = useState<'summary' | 'static' | 'active' | 'contract'>('summary');
  const [expandedEndpoints, setExpandedEndpoints] = useState<Set<string>>(new Set());
  const [showFormatMenu, setShowFormatMenu] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  const toggleEndpoint = (endpointKey: string) => {
    setExpandedEndpoints(prev => {
      const next = new Set(prev);
      if (next.has(endpointKey)) {
        next.delete(endpointKey);
      } else {
        next.add(endpointKey);
      }
      return next;
    });
  };

  const handleDownload = async (format: 'PDF' | 'JSON' | 'CONSOLE') => {
    if (!sessionId || !report) return;

    try {
      setIsDownloading(true);
      await api.downloadReport(sessionId, format);
      setShowFormatMenu(false);
    } catch (error) {
      console.error('Failed to download report:', error);
      alert('Failed to download report. Please try again.');
    } finally {
      setIsDownloading(false);
    }
  };

  if (!report) {
    return (
      <div className="results-panel">
        <div className="results-empty">
          {status === 'running' ? (
            <>
              <div className="spinner"></div>
              <p>Analysis in progress...</p>
            </>
          ) : status === 'pending' ? (
            <p>Waiting to start analysis...</p>
          ) : (
            <p>No results yet. Start an analysis to see results.</p>
          )}
        </div>
      </div>
    );
  }

  const renderSummary = () => {
    const totalIssues = report.totalIssueCount || 0;

    // Since hasStaticResults/hasActiveResults/hasContractResults are not serialized,
    // we determine them by checking if the result objects exist and don't have errors
    const hasStatic = report.staticResult && !report.staticResult.errorMessage;
    const hasActive = report.activeResult && !report.activeResult.errorMessage;
    const hasContract = report.contractResult && !report.contractResult.errorMessage;

    // Get statistics
    const staticFindings = hasStatic ? (report.staticResult?.findings?.length || 0) : 0;
    const activeVulnerabilities = hasActive ? (report.activeResult?.report?.totalVulnerabilities || report.activeResult?.report?.allVulnerabilities?.length || 0) : 0;
    const contractEndpoints = hasContract ? (report.contractResult?.report?.statistics?.totalEndpoints || report.contractResult?.report?.totalEndpoints || 0) : 0;
    const contractDivergences = hasContract ? (report.contractResult?.report?.statistics?.totalDivergences || report.contractResult?.report?.totalDivergences || 0) : 0;

    // Get vulnerabilities for endpoint grouping
    const vulnerabilities = hasActive ? (report.activeResult?.report?.allVulnerabilities || []) : [];
    const endpointGroups = vulnerabilities.length > 0 ? groupVulnerabilitiesByEndpoint(vulnerabilities) : [];

    // Get spec display name - prefer title from spec, fallback to filename
    const getSpecDisplayName = (specLocation: string, specTitle?: string): string => {
      // If we have a title from the spec, use it
      if (specTitle) {
        return specTitle;
      }

      // Fallback: extract filename from path or URL
      if (!specLocation) return 'Unknown';

      // If it's a URL, extract the filename from the URL path
      if (specLocation.startsWith('http://') || specLocation.startsWith('https://')) {
        try {
          const url = new URL(specLocation);
          const pathParts = url.pathname.split('/');
          return pathParts[pathParts.length - 1] || url.hostname;
        } catch {
          return specLocation;
        }
      }

      // For file paths, extract just the filename
      const pathParts = specLocation.split('/');
      return pathParts[pathParts.length - 1] || specLocation;
    };

    return (
      <div className="results-summary">
        <div className="summary-card">
          <h3>Analysis Summary</h3>
          <div className="summary-grid">
            <div className="summary-item">
              <span className="summary-label">Specification</span>
              <span className="summary-value" title={report.specLocation}>
                {getSpecDisplayName(report.specLocation, report.specTitle)}
              </span>
            </div>
            <div className="summary-item">
              <span className="summary-label">Mode</span>
              <span className="summary-value">{report.mode}</span>
            </div>
            <div className="summary-item">
              <span className="summary-label">Total Issues</span>
              <span className={`summary-value ${totalIssues > 0 ? 'issues' : 'success'}`}>
                {totalIssues}
              </span>
            </div>
            <div className="summary-item">
              <span className="summary-label">Duration</span>
              <span className="summary-value">
                {calculateDuration(report.startTime, report.endTime)}
              </span>
            </div>
          </div>
        </div>

        {/* Analysis Results Summary */}
        {(hasStatic || hasActive || hasContract) && (
          <div className="summary-card analysis-results-card">
            <h4>Analysis Results</h4>
            <div className="analysis-results-grid">
              {hasStatic && (
                <div className="analysis-result-item">
                  <div className="result-icon">📄</div>
                  <div className="result-content">
                    <div className="result-label">Static Analysis</div>
                    <div className="result-value">{staticFindings} findings</div>
                  </div>
                </div>
              )}
              {hasActive && (
                <div className="analysis-result-item">
                  <div className="result-icon">🔍</div>
                  <div className="result-content">
                    <div className="result-label">Active Analysis</div>
                    <div className="result-value">{activeVulnerabilities} vulnerabilities</div>
                  </div>
                </div>
              )}
              {hasContract && (
                <div className="analysis-result-item">
                  <div className="result-icon">✓</div>
                  <div className="result-content">
                    <div className="result-label">Contract Validation</div>
                    <div className="result-value">{contractEndpoints} endpoints • {contractDivergences} divergences</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Vulnerability Distribution Chart - Summary */}
        {vulnerabilities.length > 0 && (
          <VulnerabilityChart
            vulnerabilities={vulnerabilities}
            title="Vulnerability Types Distribution"
          />
        )}

        {/* Endpoints with Vulnerabilities */}
        {endpointGroups.length > 0 ? (
          <div className="summary-card">
            <h3>Endpoints with Vulnerabilities</h3>
            <div className="endpoints-vulnerability-list">
              {endpointGroups.map((endpointGroup, index) => {
                const endpointKey = `summary-${endpointGroup.method}-${endpointGroup.path}`;
                const isExpanded = expandedEndpoints.has(endpointKey);
                const totalVulns = endpointGroup.vulnerabilities.length;

                return (
                  <div key={index} className="endpoint-vulnerability-item">
                    <div
                      className="endpoint-vulnerability-header"
                      onClick={() => toggleEndpoint(endpointKey)}
                    >
                      <div className="endpoint-info">
                        <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
                        <code className="endpoint-code">
                          <span className={`method-badge ${endpointGroup.method.toLowerCase()}`}>
                            {endpointGroup.method}
                          </span>
                          {endpointGroup.path}
                        </code>
                      </div>
                      <div className="endpoint-vulnerability-badges">
                        <span className="total-badge">{totalVulns} issue{totalVulns !== 1 ? 's' : ''}</span>
                        {endpointGroup.severityCounts.CRITICAL > 0 && (
                          <span className="severity-count critical">
                            {endpointGroup.severityCounts.CRITICAL} Critical
                          </span>
                        )}
                        {endpointGroup.severityCounts.HIGH > 0 && (
                          <span className="severity-count high">
                            {endpointGroup.severityCounts.HIGH} High
                          </span>
                        )}
                        {endpointGroup.severityCounts.MEDIUM > 0 && (
                          <span className="severity-count medium">
                            {endpointGroup.severityCounts.MEDIUM} Medium
                          </span>
                        )}
                        {endpointGroup.severityCounts.LOW > 0 && (
                          <span className="severity-count low">
                            {endpointGroup.severityCounts.LOW} Low
                          </span>
                        )}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="endpoint-vulnerabilities-details">
                        {sortBySeverity(endpointGroup.vulnerabilities).map((vuln: any, vulnIndex: number) => (
                          <div key={vulnIndex} className={`vulnerability-detail-item severity-${vuln.severity?.toLowerCase()}`}>
                            <div className="vulnerability-detail-header">
                              <span className={`severity-badge ${vuln.severity?.toLowerCase()}`}>
                                {vuln.severity}
                              </span>
                              <span className="vulnerability-type">{vuln.type}</span>
                            </div>

                            <div className="vulnerability-title">{vuln.title}</div>

                            {vuln.description && (
                              <div className="vulnerability-section">
                                <strong>Description:</strong>
                                <p>{vuln.description}</p>
                              </div>
                            )}

                            {vuln.reproductionSteps && (
                              <div className="vulnerability-section">
                                <strong>Reproduction Steps:</strong>
                                <pre className="reproduction-steps">{vuln.reproductionSteps}</pre>
                              </div>
                            )}

                            {vuln.recommendations && vuln.recommendations.length > 0 && (
                              <div className="vulnerability-section">
                                <strong>Remediation:</strong>
                                <ul className="remediation-list">
                                  {vuln.recommendations.map((rec: string, recIndex: number) => (
                                    <li key={recIndex}>{rec}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {vuln.evidence && Object.keys(vuln.evidence).length > 0 && (
                              <div className="vulnerability-section">
                                <strong>Evidence:</strong>
                                <div className="evidence-data">
                                  {Object.entries(vuln.evidence).map(([key, value]) => (
                                    <div key={key} className="evidence-item">
                                      <span className="evidence-key">{key}:</span>
                                      <span className="evidence-value">{String(value)}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ) : hasActive ? (
          <div className="summary-card" style={{backgroundColor: '#fef2f2', border: '1px solid #fca5a5'}}>
            <h4 style={{color: '#dc2626'}}>⚠️ No Endpoint Data Available</h4>
            <p>Active analysis completed but no vulnerability endpoint data found.</p>
            <p>Possible reasons:</p>
            <ul>
              <li>No vulnerabilities were detected</li>
              <li>Vulnerability data structure is different than expected</li>
              <li>Check console and Debug Information above for details</li>
            </ul>
          </div>
        ) : null}
      </div>
    );
  };

  const groupStaticFindingsByEndpoint = (findings: any[]) => {
    const grouped = new Map<string, any>();

    findings.forEach(finding => {
      // Use method and path if available, otherwise use "General" category
      const method = finding.method || 'General';
      const path = finding.path || finding.location || 'Specification';
      const key = `${method} ${path}`;

      if (!grouped.has(key)) {
        grouped.set(key, {
          method,
          path,
          findings: [],
          severityCounts: {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            INFO: 0
          }
        });
      }

      const endpointData = grouped.get(key)!;
      endpointData.findings.push(finding);

      const severity = finding.severity?.toUpperCase() || 'INFO';
      if (severity in endpointData.severityCounts) {
        endpointData.severityCounts[severity as keyof typeof endpointData.severityCounts]++;
      }
    });

    return Array.from(grouped.values()).sort((a, b) => {
      const totalA = a.findings.length;
      const totalB = b.findings.length;
      return totalB - totalA;
    });
  };

  const renderStatic = () => {
    const hasStatic = report.staticResult && !report.staticResult.errorMessage;

    if (!hasStatic) {
      return <div className="results-empty">Static analysis not performed</div>;
    }

    if (report.staticResult?.errorMessage) {
      return <div className="results-error">{report.staticResult.errorMessage}</div>;
    }

    const findings = report.staticResult?.findings || [];
    const endpointGroups = groupStaticFindingsByEndpoint(findings);

    return (
      <div className="results-details">
        <h3>Static Analysis - Findings by Endpoint</h3>
        {findings.length === 0 ? (
          <p className="success-message">No issues found!</p>
        ) : (
          <>
            <div className="vulnerability-summary">
              <div className="summary-stat">
                <span className="stat-label">Total Findings</span>
                <span className="stat-value">{findings.length}</span>
              </div>
              <div className="summary-stat">
                <span className="stat-label">Affected Endpoints</span>
                <span className="stat-value">{endpointGroups.length}</span>
              </div>
            </div>

            <div className="endpoints-vulnerability-list">
              {endpointGroups.map((endpointGroup, index) => {
                const endpointKey = `static-${endpointGroup.method}-${endpointGroup.path}`;
                const isExpanded = expandedEndpoints.has(endpointKey);
                const totalFindings = endpointGroup.findings.length;

                return (
                  <div key={index} className="endpoint-vulnerability-item">
                    <div
                      className="endpoint-vulnerability-header"
                      onClick={() => toggleEndpoint(endpointKey)}
                    >
                      <div className="endpoint-info">
                        <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
                        <code className="endpoint-code">
                          {endpointGroup.method !== 'General' && (
                            <span className={`method-badge ${endpointGroup.method.toLowerCase()}`}>
                              {endpointGroup.method}
                            </span>
                          )}
                          {endpointGroup.path}
                        </code>
                      </div>
                      <div className="endpoint-vulnerability-badges">
                        <span className="total-badge">{totalFindings} finding{totalFindings !== 1 ? 's' : ''}</span>
                        {endpointGroup.severityCounts.CRITICAL > 0 && (
                          <span className="severity-count critical">
                            {endpointGroup.severityCounts.CRITICAL} Critical
                          </span>
                        )}
                        {endpointGroup.severityCounts.HIGH > 0 && (
                          <span className="severity-count high">
                            {endpointGroup.severityCounts.HIGH} High
                          </span>
                        )}
                        {endpointGroup.severityCounts.MEDIUM > 0 && (
                          <span className="severity-count medium">
                            {endpointGroup.severityCounts.MEDIUM} Medium
                          </span>
                        )}
                        {endpointGroup.severityCounts.LOW > 0 && (
                          <span className="severity-count low">
                            {endpointGroup.severityCounts.LOW} Low
                          </span>
                        )}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="endpoint-vulnerabilities-details">
                        {sortBySeverity(endpointGroup.findings).map((finding: any, findingIndex: number) => (
                          <div key={findingIndex} className={`vulnerability-detail-item severity-${finding.severity?.toLowerCase()}`}>
                            <div className="vulnerability-detail-header">
                              <span className={`severity-badge ${finding.severity?.toLowerCase()}`}>
                                {finding.severity}
                              </span>
                              <span className="vulnerability-type">{finding.type || finding.category}</span>
                            </div>

                            <div className="vulnerability-title">{finding.details || finding.message}</div>

                            {finding.location && finding.location !== endpointGroup.path && (
                              <div className="vulnerability-section">
                                <strong>Location:</strong>
                                <p><code>{finding.location}</code></p>
                              </div>
                            )}

                            {finding.recommendation && (
                              <div className="vulnerability-section">
                                <strong>Recommendation:</strong>
                                <p>{finding.recommendation}</p>
                              </div>
                            )}

                            {finding.metadata && Object.keys(finding.metadata).length > 0 && (
                              <div className="vulnerability-section">
                                <strong>Additional Information:</strong>
                                <div className="evidence-data">
                                  {Object.entries(finding.metadata).map(([key, value]) => (
                                    <div key={key} className="evidence-item">
                                      <span className="evidence-key">{key}:</span>
                                      <span className="evidence-value">{String(value)}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    );
  };

  const groupVulnerabilitiesByEndpoint = (vulnerabilities: any[]): EndpointVulnerabilities[] => {
    const grouped = new Map<string, EndpointVulnerabilities>();

    vulnerabilities.forEach(vuln => {
      if (!vuln.endpoint) return;

      const key = `${vuln.endpoint.method} ${vuln.endpoint.path}`;

      if (!grouped.has(key)) {
        grouped.set(key, {
          method: vuln.endpoint.method,
          path: vuln.endpoint.path,
          vulnerabilities: [],
          severityCounts: {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            INFO: 0
          }
        });
      }

      const endpointData = grouped.get(key)!;
      endpointData.vulnerabilities.push(vuln);

      const severity = vuln.severity?.toUpperCase() || 'INFO';
      if (severity in endpointData.severityCounts) {
        endpointData.severityCounts[severity as keyof typeof endpointData.severityCounts]++;
      }
    });

    return Array.from(grouped.values()).sort((a, b) => {
      // Sort by total vulnerabilities (descending)
      const totalA = a.vulnerabilities.length;
      const totalB = b.vulnerabilities.length;
      return totalB - totalA;
    });
  };

  const renderActive = () => {
    const hasActive = report.activeResult && !report.activeResult.errorMessage;

    if (!hasActive) {
      return <div className="results-empty">Active analysis not performed</div>;
    }

    if (report.activeResult?.errorMessage) {
      return <div className="results-error">{report.activeResult.errorMessage}</div>;
    }

    const vulnerabilities = report.activeResult?.report?.allVulnerabilities || [];
    const endpointGroups = groupVulnerabilitiesByEndpoint(vulnerabilities);

    return (
      <div className="results-details">
        <h3>Active Analysis - Vulnerabilities by Endpoint</h3>
        {vulnerabilities.length === 0 ? (
          <p className="success-message">No vulnerabilities found!</p>
        ) : (
          <>
            <div className="vulnerability-summary">
              <div className="summary-stat">
                <span className="stat-label">Total Endpoints</span>
                <span className="stat-value">{endpointGroups.length}</span>
              </div>
              <div className="summary-stat">
                <span className="stat-label">Total Vulnerabilities</span>
                <span className="stat-value">{vulnerabilities.length}</span>
              </div>
            </div>

            {/* Vulnerability Distribution Chart - Active */}
            <div style={{ marginBottom: 'var(--spacing-lg)' }}>
              <VulnerabilityChart
                vulnerabilities={vulnerabilities}
                title="Vulnerability Types Distribution"
              />
            </div>

            <div className="endpoints-vulnerability-list">
              {endpointGroups.map((endpointGroup, index) => {
                const endpointKey = `${endpointGroup.method}-${endpointGroup.path}`;
                const isExpanded = expandedEndpoints.has(endpointKey);
                const totalVulns = endpointGroup.vulnerabilities.length;

                return (
                  <div key={index} className="endpoint-vulnerability-item">
                    <div
                      className="endpoint-vulnerability-header"
                      onClick={() => toggleEndpoint(endpointKey)}
                    >
                      <div className="endpoint-info">
                        <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
                        <code className="endpoint-code">
                          <span className={`method-badge ${endpointGroup.method.toLowerCase()}`}>
                            {endpointGroup.method}
                          </span>
                          {endpointGroup.path}
                        </code>
                      </div>
                      <div className="endpoint-vulnerability-badges">
                        <span className="total-badge">{totalVulns} issue{totalVulns !== 1 ? 's' : ''}</span>
                        {endpointGroup.severityCounts.CRITICAL > 0 && (
                          <span className="severity-count critical">
                            {endpointGroup.severityCounts.CRITICAL} Critical
                          </span>
                        )}
                        {endpointGroup.severityCounts.HIGH > 0 && (
                          <span className="severity-count high">
                            {endpointGroup.severityCounts.HIGH} High
                          </span>
                        )}
                        {endpointGroup.severityCounts.MEDIUM > 0 && (
                          <span className="severity-count medium">
                            {endpointGroup.severityCounts.MEDIUM} Medium
                          </span>
                        )}
                        {endpointGroup.severityCounts.LOW > 0 && (
                          <span className="severity-count low">
                            {endpointGroup.severityCounts.LOW} Low
                          </span>
                        )}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="endpoint-vulnerabilities-details">
                        {sortBySeverity(endpointGroup.vulnerabilities).map((vuln: any, vulnIndex: number) => (
                          <div key={vulnIndex} className={`vulnerability-detail-item severity-${vuln.severity?.toLowerCase()}`}>
                            <div className="vulnerability-detail-header">
                              <span className={`severity-badge ${vuln.severity?.toLowerCase()}`}>
                                {vuln.severity}
                              </span>
                              <span className="vulnerability-type">{vuln.type}</span>
                            </div>

                            <div className="vulnerability-title">{vuln.title}</div>

                            {vuln.description && (
                              <div className="vulnerability-section">
                                <strong>Description:</strong>
                                <p>{vuln.description}</p>
                              </div>
                            )}

                            {vuln.reproductionSteps && (
                              <div className="vulnerability-section">
                                <strong>Reproduction Steps:</strong>
                                <pre className="reproduction-steps">{vuln.reproductionSteps}</pre>
                              </div>
                            )}

                            {vuln.recommendations && vuln.recommendations.length > 0 && (
                              <div className="vulnerability-section">
                                <strong>Remediation:</strong>
                                <ul className="remediation-list">
                                  {vuln.recommendations.map((rec: string, recIndex: number) => (
                                    <li key={recIndex}>{rec}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {vuln.evidence && Object.keys(vuln.evidence).length > 0 && (
                              <div className="vulnerability-section">
                                <strong>Evidence:</strong>
                                <div className="evidence-data">
                                  {Object.entries(vuln.evidence).map(([key, value]) => (
                                    <div key={key} className="evidence-item">
                                      <span className="evidence-key">{key}:</span>
                                      <span className="evidence-value">{String(value)}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    );
  };

  const groupDivergencesByEndpoint = (divergences: any[]) => {
    const grouped = new Map<string, any>();

    divergences.forEach(div => {
      const path = div.path || 'Unknown';
      const method = div.method || 'N/A';
      const key = `${method} ${path}`;

      if (!grouped.has(key)) {
        grouped.set(key, {
          method,
          path,
          divergences: [],
          severityCounts: {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            INFO: 0
          }
        });
      }

      const endpointData = grouped.get(key)!;
      endpointData.divergences.push(div);

      const severity = div.severity?.toUpperCase() || 'INFO';
      if (severity in endpointData.severityCounts) {
        endpointData.severityCounts[severity as keyof typeof endpointData.severityCounts]++;
      }
    });

    return Array.from(grouped.values()).sort((a, b) => {
      const totalA = a.divergences.length;
      const totalB = b.divergences.length;
      return totalB - totalA;
    });
  };

  const renderContract = () => {
    const hasContract = report.contractResult && !report.contractResult.errorMessage;

    if (!hasContract) {
      return <div className="results-empty">Contract validation not performed</div>;
    }

    if (report.contractResult?.errorMessage) {
      return <div className="results-error">{report.contractResult.errorMessage}</div>;
    }

    const contractReport = report.contractResult?.report;

    // Get divergences from results (each ValidationResult has endpoint, method, and divergences)
    const allDivergences: any[] = [];
    if (contractReport?.results && Array.isArray(contractReport.results)) {
      contractReport.results.forEach((result: any) => {
        if (result.divergences && Array.isArray(result.divergences)) {
          // Add endpoint and method information to each divergence
          result.divergences.forEach((div: any) => {
            allDivergences.push({
              ...div,
              path: div.path || result.endpoint,  // Use endpoint from ValidationResult if div.path is missing
              method: div.method || result.method  // Use method from ValidationResult if div.method is missing
            });
          });
        }
      });
    }

    const stats = contractReport?.statistics || {};
    const totalEndpoints = stats.totalEndpoints || contractReport?.totalEndpoints || 0;
    const totalDivergences = stats.totalDivergences || contractReport?.totalDivergences || 0;
    const criticalDivergences = stats.criticalDivergences || contractReport?.criticalDivergences || 0;
    const highDivergences = stats.highDivergences || contractReport?.highDivergences || 0;
    const passed = stats.passed || 0;
    const failed = stats.failed || 0;

    const endpointGroups = groupDivergencesByEndpoint(allDivergences);

    return (
      <div className="results-details">
        <h3>Contract Validation - Divergences by Endpoint</h3>

        <div className="contract-summary">
          <div className="contract-stat">
            <span className="stat-value">{totalEndpoints}</span>
            <span className="stat-label">Total Endpoints</span>
          </div>
          <div className="contract-stat">
            <span className="stat-value">{totalDivergences}</span>
            <span className="stat-label">Total Divergences</span>
          </div>
          <div className="contract-stat error">
            <span className="stat-value">{criticalDivergences}</span>
            <span className="stat-label">Critical</span>
          </div>
          <div className="contract-stat error">
            <span className="stat-value">{highDivergences}</span>
            <span className="stat-label">High</span>
          </div>
          <div className="contract-stat success">
            <span className="stat-value">{passed}</span>
            <span className="stat-label">Passed</span>
          </div>
          <div className="contract-stat error">
            <span className="stat-value">{failed}</span>
            <span className="stat-label">Failed</span>
          </div>
        </div>


        {allDivergences.length === 0 ? (
          <p className="success-message">✓ No divergences found - All endpoints match specification!</p>
        ) : (
          <div className="endpoints-vulnerability-list">
            {endpointGroups.map((endpointGroup, index) => {
              const endpointKey = `contract-${endpointGroup.method}-${endpointGroup.path}`;
              const isExpanded = expandedEndpoints.has(endpointKey);
              const totalDivergences = endpointGroup.divergences.length;
              const hasCritical = endpointGroup.severityCounts.CRITICAL > 0;

              return (
                <div key={index} className={`endpoint-vulnerability-item ${hasCritical ? 'failed' : 'warning'}`}>
                  <div
                    className="endpoint-vulnerability-header"
                    onClick={() => toggleEndpoint(endpointKey)}
                  >
                    <div className="endpoint-info">
                      <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
                      <code className="endpoint-code">
                        {endpointGroup.method !== 'N/A' && (
                          <span className={`method-badge ${endpointGroup.method.toLowerCase()}`}>
                            {endpointGroup.method}
                          </span>
                        )}
                        {endpointGroup.path}
                      </code>
                    </div>
                    <div className="endpoint-vulnerability-badges">
                      <span className="total-badge">{totalDivergences} divergence{totalDivergences !== 1 ? 's' : ''}</span>
                      {endpointGroup.severityCounts.CRITICAL > 0 && (
                        <span className="severity-count critical">
                          {endpointGroup.severityCounts.CRITICAL} Critical
                        </span>
                      )}
                      {endpointGroup.severityCounts.HIGH > 0 && (
                        <span className="severity-count high">
                          {endpointGroup.severityCounts.HIGH} High
                        </span>
                      )}
                      {endpointGroup.severityCounts.MEDIUM > 0 && (
                        <span className="severity-count medium">
                          {endpointGroup.severityCounts.MEDIUM} Medium
                        </span>
                      )}
                      {endpointGroup.severityCounts.LOW > 0 && (
                        <span className="severity-count low">
                          {endpointGroup.severityCounts.LOW} Low
                        </span>
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="endpoint-vulnerabilities-details">
                      {sortBySeverity(endpointGroup.divergences).map((divergence: any, divIndex: number) => (
                        <div key={divIndex} className={`vulnerability-detail-item severity-${divergence.severity?.toLowerCase()}`}>
                          <div className="vulnerability-detail-header">
                            <span className={`severity-badge ${divergence.severity?.toLowerCase()}`}>
                              {divergence.severity}
                            </span>
                            <span className="vulnerability-type">{divergence.type}</span>
                          </div>

                          <div className="vulnerability-title">{divergence.message}</div>

                          {divergence.field && (
                            <div className="vulnerability-section">
                              <strong>Field:</strong>
                              <p><code>{divergence.field}</code></p>
                            </div>
                          )}

                          {divergence.expectedValue && (
                            <div className="vulnerability-section">
                              <strong>Expected Value:</strong>
                              <p><code>{String(divergence.expectedValue)}</code></p>
                            </div>
                          )}

                          {divergence.actualValue !== undefined && divergence.actualValue !== null && (
                            <div className="vulnerability-section">
                              <strong>Actual Value:</strong>
                              <p><code>{String(divergence.actualValue)}</code></p>
                            </div>
                          )}

                          {divergence.metadata && Object.keys(divergence.metadata).length > 0 && (
                            <div className="vulnerability-section">
                              <strong>Additional Information:</strong>
                              <div className="evidence-data">
                                {Object.entries(divergence.metadata).map(([key, value]) => (
                                  <div key={key} className="evidence-item">
                                    <span className="evidence-key">{key}:</span>
                                    <span className="evidence-value">{String(value)}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  const calculateDuration = (start: string, end: string): string => {
    if (!start || !end) return 'N/A';
    const duration = new Date(end).getTime() - new Date(start).getTime();
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    }
    return `${seconds}s`;
  };

  return (
    <div className="results-panel">
      <div className="results-header">
        <h3>Results</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className={`status-badge ${status}`}>{status}</span>
          {report && sessionId && (
            <div style={{ position: 'relative' }}>
              <button
                className="download-button"
                onClick={() => setShowFormatMenu(!showFormatMenu)}
                disabled={isDownloading}
              >
                <span className="download-icon">📥</span>
                <span>{isDownloading ? 'Downloading...' : 'Download Report'}</span>
                {!isDownloading && <span className="download-arrow">▼</span>}
              </button>
              {showFormatMenu && !isDownloading && (
                <div className="download-menu">
                  <button className="download-menu-item" onClick={() => handleDownload('PDF')}>
                    <span className="menu-icon">📄</span>
                    <div className="menu-content">
                      <span>PDF Report</span>
                      <span className="menu-description">Full report with charts</span>
                    </div>
                  </button>
                  <button className="download-menu-item" onClick={() => handleDownload('JSON')}>
                    <span className="menu-icon">📊</span>
                    <div className="menu-content">
                      <span>JSON Format</span>
                      <span className="menu-description">Structured data</span>
                    </div>
                  </button>
                </div>
              )}
              {showFormatMenu && (
                <div
                  style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    zIndex: 999
                  }}
                  onClick={() => setShowFormatMenu(false)}
                />
              )}
            </div>
          )}
        </div>
      </div>

      <div className="results-tabs">
        <button
          className={activeTab === 'summary' ? 'active' : ''}
          onClick={() => setActiveTab('summary')}
        >
          Summary
        </button>
        {report.staticResult && (
          <button
            className={activeTab === 'static' ? 'active' : ''}
            onClick={() => setActiveTab('static')}
          >
            Static
          </button>
        )}
        {report.activeResult && (
          <button
            className={activeTab === 'active' ? 'active' : ''}
            onClick={() => setActiveTab('active')}
          >
            Active
          </button>
        )}
        {report.contractResult && (
          <button
            className={activeTab === 'contract' ? 'active' : ''}
            onClick={() => setActiveTab('contract')}
          >
            Contract
          </button>
        )}
      </div>

      <div className="results-content">
        {activeTab === 'summary' && renderSummary()}
        {activeTab === 'static' && renderStatic()}
        {activeTab === 'active' && renderActive()}
        {activeTab === 'contract' && renderContract()}
      </div>
    </div>
  );
};
