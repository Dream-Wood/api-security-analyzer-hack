// Type definitions for API Security Analyzer WebUI

export interface ScannerInfo {
  id: string;
  name: string;
  description: string;
  detectedVulnerabilities: string[];
  enabled: boolean;
  category: string;
}

export interface AnalysisRequest {
  specLocation: string;
  mode: string;
  baseUrl?: string;
  authHeader?: string;
  cryptoProtocol?: string;
  verifySsl: boolean;
  gostPfxPath?: string;
  gostPfxPassword?: string;
  gostPfxResource: boolean;
  verbose: boolean;
  noFuzzing: boolean;
  autoAuth: boolean;
  createTestUsers: boolean;
  maxParallelScans?: number;
  enabledScanners?: string[];
}

export interface AnalysisResponse {
  sessionId: string;
  status: string;
  message: string;
  report?: any;
}

export interface LogEntry {
  timestamp: number;
  level: string;
  message: string;
}

export interface AnalysisSession {
  sessionId: string;
  status: string;
  logs: LogEntry[];
  report?: any;
}

export type AnalysisMode = 'static' | 'active' | 'both' | 'contract' | 'full';
export type CryptoProtocol = 'standard' | 'gost';
