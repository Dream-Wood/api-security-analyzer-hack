// Type definitions for API Security Analyzer WebUI

export interface ScannerInfo {
  id: string;
  name: string;
  description: string;
  detectedVulnerabilities: string[];
  enabled: boolean;
  category: string;
}

export interface UserCredentials {
  username?: string;
  password?: string;
  clientId?: string;
  clientSecret?: string;
  token?: string;
  role?: string;
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
  serverIp?: string;        // Server IP address for GOST TLS bypass (IP+SNI technique)
  sniHostname?: string;     // SNI hostname for GOST TLS bypass (hostname from certificate SAN)
  verbose: boolean;
  noFuzzing: boolean;
  autoAuth: boolean;
  createTestUsers: boolean;
  maxParallelScans?: number;
  enabledScanners?: string[];
  scanIntensity?: string;
  requestDelayMs?: number;
  testUsers?: UserCredentials[];
  // Discovery options
  enableDiscovery?: boolean;
  discoveryStrategy?: string;
  discoveryMaxDepth?: number;
  discoveryMaxRequests?: number;
  discoveryFastCancel?: boolean;
  wordlistDir?: string;
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
  currentStep: number;
  totalSteps: number;
  progressPercentage: number;
  estimatedTimeRemaining: number;
  currentPhase: string;
  currentEndpoint: string;
  currentScanner: string;
  totalVulnerabilitiesFound: number;
}

export type AnalysisMode = 'static' | 'active' | 'both' | 'contract' | 'full';
export type CryptoProtocol = 'standard' | 'gost';
export type ScanIntensity = 'low' | 'medium' | 'high' | 'aggressive';

// AsyncAPI types
export interface ServerInfo {
  name: string;
  url: string;
  protocol: string;
  protocolVersion: string;
  description: string;
}

export interface AsyncScannerInfo {
  id: string;
  name: string;
  description: string;
  supportedProtocols: string[];
  enabledByDefault: boolean;
}

export interface AsyncApiInfo {
  servers: ServerInfo[];
  availableProtocols: string[];
  asyncScanners: AsyncScannerInfo[];
  validationMessages: string[];
  valid: boolean;
}

export interface ProtocolProperty {
  key: string;
  value: string;
}

export interface AsyncAnalysisRequest {
  specLocation: string;
  mode: 'static' | 'active' | 'both';
  selectedServer: string;
  credentials: Record<string, string>;
  protocolProperties: Record<string, string>;
  sslProperties: Record<string, string>;
  enableSsl: boolean;
  connectionTimeoutMs?: number;
  operationTimeoutMs?: number;
  enabledScanners?: string[];
  scanIntensity?: string;
  maxParallelScans?: number;
  requestDelayMs?: number;
  maxRequestsPerChannel?: number;
}
