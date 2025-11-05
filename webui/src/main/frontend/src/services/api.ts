// API service for communicating with the backend

import axios from 'axios';
import type { ScannerInfo, AnalysisRequest, AnalysisResponse, LogEntry } from '../types';

const API_BASE_URL = '/api';

export const api = {
  // Scanner endpoints
  async getScanners(): Promise<ScannerInfo[]> {
    const response = await axios.get(`${API_BASE_URL}/scanners`);
    return response.data;
  },

  // Analysis endpoints
  async startAnalysis(request: AnalysisRequest): Promise<AnalysisResponse> {
    const response = await axios.post(`${API_BASE_URL}/analysis/start`, request);
    return response.data;
  },

  async getStatus(sessionId: string): Promise<{ sessionId: string; status: string }> {
    const response = await axios.get(`${API_BASE_URL}/analysis/${sessionId}/status`);
    return response.data;
  },

  async getLogs(sessionId: string): Promise<LogEntry[]> {
    const response = await axios.get(`${API_BASE_URL}/analysis/${sessionId}/logs`);
    return response.data;
  },

  async getReport(sessionId: string): Promise<any> {
    const response = await axios.get(`${API_BASE_URL}/analysis/${sessionId}/report`);
    return response.data;
  },

  async cancelAnalysis(sessionId: string): Promise<void> {
    await axios.post(`${API_BASE_URL}/analysis/${sessionId}/cancel`);
  }
};
