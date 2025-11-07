// API service for communicating with the backend

import axios from 'axios';
import type { ScannerInfo, AnalysisRequest, AnalysisResponse, LogEntry, AnalysisSession } from '../types';

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

  async getSession(sessionId: string): Promise<AnalysisSession> {
    const response = await axios.get(`${API_BASE_URL}/analysis/${sessionId}`);
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
  },

  async downloadReport(sessionId: string, format: 'PDF' | 'JSON' | 'CONSOLE' = 'PDF'): Promise<void> {
    const response = await axios.get(`${API_BASE_URL}/analysis/${sessionId}/download`, {
      params: { format },
      responseType: 'blob'
    });

    // Create download link
    const blob = new Blob([response.data], {
      type: response.headers['content-type'] || 'application/octet-stream'
    });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;

    // Extract filename from content-disposition header or generate one
    const contentDisposition = response.headers['content-disposition'];
    let filename = `analysis-report-${sessionId}`;
    if (contentDisposition) {
      const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
      if (filenameMatch) {
        filename = filenameMatch[1];
      }
    } else {
      // Add extension based on format
      filename += format === 'PDF' ? '.pdf' : format === 'JSON' ? '.json' : '.txt';
    }

    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  },

  // Upload a file
  async uploadFile(file: File): Promise<{
    path: string;
    filename: string;
    size: string;
    error?: string;
  }> {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${API_BASE_URL}/analysis/upload-file`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      return response.data;
    } catch (error: any) {
      return {
        path: '',
        filename: '',
        size: '0',
        error: error.response?.data?.error || 'Failed to upload file'
      };
    }
  },

  // Detect specification type (OpenAPI vs AsyncAPI)
  async detectSpecType(path: string): Promise<{
    type: 'openapi' | 'asyncapi' | 'unknown';
    version?: string;
    displayName?: string;
    supportsActiveAnalysis?: boolean;
    error?: string;
  }> {
    try {
      const response = await axios.get(`${API_BASE_URL}/analysis/detect-spec-type`, {
        params: { path }
      });
      return response.data;
    } catch (error) {
      return {
        type: 'unknown',
        error: 'Failed to detect specification type'
      };
    }
  }
};
