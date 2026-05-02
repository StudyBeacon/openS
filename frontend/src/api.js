import axios from 'axios';

/**
 * Axios API client for vulnerability scanner backend
 * Base URL: http://localhost:8000
 */
const apiClient = axios.create({
  baseURL: '/', // Use absolute path from current origin to hit Vite proxy
  timeout: 120000, 
});

/**
 * Scan code for vulnerabilities
 *
 * @param {string} code - Source code to scan
 * @param {string} language - Programming language (default: 'python')
 * @returns {Promise<Object>} Scan result with risk_score, findings, etc.
 * @throws {Error} API error or network error
 */
export async function scanCode(code, language = 'python') {
  try {
    const response = await apiClient.post('/api/scan', {
      code,
      language,
    });
    return response.data;
  } catch (error) {
    throw error;
  }
}

/**
 * Scan multiple files for vulnerabilities
 *
 * @param {File[]} files - Array of File objects to scan
 * @returns {Promise<Object[]>} Array of scan results with filename added to each
 * @throws {Error} API error or network error
 */
export async function scanFiles(files) {
  try {
    const formData = new FormData();

    // Append each file with key 'files' for multipart upload
    for (const file of files) {
      formData.append('files', file);
    }

    const response = await apiClient.post('/api/scan/files', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error) {
    throw error;
  }
}

/**
 * Check API health and Ollama connectivity
 *
 * @returns {Promise<Object>} Health status with ollama availability
 * @throws {Error} API error or network error
 */
export async function checkHealth() {
  try {
    const response = await apiClient.get('/api/health');
    return response.data;
  } catch (error) {
    throw error;
  }
}
