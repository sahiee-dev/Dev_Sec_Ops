// Complete API service for DevSecOps Anomaly Detection System v2.0 with Real-Time Data
class ApiService {
    constructor() {
      this.baseURL = 'http://localhost:8000';
    }
  
    async request(endpoint, options = {}) {
      const url = `${this.baseURL}${endpoint}`;
      const config = {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      };
  
      try {
        const response = await fetch(url, config);
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
      } catch (error) {
        console.error('API request failed:', error);
        throw error;
      }
    }
  
    // Basic system endpoints
    async getStatus() {
      return this.request('/status');
    }
  
    async getAdvancedStatus() {
      return this.request('/');
    }
  
    // Original methods
    async trainModel(sampleCount = 200) {
      return this.request('/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `sample_count=${sampleCount}`,
      });
    }
  
    async testDetection() {
      return this.request('/test');
    }
  
    async generateData(normalCount = 5, suspiciousCount = 2) {
      return this.request(`/generate-data?normal_count=${normalCount}&suspicious_count=${suspiciousCount}`);
    }
  
    // NEW: Real-time data methods
    async trainOnRealData() {
      return this.request('/train-on-real-data', {
        method: 'POST',
      });
    }
  
    async testRealDetection() {
      return this.request('/test-real-detection');
    }
  
    async getRealTimeChartData() {
      return this.request('/real-time-chart-data');
    }
  
    async getSystemStats() {
      return this.request('/system-stats');
    }
  
    async healthCheck() {
      return this.request('/health');
    }
  
    // WebSocket connection for real-time updates
    connectWebSocket(onMessage, onError) {
      try {
        const ws = new WebSocket('ws://localhost:8000/ws');
        
        ws.onopen = () => {
          console.log('✅ WebSocket connected to DevSecOps API');
        };
        
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data);
          if (onMessage) onMessage(data);
        };
        
        ws.onerror = (error) => {
          console.error('❌ WebSocket error:', error);
          if (onError) onError(error);
        };
        
        ws.onclose = () => {
          console.log('🔌 WebSocket connection closed');
        };
        
        return ws;
      } catch (error) {
        console.error('Failed to create WebSocket connection:', error);
        if (onError) onError(error);
        return null;
      }
    }
  }
  
  export default new ApiService();
  