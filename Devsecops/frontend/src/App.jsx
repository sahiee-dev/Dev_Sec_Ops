import React, { useState, useEffect } from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import './App.css';

import Navbar from './components/Navbar';
import StatusCards from './components/StatusCards';
import ControlPanel from './components/ControlPanel';
import Charts from './components/Charts';
import apiService from './services/api';

function App() {
  const [systemStatus, setSystemStatus] = useState({
    online: false,
    modelTrained: false,
    realDataEnabled: false,
    version: '1.0.0'
  });

  const [stats, setStats] = useState({
    totalLogs: 0,
    normalCount: 0,
    suspiciousCount: 0,
  });

  const [realTimeStats, setRealTimeStats] = useState({
    total_logs_processed: 0,
    total_anomalies_detected: 0,
    normal_activities: 0,
    threat_rate_percent: 0,
    session_id: null
  });

  const [isLoading, setIsLoading] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [wsConnection, setWsConnection] = useState(null);
  const [apiResponding, setApiResponding] = useState(false);

  // Check system status on component mount
  useEffect(() => {
    checkSystemStatus();
    fetchSessionStats();
    setupWebSocketConnection();
  }, []);

  const checkSystemStatus = async () => {
    try {
      const advancedStatus = await apiService.getAdvancedStatus();
      if (advancedStatus.real_data_enabled !== undefined) {
        setSystemStatus({
          online: true,
          modelTrained: advancedStatus.model_trained || false,
          realDataEnabled: advancedStatus.real_data_enabled || false,
          version: advancedStatus.version || '2.0.0'
        });
        return;
      }
      // eslint-disable-next-line no-unused-vars
    } catch (error) {
      console.log('Advanced API not available, trying basic status...');
    }

    try {
      const status = await apiService.getStatus();
      setSystemStatus({
        online: status.system_status === 'healthy' || true,
        modelTrained: status.model_trained || false,
        realDataEnabled: false,
        version: '1.0.0'
      });
    } catch (error) {
      console.error('Failed to check system status:', error);
      setSystemStatus({
        online: false,
        modelTrained: false,
        realDataEnabled: false,
        version: 'Unknown'
      });
    }
  };

  // Fetch session-based statistics
  const fetchSessionStats = async () => {
    try {
      const response = await fetch('http://localhost:8000/real-time-chart-data');
      if (response.ok) {
        const data = await response.json();
        const sessionData = data.session_stats;

        // Update stats to reflect current session only
        setStats({
          totalLogs: sessionData.total_logs_processed || 0,
          normalCount: sessionData.normal_activities || 0,
          suspiciousCount: sessionData.total_anomalies_detected || 0,
        });

        setRealTimeStats(sessionData);
        setApiResponding(true);

        console.log(`📊 Session stats updated for session: ${sessionData.session_id || 'none'}`);
      } else {
        setApiResponding(false);
      }
    } catch (error) {
      console.error('Failed to fetch session stats:', error);
      setApiResponding(false);
    }
  };

  // Setup WebSocket connection for live updates
  const setupWebSocketConnection = () => {
    try {
      console.log('🔌 Attempting WebSocket connection...');
      const ws = new WebSocket('ws://localhost:8000/ws');

      ws.onopen = () => {
        console.log('✅ WebSocket connected successfully for live dashboard updates');
        setWsConnection(ws);
      };

      ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        console.log('📡 WebSocket message received:', message.type);

        if (message.type === 'session_detection_complete' ||
          message.type === 'periodic_update' ||
          message.type === 'stats_update') {
          // Refresh session stats when updates are received
          fetchSessionStats();
        }
      };

      ws.onclose = (event) => {
        console.log('🔌 WebSocket disconnected. Code:', event.code);
        setWsConnection(null);
      };

      ws.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
        setWsConnection(null);
      };

    } catch (error) {
      console.error('Failed to setup WebSocket connection:', error);
      setWsConnection(null);
    }
  };

  // Set up periodic updates every 30 seconds
  useEffect(() => {
    const interval = setInterval(fetchSessionStats, 30000);
    return () => clearInterval(interval);
  }, []);

  // Cleanup WebSocket on unmount
  useEffect(() => {
    return () => {
      if (wsConnection) {
        wsConnection.close();
      }
    };
  }, [wsConnection]);

  // Original training method (sample data)
  const handleTrainModel = async () => {
    setIsLoading(true);
    try {
      const result = await apiService.trainModel(200);
      console.log('Basic training completed:', result);

      setSystemStatus(prev => ({ ...prev, modelTrained: true }));
      addAlert('success', `✅ Basic AI model trained successfully! (${result.training_samples} samples)`);

    } catch (error) {
      console.error('Basic training failed:', error);
      addAlert('error', '❌ Basic training failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Enhanced real data training
  const handleTrainRealData = async () => {
    setIsLoading(true);
    try {
      const result = await apiService.trainOnRealData();
      console.log('Real data training completed:', result);

      setSystemStatus(prev => ({ ...prev, modelTrained: true }));
      addAlert('success', `🎯 Advanced training completed on real Linux logs! (${result.training_samples} samples)`);

      await checkSystemStatus();

    } catch (error) {
      console.error('Real data training failed:', error);
      addAlert('error', '❌ Real data training failed. Please check API connection.');
    } finally {
      setIsLoading(false);
    }
  };

  // Basic test detection
  const handleTestDetection = async () => {
    setIsLoading(true);
    try {
      const result = await apiService.testDetection();
      console.log('Basic test completed:', result);

      // Update stats immediately from result
      setStats({
        totalLogs: result.total_logs || 0,
        normalCount: result.normal_found || 0,
        suspiciousCount: result.suspicious_found || 0,
      });

      addAlert('info', `🔍 Basic test complete: ${result.summary || 'Test completed successfully'}`);

      if (result.suspicious_found > 0) {
        addAlert('warning', `🚨 Found ${result.suspicious_found} suspicious activities in sample data!`);
      }

    } catch (error) {
      console.error('Basic test failed:', error);
      addAlert('error', '❌ Basic detection test failed.');
    } finally {
      setIsLoading(false);
    }
  };

  // Session-based real detection
  const handleTestRealDetection = async () => {
    setIsLoading(true);
    try {
      const result = await apiService.testRealDetection();
      console.log('Real detection test completed:', result);

      if (result.total_analyzed !== undefined) {
        // Update stats immediately from result
        setStats({
          totalLogs: result.total_analyzed || 0,
          normalCount: result.normal_behavior || 0,
          suspiciousCount: result.anomalies_detected || 0,
        });

        addAlert('info', `🔍 Session analysis: ${result.anomalies_detected} anomalies found in ${result.total_analyzed} logs`);

        if (result.anomalies_detected > 0) {
          addAlert('warning', `🚨 SESSION THREATS: ${result.anomalies_detected} suspicious activities detected!`);
        } else {
          addAlert('success', `🛡️ Session complete: All logs show normal behavior patterns`);
        }
      }

      // Refresh session stats after test completes
      setTimeout(fetchSessionStats, 2000);

    } catch (error) {
      console.error('Real detection test failed:', error);
      addAlert('error', '❌ Real data detection test failed. Make sure advanced API is running.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGenerateData = async () => {
    setIsLoading(true);
    try {
      const result = await apiService.generateData(8, 3);
      console.log('Data generated:', result);

      addAlert('success', `📊 ${result.message}: ${result.normal_count} normal + ${result.suspicious_count} suspicious logs`);

    } catch (error) {
      console.error('Data generation failed:', error);
      addAlert('error', '❌ Data generation failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const addAlert = (type, message) => {
    const alert = {
      id: Date.now(),
      type,
      message,
      timestamp: new Date().toLocaleTimeString(),
    };

    setAlerts(prev => [alert, ...prev.slice(0, 4)]); // Keep only 5 most recent
  };

  return (
    <div className="App">
      <Navbar systemStatus={systemStatus} />

      <div className="container-fluid py-4">
        {/* System Version Banner */}
        <div className="row mb-3">
          <div className="col-12">
            <div className={`alert ${systemStatus.realDataEnabled ? 'alert-success' : 'alert-info'} mb-3`}>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <strong>
                    {systemStatus.realDataEnabled ? '🛡️ Advanced System v2.0' : '🔧 Basic System v1.0'}
                  </strong>
                  {systemStatus.realDataEnabled ?
                    ' - Real Linux Log Analysis Enabled (Session-Based)' :
                    ' - Sample Data Mode'}
                </div>
                <div>
                  {systemStatus.realDataEnabled && (
                    <span className="badge bg-success me-2">
                      <i className="bi bi-shield-check"></i> Production Ready
                    </span>
                  )}
                  <span className="badge bg-info">
                    <i className={apiResponding ? 'bi bi-wifi' : 'bi bi-wifi-off'}></i>
                    {apiResponding ? ' Live Data' : ' Offline'}
                  </span>
                  {realTimeStats.session_id && (
                    <span className="badge bg-warning ms-2">
                      Session: {realTimeStats.session_id.split('_')[1]}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        <StatusCards
          stats={stats}
          modelTrained={systemStatus.modelTrained}
          realDataEnabled={systemStatus.realDataEnabled}
          realTimeStats={realTimeStats}
        />

        <ControlPanel
          onTrainModel={handleTrainModel}
          onTrainRealData={handleTrainRealData}
          onTestDetection={handleTestDetection}
          onTestRealDetection={handleTestRealDetection}
          onGenerateData={handleGenerateData}
          isLoading={isLoading}
          modelTrained={systemStatus.modelTrained}
          realDataEnabled={systemStatus.realDataEnabled}
        />

        <Charts stats={stats} />

        {/* System Alerts Section */}
        <div className="row mt-4">
          <div className="col-12">
            <div className="card">
              <div className="card-header">
                <h5 className="mb-0">
                  <i className="bi bi-bell"></i> System Alerts & Activity Log
                </h5>
              </div>
              <div className="card-body" style={{ maxHeight: '400px', overflowY: 'auto' }}>
                {alerts.length === 0 ? (
                  <div className="text-center text-muted">
                    <i className="bi bi-info-circle fs-1"></i>
                    <p className="mt-2">No alerts yet. {systemStatus.realDataEnabled ? 'Train on real Linux data' : 'Train your AI model'} to get started!</p>
                  </div>
                ) : (
                  alerts.map(alert => (
                    <div key={alert.id} className={`alert alert-${alert.type === 'error' ? 'danger' :
                      alert.type === 'success' ? 'success' :
                        alert.type === 'warning' ? 'warning' : 'info'
                      } mb-2`}>
                      <div className="d-flex justify-content-between">
                        <div>
                          <strong>{alert.message}</strong>
                        </div>
                        <small className="text-muted">{alert.timestamp}</small>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Session-Based System Information */}
        <div className="row mt-4">
          <div className="col-12">
            <div className="card">
              <div className="card-body">
                <h6 className="card-title">Session-Based System Information</h6>
                <div className="row text-center">
                  <div className="col-md-3">
                    <h4 className="text-primary">{systemStatus.online ? '🟢' : '🔴'}</h4>
                    <p className="small">API Status</p>
                  </div>
                  <div className="col-md-3">
                    <h4 className="text-success">{systemStatus.modelTrained ? '🧠' : '❌'}</h4>
                    <p className="small">AI Model</p>
                  </div>
                  <div className="col-md-3">
                    <h4 className="text-info">{alerts.length}</h4>
                    <p className="small">Recent Alerts</p>
                  </div>
                  <div className="col-md-3">
                    <h4 className="text-warning">{stats.suspiciousCount}</h4>
                    <p className="small">Session Threats</p>
                  </div>
                </div>
                <div className="text-center mt-2">
                  <span className="badge bg-secondary">Version {systemStatus.version}</span>
                  {systemStatus.realDataEnabled && (
                    <span className="badge bg-success ms-2">Real Data Integration</span>
                  )}
                  <span className="badge bg-primary ms-2">Session-Based Analysis</span>
                  {stats.totalLogs > 0 && (
                    <span className="badge bg-warning ms-2">
                      Current Session: {stats.totalLogs} logs analyzed
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
