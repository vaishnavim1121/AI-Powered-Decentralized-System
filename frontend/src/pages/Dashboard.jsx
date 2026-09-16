import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { useNavigate } from 'react-router-dom';
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { extractFeaturesFromUrl, extractFeaturesFromHash, extractFeaturesFromFile } from '../services/featureExtraction';
import '../components/Dashboard.css';

function Dashboard() {
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [inputValue, setInputValue] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [stats, setStats] = useState({ total: 0, malicious: 0, benign: 0 });
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [detectedFeatures, setDetectedFeatures] = useState(null);
  const [submissionResult, setSubmissionResult] = useState(null);
  const fileInputRef = useRef(null);
  const navigate = useNavigate();

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const threatsRes = await api.get('/threats');
      const alertsRes = await api.get('/alerts');
      
      setThreats(threatsRes.data);
      setAlerts(alertsRes.data);
      
      const malicious = threatsRes.data.filter(t => t.prediction === 'malicious').length;
      const benign = threatsRes.data.filter(t => t.prediction === 'benign').length;
      setStats({
        total: threatsRes.data.length,
        malicious,
        benign
      });
    } catch (error) {
      console.error('Error fetching data:', error);
      if (error.response?.status === 401) {
        localStorage.removeItem('token');
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await api.get('/alerts');
      setAlerts(res.data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  }, []);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }
    fetchData();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, [fetchData, fetchAlerts, navigate]);

  const detectInputType = (value) => {
    if (value.match(/^https?:\/\/|^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/)) {
      return 'url';
    }
    if (value.match(/^[a-fA-F0-9]{32,64}$/)) {
      return 'hash';
    }
    return 'unknown';
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    setSelectedFile(file);
    toast.info(`📄 File selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
    
    try {
      const result = await extractFeaturesFromFile(file);
      setDetectedFeatures(result);
      toast.success('✅ Features extracted from file!');
    } catch (error) {
      toast.error('❌ Failed to extract features from file');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmissionResult(null);
    
    let features = [];
    let fileHash = null;
    let url = null;
    let displayUrl = inputValue;
    
    if (selectedFile) {
      fileHash = `${selectedFile.name}-${selectedFile.size}`;
      displayUrl = selectedFile.name;
      if (detectedFeatures) {
        features = detectedFeatures.features;
      } else {
        toast.error('Please wait for file features to extract');
        return;
      }
    } else if (inputValue) {
      const type = detectInputType(inputValue);
      if (type === 'url') {
        url = inputValue;
        const result = extractFeaturesFromUrl(inputValue);
        features = result.features;
      } else if (type === 'hash') {
        fileHash = inputValue;
        const result = extractFeaturesFromHash(inputValue);
        features = result.features;
      } else {
        toast.error('❌ Please enter a valid URL or hash');
        return;
      }
    } else {
      toast.error('❌ Please enter a URL/hash or upload a file');
      return;
    }

    if (features.some(f => isNaN(f) || f === undefined)) {
      toast.error('❌ Invalid feature extraction');
      return;
    }

    const payload = {
      file_hash: fileHash,
      url: url,
      features: features
    };

    try {
      const response = await api.post('/threat', payload);
      
      setSubmissionResult({
        prediction: response.data.prediction,
        confidence: response.data.confidence,
        tx_hash: response.data.tx_hash,
        url: displayUrl,
        timestamp: new Date().toLocaleString()
      });
      
      toast.success(`✅ Threat submitted!`);
      fetchData();
      setInputValue('');
      setSelectedFile(null);
      setDetectedFeatures(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (error) {
      toast.error('❌ Submission failed: ' + (error.response?.data?.msg || error.message));
    }
  };

  const handleThreatClick = (threat) => {
    setSelectedThreat(threat);
  };

  const trendData = threats.slice(0, 10).map(t => ({
    date: new Date(t.created_at).toLocaleString(),
    confidence: t.confidence * 100,
    prediction: t.prediction
  })).reverse();

  return (
    <div className="dashboard-container">
      <ToastContainer position="top-right" autoClose={3000} />
      
      <header className="dashboard-header">
        <div>
          <h1>🛡️ CTI Network</h1>
          <span style={{ fontSize: '14px', color: '#6b6560' }}>Dashboard</span>
        </div>
        <div className="user-info">
          <span>👤 {localStorage.getItem('username') || 'User'}</span>
          <Link to="/about" className="nav-link">How it works</Link>
          <button onClick={() => {
            localStorage.removeItem('token');
            localStorage.removeItem('username');
            navigate('/login');
          }} className="logout-btn">Log out</button>
        </div>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Threats</h3>
          <p className="stat-number">{stats.total}</p>
        </div>
        <div className="stat-card malicious">
          <h3>Malicious</h3>
          <p className="stat-number">{stats.malicious}</p>
        </div>
        <div className="stat-card benign">
          <h3>Benign</h3>
          <p className="stat-number">{stats.benign}</p>
        </div>
        <div className="stat-card alerts">
          <h3>Alerts</h3>
          <p className="stat-number">{alerts.length}</p>
        </div>
      </div>

      {submissionResult && (
        <div className="result-card">
          <div className="result-header">
            <h3>📊 Analysis Result</h3>
            <span className="result-time">{submissionResult.timestamp}</span>
          </div>
          <div className="result-body">
            <div className="result-prediction">
              <span className="result-label">Verdict</span>
              <span className={`result-value ${submissionResult.prediction}`}>
                {submissionResult.prediction === 'malicious' ? '⚠️ Malicious' : '✅ Benign'}
              </span>
            </div>
            <div className="result-confidence">
              <span className="result-label">Confidence</span>
              <span className="result-value">
                {(submissionResult.confidence * 100).toFixed(1)}%
              </span>
            </div>
            {submissionResult.url && (
              <div className="result-url">
                <span className="result-label">Analyzed</span>
                <span className="result-value url-text">{submissionResult.url}</span>
              </div>
            )}
            {submissionResult.tx_hash && (
              <div className="result-tx">
                <span className="result-label">Blockchain Transaction</span>
                <span className="result-value tx-hash">{submissionResult.tx_hash}</span>
              </div>
            )}
          </div>
          <button 
            className="result-close"
            onClick={() => setSubmissionResult(null)}
          >
            × Dismiss
          </button>
        </div>
      )}

      <div className="dashboard-grid">
        <div className="left-column">
          <div className="chart-card">
            <h3>Verdict signal</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={trendData.slice(-8)}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e8e0d8" />
                <XAxis dataKey="date" tick={{ fontSize: 10 }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} />
                <Tooltip />
                <Bar dataKey="confidence" fill="#c17f59" name="Confidence %" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="alerts-card">
            <div className="alerts-header">
              <h3>🔔 Live alerts</h3>
              <span className="polling-badge">polling every 5s</span>
            </div>
            {alerts.length === 0 ? (
              <p className="no-alerts">No new alerts</p>
            ) : (
              <ul className="alerts-list">
                {alerts.slice(0, 10).map((alert) => (
                  <li key={alert.id} className="alert-item">
                    <span className="alert-message">{alert.message}</span>
                    <span className="alert-time">{new Date(alert.created_at).toLocaleTimeString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        <div className="right-column">
          <div className="form-card">
            <h3>Submit a threat</h3>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>URL or File Hash</label>
                <input
                  type="text"
                  placeholder="e.g., https://example.com or 5e8848..."
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  disabled={!!selectedFile}
                />
              </div>
              
              <div style={{ textAlign: 'center', margin: '8px 0', color: '#6b6560' }}>— or —</div>
              
              <div className="form-group">
                <label>Upload file</label>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  accept="*/*"
                  style={{ padding: '8px' }}
                  disabled={!!inputValue}
                />
                {selectedFile && (
                  <div style={{ 
                    marginTop: '8px', 
                    fontSize: '12px', 
                    color: '#3a7d5a',
                    padding: '8px',
                    background: '#e4f5ed',
                    borderRadius: '4px'
                  }}>
                    ✅ {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                  </div>
                )}
              </div>

              <button type="submit" className="submit-btn">Analyse threat</button>
            </form>
          </div>

          <div className="stats-mini">
            <div className="stat-mini">
              <span className="stat-mini-label">Malicious</span>
              <span className="stat-mini-value malicious">{stats.malicious}</span>
            </div>
            <div className="stat-mini">
              <span className="stat-mini-label">Benign</span>
              <span className="stat-mini-value benign">{stats.benign}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="threats-card">
        <h3>Recent threats</h3>
        {loading ? (
          <p>Loading...</p>
        ) : (
          <div className="table-container">
            <table className="threats-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                  <th>Blockchain Tx</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {threats.slice(0, 15).map((threat) => (
                  <tr key={threat.id}>
                    <td>{new Date(threat.created_at).toLocaleTimeString()}</td>
                    <td>
                      <span className={`badge ${threat.prediction}`}>
                        {threat.prediction}
                      </span>
                    </td>
                    <td>{(threat.confidence * 100).toFixed(0)}%</td>
                    <td>
                      {threat.blockchain_tx ? (
                        <span className="tx-hash">
                          {threat.blockchain_tx.slice(0, 10)}...
                        </span>
                      ) : 'Pending'}
                    </td>
                    <td>
                      <button 
                        className="details-btn"
                        onClick={() => handleThreatClick(threat)}
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedThreat && (
        <div className="modal-overlay" onClick={() => setSelectedThreat(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Threat Details #{selectedThreat.id}</h2>
            <button className="modal-close" onClick={() => setSelectedThreat(null)}>×</button>
            <div className="modal-body">
              <p><strong>Prediction:</strong> {selectedThreat.prediction}</p>
              <p><strong>Confidence:</strong> {(selectedThreat.confidence * 100).toFixed(2)}%</p>
              <p><strong>File Hash:</strong> {selectedThreat.file_hash || 'N/A'}</p>
              <p><strong>URL:</strong> {selectedThreat.url || 'N/A'}</p>
              <p><strong>Blockchain Tx:</strong> {selectedThreat.blockchain_tx || 'Pending'}</p>
              <p><strong>Created:</strong> {new Date(selectedThreat.created_at).toLocaleString()}</p>
              
              <h4>Explanation (SHAP values):</h4>
              {selectedThreat.explanation && (
                <div className="explanation">
                  {Object.entries(selectedThreat.explanation).map(([key, value]) => (
                    <div key={key} className="explanation-item">
                      <span className="feature-name">{key}:</span>
                      <span className={`feature-value ${value > 0 ? 'positive' : 'negative'}`}>
                        {typeof value === 'number' ? value.toFixed(3) : value}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;