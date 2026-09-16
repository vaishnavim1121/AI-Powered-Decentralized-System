import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import api from '../services/api';
import { fetchThreatDetail } from '../services/api';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import '../components/Dashboard.css';

function ThreatDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [threat, setThreat] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchThreat = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetchThreatDetail(id);
      setThreat(res.data);
    } catch (error) {
      console.error('Error fetching threat:', error);
      setThreat(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }
    fetchThreat();
  }, [fetchThreat, navigate]);

  if (loading) {
    return (
      <div className="dashboard-container">
        <p>Loading threat details...</p>
      </div>
    );
  }

  if (!threat) {
    return (
      <div className="dashboard-container">
        <h2>Threat not found</h2>
        <Link to="/dashboard">Back to Dashboard</Link>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <ToastContainer />
      <header className="dashboard-header">
        <h1>🛡️ Threat Details #{threat.id}</h1>
        <Link to="/dashboard" className="logout-btn" style={{ textDecoration: 'none' }}>
          Back to Dashboard
        </Link>
      </header>

      <div className="threats-card">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <div>
            <strong>Prediction</strong>
            <p><span className={`badge ${threat.prediction}`}>{threat.prediction}</span></p>
          </div>
          <div>
            <strong>Confidence</strong>
            <p>{((threat.confidence || 0) * 100).toFixed(2)}%</p>
          </div>
          <div>
            <strong>File Hash</strong>
            <p style={{ fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all' }}>
              {threat.file_hash || 'N/A'}
            </p>
          </div>
          <div>
            <strong>URL</strong>
            <p>{threat.url || 'N/A'}</p>
          </div>
          <div>
            <strong>Blockchain Transaction</strong>
            <p style={{ fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all' }}>
              {threat.blockchain_tx || 'Pending'}
            </p>
          </div>
          <div>
            <strong>Created At</strong>
            <p>{new Date(threat.created_at).toLocaleString()}</p>
          </div>
        </div>

        {threat.explanation && (
          <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid #e8e0d8' }}>
            <h3>Explanation</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '12px' }}>
              {Object.entries(threat.explanation).map(([key, value]) => (
                <div key={key} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: '#f8f6f3',
                  borderRadius: '6px'
                }}>
                  <span>{key}:</span>
                  <span style={{ color: value > 0 ? '#d45c4c' : '#3a7d5a', fontWeight: '600' }}>
                    {typeof value === 'number' ? value.toFixed(4) : value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default ThreatDetail;