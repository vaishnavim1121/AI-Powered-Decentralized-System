import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import Navbar from '../components/Navbar';
import { fetchThreatDetail } from '../services/api';

export default function ThreatDetail() {
  const { id } = useParams();
  const [threat, setThreat] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchThreatDetail(id)
      .then((res) => setThreat(res.data))
      .catch(() => setError('Could not load this threat — it may not exist, or the API is unreachable.'));
  }, [id]);

  return (
    <div>
      <Navbar />
      <div style={{ maxWidth: 640, margin: '0 auto', padding: '32px 24px' }}>
        <Link to="/dashboard" style={{ fontSize: 13, color: 'var(--text-secondary)', textDecoration: 'none' }}>&larr; Back to dashboard</Link>

        {error && (
          <p style={{ background: 'var(--signal-alert-bg)', color: 'var(--signal-alert)', padding: '10px 16px', borderRadius: 'var(--radius-sm)', marginTop: 20 }}>
            {error}
          </p>
        )}

        {!threat && !error && <p style={{ marginTop: 20, color: 'var(--text-secondary)' }}>Loading…</p>}

        {threat && (
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ marginTop: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
              <span style={{
                fontSize: 12, padding: '3px 10px', borderRadius: 20,
                background: threat.prediction === 'malicious' ? 'var(--signal-alert-bg)' : 'var(--signal-verified-bg)',
                color: threat.prediction === 'malicious' ? 'var(--signal-alert)' : 'var(--signal-verified)',
              }}>{threat.prediction}</span>
              <span className="mono-num" style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{(threat.confidence * 100).toFixed(1)}% confidence</span>
            </div>
            <h1 style={{ fontSize: 22, margin: '0 0 20px' }}>Threat #{threat.id}</h1>

            <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 16 }}>
              {threat.file_hash && (
                <div style={{ marginBottom: 12 }}>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '0 0 4px' }}>File hash</p>
                  <p className="mono-num" style={{ fontSize: 13, wordBreak: 'break-all', margin: 0 }}>{threat.file_hash}</p>
                </div>
              )}
              {threat.url && (
                <div style={{ marginBottom: 12 }}>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '0 0 4px' }}>URL</p>
                  <p style={{ fontSize: 13, wordBreak: 'break-all', margin: 0 }}>{threat.url}</p>
                </div>
              )}
              <div>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '0 0 4px' }}>Submitted</p>
                <p style={{ fontSize: 13, margin: 0 }}>{new Date(threat.created_at).toLocaleString()}</p>
              </div>
            </div>

            {threat.explanation && (
              <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 16 }}>
                <p style={{ fontSize: 13, fontWeight: 600, margin: '0 0 10px' }}>Why the model flagged this</p>
                {Object.entries(threat.explanation).map(([feature, weight]) => (
                  <div key={feature} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, padding: '4px 0' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{feature}</span>
                    <span className="mono-num">{typeof weight === 'number' ? weight.toFixed(2) : String(weight)}</span>
                  </div>
                ))}
              </div>
            )}

            {threat.blockchain_tx && (
              <div style={{ background: 'var(--bg-ink)', color: 'var(--text-on-ink)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-on-ink-muted)', margin: '0 0 6px' }}>Verified on-chain</p>
                <p className="mono-num" style={{ fontSize: 12, wordBreak: 'break-all', margin: 0 }}>{threat.blockchain_tx}</p>
              </div>
            )}
          </motion.div>
        )}
      </div>
    </div>
  );
}