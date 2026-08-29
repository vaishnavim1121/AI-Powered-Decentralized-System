import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { clearToken, fetchAlerts, fetchThreats, submitThreat } from '../services/api';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

// Order matters: the model was trained on these five columns, in this order.
const FEATURE_NAMES = [
  'packet_rate',
  'payload_entropy',
  'conn_duration',
  'failed_logins',
  'port_scan_count',
];

const ALERT_POLL_MS = 5000;

const emptyFeatures = () => FEATURE_NAMES.map(() => '');

export default function Dashboard() {
  const [fileHash, setFileHash] = useState('');
  const [url, setUrl] = useState('');
  const [features, setFeatures] = useState(emptyFeatures);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [formError, setFormError] = useState('');

  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [pollError, setPollError] = useState('');

  const navigate = useNavigate();
  const seenAlertIds = useRef(new Set());
  const [newAlertCount, setNewAlertCount] = useState(0);

  const loadThreats = useCallback(async () => {
    const { data } = await fetchThreats();
    setThreats(data);
  }, []);

  const loadAlerts = useCallback(async () => {
    const { data } = await fetchAlerts();
    setAlerts(data);

    // Count alerts we have not seen before, so the badge means something.
    let fresh = 0;
    data.forEach((a) => {
      if (!seenAlertIds.current.has(a.id)) {
        seenAlertIds.current.add(a.id);
        fresh += 1;
      }
    });
    if (fresh > 0) setNewAlertCount((n) => n + fresh);
  }, []);

  // Poll /alerts every 5s, and refresh the chart data alongside it.
  useEffect(() => {
    let cancelled = false;

    const tick = async () => {
      try {
        await Promise.all([loadAlerts(), loadThreats()]);
        if (!cancelled) setPollError('');
      } catch (err) {
        // 401 is handled globally by the axios interceptor.
        if (!cancelled && err.response?.status !== 401) {
          setPollError('Lost contact with the API - retrying.');
        }
      }
    };

    tick();
    const id = setInterval(tick, ALERT_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [loadAlerts, loadThreats]);

  const handleFeatureChange = (index, value) => {
    setFeatures((prev) => prev.map((v, i) => (i === index ? value : v)));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    setResult(null);

    if (!fileHash.trim() && !url.trim()) {
      setFormError('Provide a file hash or a URL to identify the sample.');
      return;
    }
    if (features.some((f) => f.trim() === '' || Number.isNaN(Number(f)))) {
      setFormError('All five features must be numbers.');
      return;
    }

    setSubmitting(true);
    try {
      const { data } = await submitThreat({
        file_hash: fileHash.trim() || null,
        url: url.trim() || null,
        features: features.map(Number),
      });
      setResult(data);
      setFileHash('');
      setUrl('');
      setFeatures(emptyFeatures());
      await Promise.all([loadThreats(), loadAlerts()]);
    } catch (err) {
      setFormError(err.response?.data?.msg || 'Submission failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleLogout = () => {
    clearToken();
    navigate('/login', { replace: true });
  };

  const maliciousCount = threats.filter((t) => t.prediction === 'malicious').length;
  const benignCount = threats.filter((t) => t.prediction === 'benign').length;

  const chartData = {
    labels: ['Malicious', 'Benign'],
    datasets: [
      {
        label: 'Threats',
        data: [maliciousCount, benignCount],
        backgroundColor: ['#c0392b', '#1e8449'],
        borderRadius: 4,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      title: { display: true, text: 'Verdicts across the 20 most recent threats' },
    },
    scales: {
      y: { beginAtZero: true, ticks: { precision: 0 } },
    },
  };

  return (
    <div className="dashboard">
      <header className="topbar">
        <h1>Threat Dashboard</h1>
        <div className="topbar-right">
          <span className="badge" title="Alerts seen since page load">
            {newAlertCount} new
          </span>
          <button type="button" className="link" onClick={handleLogout}>
            Log out
          </button>
        </div>
      </header>

      {pollError && <div className="error banner">{pollError}</div>}

      <div className="grid">
        <section className="card">
          <h2>Submit a threat</h2>
          <form onSubmit={handleSubmit}>
            <label htmlFor="file_hash">File hash</label>
            <input
              id="file_hash"
              value={fileHash}
              onChange={(e) => setFileHash(e.target.value)}
              placeholder="SHA-256 of the sample"
            />

            <label htmlFor="url">URL</label>
            <input
              id="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/payload"
            />

            <fieldset>
              <legend>Features</legend>
              {FEATURE_NAMES.map((name, i) => (
                <div className="feature-row" key={name}>
                  <label htmlFor={name}>{name}</label>
                  <input
                    id={name}
                    type="number"
                    step="any"
                    value={features[i]}
                    onChange={(e) => handleFeatureChange(i, e.target.value)}
                  />
                </div>
              ))}
            </fieldset>

            {formError && <div className="error">{formError}</div>}

            <button type="submit" disabled={submitting}>
              {submitting ? 'Analysing...' : 'Analyse threat'}
            </button>
          </form>

          {result && (
            <div className={`result ${result.prediction}`}>
              <strong>{result.prediction}</strong>
              <span> - confidence {(result.confidence * 100).toFixed(1)}%</span>
              <div className="tx" title={result.tx_hash}>
                tx: {result.tx_hash || 'n/a'}
              </div>
            </div>
          )}
        </section>

        <section className="card">
          <h2>Verdict breakdown</h2>
          <div className="chart-wrap">
            <Bar data={chartData} options={chartOptions} />
          </div>
          <p className="muted">
            {maliciousCount} malicious - {benignCount} benign
          </p>
        </section>

        <section className="card">
          <h2>
            Live alerts <span className="muted">(polling every {ALERT_POLL_MS / 1000}s)</span>
          </h2>
          {alerts.length === 0 ? (
            <p className="muted">No unread alerts.</p>
          ) : (
            <ul className="alert-list">
              {alerts.map((a) => (
                <li key={a.id}>
                  <span>{a.message}</span>
                  <time>{new Date(a.created_at).toLocaleString()}</time>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card">
          <h2>Recent threats</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                  <th>Submitted</th>
                </tr>
              </thead>
              <tbody>
                {threats.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="muted">
                      Nothing submitted yet.
                    </td>
                  </tr>
                ) : (
                  threats.map((t) => (
                    <tr key={t.id}>
                      <td>{t.id}</td>
                      <td className={t.prediction}>{t.prediction}</td>
                      <td>{(t.confidence * 100).toFixed(1)}%</td>
                      <td>{new Date(t.created_at).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
