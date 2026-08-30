import { Link, useNavigate } from 'react-router-dom';
import { clearToken } from '../services/api';

export default function Navbar() {
  const navigate = useNavigate();
  const handleLogout = () => {
    clearToken();
    navigate('/login');
  };
  return (
    <nav style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '20px 32px', borderBottom: '1px solid var(--border)' }}>
      <Link to="/dashboard" style={{ fontFamily: 'var(--font-display)', fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', textDecoration: 'none' }}>
        CTI Network
      </Link>
      <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
        <Link to="/dashboard" style={{ color: 'var(--text-secondary)', textDecoration: 'none', fontSize: 14 }}>Dashboard</Link>
        <Link to="/about" style={{ color: 'var(--text-secondary)', textDecoration: 'none', fontSize: 14 }}>How it works</Link>
        <button onClick={handleLogout} style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 14px', fontSize: 14, cursor: 'pointer', color: 'var(--text-primary)' }}>
          Log out
        </button>
      </div>
    </nav>
  );
}