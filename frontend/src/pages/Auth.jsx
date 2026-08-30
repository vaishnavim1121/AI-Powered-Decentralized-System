import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import api from '../services/api';
import SignalWave from '../components/SignalWave';
import '../styles/tokens.css';

const Auth = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (isLogin) {
        const response = await api.post('/login', { username, password });
        const token = response.data.access_token;
        
        if (!token) {
          toast.error('❌ No token received from server');
          setLoading(false);
          return;
        }
        
        localStorage.setItem('token', token);
        localStorage.setItem('username', username);
        
        toast.success('✅ Welcome back!');
        
        setTimeout(() => {
          navigate('/dashboard');
        }, 500);
        
      } else {
        if (password !== confirmPassword) {
          toast.error('❌ Passwords do not match');
          setLoading(false);
          return;
        }
        await api.post('/register', { username, password });
        toast.success('✅ Account created! Please login.');
        setIsLogin(true);
        setPassword('');
        setConfirmPassword('');
        setLoading(false);
      }
    } catch (err) {
      const msg = err.response?.data?.msg || 'Something went wrong';
      toast.error('❌ ' + msg);
      setLoading(false);
    }
  };

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'minmax(0, 1.1fr) minmax(0, 1fr)',
      minHeight: '100vh',
      height: '100vh',
      width: '100vw',
      background: '#f5f0eb',
      overflow: 'hidden'
    }}>
      {/* Left side - Branding with more content */}
      <div style={{
        background: '#1a1a2e',
        padding: '48px 48px 36px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        position: 'relative',
        overflow: 'hidden',
        minHeight: '100vh',
        height: '100%'
      }}>
        {/* Decorative background circles */}
        <div style={{
          position: 'absolute',
          top: '-100px',
          right: '-100px',
          width: '400px',
          height: '400px',
          borderRadius: '50%',
          background: 'rgba(193, 127, 89, 0.05)',
          pointerEvents: 'none'
        }} />
        <div style={{
          position: 'absolute',
          bottom: '-50px',
          left: '-50px',
          width: '200px',
          height: '200px',
          borderRadius: '50%',
          background: 'rgba(193, 127, 89, 0.08)',
          pointerEvents: 'none'
        }} />

        <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '24px', width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{
              fontFamily: 'var(--font-heading)',
              fontSize: '28px',
              color: '#f5f0eb'
            }}>ADCTIN</span>
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              color: '#c17f59',
              background: 'rgba(193, 127, 89, 0.2)',
              padding: '2px 12px',
              borderRadius: '12px',
              letterSpacing: '0.5px'
            }}>v1.0</span>
          </div>
          
          <div>
            <h1 style={{
              fontFamily: 'var(--font-heading)',
              fontSize: '42px',
              color: '#f5f0eb',
              lineHeight: 1.1,
              marginBottom: '20px'
            }}>
              {isLogin ? 'Welcome Back' : 'Join the Network'}
            </h1>
            <p style={{
              color: 'rgba(245, 240, 235, 0.6)',
              fontSize: '16px',
              lineHeight: 1.8,
              maxWidth: '380px',
              marginBottom: '32px'
            }}>
              {isLogin 
                ? 'Sign in to monitor threats and collaborate with the community.'
                : 'Create an account and start contributing to decentralized threat intelligence.'
              }
            </p>
          </div>

          {/* Feature highlights */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, minmax(120px, 1fr))',
            gap: '16px',
            width: '100%',
            maxWidth: '560px'
          }}>
            {[
              { icon: '🧠', label: 'AI-Powered', desc: 'Real-time detection' },
              { icon: '⛓️', label: 'Decentralized', desc: 'Blockchain secured' },
              { icon: '⚡', label: 'Real-time', desc: 'Instant alerts' }
            ].map((item, i) => (
              <div key={i} style={{
                background: 'rgba(255,255,255,0.05)',
                padding: '16px',
                borderRadius: '8px',
                border: '1px solid rgba(255,255,255,0.06)',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '24px', marginBottom: '4px' }}>{item.icon}</div>
                <div style={{ color: '#f5f0eb', fontSize: '12px', fontWeight: '600' }}>{item.label}</div>
                <div style={{ color: 'rgba(245, 240, 235, 0.4)', fontSize: '10px' }}>{item.desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ marginTop: 'auto', position: 'relative', zIndex: 1 }}>
          <div style={{ 
            background: 'rgba(255,255,255,0.05)', 
            borderRadius: '12px', 
            padding: '20px 24px',
            border: '1px solid rgba(255,255,255,0.08)'
          }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '8px'
            }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'rgba(245, 240, 235, 0.4)' }}>
                LIVE THREAT SIGNAL
              </span>
              <span style={{ 
                fontFamily: 'var(--font-mono)', 
                fontSize: '9px', 
                color: '#3a7d5a',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}>
                <span style={{ 
                  display: 'inline-block', 
                  width: '6px', 
                  height: '6px', 
                  borderRadius: '50%', 
                  background: '#3a7d5a',
                  animation: 'pulse 2s infinite'
                }} />
                LIVE
              </span>
            </div>
            <SignalWave 
              data={Array.from({ length: 60 }, (_, i) => 0.3 + Math.sin(i / 4) * 0.3 + Math.random() * 0.1)} 
              height={50} 
              color="#c17f59" 
            />
          </div>
          <div style={{ 
            marginTop: '16px', 
            display: 'flex', 
            justifyContent: 'space-between',
            fontFamily: 'var(--font-mono)',
            fontSize: '10px',
            color: 'rgba(245, 240, 235, 0.3)'
          }}>
            <span>🟢 Network: Active</span>
            <span>🔗 Nodes: 256</span>
            <span>⚠️ Threats: 1,247</span>
          </div>
        </div>
      </div>

      {/* Right side - Form */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 48px',
        background: '#f5f0eb',
        minHeight: '100vh',
        height: '100%'
      }}>
        <div style={{
          width: '100%',
          maxWidth: '420px'
        }}>
          <div style={{ marginBottom: '32px' }}>
            <h2 style={{
              fontFamily: 'var(--font-heading)',
              fontSize: '28px',
              color: '#1a1a2e',
              marginBottom: '8px'
            }}>
              {isLogin ? 'Sign In' : 'Create Account'}
            </h2>
            <p style={{ color: '#6b6560', fontSize: '14px' }}>
              {isLogin ? 'Enter your credentials to continue' : 'Start your journey with ADCTIN'}
            </p>
          </div>

          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '16px' }}>
              <label style={{
                display: 'block',
                fontSize: '13px',
                fontWeight: '500',
                color: '#2d2a24',
                marginBottom: '6px'
              }}>
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  border: '1px solid #e8e0d8',
                  borderRadius: '8px',
                  fontSize: '14px',
                  background: 'white',
                  transition: 'border-color 0.2s',
                  outline: 'none',
                  fontFamily: 'var(--font-body)'
                }}
                onFocus={(e) => e.target.style.borderColor = '#c17f59'}
                onBlur={(e) => e.target.style.borderColor = '#e8e0d8'}
                placeholder="Enter your username"
              />
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{
                display: 'block',
                fontSize: '13px',
                fontWeight: '500',
                color: '#2d2a24',
                marginBottom: '6px'
              }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  border: '1px solid #e8e0d8',
                  borderRadius: '8px',
                  fontSize: '14px',
                  background: 'white',
                  transition: 'border-color 0.2s',
                  outline: 'none',
                  fontFamily: 'var(--font-body)'
                }}
                onFocus={(e) => e.target.style.borderColor = '#c17f59'}
                onBlur={(e) => e.target.style.borderColor = '#e8e0d8'}
                placeholder="Enter your password"
              />
            </div>

            {!isLogin && (
              <div style={{ marginBottom: '16px' }}>
                <label style={{
                  display: 'block',
                  fontSize: '13px',
                  fontWeight: '500',
                  color: '#2d2a24',
                  marginBottom: '6px'
                }}>
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    padding: '12px 16px',
                    border: '1px solid #e8e0d8',
                    borderRadius: '8px',
                    fontSize: '14px',
                    background: 'white',
                    transition: 'border-color 0.2s',
                    outline: 'none',
                    fontFamily: 'var(--font-body)'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#c17f59'}
                  onBlur={(e) => e.target.style.borderColor = '#e8e0d8'}
                  placeholder="Confirm your password"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                padding: '14px',
                background: '#1a1a2e',
                color: '#f5f0eb',
                border: 'none',
                borderRadius: '8px',
                fontSize: '16px',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'background 0.2s',
                fontFamily: 'var(--font-body)',
                opacity: loading ? 0.7 : 1,
                marginBottom: '16px'
              }}
              onMouseEnter={(e) => { if (!loading) e.target.style.background = '#2d2a40' }}
              onMouseLeave={(e) => { if (!loading) e.target.style.background = '#1a1a2e' }}
            >
              {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
            </button>
          </form>

          <div style={{
            textAlign: 'center',
            color: '#6b6560',
            fontSize: '14px'
          }}>
            <button
              onClick={() => setIsLogin(!isLogin)}
              style={{
                background: 'none',
                border: 'none',
                color: '#c17f59',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '500',
                fontFamily: 'var(--font-body)',
                transition: 'color 0.2s'
              }}
              onMouseEnter={(e) => e.target.style.color = '#9e6a4a'}
              onMouseLeave={(e) => e.target.style.color = '#c17f59'}
            >
              {isLogin ? 'Create a new account' : 'I already have an account'}
            </button>
          </div>
        </div>
      </div>

      <ToastContainer position="top-right" autoClose={3000} />
    </div>
  );
};

export default Auth;