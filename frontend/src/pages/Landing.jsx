import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import SignalWave from '../components/SignalWave';
import '../styles/tokens.css';

const Landing = () => {
  const [threatData, setThreatData] = useState([]);
  const [showOptions, setShowOptions] = useState(false);
  
  useEffect(() => {
    const generateData = () => {
      const newData = Array.from({ length: 80 }, (_, i) => {
        const base = Math.sin(i / 6) * 0.5 + 0.5;
        const spike = Math.random() > 0.9 ? 0.8 + Math.random() * 0.2 : 0;
        return Math.min(1, Math.max(0, base + spike));
      });
      setThreatData(newData);
    };
    
    generateData();
    const interval = setInterval(() => {
      setThreatData(prev => {
        const newPoint = 0.3 + Math.random() * 0.7;
        return [...prev.slice(1), newPoint];
      });
    }, 3000);
    
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ minHeight: '100vh', background: '#f5f0eb', width: '100%' }}>
      {/* Navigation */}
      <nav style={{
        padding: '24px 48px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: '1px solid #e8e0d8',
        background: 'rgba(245, 240, 235, 0.95)',
        backdropFilter: 'blur(8px)',
        position: 'sticky',
        top: 0,
        zIndex: 100
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{
            fontFamily: 'var(--font-heading)',
            fontSize: '22px',
            color: '#1a1a2e'
          }}>ADCTIN</span>
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            color: '#c17f59',
            background: '#e8e0d8',
            padding: '2px 10px',
            borderRadius: '12px',
            letterSpacing: '0.5px'
          }}>v1.0</span>
        </div>
        <div style={{ display: 'flex', gap: '32px', alignItems: 'center' }}>
          <Link to="/about" style={{
            color: '#2d2a24',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'color 0.2s'
          }} onMouseEnter={e => e.target.style.color = '#c17f59'} onMouseLeave={e => e.target.style.color = '#2d2a24'}>
            About
          </Link>
          <Link to="/login" style={{
            color: '#2d2a24',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'color 0.2s'
          }} onMouseEnter={e => e.target.style.color = '#c17f59'} onMouseLeave={e => e.target.style.color = '#2d2a24'}>
            Sign In
          </Link>
          <Link to="/login" style={{
            background: '#1a1a2e',
            color: '#f5f0eb',
            padding: '10px 24px',
            borderRadius: '6px',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'background 0.2s'
          }} onMouseEnter={e => e.target.style.background = '#2d2a40'} onMouseLeave={e => e.target.style.background = '#1a1a2e'}>
            Get Started
          </Link>
        </div>
      </nav>

      {/* Hero Section - Full Width */}
      <section style={{
        padding: '80px 48px 60px',
        maxWidth: '1200px',
        margin: '0 auto',
        width: '100%'
      }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '60px',
          alignItems: 'center'
        }}>
          <div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: '#c17f59',
                textTransform: 'uppercase',
                letterSpacing: '2px',
                background: '#e8e0d8',
                padding: '4px 14px',
                borderRadius: '20px',
                display: 'inline-block',
                marginBottom: '16px'
              }}>
                Threat Intelligence Network
              </span>
            </motion.div>
            
            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
              style={{
                fontFamily: 'var(--font-heading)',
                fontSize: '52px',
                color: '#1a1a2e',
                lineHeight: 1.1,
                marginBottom: '20px'
              }}
            >
              AI-Powered<br />
              <span style={{ color: '#c17f59' }}>Decentralized</span><br />
              Threat Defense
            </motion.h1>
            
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              style={{
                fontSize: '18px',
                color: '#6b6560',
                lineHeight: 1.7,
                marginBottom: '32px',
                maxWidth: '480px'
              }}
            >
              Real-time threat detection powered by AI, secured by blockchain.
              Share and validate threat intelligence across a decentralized network.
            </motion.p>
            
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3 }}
              style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}
            >
              <Link to="/login" style={{
                background: '#1a1a2e',
                color: '#f5f0eb',
                padding: '14px 36px',
                borderRadius: '6px',
                fontSize: '16px',
                fontWeight: '600',
                transition: 'background 0.2s'
              }} onMouseEnter={e => e.target.style.background = '#2d2a40'} onMouseLeave={e => e.target.style.background = '#1a1a2e'}>
                Submit a Threat
              </Link>
              <Link to="/about" style={{
                border: '2px solid #e8e0d8',
                color: '#2d2a24',
                padding: '14px 36px',
                borderRadius: '6px',
                fontSize: '16px',
                fontWeight: '500',
                transition: 'border-color 0.2s'
              }} onMouseEnter={e => e.target.style.borderColor = '#c17f59'} onMouseLeave={e => e.target.style.borderColor = '#e8e0d8'}>
                Learn How It Works
              </Link>
            </motion.div>
          </div>
          
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.8, delay: 0.3 }}
            style={{
              background: 'white',
              padding: '32px',
              borderRadius: '16px',
              boxShadow: '0 8px 40px rgba(26, 26, 46, 0.06)',
              border: '1px solid #e8e0d8'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#6b6560', letterSpacing: '0.5px' }}>
                LIVE THREAT SIGNAL
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#c17f59' }}>
                ● ACTIVE
              </span>
            </div>
            <SignalWave data={threatData} height={160} color="#c17f59" />
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginTop: '12px',
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              color: '#6b6560'
            }}>
              <span>Confidence Score</span>
              <span>{threatData.length > 0 ? `${Math.round(threatData[threatData.length - 1] * 100)}%` : '0%'}</span>
            </div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr 1fr',
              gap: '12px',
              marginTop: '20px',
              paddingTop: '20px',
              borderTop: '1px solid #f0ece7'
            }}>
              <div>
                <div style={{ fontSize: '11px', color: '#6b6560' }}>Threats Detected</div>
                <div style={{ fontFamily: 'var(--font-heading)', fontSize: '24px', color: '#1a1a2e' }}>1,247</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#6b6560' }}>Malicious</div>
                <div style={{ fontFamily: 'var(--font-heading)', fontSize: '24px', color: '#d45c4c' }}>89%</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#6b6560' }}>Network Nodes</div>
                <div style={{ fontFamily: 'var(--font-heading)', fontSize: '24px', color: '#1a1a2e' }}>256</div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* How It Works Section */}
      <motion.section
        initial={{ opacity: 0, y: 40 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        viewport={{ once: true }}
        style={{
          padding: '80px 48px',
          maxWidth: '1200px',
          margin: '0 auto',
          borderTop: '1px solid #e8e0d8',
          width: '100%'
        }}
      >
        <h2 style={{
          fontFamily: 'var(--font-heading)',
          fontSize: '36px',
          color: '#1a1a2e',
          textAlign: 'center',
          marginBottom: '12px'
        }}>
          How It Works
        </h2>
        <p style={{
          fontSize: '18px',
          color: '#6b6560',
          textAlign: 'center',
          maxWidth: '560px',
          margin: '0 auto 48px'
        }}>
          Three layers of intelligent defense working together
        </p>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr 1fr',
          gap: '32px'
        }}>
          {[
            {
              number: '01',
              title: 'AI Detection',
              description: 'Machine learning models analyze threat patterns with 95% accuracy, identifying malicious activity in real-time.',
              icon: '🧠'
            },
            {
              number: '02',
              title: 'Blockchain Storage',
              description: 'Immutable ledger secures threat intelligence across decentralized nodes, ensuring data integrity and trust.',
              icon: '⛓️'
            },
            {
              number: '03',
              title: 'Real-time Alerts',
              description: 'Instant notifications when threats are detected and verified, enabling rapid response to emerging attacks.',
              icon: '⚡'
            }
          ].map((item, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              viewport={{ once: true }}
              style={{
                background: 'white',
                padding: '32px',
                borderRadius: '12px',
                border: '1px solid #e8e0d8',
                textAlign: 'center'
              }}
            >
              <div style={{ fontSize: '36px', marginBottom: '12px' }}>{item.icon}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#c17f59', marginBottom: '8px' }}>
                {item.number}
              </div>
              <h3 style={{ fontFamily: 'var(--font-heading)', fontSize: '20px', color: '#1a1a2e', marginBottom: '8px' }}>
                {item.title}
              </h3>
              <p style={{ color: '#6b6560', fontSize: '14px', lineHeight: 1.6 }}>
                {item.description}
              </p>
            </motion.div>
          ))}
        </div>
      </motion.section>

      {/* Footer */}
      <footer style={{
        padding: '32px 48px',
        borderTop: '1px solid #e8e0d8',
        textAlign: 'center',
        color: '#6b6560',
        fontSize: '14px',
        background: 'white'
      }}>
        <p>© 2025 ADCTIN — AI-Powered Decentralized Cyber Threat Intelligence Network</p>
      </footer>
    </div>
  );
};

export default Landing;