import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import '../styles/tokens.css';

const About = () => {
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
          <Link to="/" style={{
            fontFamily: 'var(--font-heading)',
            fontSize: '22px',
            color: '#1a1a2e',
            textDecoration: 'none'
          }}>ADCTIN</Link>
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
          <Link to="/" style={{
            color: '#2d2a24',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'color 0.2s',
            textDecoration: 'none'
          }}>Home</Link>
          <Link to="/login" style={{
            background: '#1a1a2e',
            color: '#f5f0eb',
            padding: '10px 24px',
            borderRadius: '6px',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'background 0.2s',
            textDecoration: 'none'
          }}>Get Started</Link>
        </div>
      </nav>

      {/* About Content */}
      <section style={{
        padding: '80px 48px 60px',
        maxWidth: '900px',
        margin: '0 auto',
        width: '100%'
      }}>
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <h1 style={{
            fontFamily: 'var(--font-heading)',
            fontSize: '44px',
            color: '#1a1a2e',
            marginBottom: '24px',
            lineHeight: 1.1
          }}>
            About <span style={{ color: '#c17f59' }}>ADCTIN</span>
          </h1>
          <p style={{
            fontSize: '18px',
            color: '#6b6560',
            lineHeight: 1.8,
            marginBottom: '40px'
          }}>
            The AI-Powered Decentralized Cyber Threat Intelligence Network (ADCTIN) 
            is a next-generation platform that combines artificial intelligence and 
            blockchain technology to create a secure, collaborative threat intelligence ecosystem.
          </p>

          <div style={{
            display: 'grid',
            gap: '32px'
          }}>
            {/* How It Works */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              style={{
                background: 'white',
                padding: '32px',
                borderRadius: '12px',
                border: '1px solid #e8e0d8'
              }}
            >
              <h2 style={{
                fontFamily: 'var(--font-heading)',
                fontSize: '24px',
                color: '#1a1a2e',
                marginBottom: '12px'
              }}>🧠 How It Works</h2>
              <p style={{ color: '#6b6560', lineHeight: 1.7 }}>
                ADCTIN uses machine learning models to analyze threat indicators — 
                malicious IPs, phishing URLs, and malware hashes — with high accuracy. 
                Verified threats are immutably stored on a blockchain, ensuring 
                transparency and tamper-proof records.
              </p>
            </motion.div>

            {/* Privacy & Trust */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              style={{
                background: 'white',
                padding: '32px',
                borderRadius: '12px',
                border: '1px solid #e8e0d8'
              }}
            >
              <h2 style={{
                fontFamily: 'var(--font-heading)',
                fontSize: '24px',
                color: '#1a1a2e',
                marginBottom: '12px'
              }}>🔒 Privacy & Trust</h2>
              <p style={{ color: '#6b6560', lineHeight: 1.7 }}>
                Zero-Knowledge Proof mechanisms enable organizations to contribute 
                threat data without exposing sensitive internal details. A token-based 
                reputation economy incentivizes active participation, creating a 
                sustainable, community-driven defense network.
              </p>
            </motion.div>

            {/* Real-Time Defense */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              style={{
                background: 'white',
                padding: '32px',
                borderRadius: '12px',
                border: '1px solid #e8e0d8'
              }}
            >
              <h2 style={{
                fontFamily: 'var(--font-heading)',
                fontSize: '24px',
                color: '#1a1a2e',
                marginBottom: '12px'
              }}>⚡ Real-Time Defense</h2>
              <p style={{ color: '#6b6560', lineHeight: 1.7 }}>
                Real-time alerts, a threat decay scoring model, and an interactive 
                dashboard ensure the platform remains accurate and operationally effective. 
                Organizations can respond to emerging threats faster than ever before.
              </p>
            </motion.div>

            {/* Who It's For */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
              style={{
                background: 'white',
                padding: '32px',
                borderRadius: '12px',
                border: '1px solid #e8e0d8'
              }}
            >
              <h2 style={{
                fontFamily: 'var(--font-heading)',
                fontSize: '24px',
                color: '#1a1a2e',
                marginBottom: '12px'
              }}>🛡️ Who It's For</h2>
              <p style={{ color: '#6b6560', lineHeight: 1.7 }}>
                ADCTIN is designed for cybersecurity teams, enterprises, government 
                agencies, and security researchers who need a reliable, transparent, 
                and collaborative threat intelligence platform.
              </p>
            </motion.div>
          </div>

          {/* Call to Action */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.5 }}
            style={{
              marginTop: '48px',
              textAlign: 'center',
              padding: '40px',
              background: 'white',
              borderRadius: '12px',
              border: '1px solid #e8e0d8'
            }}
          >
            <h2 style={{
              fontFamily: 'var(--font-heading)',
              fontSize: '28px',
              color: '#1a1a2e',
              marginBottom: '12px'
            }}>
              Ready to contribute?
            </h2>
            <p style={{ color: '#6b6560', marginBottom: '24px' }}>
              Join the network and start collaborating on cyber threat intelligence.
            </p>
            <Link to="/login" style={{
              background: '#1a1a2e',
              color: '#f5f0eb',
              padding: '14px 40px',
              borderRadius: '6px',
              fontSize: '16px',
              fontWeight: '600',
              transition: 'background 0.2s',
              display: 'inline-block',
              textDecoration: 'none'
            }}>Get Started Now</Link>
          </motion.div>
        </motion.div>
      </section>

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

export default About;