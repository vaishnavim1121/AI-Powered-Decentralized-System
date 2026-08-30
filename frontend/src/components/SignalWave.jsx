import React, { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

const SignalWave = ({ data = [], height = 120, width = '100%', color = '#c17f59' }) => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement?.getBoundingClientRect() || { width: 600 };
    
    canvas.width = rect.width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${height}px`;
    
    ctx.scale(dpr, dpr);
    
    const w = rect.width;
    const h = height;
    const mid = h / 2;
    
    ctx.clearRect(0, 0, w, h);
    
    // Subtle grid
    ctx.strokeStyle = 'rgba(26, 26, 46, 0.04)';
    ctx.lineWidth = 0.5;
    for (let y = 0; y <= h; y += h / 4) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }
    
    const points = data.length > 0 ? data : Array.from({ length: 80 }, (_, i) => {
      const base = Math.sin(i / 8) * 0.6 + 0.5;
      const spike = Math.random() > 0.92 ? 1.0 : 0;
      return Math.min(1, Math.max(0, base + spike * 0.4));
    });
    
    ctx.beginPath();
    const step = w / (points.length - 1);
    
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, color);
    grad.addColorStop(0.4, color);
    grad.addColorStop(1, 'rgba(193, 127, 89, 0.05)');
    
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    
    points.forEach((p, i) => {
      const x = i * step;
      const y = mid - (p - 0.5) * (h * 0.8);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
    
    const lastX = (points.length - 1) * step;
    ctx.lineTo(lastX, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
    
    points.forEach((p, i) => {
      if (p > 0.85) {
        const x = i * step;
        const y = mid - (p - 0.5) * (h * 0.8);
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.shadowColor = color;
        ctx.shadowBlur = 12;
        ctx.beginPath();
        ctx.arc(x, y, 8, 0, Math.PI * 2);
        ctx.fillStyle = color + '30';
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    });
    
  }, [data, height, color]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8 }}
      style={{ width, height }}
    >
      <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block' }} />
    </motion.div>
  );
};

export default SignalWave;