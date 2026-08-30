import { BrowserRouter, Routes, Route } from 'react-router-dom';
import './styles/tokens.css';
import Landing from './pages/Landing';
import Auth from './pages/Auth';
import Dashboard from './pages/Dashboard';
import About from './pages/About';
import ThreatDetail from './pages/ThreatDetail';
import ProtectedRoute from './components/ProtectedRoute';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Auth />} />
        <Route path="/about" element={<About />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/threats/:id" element={<ProtectedRoute><ThreatDetail /></ProtectedRoute>} />
      </Routes>
    </BrowserRouter>
  );
}