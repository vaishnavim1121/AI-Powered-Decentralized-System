import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

// Create axios instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add token to every request
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Only redirect to login for 401, but NOT for login/register requests
    if (error.response?.status === 401) {
      const currentPath = window.location.pathname;
      // Don't redirect if we're already on login/register
      if (currentPath !== '/login' && currentPath !== '/register') {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// Auth API calls
export const register = (username, password) => {
  return api.post('/register', { username, password });
};

export const login = (username, password) => {
  return api.post('/login', { username, password });
};

export const clearToken = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
};

// Threat API calls
export const submitThreat = (payload) => {
  return api.post('/threat', payload);
};

export const fetchThreats = () => {
  return api.get('/threats');
};

export const fetchAlerts = () => {
  return api.get('/alerts');
};

export default api;