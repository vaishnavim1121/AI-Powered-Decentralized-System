import axios from 'axios';

export const TOKEN_KEY = 'adctin_token';

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (token) => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
  headers: { 'Content-Type': 'application/json' },
});

// Attach the JWT to every outgoing request.
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// A 401 means the token is missing/expired: drop it and bounce to the login page.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      clearToken();
      if (window.location.pathname !== '/login') {
        window.location.replace('/login');
      }
    }
    return Promise.reject(error);
  }
);

// ---------- API calls ----------
export const register = (username, password) =>
  api.post('/register', { username, password });

export const login = (username, password) =>
  api.post('/login', { username, password });

export const submitThreat = (payload) => api.post('/threat', payload);

export const fetchThreats = () => api.get('/threats');

export const fetchAlerts = () => api.get('/alerts');

export default api;
