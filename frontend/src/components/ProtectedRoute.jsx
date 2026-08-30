import React from 'react';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  console.log('ProtectedRoute - token exists?', !!token); // Debug log
  
  if (!token) {
    console.log('No token, redirecting to login');
    return <Navigate to="/login" replace />;
  }
  
  console.log('Token found, rendering protected component');
  return children;
};

export default ProtectedRoute;