'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import axios from 'axios';

export default function AuthPage() {
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({ email: '', username: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [statusMsg, setStatusMsg] = useState({ type: '', text: '' });
  const [loading, setLoading] = useState(false);

  const resetForm = () => {
    setFormData({ email: '', username: '', password: '' });
    setShowPassword(false);
  };

  const rules = {
    length: formData.password.length >= 8,
    upper: /[A-Z]/.test(formData.password),
    lower: /[a-z]/.test(formData.password),
    number: /[0-9]/.test(formData.password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password),
  };

  const isPasswordValid = Object.values(rules).every(Boolean);

  const generateStrongPassword = () => {
    const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowers = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const specials = '!@#$%^&*()_+~|}{[]:;?><,.-=';
    const allChars = uppers + lowers + numbers + specials;

    const guaranteed = [
      uppers[Math.floor(Math.random() * uppers.length)],
      lowers[Math.floor(Math.random() * lowers.length)],
      numbers[Math.floor(Math.random() * numbers.length)],
      specials[Math.floor(Math.random() * specials.length)],
    ];

    for (let i = 0; i < 10; i++) {
      guaranteed.push(allChars[Math.floor(Math.random() * allChars.length)]);
    }

    for (let i = guaranteed.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [guaranteed[i], guaranteed[j]] = [guaranteed[j], guaranteed[i]];
    }

    setFormData({ ...formData, password: guaranteed.join('') });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!isLogin && !isPasswordValid) {
      setStatusMsg({ type: 'error', text: 'Please satisfy all password complexity criteria.' });
      return;
    }

    setLoading(true);
    setStatusMsg({ type: '', text: '' });

    const endpoint = isLogin ? 'http://127.0.0.1:8000/auth/login' : 'http://127.0.0.1:8000/auth/register';
    const payload = isLogin
      ? { username: formData.username, password: formData.password }
      : { email: formData.email, username: formData.username, password: formData.password };

    try {
      const res = await axios.post(endpoint, payload);
      if (isLogin) {
        localStorage.setItem('access_token', res.data.access_token);
        router.push('/dashboard');
      } else {
        setStatusMsg({ type: 'success', text: 'Operator registered successfully! You can now sign in.' });
        resetForm();
        setIsLogin(true);
      }
    } catch (err) {
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        setStatusMsg({ type: 'error', text: Array.isArray(detail) ? detail.map(d => d.msg).join(', ') : detail });
      } else {
        setStatusMsg({ type: 'error', text: 'Cannot connect to backend service (Port 5000).' });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#0a0d14',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Segoe UI, Roboto, sans-serif',
      color: '#e2e8f0',
      padding: '20px'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '430px',
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '12px',
        padding: '32px',
        boxShadow: '0 8px 30px rgba(0, 0, 0, 0.5)'
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <div style={{
            display: 'inline-block',
            padding: '6px 12px',
            borderRadius: '6px',
            backgroundColor: '#1e293b',
            color: '#38bdf8',
            fontWeight: 'bold',
            fontSize: '12px',
            letterSpacing: '1.2px',
            textTransform: 'uppercase',
            marginBottom: '10px',
            border: '1px solid #334155'
          }}>
            SOC Threat Agent
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 6px 0', color: '#f8fafc' }}>
            {isLogin ? 'Security Analyst Login' : 'Register Operator'}
          </h2>
          <p style={{ fontSize: '13px', color: '#94a3b8', margin: 0 }}>
            {isLogin ? 'Enter SOC credentials to access threat platform' : 'Configure role credentials & complexity'}
          </p>
        </div>

        {/* Status Notification */}
        {statusMsg.text && (
          <div style={{
            padding: '10px 14px',
            borderRadius: '6px',
            fontSize: '13px',
            marginBottom: '16px',
            backgroundColor: statusMsg.type === 'error' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
            color: statusMsg.type === 'error' ? '#f87171' : '#4ade80',
            border: `1px solid ${statusMsg.type === 'error' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)'}`
          }}>
            {statusMsg.text}
          </div>
        )}

        <form onSubmit={handleSubmit} autoComplete="off">
          {!isLogin && (
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>EMAIL</label>
              <input
                type="email"
                required
                autoComplete="off"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  backgroundColor: '#0f172a',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  color: '#fff',
                  fontSize: '14px',
                  boxSizing: 'border-box'
                }}
                placeholder="analyst@soc.local"
              />
            </div>
          )}

          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>USERNAME</label>
            <input
              type="text"
              required
              autoComplete="off"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              style={{
                width: '100%',
                padding: '10px 12px',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#fff',
                fontSize: '14px',
                boxSizing: 'border-box'
              }}
              placeholder="operator_1"
            />
          </div>

          <div style={{ marginBottom: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <label style={{ fontSize: '12px', color: '#94a3b8' }}>PASSWORD</label>
              {!isLogin && (
                <button
                  type="button"
                  onClick={generateStrongPassword}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#38bdf8',
                    fontSize: '11px',
                    cursor: 'pointer',
                    textDecoration: 'underline',
                    padding: 0
                  }}
                >
                  ⚡ Suggest a strong password
                </button>
              )}
            </div>

            <div style={{ position: 'relative', width: '100%' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                autoComplete="new-password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                style={{
                  width: '100%',
                  padding: '10px 40px 10px 12px',
                  backgroundColor: '#0f172a',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  color: '#fff',
                  fontSize: '14px',
                  boxSizing: 'border-box'
                }}
                placeholder="••••••••••••"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: showPassword ? '#38bdf8' : '#64748b',
                  padding: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
                title={showPassword ? 'Hide Password' : 'Show Password'}
              >
                {showPassword ? (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                    <line x1="1" y1="1" x2="23" y2="23"></line>
                  </svg>
                ) : (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                  </svg>
                )}
              </button>
            </div>
          </div>

          {/* Password Validation Checklist */}
          {!isLogin && formData.password.length > 0 && (
            <div style={{
              backgroundColor: '#0f172a',
              border: '1px solid #1e293b',
              borderRadius: '6px',
              padding: '10px 12px',
              marginBottom: '16px',
              fontSize: '12px',
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '6px'
            }}>
              <span style={{ color: rules.length ? '#4ade80' : '#94a3b8' }}>
                {rules.length ? '✓' : '○'} Min 8 characters
              </span>
              <span style={{ color: rules.upper ? '#4ade80' : '#94a3b8' }}>
                {rules.upper ? '✓' : '○'} Uppercase (A-Z)
              </span>
              <span style={{ color: rules.lower ? '#4ade80' : '#94a3b8' }}>
                {rules.lower ? '✓' : '○'} Lowercase (a-z)
              </span>
              <span style={{ color: rules.number ? '#4ade80' : '#94a3b8' }}>
                {rules.number ? '✓' : '○'} Number (0-9)
              </span>
              <span style={{ color: rules.special ? '#4ade80' : '#94a3b8', gridColumn: 'span 2' }}>
                {rules.special ? '✓' : '○'} Symbol (!@#$%^&*)
              </span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || (!isLogin && formData.password && !isPasswordValid)}
            style={{
              width: '100%',
              padding: '11px',
              backgroundColor: (!isLogin && formData.password && !isPasswordValid) ? '#334155' : '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontWeight: '600',
              fontSize: '14px',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.2s'
            }}
          >
            {loading ? 'Processing...' : isLogin ? 'Sign In' : 'Create Operator Account'}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '20px', fontSize: '13px', color: '#64748b' }}>
          {isLogin ? "Need access credentials? " : "Already configured? "}
          <button
            type="button"
            onClick={() => {
              setIsLogin(!isLogin);
              resetForm();
              setStatusMsg({ type: '', text: '' });
            }}
            style={{
              background: 'none',
              border: 'none',
              color: '#38bdf8',
              cursor: 'pointer',
              fontWeight: '500',
              textDecoration: 'underline',
              padding: 0
            }}
          >
            {isLogin ? 'Register here' : 'Sign in'}
          </button>
        </div>
      </div>
    </div>
  );
}