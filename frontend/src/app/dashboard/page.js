'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function DashboardPage() {
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('access_token');

    if (!token) {
      router.replace('/');
    }
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    router.replace('/');
  };

  return (
    <main
      style={{
        minHeight: '100vh',
        backgroundColor: '#0a0d14',
        color: '#e2e8f0',
        padding: '40px 20px',
        fontFamily: 'Segoe UI, Roboto, sans-serif',
      }}
    >
      <div
        style={{
          maxWidth: '1000px',
          margin: '0 auto',
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '40px',
          }}
        >
          <div>
            <div
              style={{
                color: '#38bdf8',
                fontSize: '12px',
                fontWeight: 'bold',
                letterSpacing: '1px',
              }}
            >
              SOC THREAT AGENT
            </div>

            <h1
              style={{
                color: '#f8fafc',
                margin: '8px 0',
              }}
            >
              Security Dashboard
            </h1>

            <p style={{ color: '#94a3b8' }}>
              Select a security analysis module.
            </p>
          </div>

          <button
            onClick={handleLogout}
            style={{
              padding: '10px 18px',
              borderRadius: '6px',
              border: '1px solid #334155',
              backgroundColor: '#1e293b',
              color: '#f8fafc',
              cursor: 'pointer',
            }}
          >
            Logout
          </button>
        </div>

        {/* Static Analysis Card */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '20px',
          }}
        >
          <div
            style={{
              backgroundColor: '#111827',
              border: '1px solid #1f2937',
              borderRadius: '12px',
              padding: '24px',
            }}
          >
            <div
              style={{
                color: '#38bdf8',
                fontSize: '13px',
                fontWeight: 'bold',
                marginBottom: '10px',
              }}
            >
              STATIC ANALYSIS
            </div>

            <h2
              style={{
                color: '#f8fafc',
                fontSize: '20px',
              }}
            >
              Threat Analyzer
            </h2>

            <p
              style={{
                color: '#94a3b8',
                lineHeight: '1.6',
              }}
            >
              Analyze text and scripts for suspicious
              keywords, PowerShell commands, encoded
              content, and other static indicators.
            </p>

            <button
              onClick={() => router.push('/analysis')}
              style={{
                marginTop: '15px',
                width: '100%',
                padding: '12px',
                border: 'none',
                borderRadius: '7px',
                backgroundColor: '#0284c7',
                color: '#fff',
                fontWeight: '600',
                cursor: 'pointer',
              }}
            >
              Open Static Analysis
            </button>
          </div>
        </div>
      </div>
    </main>
  );
}