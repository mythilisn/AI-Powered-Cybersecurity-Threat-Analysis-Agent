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

  const modules = [
    {
      category: 'STATIC ANALYSIS',
      title: 'Threat Analyzer',
      description:
        'Analyze text and scripts for suspicious keywords, PowerShell commands, encoded content, obfuscation, and other static indicators.',
      button: 'Open Static Analysis',
      action: () => router.push('/analysis'),
      status: 'AVAILABLE',
    },
    {
      category: 'IOC EXTRACTION',
      title: 'Threat Intelligence Extractor',
      description:
        'Extract IP addresses, URLs, domains, email addresses, hashes, and CVE identifiers from threat reports and uploaded forensic files.',
      button: 'Open IoC Extraction',
      action: () => router.push('/ioc'),
      status: 'AVAILABLE',
    },
    {
  category: 'THREAT INTELLIGENCE',
  title: 'VirusTotal Lookup',
  description:
    'Check URL and file-hash indicators against VirusTotal to obtain reputation and threat-intelligence information.',
  button: 'Open VirusTotal Lookup',
  action: () => router.push('/virustotal'),
  status: 'AVAILABLE',
},
    {
      category: 'THREAT SUBMISSION',
      title: 'Text / Email + URL Submission',
      description:
        'Submit suspicious text, emails, or URLs for comprehensive threat analysis including IOC extraction, static analysis, and VirusTotal reputation checks.',
      button: 'Open Threat Submission',
      action: () => router.push('/submission'),
      status: 'AVAILABLE',
    },
  ];

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
          maxWidth: '1100px',
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
                fontSize: '32px',
              }}
            >
              Security Analysis Platform
            </h1>

            <p
              style={{
                color: '#94a3b8',
                margin: 0,
              }}
            >
              Select a security analysis module to begin.
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

        {/* Module Cards */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '20px',
          }}
        >
          {modules.map((module) => (
            <div
              key={module.title}
              style={{
                backgroundColor: '#111827',
                border: '1px solid #1f2937',
                borderRadius: '12px',
                padding: '26px',
                display: 'flex',
                flexDirection: 'column',
                minHeight: '280px',
              }}
            >
              <div
                style={{
                  color:
                    module.status === 'AVAILABLE'
                      ? '#38bdf8'
                      : '#f59e0b',
                  fontSize: '12px',
                  fontWeight: 'bold',
                  letterSpacing: '1px',
                  marginBottom: '12px',
                }}
              >
                {module.category}
              </div>

              <h2
                style={{
                  color: '#f8fafc',
                  fontSize: '21px',
                  margin: '0 0 12px 0',
                }}
              >
                {module.title}
              </h2>

              <p
                style={{
                  color: '#94a3b8',
                  lineHeight: '1.6',
                  flex: 1,
                  margin: 0,
                }}
              >
                {module.description}
              </p>

              <button
                onClick={module.action || undefined}
                disabled={!module.action}
                style={{
                  marginTop: '22px',
                  width: '100%',
                  padding: '12px',
                  border: 'none',
                  borderRadius: '7px',
                  backgroundColor: module.action
                    ? '#0284c7'
                    : '#334155',
                  color: '#fff',
                  fontWeight: '600',
                  cursor: module.action
                    ? 'pointer'
                    : 'not-allowed',
                  opacity: module.action ? 1 : 0.7,
                }}
              >
                {module.button}
              </button>
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}