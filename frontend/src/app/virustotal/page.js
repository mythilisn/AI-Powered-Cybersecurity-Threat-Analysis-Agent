'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import axios from 'axios';

export default function VirusTotalPage() {
  const router = useRouter();

  const [indicator, setIndicator] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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

  const handleLookup = async (e) => {
    e.preventDefault();

    if (!indicator.trim()) {
      setError('Please enter a URL or file hash.');
      setResult(null);
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const res = await axios.post(
        'http://127.0.0.1:8000/virustotal/lookup',
        {
          indicator: indicator.trim(),
        }
      );

      setResult(res.data);
    } catch (err) {
      const message =
        err.response?.data?.detail ||
        'Failed to perform VirusTotal lookup.';

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const renderStat = (label, value) => (
    <div
      style={{
        backgroundColor: '#0f172a',
        border: '1px solid #263449',
        borderRadius: '8px',
        padding: '18px',
        textAlign: 'center',
      }}
    >
      <div
        style={{
          color: '#94a3b8',
          fontSize: '12px',
          textTransform: 'uppercase',
          marginBottom: '8px',
        }}
      >
        {label}
      </div>

      <div
        style={{
          color: '#f8fafc',
          fontSize: '24px',
          fontWeight: '700',
        }}
      >
        {value ?? 0}
      </div>
    </div>
  );

  return (
    <main
      style={{
        minHeight: '100vh',
        backgroundColor: '#0a0d14',
        color: '#e2e8f0',
        padding: '30px 20px',
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
            marginBottom: '30px',
          }}
        >
          <div>
            <div
              style={{
                color: '#f59e0b',
                fontSize: '12px',
                fontWeight: 'bold',
                letterSpacing: '1px',
              }}
            >
              THREAT INTELLIGENCE
            </div>

            <h1
              style={{
                color: '#f8fafc',
                margin: '8px 0',
                fontSize: '32px',
              }}
            >
              VirusTotal Lookup
            </h1>

            <p style={{ color: '#94a3b8' }}>
              Check URLs and file hashes against VirusTotal.
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

        {/* Back button */}
        <button
          onClick={() => router.push('/dashboard')}
          style={{
            marginBottom: '20px',
            padding: '9px 15px',
            borderRadius: '6px',
            border: '1px solid #334155',
            backgroundColor: '#111827',
            color: '#cbd5e1',
            cursor: 'pointer',
          }}
        >
          ← Back to Dashboard
        </button>

        {/* Lookup form */}
        <div
          style={{
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '12px',
            padding: '25px',
            marginBottom: '25px',
          }}
        >
          <div
            style={{
              color: '#f59e0b',
              fontSize: '13px',
              fontWeight: 'bold',
              marginBottom: '10px',
            }}
          >
            INDICATOR LOOKUP
          </div>

          <h2
            style={{
              color: '#f8fafc',
              marginTop: '0',
            }}
          >
            Analyze an Indicator
          </h2>

          <p
            style={{
              color: '#94a3b8',
              lineHeight: '1.6',
            }}
          >
            Enter a URL, MD5, SHA-1, or SHA-256 hash to retrieve
            threat-intelligence information from VirusTotal.
          </p>

          <form onSubmit={handleLookup}>
            <input
              type="text"
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              placeholder="https://example.com or SHA-256 hash..."
              style={{
                width: '100%',
                boxSizing: 'border-box',
                padding: '14px',
                marginTop: '10px',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '7px',
                color: '#f8fafc',
                outline: 'none',
                fontSize: '14px',
              }}
            />

            <button
              type="submit"
              disabled={loading}
              style={{
                marginTop: '15px',
                width: '100%',
                padding: '13px',
                border: 'none',
                borderRadius: '7px',
                backgroundColor: loading ? '#475569' : '#d97706',
                color: '#fff',
                fontWeight: '600',
                cursor: loading ? 'not-allowed' : 'pointer',
              }}
            >
              {loading ? 'Checking VirusTotal...' : 'Lookup Indicator'}
            </button>
          </form>

          {error && (
            <div
              style={{
                marginTop: '15px',
                padding: '12px',
                borderRadius: '6px',
                backgroundColor: '#2a1822',
                border: '1px solid #5b2333',
                color: '#f87171',
              }}
            >
              {error}
            </div>
          )}
        </div>

        {/* Results */}
        {result && (
          <div
            style={{
              backgroundColor: '#111827',
              border: '1px solid #1f2937',
              borderRadius: '12px',
              padding: '25px',
            }}
          >
            <div
              style={{
                color: '#22c55e',
                fontSize: '13px',
                fontWeight: 'bold',
                marginBottom: '10px',
              }}
            >
              VIRUSTOTAL RESULT
            </div>

            {!result.found ? (
              <div
                style={{
                  padding: '20px',
                  backgroundColor: '#0f172a',
                  borderRadius: '8px',
                  color: '#fbbf24',
                }}
              >
                {result.message || 'Indicator was not found in VirusTotal.'}
              </div>
            ) : (
              <>
                {/* Indicator information */}
                <div
                  style={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #263449',
                    borderRadius: '8px',
                    padding: '18px',
                    marginBottom: '20px',
                  }}
                >
                  <div
                    style={{
                      color: '#94a3b8',
                      fontSize: '12px',
                      marginBottom: '6px',
                    }}
                  >
                    INDICATOR
                  </div>

                  <div
                    style={{
                      color: '#f8fafc',
                      wordBreak: 'break-all',
                      fontFamily: 'Consolas, monospace',
                    }}
                  >
                    {result.indicator}
                  </div>

                  <div
                    style={{
                      marginTop: '15px',
                      display: 'flex',
                      gap: '10px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <span
                      style={{
                        padding: '5px 10px',
                        borderRadius: '5px',
                        backgroundColor: '#1e3a5f',
                        color: '#60a5fa',
                        fontSize: '12px',
                        fontWeight: '600',
                      }}
                    >
                      {result.indicator_type?.toUpperCase()}
                    </span>

                    {result.reputation !== null &&
                      result.reputation !== undefined && (
                        <span
                          style={{
                            padding: '5px 10px',
                            borderRadius: '5px',
                            backgroundColor: '#172554',
                            color: '#93c5fd',
                            fontSize: '12px',
                            fontWeight: '600',
                          }}
                        >
                          Reputation: {result.reputation}
                        </span>
                      )}
                  </div>
                </div>

                {/* Analysis statistics */}
                <h3
                  style={{
                    color: '#f8fafc',
                    marginBottom: '15px',
                  }}
                >
                  Analysis Statistics
                </h3>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns:
                      'repeat(auto-fit, minmax(140px, 1fr))',
                    gap: '12px',
                    marginBottom: '25px',
                  }}
                >
                  {renderStat(
                    'Malicious',
                    result.analysis_stats?.malicious
                  )}

                  {renderStat(
                    'Suspicious',
                    result.analysis_stats?.suspicious
                  )}

                  {renderStat(
                    'Harmless',
                    result.analysis_stats?.harmless
                  )}

                  {renderStat(
                    'Undetected',
                    result.analysis_stats?.undetected
                  )}

                  {renderStat(
                    'Timeout',
                    result.analysis_stats?.timeout
                  )}
                </div>

                {/* Additional information */}
                <h3
                  style={{
                    color: '#f8fafc',
                    marginBottom: '15px',
                  }}
                >
                  Threat Intelligence
                </h3>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns:
                      'repeat(auto-fit, minmax(280px, 1fr))',
                    gap: '15px',
                  }}
                >
                  <div
                    style={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #263449',
                      borderRadius: '8px',
                      padding: '18px',
                    }}
                  >
                    <div
                      style={{
                        color: '#94a3b8',
                        fontSize: '12px',
                        marginBottom: '8px',
                      }}
                    >
                      NAME
                    </div>

                    <div style={{ color: '#f8fafc' }}>
                      {result.meaningful_name || 'Not available'}
                    </div>
                  </div>

                  <div
                    style={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #263449',
                      borderRadius: '8px',
                      padding: '18px',
                    }}
                  >
                    <div
                      style={{
                        color: '#94a3b8',
                        fontSize: '12px',
                        marginBottom: '8px',
                      }}
                    >
                      LAST ANALYSIS
                    </div>

                    <div style={{ color: '#f8fafc' }}>
                      {result.last_analysis_date
                        ? new Date(
                            result.last_analysis_date * 1000
                          ).toLocaleString()
                        : 'Not available'}
                    </div>
                  </div>
                </div>

                {/* Tags */}
                {result.tags && result.tags.length > 0 && (
                  <div style={{ marginTop: '20px' }}>
                    <div
                      style={{
                        color: '#94a3b8',
                        fontSize: '12px',
                        marginBottom: '8px',
                      }}
                    >
                      TAGS
                    </div>

                    <div
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: '8px',
                      }}
                    >
                      {result.tags.map((tag, index) => (
                        <span
                          key={`${tag}-${index}`}
                          style={{
                            padding: '6px 10px',
                            borderRadius: '5px',
                            backgroundColor: '#1e293b',
                            border: '1px solid #334155',
                            color: '#cbd5e1',
                            fontSize: '12px',
                          }}
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </main>
  );
}