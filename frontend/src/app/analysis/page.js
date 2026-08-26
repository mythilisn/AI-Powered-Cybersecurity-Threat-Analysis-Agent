'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export default function StaticAnalysisPage() {
  const router = useRouter();

  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Check whether the user is logged in
  useEffect(() => {
    const token = localStorage.getItem('access_token');

    if (!token) {
      router.replace('/');
    }
  }, [router]);

  const analyzeText = async (event) => {
    event.preventDefault();

    if (!text.trim()) {
      setError('Please enter some text or script to analyze.');
      setResult(null);
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/analysis/static',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            text: text,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || 'Static analysis request failed.'
        );
      }

      setResult(data);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          'Unable to connect to the static analysis service.'
      );
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (riskLevel) => {
    if (riskLevel === 'high') {
      return '#ef4444';
    }

    if (riskLevel === 'medium') {
      return '#f59e0b';
    }

    return '#22c55e';
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
          maxWidth: '900px',
          margin: '0 auto',
        }}
      >
        {/* Back to Dashboard */}
        <button
          onClick={() => router.push('/dashboard')}
          style={{
            marginBottom: '20px',
            padding: '9px 16px',
            borderRadius: '6px',
            border: '1px solid #334155',
            backgroundColor: '#1e293b',
            color: '#e2e8f0',
            cursor: 'pointer',
          }}
        >
          ← Back to Dashboard
        </button>

        {/* Header */}
        <div style={{ marginBottom: '30px' }}>
          <div
            style={{
              display: 'inline-block',
              padding: '6px 12px',
              borderRadius: '6px',
              backgroundColor: '#1e293b',
              color: '#38bdf8',
              fontWeight: 'bold',
              fontSize: '12px',
              letterSpacing: '1px',
            }}
          >
            STATIC ANALYSIS
          </div>

          <h1
            style={{
              fontSize: '32px',
              margin: '14px 0 8px',
              color: '#f8fafc',
            }}
          >
            Cybersecurity Threat Analyzer
          </h1>

          <p
            style={{
              color: '#94a3b8',
              fontSize: '15px',
            }}
          >
            Submit text or script content for deterministic
            static analysis.
          </p>
        </div>

        {/* Input Form */}
        <form onSubmit={analyzeText}>
          <div
            style={{
              backgroundColor: '#111827',
              border: '1px solid #1f2937',
              borderRadius: '12px',
              padding: '24px',
            }}
          >
            <label
              htmlFor="analysis-text"
              style={{
                display: 'block',
                fontSize: '13px',
                fontWeight: '600',
                color: '#cbd5e1',
                marginBottom: '8px',
              }}
            >
              TEXT / SCRIPT CONTENT
            </label>

            <textarea
              id="analysis-text"
              value={text}
              onChange={(event) => setText(event.target.value)}
              placeholder="Paste text or script content here..."
              rows={12}
              maxLength={100000}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                resize: 'vertical',
                padding: '14px',
                borderRadius: '8px',
                border: '1px solid #334155',
                backgroundColor: '#0f172a',
                color: '#f8fafc',
                fontSize: '14px',
                lineHeight: '1.5',
                outline: 'none',
              }}
            />

            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginTop: '12px',
                gap: '15px',
              }}
            >
              <span
                style={{
                  fontSize: '12px',
                  color: '#64748b',
                }}
              >
                {text.length} / 100000 characters
              </span>

              <button
                type="submit"
                disabled={loading}
                style={{
                  padding: '11px 22px',
                  border: 'none',
                  borderRadius: '7px',
                  backgroundColor: loading
                    ? '#334155'
                    : '#0284c7',
                  color: '#fff',
                  fontWeight: '600',
                  cursor: loading
                    ? 'not-allowed'
                    : 'pointer',
                }}
              >
                {loading
                  ? 'Analyzing...'
                  : 'Analyze Threat'}
              </button>
            </div>
          </div>
        </form>

        {/* Error */}
        {error && (
          <div
            style={{
              marginTop: '20px',
              padding: '14px',
              borderRadius: '8px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#f87171',
            }}
          >
            {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div style={{ marginTop: '25px' }}>
            <div
              style={{
                backgroundColor: '#111827',
                border: '1px solid #1f2937',
                borderRadius: '12px',
                padding: '24px',
              }}
            >
              <h2
                style={{
                  marginTop: 0,
                  color: '#f8fafc',
                  fontSize: '20px',
                }}
              >
                Analysis Result
              </h2>

              {/* Risk Cards */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns:
                    'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '15px',
                  marginBottom: '20px',
                }}
              >
                <div
                  style={{
                    padding: '18px',
                    backgroundColor: '#0f172a',
                    borderRadius: '8px',
                  }}
                >
                  <div
                    style={{
                      color: '#64748b',
                      fontSize: '12px',
                      marginBottom: '6px',
                    }}
                  >
                    RISK LEVEL
                  </div>

                  <div
                    style={{
                      color: getRiskColor(result.risk_level),
                      fontSize: '24px',
                      fontWeight: '700',
                      textTransform: 'uppercase',
                    }}
                  >
                    {result.risk_level}
                  </div>
                </div>

                <div
                  style={{
                    padding: '18px',
                    backgroundColor: '#0f172a',
                    borderRadius: '8px',
                  }}
                >
                  <div
                    style={{
                      color: '#64748b',
                      fontSize: '12px',
                      marginBottom: '6px',
                    }}
                  >
                    RISK SCORE
                  </div>

                  <div
                    style={{
                      color: '#f8fafc',
                      fontSize: '24px',
                      fontWeight: '700',
                    }}
                  >
                    {result.risk_score}
                  </div>
                </div>
              </div>

              {/* Summary */}
              <div
                style={{
                  padding: '14px',
                  backgroundColor: '#0f172a',
                  borderRadius: '8px',
                  marginBottom: '20px',
                  color: '#cbd5e1',
                }}
              >
                {result.summary}
              </div>

              {/* Findings */}
              <h3
                style={{
                  color: '#f8fafc',
                  fontSize: '17px',
                  marginBottom: '12px',
                }}
              >
                Findings ({result.findings?.length || 0})
              </h3>

              {result.findings?.length === 0 ? (
                <div
                  style={{
                    padding: '18px',
                    backgroundColor:
                      'rgba(34, 197, 94, 0.08)',
                    border:
                      '1px solid rgba(34, 197, 94, 0.2)',
                    borderRadius: '8px',
                    color: '#4ade80',
                  }}
                >
                  No suspicious patterns were detected.
                </div>
              ) : (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px',
                  }}
                >
                  {result.findings.map((finding, index) => (
                    <div
                      key={index}
                      style={{
                        padding: '18px',
                        backgroundColor: '#0f172a',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: '10px',
                          flexWrap: 'wrap',
                          marginBottom: '10px',
                        }}
                      >
                        <strong
                          style={{
                            color: '#f8fafc',
                          }}
                        >
                          {finding.name}
                        </strong>

                        <span
                          style={{
                            color: getRiskColor(
                              finding.severity
                            ),
                            fontWeight: '700',
                            textTransform: 'uppercase',
                            fontSize: '12px',
                          }}
                        >
                          {finding.severity}
                        </span>
                      </div>

                      <div
                        style={{
                          color: '#94a3b8',
                          fontSize: '13px',
                          marginBottom: '8px',
                        }}
                      >
                        Category: {finding.category}
                      </div>

                      <div
                        style={{
                          color: '#cbd5e1',
                          fontSize: '13px',
                          marginBottom: '8px',
                        }}
                      >
                        {finding.description}
                      </div>

                      <div
                        style={{
                          padding: '10px',
                          backgroundColor: '#020617',
                          borderRadius: '6px',
                          color: '#fbbf24',
                          fontSize: '12px',
                          wordBreak: 'break-word',
                        }}
                      >
                        Evidence: {finding.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </main>
  );
}