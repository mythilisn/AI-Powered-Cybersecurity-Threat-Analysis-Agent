'use client';

import { useState } from 'react';
import axios from 'axios';

export default function InjectionPage() {
  const [activeTab, setActiveTab] = useState('text');
  const [rawLog, setRawLog] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const sampleScenarios = {
    dll_injection: `[Sysmon Event ID 8 - CreateRemoteThread]
UtcTime: 2026-08-24 10:14:22.108
SourceImage: C:\\Users\\Administrator\\AppData\\Local\\Temp\\updater_payload.exe
SourceProcessId: 4920
TargetImage: C:\\Windows\\System32\\explorer.exe
TargetProcessId: 2184
StartAddress: 0x00007FFB32A1000
StartFunction: LoadLibraryA
Observed APIs: OpenProcess, VirtualAllocEx (PAGE_EXECUTE_READWRITE), WriteProcessMemory, CreateRemoteThread
Details: Injected payload binary path into target address space and invoked thread.`,

    process_hollowing: `[EDR Telemetry - Process Tampering]
Timestamp: 2026-08-24T12:05:01Z
CallerProcess: C:\\Users\\Victim\\Downloads\\invoice_doc.exe
CallerPID: 8840
VictimProcess: C:\\Windows\\System32\\svchost.exe
VictimPID: 9112
API Sequence:
1. CreateProcessA (CREATE_SUSPENDED) -> svchost.exe
2. NtUnmapViewOfSection (Unmapping legitimate PE headers)
3. VirtualAllocEx (Allocating RWX memory at image base)
4. WriteProcessMemory (Writing unbacked payload PE)
5. SetThreadContext (Redirecting entry point register RIP/EIP)
6. ResumeThread (Spawning malicious execution inside svchost)`
  };

  const handleAnalyzeText = async (e) => {
    if (e) e.preventDefault();
    if (!rawLog.trim()) return;

    setLoading(true);
    setError('');

    try {
      const res = await axios.post('http://127.0.0.1:5000/injection/analyze', {
        raw_log: rawLog,
        source_tag: 'Interactive Analysis'
      });
      setResults(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze injection trace with backend.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    if (e) e.preventDefault();
    if (!selectedFile) return;

    setLoading(true);
    setError('');

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('source_tag', `File: ${selectedFile.name}`);

    try {
      const res = await axios.post('http://127.0.0.1:5000/injection/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResults(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze uploaded telemetry file.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadgeColor = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return '#dc2626';
      case 'HIGH': return '#ea580c';
      case 'MEDIUM': return '#d97706';
      default: return '#059669';
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#0a0d14',
      color: '#e2e8f0',
      fontFamily: 'Segoe UI, Roboto, sans-serif',
      padding: '24px'
    }}>
      {/* Top Navbar */}
      <div style={{
        maxWidth: '1200px',
        margin: '0 auto 24px auto',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: '1px solid #1f2937',
        paddingBottom: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            backgroundColor: '#dc2626',
            color: '#fff',
            fontWeight: 'bold',
            padding: '6px 12px',
            borderRadius: '6px',
            fontSize: '13px',
            letterSpacing: '1px'
          }}>
            CYBER_CORE
          </div>
          <h1 style={{ fontSize: '18px', fontWeight: '600', margin: 0 }}>
            Malware Process Injection AI Agent (MITRE T1055)
          </h1>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            type="button"
            onClick={() => { window.location.href = '/dashboard'; }}
            style={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              color: '#38bdf8',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            ← Switch to Threat Intel (IoC Extractor)
          </button>
          <button
            type="button"
            onClick={() => {
              localStorage.removeItem('access_token');
              window.location.href = '/';
            }}
            style={{
              backgroundColor: 'transparent',
              border: '1px solid #334155',
              color: '#94a3b8',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              cursor: 'pointer'
            }}
          >
            Sign Out
          </button>
        </div>
      </div>

      {/* Main Grid */}
      <div style={{
        maxWidth: '1200px',
        margin: '0 auto',
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '24px'
      }}>
        {/* Left Column: Ingestion Options */}
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '10px',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column'
        }}>
          {/* Tab Selection */}
          <div style={{
            display: 'flex',
            backgroundColor: '#0f172a',
            padding: '4px',
            borderRadius: '6px',
            marginBottom: '16px',
            border: '1px solid #334155'
          }}>
            <button
              type="button"
              onClick={() => setActiveTab('text')}
              style={{
                flex: 1,
                padding: '6px',
                border: 'none',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                backgroundColor: activeTab === 'text' ? '#1e293b' : 'transparent',
                color: activeTab === 'text' ? '#f8fafc' : '#94a3b8'
              }}
            >
              📝 Raw Log Text
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('file')}
              style={{
                flex: 1,
                padding: '6px',
                border: 'none',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                backgroundColor: activeTab === 'file' ? '#1e293b' : 'transparent',
                color: activeTab === 'file' ? '#f8fafc' : '#94a3b8'
              }}
            >
              📁 File Upload (.log / .txt)
            </button>
          </div>

          {/* Mode 1: Text Ingestion */}
          {activeTab === 'text' && (
            <form onSubmit={handleAnalyzeText} style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 'bold' }}>SAMPLE SCENARIOS</span>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button
                    type="button"
                    onClick={() => setRawLog(sampleScenarios.dll_injection)}
                    style={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #334155',
                      color: '#38bdf8',
                      fontSize: '11px',
                      padding: '3px 8px',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    DLL Inject
                  </button>
                  <button
                    type="button"
                    onClick={() => setRawLog(sampleScenarios.process_hollowing)}
                    style={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #334155',
                      color: '#f87171',
                      fontSize: '11px',
                      padding: '3px 8px',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    Hollowing
                  </button>
                </div>
              </div>

              <textarea
                required
                rows={15}
                value={rawLog}
                onChange={(e) => setRawLog(e.target.value)}
                placeholder="Paste Sysmon logs (CreateRemoteThread, ImageLoaded), sandbox API traces, or memory write sequences..."
                style={{
                  width: '100%',
                  flex: 1,
                  backgroundColor: '#0f172a',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  padding: '12px',
                  color: '#e2e8f0',
                  fontFamily: 'monospace',
                  fontSize: '13px',
                  resize: 'vertical',
                  boxSizing: 'border-box',
                  marginBottom: '14px'
                }}
              />

              {error && (
                <div style={{
                  padding: '8px 12px',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  color: '#f87171',
                  borderRadius: '6px',
                  fontSize: '12px',
                  marginBottom: '12px'
                }}>
                  {error}
                </div>
              )}

              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    flex: 1,
                    padding: '10px',
                    backgroundColor: '#dc2626',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    fontWeight: '600',
                    fontSize: '13px',
                    cursor: loading ? 'not-allowed' : 'pointer'
                  }}
                >
                  {loading ? 'Executing AI Reasoning...' : 'Analyze Process Injection'}
                </button>
                <button
                  type="button"
                  onClick={() => { setRawLog(''); setResults(null); }}
                  style={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    color: '#94a3b8',
                    padding: '10px 16px',
                    borderRadius: '6px',
                    fontSize: '13px',
                    cursor: 'pointer'
                  }}
                >
                  Clear
                </button>
              </div>
            </form>
          )}

          {/* Mode 2: File Ingestion */}
          {activeTab === 'file' && (
            <form onSubmit={handleFileUpload} style={{ display: 'flex', flexDirection: 'column', flex: 1, justifyContent: 'space-between' }}>
              <div style={{
                border: '2px dashed #334155',
                borderRadius: '8px',
                padding: '36px 20px',
                textAlign: 'center',
                backgroundColor: '#0f172a',
                marginBottom: '16px'
              }}>
                <div style={{ fontSize: '36px', marginBottom: '8px' }}>📂</div>
                <div style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc', marginBottom: '4px' }}>
                  Upload Telemetry / Sysmon Log File
                </div>
                <div style={{ fontSize: '11px', color: '#64748b', marginBottom: '14px' }}>
                  Accepts .log, .txt, .json, and raw memory traces
                </div>

                <input
                  type="file"
                  id="log-file"
                  onChange={(e) => setSelectedFile(e.target.files[0] || null)}
                  style={{ display: 'none' }}
                />
                <label
                  htmlFor="log-file"
                  style={{
                    display: 'inline-block',
                    backgroundColor: '#1e293b',
                    border: '1px solid #475569',
                    color: '#38bdf8',
                    padding: '8px 16px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  {selectedFile ? selectedFile.name : 'Select File from Disk'}
                </label>
              </div>

              {selectedFile && (
                <div style={{
                  padding: '10px',
                  backgroundColor: '#0f172a',
                  border: '1px solid #1f2937',
                  borderRadius: '6px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: '#94a3b8'
                }}>
                  Selected: <strong style={{ color: '#f8fafc' }}>{selectedFile.name}</strong> ({(selectedFile.size / 1024).toFixed(1)} KB)
                </div>
              )}

              {error && (
                <div style={{
                  padding: '8px 12px',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  color: '#f87171',
                  borderRadius: '6px',
                  fontSize: '12px',
                  marginBottom: '12px'
                }}>
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading || !selectedFile}
                style={{
                  padding: '10px',
                  backgroundColor: '#dc2626',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: '600',
                  fontSize: '13px',
                  cursor: (loading || !selectedFile) ? 'not-allowed' : 'pointer'
                }}
              >
                {loading ? 'Uploading & Analyzing...' : 'Upload & Analyze File'}
              </button>
            </form>
          )}
        </div>

        {/* Right Column: AI Triage & Attack Graph */}
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '10px',
          padding: '20px',
          overflowY: 'auto',
          maxHeight: 'calc(100vh - 140px)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h2 style={{ fontSize: '15px', fontWeight: '600', margin: 0, color: '#f8fafc' }}>
                Forensic Triage & Attack Graph
              </h2>
              {results?.filename && (
                <span style={{ fontSize: '11px', color: '#64748b' }}>Analyzed: {results.filename}</span>
              )}
            </div>

            {results && (
              <span style={{
                backgroundColor: getSeverityBadgeColor(results.risk_level),
                color: '#fff',
                fontSize: '11px',
                fontWeight: '700',
                padding: '4px 10px',
                borderRadius: '4px',
                textTransform: 'uppercase'
              }}>
                {results.risk_level} RISK
              </span>
            )}
          </div>

          {!results && (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              minHeight: '340px',
              color: '#64748b',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '36px', marginBottom: '8px' }}>💉</div>
              <p style={{ margin: 0, fontSize: '13px' }}>
                Load a sample scenario or upload an execution trace log to trigger MITRE T1055 analysis.
              </p>
            </div>
          )}

          {results && (
            <div>
              {/* Process Visualizer Chain */}
              <div style={{
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '8px',
                padding: '14px',
                marginBottom: '16px'
              }}>
                <span style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 'bold' }}>
                  Target Architecture
                </span>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginTop: '10px',
                  gap: '8px',
                  fontSize: '12px'
                }}>
                  <div style={{
                    backgroundColor: '#1e293b',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid #475569',
                    flex: 1,
                    textAlign: 'center'
                  }}>
                    <div style={{ color: '#ef4444', fontWeight: 'bold' }}>Source Process</div>
                    <div style={{ color: '#cbd5e1', fontSize: '11px', marginTop: '2px', wordBreak: 'break-all' }}>
                      {results.process_metadata.source_process || 'Unknown Caller'}
                    </div>
                    {results.process_metadata.source_pid && (
                      <div style={{ color: '#64748b', fontSize: '10px' }}>PID: {results.process_metadata.source_pid}</div>
                    )}
                  </div>

                  <div style={{ color: '#f59e0b', fontWeight: 'bold', fontSize: '16px' }}>➔</div>

                  <div style={{
                    backgroundColor: '#1e293b',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid #475569',
                    flex: 1,
                    textAlign: 'center'
                  }}>
                    <div style={{ color: '#38bdf8', fontWeight: 'bold' }}>Target Process</div>
                    <div style={{ color: '#cbd5e1', fontSize: '11px', marginTop: '2px', wordBreak: 'break-all' }}>
                      {results.process_metadata.target_process || 'Target Binary'}
                    </div>
                    {results.process_metadata.target_pid && (
                      <div style={{ color: '#64748b', fontSize: '10px' }}>PID: {results.process_metadata.target_pid}</div>
                    )}
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK Classification */}
              {results.mitre_techniques.length > 0 && (
                <div style={{ marginBottom: '16px' }}>
                  <span style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 'bold' }}>
                    MITRE ATT&CK Classification
                  </span>
                  <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {results.mitre_techniques.map((tech, i) => (
                      <div key={i} style={{
                        backgroundColor: '#0f172a',
                        border: '1px solid #334155',
                        borderRadius: '6px',
                        padding: '10px'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ color: '#f87171', fontWeight: 'bold', fontSize: '13px' }}>
                            {tech.technique_id}: {tech.technique_name}
                          </span>
                          <span style={{
                            backgroundColor: '#374151',
                            color: '#93c5fd',
                            fontSize: '10px',
                            padding: '2px 6px',
                            borderRadius: '4px'
                          }}>
                            {tech.confidence} CONFIDENCE
                          </span>
                        </div>
                        <p style={{ margin: '6px 0 0 0', fontSize: '12px', color: '#94a3b8' }}>
                          {tech.description}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Detected APIs */}
              {results.detected_apis.length > 0 && (
                <div style={{ marginBottom: '16px' }}>
                  <span style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 'bold' }}>
                    Identified Memory & Thread APIs ({results.detected_apis.length})
                  </span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                    {results.detected_apis.map((api, idx) => (
                      <span key={idx} style={{
                        fontFamily: 'monospace',
                        fontSize: '11px',
                        backgroundColor: '#0f172a',
                        border: '1px solid #334155',
                        color: '#38bdf8',
                        padding: '3px 8px',
                        borderRadius: '4px'
                      }}>
                        {api}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Agent Synthesis Panel */}
              {results.ai_insights && (
                <div style={{
                  backgroundColor: '#0f172a',
                  border: '1px solid #38bdf8',
                  borderRadius: '8px',
                  padding: '14px',
                  marginBottom: '16px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ color: '#38bdf8', fontSize: '12px', fontWeight: 'bold', textTransform: 'uppercase' }}>
                      AI Agent Forensic Assessment
                    </span>
                    <span style={{ color: '#64748b', fontSize: '10px' }}>
                      {results.ai_insights.agent_mode}
                    </span>
                  </div>

                  <p style={{ fontSize: '12px', color: '#cbd5e1', lineHeight: '1.5', margin: '0 0 10px 0' }}>
                    {results.ai_insights.attack_narrative}
                  </p>

                  <div style={{ marginBottom: '10px' }}>
                    <div style={{ fontSize: '11px', color: '#f59e0b', fontWeight: 'bold', marginBottom: '4px' }}>
                      Adversary Objective:
                    </div>
                    <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                      {results.ai_insights.adversary_objective}
                    </div>
                  </div>

                  {results.ai_insights.attack_chain_steps?.length > 0 && (
                    <div style={{ marginBottom: '10px' }}>
                      <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 'bold', marginBottom: '4px' }}>
                        Execution Sequence:
                      </div>
                      <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: '#cbd5e1' }}>
                        {results.ai_insights.attack_chain_steps.map((step, idx) => (
                          <li key={idx} style={{ marginBottom: '3px' }}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {results.ai_insights.remediation_playbook?.length > 0 && (
                    <div>
                      <div style={{ fontSize: '11px', color: '#4ade80', fontWeight: 'bold', marginBottom: '4px' }}>
                        SOC Incident Response Playbook:
                      </div>
                      <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: '#86efac' }}>
                        {results.ai_insights.remediation_playbook.map((rem, idx) => (
                          <li key={idx} style={{ marginBottom: '3px' }}>{rem}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}