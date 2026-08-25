'use client';

import { useState } from 'react';
import axios from 'axios';

export default function IoCDashboard() {
  const [activeTab, setActiveTab] = useState('text'); // 'text' | 'file'
  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isDefanged, setIsDefanged] = useState(true);

  const sampleThreatFeeds = {
    phishing: `From: security-alert@paypal-update-center.com
To: victim@enterprise-corp.com
Subject: Urgent: Suspicious Login Detected (CVE-2024-38077 PoC attached)
Date: 25 Aug 2026 14:02:11 +0000

Dear Customer,
We detected unauthorized activity from IP address 185.220.101.7 and secondary node 2a02:4780:11:100::1.
Please verify your corporate credentials immediately at:
hxxps://auth-checkpoint-portal.xyz/login.php?user=enterprise

Attached Artifact Hashes:
Payload SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Stager MD5: e110adc3949ba59abbe56e057f20f883
C2 Host: command-and-control-node.top`,

    honeypot: `[Honeypot Suricata Alert - Outbound C2 Beaconing]
Timestamp: 2026-08-25T19:00:14Z
Source Internal: 10.0.4.12 -> Dest IP: 194.26.29.112
Referenced Exploit: CVE-2023-38606
Involved Domain: malicious-payload-drop.biz
Downloaded Dropper Hash: a3543d34b41b9e07fb6a54160d5b1219b1da5346 (SHA1)
Secondary Backup: http://stage2-c2.cloud/beacon.bin`
  };

  const defangValue = (val) => {
    if (!val || typeof val !== 'string') return val;
    return val
      .replace(/https?:\/\//gi, (match) => match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://')
      .replace(/\./g, '[.]')
      .replace(/@/g, '[at]');
  };

  const handleAnalyzeText = async (e) => {
    if (e) e.preventDefault();
    if (!rawText.trim()) return;

    setLoading(true);
    setError('');

    try {
      const res = await axios.post('http://127.0.0.1:5000/ioc/extract', {
        raw_text: rawText,
        source_tag: 'Analyst Interactive Triage'
      });
      setResults(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to extract IoCs from backend.');
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
      const res = await axios.post('http://127.0.0.1:5000/ioc/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResults(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze uploaded threat file.');
    } finally {
      setLoading(false);
    }
  };

  const getNormalizedIndicators = () => {
    if (!results || !results.results) return {};
    return results.results;
  };

  const getTotalCount = () => {
    const data = getNormalizedIndicators();
    return Object.values(data).reduce((acc, curr) => acc + (Array.isArray(curr) ? curr.length : 0), 0);
  };

  const calculateThreatScore = () => {
    const data = getNormalizedIndicators();
    const sha256Count = data.sha256?.length || 0;
    const urlsCount = data.urls?.length || 0;
    const ipsCount = (data.ips?.length || 0) + (data.ipv4?.length || 0);
    const cvesCount = data.cves?.length || 0;

    const score = Math.min(100, (sha256Count * 25) + (urlsCount * 20) + (cvesCount * 20) + (ipsCount * 10));
    let verdict = 'CLEAN';
    let badgeColor = '#059669';

    if (score >= 70) {
      verdict = 'CRITICAL';
      badgeColor = '#dc2626';
    } else if (score >= 40) {
      verdict = 'SUSPICIOUS';
      badgeColor = '#ea580c';
    } else if (score > 0) {
      verdict = 'LOW RISK';
      badgeColor = '#d97706';
    }

    return { score, verdict, badgeColor };
  };

  const exportJSON = () => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_intel_iocs_${Date.now()}.json`;
    a.click();
  };

  const exportCSV = () => {
    if (!results) return;
    let csv = 'Indicator Category,Raw Value,Defanged Value\n';
    const data = getNormalizedIndicators();
    Object.keys(data).forEach((cat) => {
      if (Array.isArray(data[cat])) {
        data[cat].forEach((item) => {
          const raw = typeof item === 'object' ? (item.raw || item.value || JSON.stringify(item)) : String(item);
          const def = defangValue(raw);
          csv += `"${cat}","${raw}","${def}"\n`;
        });
      }
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_intel_blocklist_${Date.now()}.csv`;
    a.click();
  };

  const exportSTIX = () => {
    if (!results) return;
    const data = getNormalizedIndicators();
    const stixObjects = [];
    const timestamp = new Date().toISOString();

    Object.keys(data).forEach((cat) => {
      if (Array.isArray(data[cat])) {
        data[cat].forEach((item, idx) => {
          const raw = typeof item === 'object' ? (item.raw || item.value) : String(item);
          stixObjects.push({
            type: "indicator",
            spec_version: "2.1",
            id: `indicator--${Date.now()}-${idx}`,
            created: timestamp,
            name: `${cat.toUpperCase()}: ${raw}`,
            pattern: `[${cat}:value = '${raw}']`,
            pattern_type: "stix"
          });
        });
      }
    });

    const bundle = {
      type: "bundle",
      id: `bundle--${Date.now()}`,
      objects: stixObjects
    };

    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `stix2.1_bundle_${Date.now()}.json`;
    a.click();
  };

  const threatMeta = calculateThreatScore();

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
            backgroundColor: '#0284c7',
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
            Cyber Threat Intelligence & IoC Extractor (CTI)
          </h1>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            type="button"
            onClick={() => { window.location.href = '/injection'; }}
            style={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              color: '#f87171',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            ← Switch to Process Injection AI
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
              📝 Raw Threat Feed / Email
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
              📁 File Upload (.txt / .eml)
            </button>
          </div>

          {/* Mode 1: Text Ingestion */}
          {activeTab === 'text' && (
            <form onSubmit={handleAnalyzeText} style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 'bold' }}>SAMPLE FEEDS</span>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button
                    type="button"
                    onClick={() => setRawText(sampleThreatFeeds.phishing)}
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
                    Phishing Email
                  </button>
                  <button
                    type="button"
                    onClick={() => setRawText(sampleThreatFeeds.honeypot)}
                    style={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #334155',
                      color: '#fbbf24',
                      fontSize: '11px',
                      padding: '3px 8px',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    Honeypot Alert
                  </button>
                </div>
              </div>

              <textarea
                required
                rows={15}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste OSINT bulletins, honeypot alerts, suspicious emails, C2 lists, or hash dumps..."
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
                    backgroundColor: '#0284c7',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    fontWeight: '600',
                    fontSize: '13px',
                    cursor: loading ? 'not-allowed' : 'pointer'
                  }}
                >
                  {loading ? 'Extracting & De-fanging...' : 'Parse & Extract IoCs'}
                </button>
                <button
                  type="button"
                  onClick={() => { setRawText(''); setResults(null); }}
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
                <div style={{ fontSize: '36px', marginBottom: '8px' }}>📄</div>
                <div style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc', marginBottom: '4px' }}>
                  Upload Threat Report / Raw Intel File
                </div>
                <div style={{ fontSize: '11px', color: '#64748b', marginBottom: '14px' }}>
                  Accepts .txt, .eml, .log, .json, and raw security advisories
                </div>

                <input
                  type="file"
                  id="ioc-file"
                  onChange={(e) => setSelectedFile(e.target.files[0] || null)}
                  style={{ display: 'none' }}
                />
                <label
                  htmlFor="ioc-file"
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
                  backgroundColor: '#0284c7',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: '600',
                  fontSize: '13px',
                  cursor: (loading || !selectedFile) ? 'not-allowed' : 'pointer'
                }}
              >
                {loading ? 'Processing File...' : 'Upload & Extract IoCs'}
              </button>
            </form>
          )}
        </div>

        {/* Right Column: Structured Indicator Grid */}
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
                Extracted Threat Indicators
              </h2>
              {results && (
                <span style={{ fontSize: '11px', color: '#64748b' }}>
                  {results.filename ? `File: ${results.filename} • ` : ''}Identified {getTotalCount()} unique artifacts
                </span>
              )}
            </div>

            {results && (
              <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                <span style={{
                  backgroundColor: threatMeta.badgeColor,
                  color: '#fff',
                  fontSize: '10px',
                  fontWeight: 'bold',
                  padding: '3px 8px',
                  borderRadius: '4px',
                  textTransform: 'uppercase'
                }}>
                  {threatMeta.verdict} ({threatMeta.score}/100)
                </span>
                <button
                  type="button"
                  onClick={() => setIsDefanged(!isDefanged)}
                  style={{
                    backgroundColor: isDefanged ? '#065f46' : '#334155',
                    color: isDefanged ? '#6ee7b7' : '#94a3b8',
                    border: '1px solid #475569',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    cursor: 'pointer',
                    fontWeight: 'bold'
                  }}
                >
                  {isDefanged ? '🔒 DEFANGED' : '⚠️ RAW'}
                </button>
                <button
                  type="button"
                  onClick={exportJSON}
                  style={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    color: '#38bdf8',
                    padding: '3px 6px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    cursor: 'pointer',
                    fontWeight: 'bold'
                  }}
                >
                  JSON
                </button>
                <button
                  type="button"
                  onClick={exportCSV}
                  style={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    color: '#34d399',
                    padding: '3px 6px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    cursor: 'pointer',
                    fontWeight: 'bold'
                  }}
                >
                  CSV
                </button>
                <button
                  type="button"
                  onClick={exportSTIX}
                  style={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    color: '#f59e0b',
                    padding: '3px 6px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    cursor: 'pointer',
                    fontWeight: 'bold'
                  }}
                >
                  STIX 2.1
                </button>
              </div>
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
              <div style={{ fontSize: '36px', marginBottom: '8px' }}>🔍</div>
              <p style={{ margin: 0, fontSize: '13px' }}>
                Load a sample feed or upload a threat document to extract structured network and malware IoCs.
              </p>
            </div>
          )}

          {results && results.results && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {Object.keys(results.results).map((category) => {
                const items = results.results[category];
                if (!Array.isArray(items) || items.length === 0) return null;

                return (
                  <div key={category} style={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '12px'
                  }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '8px'
                    }}>
                      <span style={{ fontSize: '11px', fontWeight: 'bold', color: '#38bdf8', textTransform: 'uppercase' }}>
                        {category.replace('_', ' ')}
                      </span>
                      <span style={{ fontSize: '10px', color: '#64748b' }}>
                        {items.length} found
                      </span>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {items.map((item, idx) => {
                        const rawVal = typeof item === 'object' ? (item.raw || item.value || JSON.stringify(item)) : String(item);
                        const displayVal = isDefanged ? defangValue(rawVal) : rawVal;

                        return (
                          <div key={idx} style={{
                            backgroundColor: '#1e293b',
                            border: '1px solid #334155',
                            borderRadius: '4px',
                            padding: '6px 10px',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            fontSize: '12px',
                            fontFamily: 'monospace'
                          }}>
                            <span style={{ color: '#f8fafc', wordBreak: 'break-all' }}>
                              {displayVal}
                            </span>
                            <span style={{
                              fontSize: '9px',
                              color: isDefanged ? '#6ee7b7' : '#f87171',
                              backgroundColor: '#0f172a',
                              padding: '2px 5px',
                              borderRadius: '3px',
                              border: '1px solid #334155',
                              marginLeft: '8px',
                              whiteSpace: 'nowrap'
                            }}>
                              {isDefanged ? 'DEFANGED' : 'RAW'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}