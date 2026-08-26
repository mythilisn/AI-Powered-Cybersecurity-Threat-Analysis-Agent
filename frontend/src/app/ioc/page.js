'use client';

import { useState } from 'react';
import axios from 'axios';

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState('text'); // 'text' | 'file'
  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [sourceTag, setSourceTag] = useState('Manual Triage');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [defangedView, setDefangedView] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);

  const sampleReports = {
    phishing: `Alert ID: #SEC-9821\nSender: malicious-actor@spoofed-phish.net\nPayload URL: hxxps[://]auth-internal-secure[.]com/login.php\nDrop IP: 185.220.101.5\nSecondary C2: 198.51.100.45\nAttached Binary: invoice_scan.exe\nSHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\nMD5: 44d88612fea8a8f36de82e1278abb02f\nExploits: CVE-2023-38606, CVE-2024-3400`,
    c2_beacon: `[C2 Telemetry Log]\nCallback host: telemetry-collector-cdn[.]xyz\nBeacon IP: 103.203.57.18\nTargeting: enterprise-auth.target-domain.com\nAttacking IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334\nAssociated CVE: CVE-2021-44228\nSHA1 Hash: 3b7145048d3c3f699941dd97951a00b1f16c1f69`
  };

  const handleExtractText = async (e) => {
    if (e) e.preventDefault();
    if (!rawText.trim()) return;

    setLoading(true);
    setError('');

    try {
      const res = await axios.post('http://127.0.0.1:8000/ioc/extract', {
        raw_text: rawText,
        source_tag: sourceTag
      });
      setResults(res.data.results);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to extract indicators from backend.');
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
    formData.append('source_tag', sourceTag);

    try {
      const res = await axios.post('http://127.0.0.1:8000/ioc/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResults(res.data.results);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to parse the uploaded file.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const defangString = (val) => {
    return val
      .replace(/\./g, '[.]')
      .replace(/http:\/\//gi, 'hxxp://')
      .replace(/https:\/\//gi, 'hxxps://');
  };

  const renderIOCSection = (title, items, typeKey, badgeColor) => {
    if (!items || items.length === 0) return null;

    return (
      <div style={{
        marginBottom: '16px',
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '8px',
        padding: '14px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              backgroundColor: badgeColor,
              color: '#fff',
              fontSize: '11px',
              fontWeight: '700',
              padding: '3px 8px',
              borderRadius: '4px',
              textTransform: 'uppercase'
            }}>
              {title}
            </span>
            <span style={{ fontSize: '12px', color: '#94a3b8' }}>({items.length})</span>
          </div>
          <button
            onClick={() => copyToClipboard(items.join('\n'), typeKey)}
            style={{
              background: 'transparent',
              border: '1px solid #334155',
              borderRadius: '4px',
              color: copiedKey === typeKey ? '#4ade80' : '#94a3b8',
              fontSize: '11px',
              padding: '4px 8px',
              cursor: 'pointer'
            }}
          >
            {copiedKey === typeKey ? 'G£ô Copied' : 'Copy All'}
          </button>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          {items.map((item, idx) => {
            const displayVal = defangedView ? defangString(item) : item;
            const singleKey = `${typeKey}-${idx}`;
            return (
              <span
                key={idx}
                onClick={() => copyToClipboard(displayVal, singleKey)}
                title="Click to copy"
                style={{
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  backgroundColor: '#0f172a',
                  border: '1px solid #334155',
                  color: '#e2e8f0',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                {displayVal} {copiedKey === singleKey && <span style={{ color: '#4ade80', fontSize: '11px' }}>G£ô</span>}
              </span>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#0a0d14',
      color: '#e2e8f0',
      fontFamily: 'Segoe UI, Roboto, sans-serif',
      padding: '24px'
    }}>
      {/* Top Bar */}
      <div style={{
        maxWidth: '1200px',
        margin: '0 auto 20px auto',
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
            Threat Intelligence & Artifact Extractor
          </h1>
        </div>

        <button
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

      {/* Main Grid */}
      <div style={{
        maxWidth: '1200px',
        margin: '0 auto',
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '24px'
      }}>
        {/* Left Column: Input Form */}
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '10px',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column'
        }}>
          {/* Tab Selection */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', borderBottom: '1px solid #1f2937', paddingBottom: '12px' }}>
            <button
              onClick={() => setActiveTab('text')}
              style={{
                backgroundColor: activeTab === 'text' ? '#0284c7' : '#1e293b',
                color: activeTab === 'text' ? '#fff' : '#94a3b8',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Raw Text / Logs
            </button>
            <button
              onClick={() => setActiveTab('file')}
              style={{
                backgroundColor: activeTab === 'file' ? '#0284c7' : '#1e293b',
                color: activeTab === 'file' ? '#fff' : '#94a3b8',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Upload Threat File (.pdf, .eml, .pcap, .log)
            </button>
          </div>

          <div style={{ marginBottom: '12px' }}>
            <label style={{ fontSize: '11px', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
              CASE / SOURCE TAG
            </label>
            <input
              type="text"
              value={sourceTag}
              onChange={(e) => setSourceTag(e.target.value)}
              style={{
                width: '100%',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '6px',
                padding: '8px 10px',
                color: '#fff',
                fontSize: '13px',
                boxSizing: 'border-box'
              }}
            />
          </div>

          {activeTab === 'text' ? (
            <form onSubmit={handleExtractText} style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <label style={{ fontSize: '11px', color: '#94a3b8' }}>
                  PASTE UNSTRUCTURED THREAT FEED
                </label>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button
                    type="button"
                    onClick={() => setRawText(sampleReports.phishing)}
                    style={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #334155',
                      color: '#38bdf8',
                      fontSize: '11px',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    Phishing
                  </button>
                  <button
                    type="button"
                    onClick={() => setRawText(sampleReports.c2_beacon)}
                    style={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #334155',
                      color: '#38bdf8',
                      fontSize: '11px',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    C2 Beacon
                  </button>
                </div>
              </div>

              <textarea
                required
                rows={12}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste threat report, defanged domains (hxxp, [.], etc.), firewall logs, hashes, or emails..."
                style={{
                  width: '100%',
                  flex: 1,
                  backgroundColor: '#0f172a',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  padding: '12px',
                  color: '#e2e8f0',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  resize: 'vertical',
                  boxSizing: 'border-box',
                  marginBottom: '14px'
                }}
              />

              {error && (
                <div style={{ padding: '8px', backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171', borderRadius: '6px', fontSize: '12px', marginBottom: '12px' }}>
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
                  {loading ? 'Extracting Indicators...' : 'Parse & Extract IoCs'}
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
          ) : (
            <form onSubmit={handleFileUpload} style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              <div style={{
                flex: 1,
                border: '2px dashed #334155',
                borderRadius: '8px',
                padding: '30px',
                textAlign: 'center',
                backgroundColor: '#0f172a',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                marginBottom: '14px'
              }}>
                <div style={{ fontSize: '32px', marginBottom: '10px' }}>=ƒôü</div>
                <p style={{ margin: '0 0 6px 0', fontSize: '13px', color: '#f8fafc', fontWeight: '500' }}>
                  Choose a threat forensic file to ingest
                </p>
                <p style={{ margin: '0 0 16px 0', fontSize: '11px', color: '#64748b' }}>
                  Supports .pcap, .cap, .eml (phishing emails), .pdf reports, and .log files
                </p>
                <input
                  type="file"
                  accept=".pdf,.eml,.pcap,.cap,.pcapng,.txt,.log,.csv,.json"
                  onChange={(e) => setSelectedFile(e.target.files[0])}
                  style={{ fontSize: '12px', color: '#94a3b8' }}
                />
              </div>

              {selectedFile && (
                <div style={{ fontSize: '12px', color: '#38bdf8', marginBottom: '12px' }}>
                  Selected: <strong>{selectedFile.name}</strong> ({(selectedFile.size / 1024).toFixed(1)} KB)
                </div>
              )}

              {error && (
                <div style={{ padding: '8px', backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171', borderRadius: '6px', fontSize: '12px', marginBottom: '12px' }}>
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
                {loading ? 'Uploading & Parsing File...' : 'Upload & Ingest File'}
              </button>
            </form>
          )}
        </div>

        {/* Right Column: Parsed Indicators */}
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '10px',
          padding: '20px',
          overflowY: 'auto',
          maxHeight: 'calc(100vh - 120px)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h2 style={{ fontSize: '15px', fontWeight: '600', margin: '0 0 2px 0', color: '#f8fafc' }}>
                Extracted Intelligence
              </h2>
              {results && (
                <span style={{ fontSize: '12px', color: '#38bdf8' }}>
                  {results.total_count} indicator{results.total_count === 1 ? '' : 's'} identified
                </span>
              )}
            </div>

            {results && (
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#94a3b8', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={defangedView}
                  onChange={(e) => setDefangedView(e.target.checked)}
                />
                Defang Output
              </label>
            )}
          </div>

          {!results && (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              minHeight: '300px',
              color: '#64748b',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '32px', marginBottom: '8px' }}>=ƒ¢ín+Å</div>
              <p style={{ margin: 0, fontSize: '13px' }}>Paste text or upload a forensic file to extract indicators.</p>
            </div>
          )}

          {results && results.total_count === 0 && (
            <div style={{ textAlign: 'center', padding: '40px 0', color: '#94a3b8' }}>
              No threat indicators detected.
            </div>
          )}

          {results && (
            <>
              {renderIOCSection('IPv4 Addresses', results.ipv4, 'ipv4', '#0284c7')}
              {renderIOCSection('IPv6 Addresses', results.ipv6, 'ipv6', '#0369a1')}
              {renderIOCSection('CVE Vulnerabilities', results.cve, 'cve', '#dc2626')}
              {renderIOCSection('SHA-256 Hashes', results.sha256, 'sha256', '#d97706')}
              {renderIOCSection('SHA-1 Hashes', results.sha1, 'sha1', '#b45309')}
              {renderIOCSection('MD5 Hashes', results.md5, 'md5', '#78350f')}
              {renderIOCSection('URLs', results.urls, 'urls', '#7c3aed')}
              {renderIOCSection('Domain Names', results.domains, 'domains', '#059669')}
              {renderIOCSection('Email Entities', results.emails, 'emails', '#475569')}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
