import React, { useState, useEffect, useRef } from 'react';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [userRole, setUserRole] = useState({ name: 'Chief Security Auditor', email: 'auditor@worldmonitor.secops' });
  const [activeNav, setActiveNav] = useState('overview');
  const [status, setStatus] = useState('COMPLETED');
  const [stats, setStats] = useState({
    endpoints_discovered: 74,
    api_endpoints: 48,
    candidates_count: 6,
    verified_count: 6,
    rejected_count: 0,
    retest_passed_count: 1,
    risk_high: 2,
    risk_critical: 0
  });
  const [findings, setFindings] = useState([]);
  const [logs, setLogs] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAuthModal, setShowAuthModal] = useState(false);

  const wsRef = useRef(null);

  useEffect(() => {
    const saved = localStorage.getItem('wm_secops_session');
    if (saved) {
      try {
        const u = JSON.parse(saved);
        if (u.name && u.name.includes('SIH')) {
          u.name = 'Chief Security Auditor';
        }
        setUserRole(u);
        setIsAuthenticated(true);
      } catch (e) {}
    }

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/ws/assessment`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'INIT_STATE' || msg.type === 'ATTACK_SURFACE_READY') {
        if (msg.stats) setStats(msg.stats);
        if (msg.findings) setFindings(msg.findings);
        if (msg.logs) setLogs(msg.logs);
      } else if (msg.type === 'STATUS_UPDATE') {
        setStatus(msg.status);
      } else if (msg.type === 'LOG_ENTRY') {
        setLogs(prev => [...prev.slice(-100), msg.log]);
      } else if (msg.type === 'FINDING_UPDATE') {
        if (msg.stats) setStats(msg.stats);
        setFindings(prev => {
          const idx = prev.findIndex(f => f.id === msg.finding.id);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = msg.finding;
            return next;
          }
          return [...prev, msg.finding];
        });
      } else if (msg.type === 'ASSESSMENT_COMPLETED') {
        setStatus('COMPLETED');
        if (msg.stats) setStats(msg.stats);
        if (msg.findings) setFindings(msg.findings);
      } else if (msg.type === 'RETEST_COMPLETED') {
        if (msg.stats) setStats(msg.stats);
        setFindings(prev => {
          const idx = prev.findIndex(f => f.id === msg.finding.id);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = msg.finding;
            return next;
          }
          return prev;
        });
      }
    };

    fetch('/api/assessment/state')
      .then(r => r.json())
      .then(d => {
        if (d.stats) setStats(d.stats);
        if (d.findings) setFindings(d.findings);
        if (d.logs) setLogs(d.logs);
      })
      .catch(() => {});

    return () => ws.close();
  }, []);

  const loginRole = (name, email) => {
    setUserRole({ name, email });
    setIsAuthenticated(true);
    setShowAuthModal(false);
    localStorage.setItem('wm_secops_session', JSON.stringify({ name, email }));
  };

  const logout = () => {
    setIsAuthenticated(false);
    localStorage.removeItem('wm_secops_session');
  };

  const triggerScan = () => {
    if (!isAuthenticated) {
      setShowAuthModal(true);
      return;
    }
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      setStatus('RUNNING');
      wsRef.current.send(JSON.stringify({
        action: 'START_ASSESSMENT',
        config: { target_url: 'https://www.worldmonitor.app', use_local_mock: true, target_source_path: 'target_repo' }
      }));
    }
  };

  const triggerRetest = (id) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'RUN_RETEST', finding_id: id }));
    }
  };

  const filteredFindings = findings.filter(f =>
    f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.affected_component.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div style={{ height: '100vh', display: 'flex', background: '#06080e', color: '#f8fafc', overflow: 'hidden', fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      
      {/* Auth Modal */}
      {showAuthModal && (
        <div onClick={() => setShowAuthModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(3, 5, 10, 0.88)', backdropFilter: 'blur(12px)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1.5rem' }}>
          <div onClick={e => e.stopPropagation()} style={{ background: '#0e1424', border: '1px solid rgba(0,240,255,0.4)', borderRadius: 16, width: '100%', maxWidth: 440, padding: '2rem', boxShadow: '0 0 50px rgba(0,240,255,0.18)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
              <div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 800, color: '#fff' }}>WorldKavach SecOps</h2>
                <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Analyst Clearance Sign-In (Autonomous DAST)</p>
              </div>
              <button onClick={() => setShowAuthModal(false)} style={{ background: 'transparent', border: 'none', color: '#64748b', fontSize: '1.2rem', cursor: 'pointer' }}>&times;</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              <button
                onClick={() => loginRole('Chief Security Auditor', 'auditor@worldmonitor.secops')}
                style={{ background: '#131b30', border: '1px solid rgba(0,240,255,0.3)', color: '#fff', padding: '0.65rem 0.85rem', borderRadius: 8, textAlign: 'left', cursor: 'pointer', fontWeight: 600, fontSize: '0.82rem' }}
              >
                👤 <strong>Chief Security Auditor</strong> (Full Clearance L4)
              </button>
              <button
                onClick={() => loginRole('Red Team Operator', 'redteam@worldmonitor.secops')}
                style={{ background: '#131b30', border: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8', padding: '0.65rem 0.85rem', borderRadius: 8, textAlign: 'left', cursor: 'pointer', fontSize: '0.82rem' }}
              >
                ⚡ <strong>Red Team Operator</strong> (Prover &amp; Exploitation)
              </button>
              <button
                onClick={() => loginRole('DevSecOps Engineer', 'devsecops@worldmonitor.secops')}
                style={{ background: '#131b30', border: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8', padding: '0.65rem 0.85rem', borderRadius: 8, textAlign: 'left', cursor: 'pointer', fontSize: '0.82rem' }}
              >
                🔧 <strong>DevSecOps Engineer</strong> (Fixer &amp; Patch Lab)
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Left Sidebar */}
      <aside style={{ width: isSidebarCollapsed ? 68 : 250, background: '#090d18', borderRight: '1px solid rgba(255,255,255,0.08)', display: 'flex', flexDirection: 'column', flexShrink: 0, transition: 'width 0.2s' }}>
        <div style={{ height: 56, padding: '0 1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', overflow: 'hidden' }}>
            <div style={{ width: 32, height: 32, background: 'linear-gradient(135deg, #00f0ff, #0284c7)', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              🛡️
            </div>
            {!isSidebarCollapsed && (
              <div>
                <div style={{ fontWeight: 800, fontSize: '0.95rem', lineHeight: 1.2 }}>WorldKavach</div>
                <div style={{ fontSize: '0.62rem', color: '#00f0ff', fontFamily: 'monospace', fontWeight: 700 }}>SECOPS DAST</div>
              </div>
            )}
          </div>
          <button onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)} style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', color: '#64748b', cursor: 'pointer', borderRadius: 4, padding: '2px 6px' }}>
            {isSidebarCollapsed ? '▶' : '◀'}
          </button>
        </div>

        <div style={{ flex: 1, padding: '0.9rem 0.65rem', display: 'flex', flexDirection: 'column', gap: '0.25rem', overflowY: 'auto' }}>
          {[
            { id: 'overview', label: 'Executive Overview', icon: '📊' },
            { id: 'findings', label: 'Vulnerabilities & PoC', icon: '🛡️', badge: findings.length },
            { id: 'terminal', label: 'AI Agent Feed', icon: '🤖' },
            { id: 'sandbox', label: 'Sandbox Patch Lab', icon: '🧪' },
            { id: 'cvss', label: 'CVSS 3.1 Radar', icon: '📐' },
            { id: 'reports', label: 'Compliance Reports', icon: '📑' }
          ].map(item => (
            <div
              key={item.id}
              onClick={() => {
                if (!isAuthenticated) setShowAuthModal(true);
                else setActiveNav(item.id);
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.55rem 0.75rem',
                borderRadius: 8,
                color: activeNav === item.id ? '#00f0ff' : '#94a3b8',
                background: activeNav === item.id ? 'rgba(0, 240, 255, 0.08)' : 'transparent',
                fontWeight: 600,
                fontSize: '0.82rem',
                cursor: 'pointer',
                whiteSpace: 'nowrap'
              }}
            >
              <span>{item.icon}</span>
              {!isSidebarCollapsed && <span>{item.label}</span>}
              {!isSidebarCollapsed && item.badge && (
                <span style={{ marginLeft: 'auto', background: 'rgba(255,0,85,0.2)', color: '#ff85a2', padding: '0.1rem 0.45rem', borderRadius: 9999, fontSize: '0.65rem', fontWeight: 700 }}>
                  {item.badge}
                </span>
              )}
            </div>
          ))}
        </div>

        {isAuthenticated && (
          <div style={{ padding: '0.85rem 1rem', borderTop: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            {!isSidebarCollapsed && (
              <div>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#fff' }}>{userRole.name}</div>
                <div style={{ fontSize: '0.65rem', color: '#10b981', fontFamily: 'monospace' }}>CLEARANCE: L4</div>
              </div>
            )}
            <button onClick={logout} style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '1rem' }} title="Sign Out">
              🚪
            </button>
          </div>
        )}
      </aside>

      {/* Main Viewport */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ height: 56, borderBottom: '1px solid rgba(255,255,255,0.08)', padding: '0 1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(10, 14, 24, 0.9)', backdropFilter: 'blur(12px)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ fontSize: '1.05rem', fontWeight: 800 }}>
              {activeNav === 'overview' && 'Executive Security Overview'}
              {activeNav === 'findings' && 'Verified Vulnerabilities & Proof-of-Concepts'}
              {activeNav === 'terminal' && 'AI Security Team Feed'}
              {activeNav === 'sandbox' && 'Controlled Sandbox Mitigation Lab'}
              {activeNav === 'cvss' && 'CVSS v3.1 Base Score Radar'}
              {activeNav === 'reports' && 'Compliance Deliverables & Reports'}
            </div>
            <div style={{ background: '#131b30', border: '1px solid rgba(255,255,255,0.08)', padding: '0.25rem 0.65rem', borderRadius: 9999, fontSize: '0.72rem', fontFamily: 'monospace' }}>
              worldmonitor.app &bull; <span style={{ color: '#10b981' }}>ONLINE</span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ background: '#131b30', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 9999, padding: '0.3rem 0.65rem', fontSize: '0.7rem', fontFamily: 'monospace', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: status === 'RUNNING' ? '#00f0ff' : '#10b981' }}></span>
              {status}
            </div>

            <button
              onClick={triggerScan}
              style={{ background: 'linear-gradient(135deg, #00f0ff, #0284c7)', color: '#06080e', fontWeight: 700, padding: '0.4rem 0.85rem', borderRadius: 7, border: 'none', cursor: 'pointer', boxShadow: '0 0 16px rgba(0,240,255,0.3)', fontSize: '0.78rem' }}
            >
              Run Assessment
            </button>

            {!isAuthenticated ? (
              <button
                onClick={() => setShowAuthModal(true)}
                style={{ background: 'rgba(0, 240, 255, 0.1)', border: '1px solid #00f0ff', color: '#00f0ff', padding: '0.38rem 0.85rem', borderRadius: 7, fontWeight: 700, fontSize: '0.78rem', cursor: 'pointer' }}
              >
                🔒 Sign In
              </button>
            ) : (
              <button
                onClick={logout}
                style={{ background: '#131b30', border: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', padding: '0.38rem 0.75rem', borderRadius: 7, fontSize: '0.75rem', cursor: 'pointer' }}
              >
                Sign Out
              </button>
            )}
          </div>
        </div>

        {/* Viewport Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '1.25rem 1.75rem' }}>
          
          {/* If unauthenticated, show Index Landing Gate */}
          {!isAuthenticated ? (
            <div style={{ background: 'radial-gradient(circle at 50% 20%, rgba(0, 240, 255, 0.08) 0%, rgba(14, 20, 36, 0.4) 60%, transparent 100%)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 16, padding: '2.5rem 2rem', textAlign: 'center', maxWidth: 900, margin: '1.5rem auto', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.5rem' }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.3)', color: '#00f0ff', padding: '0.3rem 0.85rem', borderRadius: 9999, fontSize: '0.72rem', fontFamily: 'monospace', fontWeight: 700 }}>
                AUTONOMOUS EVIDENCE-FIRST DAST PLATFORM
              </div>
              <h1 style={{ fontSize: '2.1rem', fontWeight: 800, color: '#fff', lineHeight: 1.2 }}>
                AI-Powered Evidence-First<br />
                <span style={{ color: '#00f0ff' }}>Security Assessment Platform</span>
              </h1>
              <p style={{ fontSize: '0.95rem', color: '#94a3b8', maxWidth: 650, lineHeight: 1.55 }}>
                Autonomous AST source parsing, AST attack surface categorization, deterministic live HTTP DAST proof validation, and surgical code patching for web applications.
              </p>

              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
                <button
                  onClick={() => setShowAuthModal(true)}
                  style={{ background: 'linear-gradient(135deg, #00f0ff, #0284c7)', color: '#06080e', fontWeight: 700, padding: '0.75rem 1.6rem', borderRadius: 8, border: 'none', cursor: 'pointer', fontSize: '0.9rem', boxShadow: '0 0 16px rgba(0,240,255,0.3)' }}
                >
                  🔒 Sign In to Access Assessment Suite
                </button>
                <button
                  onClick={() => loginRole('Chief Security Auditor', 'auditor@worldmonitor.secops')}
                  style={{ background: '#131b30', color: '#fff', border: '1px solid rgba(255,255,255,0.1)', padding: '0.75rem 1.25rem', borderRadius: 8, cursor: 'pointer', fontSize: '0.9rem' }}
                >
                  🚀 Instant Auditor Demo Access
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', width: '100%', marginTop: '1rem' }}>
                <div onClick={() => loginRole('Chief Security Auditor', 'auditor@worldmonitor.secops')} style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1.25rem 1rem', textAlign: 'left', cursor: 'pointer' }}>
                  <div style={{ fontSize: '1.4rem', marginBottom: '0.5rem' }}>👤</div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#fff' }}>Chief Security Auditor</div>
                  <div style={{ fontSize: '0.65rem', fontFamily: 'monospace', color: '#00f0ff', marginBottom: '0.35rem' }}>CLEARANCE LEVEL 4</div>
                  <div style={{ fontSize: '0.72rem', color: '#94a3b8', lineHeight: 1.4 }}>Full governance clearance, compliance report exports, and executive metrics.</div>
                </div>

                <div onClick={() => loginRole('Red Team Operator', 'redteam@worldmonitor.secops')} style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1.25rem 1rem', textAlign: 'left', cursor: 'pointer' }}>
                  <div style={{ fontSize: '1.4rem', marginBottom: '0.5rem' }}>⚡</div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#fff' }}>Red Team Operator</div>
                  <div style={{ fontSize: '0.65rem', fontFamily: 'monospace', color: '#00f0ff', marginBottom: '0.35rem' }}>CLEARANCE LEVEL 3</div>
                  <div style={{ fontSize: '0.72rem', color: '#94a3b8', lineHeight: 1.4 }}>Interactive live HTTP prober, attack surface node exploitation, and PoC replay.</div>
                </div>

                <div onClick={() => loginRole('DevSecOps Engineer', 'devsecops@worldmonitor.secops')} style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1.25rem 1rem', textAlign: 'left', cursor: 'pointer' }}>
                  <div style={{ fontSize: '1.4rem', marginBottom: '0.5rem' }}>🔧</div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#fff' }}>DevSecOps Engineer</div>
                  <div style={{ fontSize: '0.65rem', fontFamily: 'monospace', color: '#00f0ff', marginBottom: '0.35rem' }}>CLEARANCE LEVEL 2</div>
                  <div style={{ fontSize: '0.72rem', color: '#94a3b8', lineHeight: 1.4 }}>Automated sandbox patch lab, unified diffs, and Before vs After re-test.</div>
                </div>
              </div>
            </div>
          ) : (
            <>
              {activeNav === 'overview' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
                    <div style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1rem 1.25rem', borderTop: '3px solid #00f0ff' }}>
                      <div style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Endpoints Mapped</div>
                      <div style={{ fontSize: '1.7rem', fontWeight: 800 }}>{stats.endpoints_discovered}</div>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>48 API Routes &bull; 18 Auth</div>
                    </div>
                    <div style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1rem 1.25rem', borderTop: '3px solid #ff0055' }}>
                      <div style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Verified Vulnerabilities</div>
                      <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#ff0055' }}>{stats.verified_count}</div>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Live HTTP Evidence Traces</div>
                    </div>
                    <div style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1rem 1.25rem', borderTop: '3px solid #10b981' }}>
                      <div style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>False Positives Pruned</div>
                      <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#10b981' }}>{stats.rejected_count}</div>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Applicability Engine Gating</div>
                    </div>
                    <div style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1rem 1.25rem', borderTop: '3px solid #10b981' }}>
                      <div style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Re-Tests Verified</div>
                      <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#10b981' }}>{stats.retest_passed_count}</div>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Before vs After Passed</div>
                    </div>
                  </div>

                  <div style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1.25rem' }}>
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 800, marginBottom: '0.85rem' }}>High Priority Verified Findings</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                      {findings.slice(0, 3).map(f => (
                        <div key={f.id} style={{ background: '#141d33', padding: '0.75rem 0.9rem', borderRadius: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{f.id}: {f.title}</div>
                            <div style={{ fontSize: '0.72rem', color: '#00f0ff', fontFamily: 'monospace' }}>{f.affected_component} &bull; CVSS {f.cvss_score}</div>
                          </div>
                          <button onClick={() => setSelectedFinding(f)} style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.2)', color: '#fff', padding: '0.25rem 0.55rem', borderRadius: 6, fontSize: '0.7rem', cursor: 'pointer' }}>
                            View PoC &rarr;
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {activeNav === 'findings' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <input
                      type="text"
                      placeholder="Search findings..."
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                      style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', padding: '0.45rem 0.85rem', borderRadius: 8, color: '#fff', fontSize: '0.82rem', width: 300 }}
                    />
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>6 candidate findings &bull; 6 verified with deterministic HTTP traces</span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(460px, 1fr))', gap: '1.15rem' }}>
                    {filteredFindings.map(f => (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        style={{ background: '#141d33', border: '1px solid rgba(255,255,255,0.08)', borderLeft: `4px solid ${f.retest_status === 'FIX_VERIFIED' ? '#10b981' : '#ff0055'}`, borderRadius: 12, padding: '1.25rem', cursor: 'pointer' }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                          <span style={{ fontSize: '0.65rem', padding: '0.18rem 0.5rem', borderRadius: 4, background: 'rgba(255,0,85,0.15)', color: '#ff85a2', fontWeight: 800 }}>
                            {f.severity} ({f.cvss_score})
                          </span>
                          <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: '#64748b' }}>{f.id}</span>
                        </div>

                        <div style={{ fontWeight: 700, fontSize: '0.92rem', color: '#fff' }}>{f.title}</div>
                        <div style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: '#00f0ff', margin: '0.2rem 0' }}>{f.affected_component}</div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.65rem', fontSize: '0.72rem', color: '#64748b' }}>
                          <span>Confidence: {Math.round(f.confidence * 100)}%</span>
                          <button
                            onClick={(e) => { e.stopPropagation(); triggerRetest(f.id); }}
                            style={{ background: 'transparent', border: '1px solid #10b981', color: '#34d399', padding: '0.25rem 0.6rem', borderRadius: 4, cursor: 'pointer', fontSize: '0.7rem', fontWeight: 700 }}
                          >
                            &#9851; Re-Test Fix
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeNav === 'terminal' && (
                <div style={{ background: '#04060c', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, minHeight: 500, padding: '1.15rem', fontFamily: 'monospace', fontSize: '0.78rem', overflowY: 'auto' }}>
                  {logs.map((log, i) => (
                    <div key={i} style={{ display: 'flex', gap: '0.75rem', marginBottom: '0.4rem' }}>
                      <span style={{ color: '#64748b' }}>[{log.timestamp}]</span>
                      <span style={{ fontWeight: 700, width: 95, color: log.sender === 'PROVER' ? '#f59e0b' : (log.sender === 'FIXER' ? '#10b981' : '#00f0ff') }}>
                        {log.sender}
                      </span>
                      <span style={{ color: '#cbd5e1' }}>{log.message}</span>
                    </div>
                  ))}
                </div>
              )}

              {activeNav === 'sandbox' && (
                <div style={{ background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '1.25rem', maxWidth: 850 }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 800, marginBottom: '0.4rem' }}>Controlled Sandbox Mitigation Lab</h3>
                  <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginBottom: '1.25rem' }}>Run automated before/after re-tests against target sandbox patches:</p>
                  {['FIND-WM-001', 'FIND-WM-002', 'FIND-WM-003', 'FIND-WM-004'].map(pid => (
                    <div key={pid} style={{ background: '#141d33', padding: '1rem', borderRadius: 8, marginBottom: '0.85rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.88rem' }}>{pid} Mitigation Patch</span>
                      <button onClick={() => triggerRetest(pid)} style={{ background: '#059669', color: '#fff', border: 'none', padding: '0.35rem 0.8rem', borderRadius: 6, fontWeight: 700, fontSize: '0.72rem', cursor: 'pointer' }}>
                        Run Re-Test
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {activeNav === 'reports' && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem', maxWidth: 850 }}>
                  <a href="/api/assessment/report/html" target="_blank" rel="noreferrer" style={{ textDecoration: 'none', background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', padding: '1.15rem', borderRadius: 10, color: '#fff', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                    <div style={{ fontWeight: 800, fontSize: '0.9rem' }}>📄 Executive HTML Report</div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Standalone interactive executive presentation</div>
                  </a>
                  <a href="/api/assessment/report/pdf" target="_blank" rel="noreferrer" style={{ textDecoration: 'none', background: '#0e1424', border: '1px solid rgba(255,255,255,0.08)', padding: '1.15rem', borderRadius: 10, color: '#fff', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                    <div style={{ fontWeight: 800, fontSize: '0.9rem' }}>📄 Formal PDF Document</div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Auditor-grade PDF with metrics tables</div>
                  </a>
                </div>
              )}
            </>
          )}

        </div>
      </main>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(3, 5, 10, 0.88)', backdropFilter: 'blur(12px)', zIndex: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1.5rem' }}>
          <div style={{ background: '#0e1424', border: '1px solid rgba(0,240,255,0.4)', borderRadius: 14, width: '100%', maxWidth: 860, maxHeight: '88vh', overflowY: 'auto', padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.85rem', marginBottom: '1.15rem' }}>
              <div>
                <span style={{ fontSize: '0.65rem', padding: '0.18rem 0.5rem', borderRadius: 4, background: '#ff0055', color: '#fff', fontWeight: 800 }}>
                  {selectedFinding.severity} ({selectedFinding.cvss_score})
                </span>
                <h3 style={{ marginTop: '0.35rem', fontSize: '1.1rem' }}>{selectedFinding.id}: {selectedFinding.title}</h3>
              </div>
              <button onClick={() => setSelectedFinding(null)} style={{ background: 'transparent', border: 'none', color: '#64748b', fontSize: '1.3rem', cursor: 'pointer' }}>&times;</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.82rem', color: '#cbd5e1' }}>
              <div>
                <h4 style={{ color: '#00f0ff', fontSize: '0.7rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Description</h4>
                <p style={{ lineHeight: 1.5 }}>{selectedFinding.description}</p>
              </div>

              <div>
                <h4 style={{ color: '#00f0ff', fontSize: '0.7rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Controlled Proof of Concept</h4>
                <pre style={{ background: '#04060c', padding: '0.75rem', borderRadius: 6, color: '#00f0ff', fontFamily: 'monospace', overflowX: 'auto', fontSize: '0.75rem' }}>
                  {selectedFinding.poc_code}
                </pre>
              </div>

              {selectedFinding.evidence && (
                <div>
                  <h4 style={{ color: '#10b981', fontSize: '0.7rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Live Captured HTTP Evidence Trace</h4>
                  <pre style={{ background: '#04060c', padding: '0.75rem', borderRadius: 6, color: '#34d399', fontFamily: 'monospace', overflowX: 'auto', fontSize: '0.75rem' }}>
                    {`URL: ${selectedFinding.evidence.method} ${selectedFinding.evidence.url}\nStatus: ${selectedFinding.evidence.response_status} (${selectedFinding.evidence.duration_ms} ms)\n\nResponse Body:\n${selectedFinding.evidence.response_body}`}
                  </pre>
                </div>
              )}

              {selectedFinding.remediation_diff && (
                <div>
                  <h4 style={{ color: '#f97316', fontSize: '0.7rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Proposed Code Patch (Unified Diff)</h4>
                  <pre style={{ background: '#04060c', borderLeft: '3px solid #f97316', padding: '0.75rem', borderRadius: 6, color: '#fdba74', fontFamily: 'monospace', overflowX: 'auto', fontSize: '0.75rem' }}>
                    {selectedFinding.remediation_diff}
                  </pre>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.25rem', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '0.85rem' }}>
              <button onClick={() => triggerRetest(selectedFinding.id)} style={{ background: 'linear-gradient(135deg, #059669, #10b981)', color: '#fff', border: 'none', padding: '0.45rem 0.95rem', borderRadius: 8, fontWeight: 700, cursor: 'pointer', fontSize: '0.78rem' }}>
                &#9851; Run Before vs After Re-Test
              </button>
              <button onClick={() => setSelectedFinding(null)} style={{ background: '#141d33', color: '#fff', border: '1px solid rgba(255,255,255,0.1)', padding: '0.45rem 0.95rem', borderRadius: 8, cursor: 'pointer', fontSize: '0.78rem' }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
