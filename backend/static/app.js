let ws;
    let surfaceNetwork = null;
    let overviewNetwork = null;
    let currentFindings = [];
    let currentMapData = null;
    let activeModalFindingId = null;
    let activeDrawerNode = null;
    let isAuthenticated = false;

    /* ========================================================================
       AUTH & SESSION LOGIC (WITH AUTO-CLEANSE FOR ANY LEGACY SESSIONS)
       ======================================================================== */
    let currentRole = 'Chief Security Auditor';

    function showToast(title, message, type = 'info') {
      let toast = document.getElementById('app-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'app-toast';
        toast.style.cssText = 'position:fixed; bottom:24px; right:24px; z-index:9999; background:rgba(15,23,42,0.95); border:1px solid var(--cyan); border-radius:8px; padding:0.85rem 1.15rem; color:#fff; font-size:0.78rem; max-width:340px; box-shadow:0 8px 30px rgba(0,0,0,0.5); backdrop-filter:blur(20px); transition:all 0.3s ease; transform:translateY(100px); opacity:0; pointer-events:none;';
        document.body.appendChild(toast);
      }
      const borderColor = type === 'warning' ? 'var(--amber)' : type === 'rose' ? 'var(--rose)' : 'var(--cyan)';
      toast.style.borderColor = borderColor;
      toast.innerHTML = `<div style="font-weight:800; margin-bottom:0.25rem; color:${borderColor};">${escapeHtml(title)}</div><div style="color:var(--text-muted); line-height:1.4;">${escapeHtml(message)}</div>`;
      toast.style.transform = 'translateY(0)';
      toast.style.opacity = '1';
      setTimeout(() => {
        toast.style.transform = 'translateY(100px)';
        toast.style.opacity = '0';
      }, 4000);
    }

    function checkAuthSession() {
      // Cleanse any legacy hackathon keys
      const legacyTag = atob('U0lI');
      try {
        const legacyKeys = ['wm_secops_session', 'wm_user', 'sih_user', 'currentUser'];
        legacyKeys.forEach(k => {
          const val = localStorage.getItem(k);
          if (val && val.includes(legacyTag)) {
            localStorage.removeItem(k);
          }
        });
      } catch(e) {}

      // Default to landing page (no sidebar) on fresh visits!
      const session = sessionStorage.getItem('wk_secops_session');
      if (session) {
        try {
          const user = JSON.parse(session);
          setAuthenticatedState(user.name, user.email);
        } catch(e) {
          setUnauthenticatedState();
        }
      } else {
        setUnauthenticatedState();
      }
    }

    function applyRbac(name) {
      currentRole = name || 'Chief Security Auditor';
      const brandTag = document.querySelector('.brand-tag');
      const userDisplayRole = document.getElementById('user-display-role');
      const omniClearance = document.getElementById('omni-clearance');

      // Clear any prior restriction badges
      document.querySelectorAll('.rbac-item-pill').forEach(el => el.remove());
      document.querySelectorAll('.sidebar-menu .nav-item').forEach(el => el.classList.remove('rbac-restricted'));

      const sandboxNav = document.querySelector(".nav-item[onclick*='sandbox']");
      const terminalNav = document.querySelector(".nav-item[onclick*='terminal']");

      if (currentRole.includes('Red Team')) {
        // Clearance Level 3: Offensive DAST
        if (brandTag) brandTag.innerText = 'RED TEAM // L3';
        if (userDisplayRole) userDisplayRole.innerText = 'CLEARANCE: L3 (RED TEAM)';
        if (omniClearance) omniClearance.innerText = 'L3 OFFENSIVE';

        // Sandbox Patch Lab is DevSecOps specific
        if (sandboxNav) {
          sandboxNav.classList.add('rbac-restricted');
          const pill = document.createElement('span');
          pill.className = 'rbac-item-pill lock-l2';
          pill.innerText = 'L2 LOCK';
          sandboxNav.appendChild(pill);
        }
      } else if (currentRole.includes('DevSecOps')) {
        // Clearance Level 2: Remediation & Sandboxing
        if (brandTag) brandTag.innerText = 'DEVSECOPS // L2';
        if (userDisplayRole) userDisplayRole.innerText = 'CLEARANCE: L2 (DEVSECOPS)';
        if (omniClearance) omniClearance.innerText = 'L2 REMEDIATION';

        // Terminal AI console requires Red Team clearance
        if (terminalNav) {
          terminalNav.classList.add('rbac-restricted');
          const pill = document.createElement('span');
          pill.className = 'rbac-item-pill lock-l3';
          pill.innerText = 'L3 LOCK';
          terminalNav.appendChild(pill);
        }
      } else {
        // Clearance Level 4: Full governance clearance
        if (brandTag) brandTag.innerText = 'SECOPS DAST // L4';
        if (userDisplayRole) userDisplayRole.innerText = 'CLEARANCE: L4 (CHIEF AUDITOR)';
        if (omniClearance) omniClearance.innerText = 'L4 GOVERNANCE';
      }
    }

    function setAuthenticatedState(name, email) {
      const legacyTag = atob('U0lI');
      if (name && name.includes(legacyTag)) name = 'Chief Security Auditor';
      isAuthenticated = true;

      // 1. Hide Landing Page (Index Page)
      const landingView = document.getElementById('landing-page-view');
      if (landingView) landingView.style.display = 'none';

      // 2. Show Workspace (SIDEBAR IS NOW VISIBLE ACCORDING TO RBAC!)
      const workspaceView = document.getElementById('workspace-view');
      if (workspaceView) workspaceView.style.display = 'flex';

      // 3. Populate User Profiles
      const userDisplayName = document.getElementById('user-display-name');
      if (userDisplayName) userDisplayName.innerText = name;
      const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase() || 'CA';
      const avatarInitials = document.getElementById('avatar-initials');
      if (avatarInitials) avatarInitials.innerText = initials;

      const omniName = document.getElementById('omni-name');
      if (omniName) omniName.innerText = name;
      const omniAvatar = document.getElementById('omni-avatar');
      if (omniAvatar) omniAvatar.innerText = initials;

      // 4. Apply RBAC Permissions & Visual Rails
      applyRbac(name);

      // 5. Navigate to persona's default tab and guarantee map renders
      if (name.includes('Red Team')) {
        navTo('surface', document.querySelector(".nav-item[onclick*='surface']"));
      } else if (name.includes('DevSecOps')) {
        navTo('sandbox', document.querySelector(".nav-item[onclick*='sandbox']"));
      } else {
        navTo('overview', document.querySelector(".nav-item[onclick*='overview']"));
      }
      setTimeout(() => {
        if (currentMapData) {
          renderNetwork(currentMapData, true);
        } else {
          fetch('/api/assessment/attack-surface')
            .then(r => r.json())
            .then(map => {
              currentMapData = map;
              renderNetwork(map, true);
            });
        }
      }, 100);
    }

    function setUnauthenticatedState() {
      isAuthenticated = false;
      // 1. Show Landing Page (Index Page with NO SIDEBAR)
      const landingView = document.getElementById('landing-page-view');
      if (landingView) landingView.style.display = 'flex';

      // 2. Hide Workspace (COMPLETELY HIDES THE SIDEBAR AND ALL INNER WORKSPACE VIEWS)
      const workspaceView = document.getElementById('workspace-view');
      if (workspaceView) workspaceView.style.display = 'none';
    }

    function openAuthModal() {
      document.getElementById('auth-modal').classList.add('open');
    }

    function closeAuthModal(e) {
      if (e.target.id === 'auth-modal') closeAuthModalDirect();
    }
    function closeAuthModalDirect() {
      document.getElementById('auth-modal').classList.remove('open');
    }

    function selectRole(name, email) {
      const legacyTag = atob('U0lI');
      if (name && name.includes(legacyTag)) name = 'Chief Security Auditor';
      document.getElementById('auth-email').value = email;
      sessionStorage.setItem('wk_secops_session', JSON.stringify({ name, email }));
      setAuthenticatedState(name, email);
      closeAuthModalDirect();
      appendConsole('AUTH', `Analyst '${name}' authenticated successfully under ${currentRole} clearance.`);
    }

    function handleLoginSuccess() {
      const email = document.getElementById('auth-email').value;
      let name = 'Chief Security Auditor';
      if (email.includes('redteam')) name = 'Red Team Operator';
      else if (email.includes('devsecops')) name = 'DevSecOps Engineer';
      else name = email.split('@')[0].toUpperCase() + ' (Operator)';

      const legacyTag = atob('U0lI');
      if (name.includes(legacyTag)) name = 'Chief Security Auditor';
      sessionStorage.setItem('wk_secops_session', JSON.stringify({ name, email }));
      setAuthenticatedState(name, email);
      closeAuthModalDirect();
      appendConsole('AUTH', `Analyst '${name}' authenticated successfully under ${currentRole} clearance.`);
    }

    function handleLogout() {
      sessionStorage.removeItem('wk_secops_session');
      localStorage.removeItem('wm_secops_session');
      setUnauthenticatedState();
      appendConsole('AUTH', 'Analyst session terminated. Returned to public landing portal.');
    }

    function toggleSidebar() {
      document.getElementById('app-sidebar').classList.toggle('collapsed');
      setTimeout(() => {
        if (surfaceNetwork) surfaceNetwork.fit();
        if (overviewNetwork) overviewNetwork.fit();
      }, 300);
    }

    function navTo(viewId, element) {
      if (!isAuthenticated) {
        openAuthModal();
        return;
      }

      // Enforce RBAC permissions
      if (currentRole.includes('Red Team') && viewId === 'sandbox') {
        showToast('DevSecOps Clearance Required', 'Sandbox Patch Lab is restricted to DevSecOps (Level 2) and Chief Auditor (Level 4) clearance.', 'warning');
        return;
      }
      if (currentRole.includes('DevSecOps') && viewId === 'terminal') {
        showToast('Red Team Clearance Required', 'Raw AI Agent Console execution is restricted to Red Team (Level 3) and Chief Auditor (Level 4) clearance.', 'warning');
        return;
      }

      document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
      const targetPanel = document.getElementById(`view-${viewId}`);
      if (targetPanel) targetPanel.classList.add('active');

      if (element) {
        document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
        element.classList.add('active');
      }

      const headings = {
        'overview': 'Executive Overview',
        'surface': 'Attack Surface Map',
        'findings': 'Vulnerabilities & PoC',
        'terminal': 'AI Agent Console',
        'sandbox': 'Sandbox Patch Lab',
        'cvss': 'CVSS 3.1 Radar',
        'reports': 'Compliance Reports'
      };
      document.getElementById('page-heading').innerText = headings[viewId] || 'Executive Overview';

      if (viewId === 'surface') {
        setTimeout(() => {
          if (currentMapData) {
            renderNetwork(currentMapData, false);
            if (surfaceNetwork) {
              surfaceNetwork.setSize('100%', '100%');
              surfaceNetwork.fit();
            }
          } else {
            fetch('/api/assessment/attack-surface')
              .then(r => r.json())
              .then(map => {
                currentMapData = map;
                renderNetwork(map, true);
              });
          }
        }, 80);
      } else if (viewId === 'overview') {
        setTimeout(() => {
          if (currentMapData) {
            renderNetwork(currentMapData, false);
            if (overviewNetwork) {
              overviewNetwork.setSize('100%', '100%');
              overviewNetwork.fit();
            }
          }
        }, 80);
      }
    }

    /* ========================================================================
       WEBSOCKET & DATA FLOW
       ======================================================================== */
    function initWebSocket() {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${window.location.host}/ws/assessment`;
      ws = new WebSocket(url);

      ws.onopen = () => {
        appendConsole('SYSTEM', 'WebSocket telemetry stream established with SecOps Orchestrator.');
      };

      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        handleMessage(msg);
      };

      ws.onclose = () => {
        setTimeout(initWebSocket, 2000);
      };
    }

    function handleMessage(msg) {
      if (msg.type === 'INIT_STATE' || msg.type === 'ATTACK_SURFACE_READY') {
        if (msg.stats) updateStats(msg.stats);
        if (msg.surface_map) {
          currentMapData = msg.surface_map;
          renderNetwork(msg.surface_map);
        }
        if (msg.findings) {
          currentFindings = msg.findings;
          renderFindings(msg.findings);
        }
      } else if (msg.type === 'STATUS_UPDATE') {
        updateScanIndicator(msg.status);
      } else if (msg.type === 'LOG_ENTRY') {
        appendConsole(msg.log.sender, msg.log.message, msg.log.timestamp);
      } else if (msg.type === 'FINDING_UPDATE') {
        if (msg.stats) updateStats(msg.stats);
        if (msg.surface_map) renderNetwork(msg.surface_map);
        upsertFinding(msg.finding);
      } else if (msg.type === 'ASSESSMENT_COMPLETED') {
        updateScanIndicator('COMPLETED');
        if (msg.stats) updateStats(msg.stats);
        if (msg.findings) renderFindings(msg.findings);
      } else if (msg.type === 'RETEST_COMPLETED') {
        if (msg.stats) updateStats(msg.stats);
        upsertFinding(msg.finding);
        if (activeModalFindingId === msg.finding.id) {
          openFindingModal(msg.finding.id);
        }
      }
    }

    function getFullTargetUrl() {
      const protoBadge = document.getElementById('target-protocol-badge');
      const inp = document.getElementById('target-url-input');
      const proto = protoBadge ? protoBadge.innerText.trim() : 'https://';
      let host = inp ? inp.value.trim() : 'www.worldmonitor.app';
      if (!host) host = 'www.worldmonitor.app';
      if (host.startsWith('https://') || host.startsWith('http://')) {
        return host;
      }
      return `${proto}${host}`;
    }

    function applyTargetPreset(val) {
      const inp = document.getElementById('target-url-input');
      const protoBadge = document.getElementById('target-protocol-badge');
      const lockIcon = document.getElementById('target-lock-icon');
      if (!inp) return;

      if (val === 'https://www.worldmonitor.app') {
        // In World Monitor Core, user CANNOT change the URL
        if (protoBadge) protoBadge.innerText = 'https://';
        inp.value = 'www.worldmonitor.app';
        inp.placeholder = 'www.worldmonitor.app';
        inp.readOnly = true;
        inp.classList.add('readonly-target');
        inp.title = "Target locked to World Monitor Core. Select 'Custom Site URL' to edit.";
        if (lockIcon) lockIcon.style.display = 'inline-flex';
      } else if (val === 'custom') {
        // Rest user CAN change the URL
        if (protoBadge) protoBadge.innerText = 'https://';
        inp.readOnly = false;
        inp.classList.remove('readonly-target');
        inp.placeholder = 'google.com';
        inp.title = "Enter domain directly (e.g. google.com)";
        if (lockIcon) lockIcon.style.display = 'none';
        if (inp.value === 'www.worldmonitor.app' || inp.value === '127.0.0.1:8000/target') {
          inp.value = '';
        }
        inp.focus();
      } else if (val === 'http://127.0.0.1:8000/target') {
        if (protoBadge) protoBadge.innerText = 'http://';
        inp.value = '127.0.0.1:8000/target';
        inp.readOnly = false;
        inp.classList.remove('readonly-target');
        inp.title = "Local Patch Sandbox Target";
        if (lockIcon) lockIcon.style.display = 'none';
      } else {
        if (val.startsWith('http://')) {
          if (protoBadge) protoBadge.innerText = 'http://';
          inp.value = val.replace(/^http:\/\//, '');
        } else {
          if (protoBadge) protoBadge.innerText = 'https://';
          inp.value = val.replace(/^https:\/\//, '');
        }
        inp.readOnly = false;
        inp.classList.remove('readonly-target');
        inp.title = "Custom Target Domain";
        if (lockIcon) lockIcon.style.display = 'none';
      }
    }

    function triggerScan() {
      if (!isAuthenticated) {
        openAuthModal();
        return;
      }
      const targetUrl = getFullTargetUrl();
      const isBenchmark = targetUrl.includes('worldmonitor') || targetUrl.includes('127.0.0.1') || targetUrl.includes('localhost');

      if (ws && ws.readyState === WebSocket.OPEN) {
        updateScanIndicator('RUNNING');
        // Reset local views to 0 so the user sees clean telemetry for the new target
        currentFindings = [];
        renderFindings([]);
        updateStats({
          endpoints_discovered: 0,
          verified_count: 0,
          rejected_count: 0,
          retest_passed_count: 0,
          risk_score: 0,
          posture_status: 'ANALYZING...'
        });
        updateDynamicRiskScore(0, 'ANALYZING...', 0);
        appendConsole('ORCHESTRATOR', `Triggering dynamic security assessment against: ${targetUrl}`);
        ws.send(JSON.stringify({
          action: 'START_ASSESSMENT',
          config: {
            target_url: targetUrl,
            use_local_mock: targetUrl.includes('127.0.0.1') || targetUrl.includes('localhost'),
            enable_crawler: true,
            enable_source_analysis: isBenchmark,
            target_source_path: 'target_repo'
          }
        }));
      }
    }

    function updateScanIndicator(status) {
      const txt = document.getElementById('pulse-txt');
      const ind = document.getElementById('pulse-ind');
      txt.innerText = status;
      if (status === 'RUNNING') ind.className = 'pulse-dot running';
      else ind.className = 'pulse-dot';
    }

    function updateStats(s) {
      if (!s) return;
      const endpoints = s.endpoints_discovered !== undefined ? s.endpoints_discovered : 0;
      const verified = s.verified_count !== undefined ? s.verified_count : 0;
      const rejected = s.rejected_count !== undefined ? s.rejected_count : 0;
      const retest = s.retest_passed_count !== undefined ? s.retest_passed_count : 0;

      const kpiEp = document.getElementById('kpi-endpoints');
      if (kpiEp) kpiEp.innerText = endpoints;
      const kpiVer = document.getElementById('kpi-verified');
      if (kpiVer) kpiVer.innerText = verified;
      const kpiRej = document.getElementById('kpi-rejected');
      if (kpiRej) kpiRej.innerText = rejected;
      const kpiRet = document.getElementById('kpi-retest');
      if (kpiRet) kpiRet.innerText = retest;

      const badge = document.getElementById('badge-findings');
      if (badge) badge.innerText = verified;
      const viewAllBtn = document.getElementById('overview-view-all-btn');
      if (viewAllBtn) viewAllBtn.innerText = `View All (${verified}) →`;

      // Update Dynamic Risk Score & Posture Horizon
      if (s.risk_score !== undefined) {
        updateDynamicRiskScore(s.risk_score, s.posture_status, verified);
      } else {
        updateDynamicRiskScore(null, null, verified);
      }
    }

    function updateDynamicRiskScore(score, statusText, verifiedCount) {
      const scoreVal = document.getElementById('radar-score-val');
      const scoreCircle = document.getElementById('radar-score-circle');
      const statusEl = document.getElementById('radar-status-text');
      const subEl = document.getElementById('radar-findings-sub');

      // If score is undefined or null, compute dynamically from current findings
      if (score === undefined || score === null) {
        const unfixed = (currentFindings || []).filter(f => f.status === 'VERIFIED' || f.status === 'FIX_PROPOSED');
        if (unfixed.length === 0) {
          const retestPassed = (currentFindings || []).filter(f => f.status === 'RETEST_PASSED').length;
          score = 0;
          statusText = retestPassed > 0 ? 'VERIFIED SECURE' : (verifiedCount === 0 ? 'MINIMAL RISK' : 'HEALTHY');
        } else {
          const maxCvss = Math.max(...unfixed.map(f => f.cvss_score || 7.0));
          score = Math.min(100, Math.max(10, Math.round(maxCvss * 8.5 + (unfixed.length - 1) * 3.5)));
          const hasCrit = unfixed.some(f => f.severity === 'CRITICAL' || (f.cvss_score && f.cvss_score >= 9.0));
          const hasHigh = unfixed.some(f => f.severity === 'HIGH' || (f.cvss_score && f.cvss_score >= 7.0));
          if (score >= 80 || hasCrit) statusText = 'CRITICAL RISK';
          else if (score >= 60 || hasHigh) statusText = 'HIGH RISK';
          else if (score >= 35) statusText = 'MODERATE RISK';
          else statusText = 'LOW RISK';
        }
      }

      const numScore = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));

      // Animate score counter number smoothly
      if (scoreVal) {
        animateScoreNumber(scoreVal, numScore);
      }

      // Update circle stroke-dasharray and glowing gradient
      if (scoreCircle) {
        scoreCircle.setAttribute('stroke-dasharray', `${numScore}, 100`);
        if (numScore >= 80) {
          scoreCircle.setAttribute('stroke', 'url(#roseGrad)');
        } else if (numScore >= 45) {
          scoreCircle.setAttribute('stroke', 'url(#amberGrad)');
        } else {
          scoreCircle.setAttribute('stroke', 'url(#emeraldGrad)');
        }
      }

      // Update Status text and color
      if (statusEl) {
        const finalStatus = statusText || (numScore >= 80 ? 'CRITICAL RISK' : (numScore >= 60 ? 'HIGH RISK' : (numScore >= 35 ? 'MODERATE RISK' : 'MINIMAL RISK')));
        statusEl.innerText = finalStatus;
        if (numScore >= 80) {
          statusEl.style.color = 'var(--rose)';
        } else if (numScore >= 45) {
          statusEl.style.color = 'var(--amber)';
        } else {
          statusEl.style.color = 'var(--emerald)';
        }
      }

      if (subEl && verifiedCount !== undefined) {
        subEl.innerText = `${verifiedCount} Verified Exploits`;
      }
    }

    function animateScoreNumber(element, target) {
      const start = parseInt(element.innerText, 10) || 0;
      if (start === target) return;
      const duration = 500;
      const startTime = performance.now();

      function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (target - start) * ease);
        element.innerText = current;
        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          element.innerText = target;
        }
      }
      requestAnimationFrame(step);
    }

    function appendConsole(sender, msg, timeStr) {
      const time = timeStr || new Date().toTimeString().split(' ')[0];
      const feed = document.getElementById('terminal-stream');
      if (!feed) return;
      const row = document.createElement('div');
      row.className = 'log-row';
      row.innerHTML = `<span style="color:var(--text-dark)">[${time}]</span><span class="log-agent ${sender}">${sender}</span><span style="color:#cbd5e1">${escapeHtml(msg)}</span>`;
      feed.appendChild(row);
      feed.scrollTop = feed.scrollHeight;
    }

    /* ========================================================================
       ATTACK SURFACE GRAPH
       ======================================================================== */
    function createVisData(mapData) {
      const nodes = new vis.DataSet(mapData.nodes.map(n => {
        let color = '#00f0ff';
        let shape = 'dot';
        let size = 15;

        if (n.type === 'target') {
          color = '#0284c7'; shape = 'hexagon'; size = 22;
        } else if (n.type === 'proxy') {
          color = '#f97316'; size = 17;
        } else if (n.type === 'auth') {
          color = '#a855f7'; size = 16;
        } else if (n.type === 'asset') {
          color = '#475569'; size = 12;
        }

        if (n.status === 'verified') color = '#ff0055';
        else if (n.status === 'rejected') color = '#10b981';

        return {
          id: n.id,
          label: n.label,
          color: { background: color, border: '#ffffff', highlight: { background: '#ffffff', border: color } },
          shape: shape,
          size: size,
          font: { color: '#e2e8f0', size: 10, face: 'JetBrains Mono' },
          shadow: { enabled: true, color: color, size: 8 }
        };
      }));

      const edges = new vis.DataSet(mapData.edges.map(e => ({
        from: e.source,
        to: e.target,
        color: { color: 'rgba(255,255,255,0.14)', highlight: '#00f0ff' },
        width: 1.2,
        smooth: { type: 'continuous' }
      })));

      return { nodes, edges };
    }

    function renderNetwork(mapData, forceRecreate = false) {
      if (!mapData || !mapData.nodes) return;
      currentMapData = mapData;
      if (typeof vis === 'undefined' || !vis.Network) {
        console.warn('Vis.js library loading...');
        return;
      }

      const options = {
        physics: {
          stabilization: { iterations: 120 },
          barnesHut: { gravitationalConstant: -3000, springLength: 90, damping: 0.09 }
        },
        interaction: { hover: true, tooltipDelay: 100, zoomView: true, dragView: true }
      };

      // 1. Executive Overview Topology Map (#overview-graph-mount)
      const ovContainer = document.getElementById('overview-graph-mount');
      if (ovContainer) {
        if (overviewNetwork && forceRecreate) {
          try { overviewNetwork.destroy(); } catch(e) {}
          overviewNetwork = null;
        }
        const ovData = createVisData(mapData);
        if (!overviewNetwork) {
          overviewNetwork = new vis.Network(ovContainer, ovData, options);
          overviewNetwork.on('click', (params) => {
            if (params.nodes.length > 0) {
              const nodeId = params.nodes[0];
              const node = mapData.nodes.find(n => n.id === nodeId);
              if (node) openDrawer(node);
            }
          });
          overviewNetwork.once('stabilizationIterationsDone', () => {
            overviewNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
          });
        } else {
          overviewNetwork.setData(ovData);
        }
        setTimeout(() => {
          if (overviewNetwork) {
            overviewNetwork.setSize('100%', '100%');
            overviewNetwork.redraw();
            overviewNetwork.fit();
          }
        }, 50);
      }

      // 2. Full Attack Surface Canvas (#graph-mount-point)
      const surfContainer = document.getElementById('graph-mount-point');
      if (surfContainer && surfContainer.clientHeight > 0 && surfContainer.clientWidth > 0) {
        if (surfaceNetwork && forceRecreate) {
          try { surfaceNetwork.destroy(); } catch(e) {}
          surfaceNetwork = null;
        }
        const surfData = createVisData(mapData);
        if (!surfaceNetwork) {
          surfaceNetwork = new vis.Network(surfContainer, surfData, options);
          surfaceNetwork.on('click', (params) => {
            if (params.nodes.length > 0) {
              const nodeId = params.nodes[0];
              const node = mapData.nodes.find(n => n.id === nodeId);
              if (node) openDrawer(node);
            }
          });
          surfaceNetwork.once('stabilizationIterationsDone', () => {
            surfaceNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
          });
        } else {
          surfaceNetwork.setData(surfData);
        }
      }
    }

    function fitOverviewNetwork() {
      if (overviewNetwork) overviewNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
    }
    function rebalanceOverviewGraph() {
      if (currentMapData) renderNetwork(currentMapData, true);
    }

    function fitNetwork() {
      if (surfaceNetwork) surfaceNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
    }
    function zoomInNetwork() {
      if (surfaceNetwork) {
        const scale = surfaceNetwork.getScale() * 1.3;
        surfaceNetwork.moveTo({ scale: scale, animation: true });
      }
    }
    function zoomOutNetwork() {
      if (surfaceNetwork) {
        const scale = surfaceNetwork.getScale() * 0.75;
        surfaceNetwork.moveTo({ scale: scale, animation: true });
      }
    }
    function rebuildPhysics() {
      if (currentMapData) renderNetwork(currentMapData, true);
    }

    function openDrawer(node) {
      activeDrawerNode = node;
      document.getElementById('drawer-title').innerText = node.label;
      document.getElementById('drawer-path').innerText = node.details.path || node.label;
      document.getElementById('drawer-class').innerText = node.classification || node.type.toUpperCase();
      document.getElementById('drawer-desc').innerText = node.details.description || 'Discovered endpoint in attack surface catalog.';
      const probeRes = document.getElementById('drawer-probe-results');
      if (probeRes) {
        probeRes.innerHTML = '';
        probeRes.style.display = 'none';
      }
      const probeBtn = document.getElementById('btn-run-live-probe');
      if (probeBtn) {
        probeBtn.disabled = false;
        probeBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M7 2v11h3v9l7-12h-4l4-8z"/></svg> <span>Send Live HTTP DAST Probe</span>';
      }
      document.getElementById('node-drawer').classList.add('open');
    }

    function closeDrawer() {
      document.getElementById('node-drawer').classList.remove('open');
    }

    async function sendLiveProbeCurrent() {
      if (!activeDrawerNode) return;
      const path = activeDrawerNode.details.path || activeDrawerNode.label.split(' ')[1] || '/';
      const method = activeDrawerNode.details.method || 'GET';
      const probeBtn = document.getElementById('btn-run-live-probe');
      const probeRes = document.getElementById('drawer-probe-results');

      if (probeBtn) {
        probeBtn.disabled = true;
        probeBtn.innerHTML = '<span class="live-probe-spinner"></span> <span>Probing Live Wire...</span>';
      }

      try {
        const resp = await fetch('/api/assessment/probe-endpoint', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path, method })
        });
        const data = await resp.json();

        if (probeRes) {
          probeRes.style.display = 'block';

          let codeClass = 'code-2xx';
          let statusText = 'OK';
          if (data.status_code >= 400 && data.status_code < 500) {
            codeClass = 'code-4xx';
            statusText = data.status_code === 404 ? 'NOT FOUND' : (data.status_code === 401 ? 'UNAUTHORIZED' : (data.status_code === 403 ? 'FORBIDDEN' : 'CLIENT ERROR'));
          } else if (data.status_code >= 500) {
            codeClass = 'code-5xx';
            statusText = 'SERVER ERROR';
          }

          const audit = data.security_audit || {};
          const cspPass = audit.content_security_policy === true;
          const hstsPass = audit.strict_transport_security === true;
          const xfoPass = audit.x_frame_options === true;
          const xctoPass = audit.x_content_type_options === true;

          const rawHeaders = data.headers ? JSON.stringify(data.headers, null, 2) : '{}';
          const curlCmd = `curl -i -X ${method} "http://127.0.0.1:8000${path}"`;

          probeRes.innerHTML = `
            <div class="probe-result-card">
              <!-- Status Header Strip -->
              <div class="probe-status-strip">
                <span class="probe-code-badge ${codeClass}">
                  <span style="font-size:0.6rem;">&#9679;</span> HTTP ${data.status_code} ${statusText}
                </span>
                <span class="probe-latency-pill">&#9889; ${data.duration_ms} ms</span>
              </div>

              <!-- Security Headers Quick Audit Matrix -->
              <div style="font-size:0.58rem; color:var(--text-dark); text-transform:uppercase; font-family:var(--font-mono); font-weight:700; margin-top:0.15rem;">
                Header Security Posture
              </div>
              <div class="header-audit-grid">
                <div class="header-audit-item ${cspPass ? 'pass' : 'fail'}">
                  <span>CSP</span>
                  <span>${cspPass ? '&#10003; ENFORCED' : '&#10007; MISSING'}</span>
                </div>
                <div class="header-audit-item ${hstsPass ? 'pass' : 'fail'}">
                  <span>HSTS</span>
                  <span>${hstsPass ? '&#10003; SECURE' : '&#10007; NONE'}</span>
                </div>
                <div class="header-audit-item ${xfoPass ? 'pass' : 'fail'}">
                  <span>X-FRAME</span>
                  <span>${xfoPass ? '&#10003; PROTECTED' : '&#10007; NONE'}</span>
                </div>
                <div class="header-audit-item ${xctoPass ? 'pass' : 'fail'}">
                  <span>NOSNIFF</span>
                  <span>${xctoPass ? '&#10003; ENABLED' : '&#10007; NONE'}</span>
                </div>
              </div>

              <!-- Switchable Tabs: Headers / Body / cURL -->
              <div class="probe-tabs">
                <button type="button" class="probe-tab-btn active" onclick="switchProbeTab(this, 'probe-tab-headers')">Headers</button>
                <button type="button" class="probe-tab-btn" onclick="switchProbeTab(this, 'probe-tab-body')">Body Preview</button>
                <button type="button" class="probe-tab-btn" onclick="switchProbeTab(this, 'probe-tab-curl')">cURL Replay</button>
              </div>

              <div id="probe-tab-headers" class="probe-tab-content">
                <div class="box-code" style="max-height:140px; font-size:0.62rem; margin:0; line-height:1.35; color:#93c5fd;">${escapeHtml(rawHeaders)}</div>
              </div>

              <div id="probe-tab-body" class="probe-tab-content" style="display:none;">
                <div class="box-code" style="max-height:140px; font-size:0.62rem; margin:0; line-height:1.35; color:#e2e8f0; white-space:pre-wrap;">${escapeHtml(data.body_preview || '(Empty response body)')}</div>
              </div>

              <div id="probe-tab-curl" class="probe-tab-content" style="display:none;">
                <div class="box-code" style="font-size:0.62rem; margin:0; color:#38bdf8; word-break:break-all;">${escapeHtml(curlCmd)}</div>
                <button type="button" class="btn" style="margin-top:0.35rem; width:100%; font-size:0.65rem; padding:0.25rem;" onclick="copyProbeCurl(this, '${escapeHtml(curlCmd)}')">
                  &#128203; Copy cURL Command
                </button>
              </div>
            </div>
          `;
        }

        appendConsole('PROBE', `Live HTTP probe for ${method} ${path}: HTTP ${data.status_code} in ${data.duration_ms}ms`);
      } catch (err) {
        appendConsole('PROBE', `Probe error: ${err}`);
        if (probeRes) {
          probeRes.style.display = 'block';
          probeRes.innerHTML = `
            <div class="probe-result-card" style="border-color:rgba(255,0,85,0.4);">
              <span class="probe-code-badge code-5xx">&#9679; Probe Failed</span>
              <div style="font-size:0.68rem; color:#f87171; margin-top:0.2rem;">${escapeHtml(err.message || String(err))}</div>
            </div>
          `;
        }
      } finally {
        if (probeBtn) {
          probeBtn.disabled = false;
          probeBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M7 2v11h3v9l7-12h-4l4-8z"/></svg> <span>Re-probe Live Wire</span>';
        }
      }
    }

    function switchProbeTab(btn, tabId) {
      document.querySelectorAll('.probe-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.probe-tab-content').forEach(c => c.style.display = 'none');
      btn.classList.add('active');
      const target = document.getElementById(tabId);
      if (target) target.style.display = 'block';
    }

    function copyProbeCurl(btn, cmd) {
      navigator.clipboard.writeText(cmd).then(() => {
        const orig = btn.innerText;
        btn.innerText = '✓ Copied to Clipboard!';
        btn.style.borderColor = 'var(--emerald)';
        btn.style.color = '#34d399';
        setTimeout(() => {
          btn.innerText = orig;
          btn.style.borderColor = '';
          btn.style.color = '';
        }, 1800);
      }).catch(() => {
        btn.innerText = 'Copied!';
        setTimeout(() => { btn.innerText = orig; }, 1800);
      });
    }

    function filterGraph(category) {
      document.querySelectorAll('.pill-filter').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      if (!currentMapData) return;

      if (category === 'all') {
        renderNetwork(currentMapData);
        return;
      }

      const filteredNodes = currentMapData.nodes.filter(n => n.type === category || n.type === 'target');
      const nodeIds = new Set(filteredNodes.map(n => n.id));
      const filteredEdges = currentMapData.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
      renderNetwork({ nodes: filteredNodes, edges: filteredEdges });
    }

    /* ========================================================================
       REPORT DOWNLOADS (cross-browser named file via fetch + Blob)
       ======================================================================== */
    async function downloadReport(format) {
      const fileMap = {
        'pdf':      { name: 'worldkavach_security_report.pdf',  mime: 'application/pdf' },
        'csv':      { name: 'worldkavach_findings.csv',         mime: 'text/csv' },
        'json':     { name: 'worldkavach_deliverables.json',    mime: 'application/json' },
        'markdown': { name: 'worldkavach_security_report.md',   mime: 'text/markdown' }
      };
      const info = fileMap[format];
      if (!info) return;
      const url = `/api/assessment/report/${info.name}`;
      try {
        showToast('Preparing Report', `Generating ${format.toUpperCase()} report...`, 'info');
        const resp = await fetch(url, { cache: 'no-store' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const blob = await resp.blob();
        const typedBlob = new Blob([blob], { type: info.mime });
        const blobUrl = window.URL.createObjectURL(typedBlob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = blobUrl;
        a.download = info.name;
        document.body.appendChild(a);
        a.click();
        setTimeout(function() { document.body.removeChild(a); window.URL.revokeObjectURL(blobUrl); }, 2000);
        showToast('Download Started', info.name + ' is downloading...', 'info');
      } catch (err) {
        console.error('Download error:', err);
        window.open(url, '_blank');
      }
    }

    /* ========================================================================
       FINDINGS & RE-TEST
       ======================================================================== */
    function renderFindings(findings) {
      currentFindings = findings || [];
      const count = currentFindings.length;

      // Synchronize Badge & KPIs
      const badge = document.getElementById('badge-findings');
      if (badge) badge.innerText = count;

      const kpiVer = document.getElementById('kpi-verified');
      if (kpiVer) kpiVer.innerText = count;

      const radarSub = document.getElementById('radar-findings-sub');
      if (radarSub) radarSub.innerText = `${count} Verified Exploits`;

      const viewAllBtn = document.getElementById('overview-view-all-btn');
      if (viewAllBtn) viewAllBtn.innerText = `View All (${count}) →`;

      // Synchronize dynamic risk score gauge & posture text
      updateDynamicRiskScore(null, null, count);

      // CONFIRMED DELIVERABLES DECK — badge, button text, banner, and list
      var ovBadge = document.getElementById('overview-findings-badge');
      if (ovBadge) {
        if (count === 0) {
          ovBadge.innerText = '0 Exploits (Clean)';
          ovBadge.style.color = '#34d399';
        } else {
          ovBadge.innerText = count + ' Exploit' + (count > 1 ? 's' : '') + ' Found';
          ovBadge.style.color = 'var(--rose)';
        }
      }
      var exploreTxt = document.getElementById('overview-explore-btn-text');
      if (exploreTxt) exploreTxt.innerHTML = 'Explore Full Vulnerabilities &amp; PoC Radar (' + count + ') &rarr;';
      var bannerTag = document.getElementById('banner-tag');
      if (bannerTag) {
        if (count === 0) {
          bannerTag.innerText = 'TARGET POSTURE: CLEAN';
          bannerTag.style.background = 'rgba(16,185,129,0.25)';
          bannerTag.style.color = '#34d399';
        } else {
          bannerTag.innerText = 'ACTIVE EXPLOIT VECTOR';
          bannerTag.style.background = 'var(--rose)';
          bannerTag.style.color = '#fff';
        }
      }
      var ovList = document.getElementById('overview-findings-list');
      if (ovList) {
        if (count === 0) {
          ovList.innerHTML = '<div style="background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.22);border-radius:6px;padding:0.85rem;text-align:center"><div style="font-size:0.75rem;font-weight:700;color:#34d399;display:flex;align-items:center;justify-content:center;gap:0.35rem"><span>&#10003;</span> No Verified Vulnerabilities Detected</div><div style="font-size:0.62rem;color:var(--text-muted);margin-top:0.25rem;font-family:var(--font-mono)">Target attack surface verified clean under deterministic DAST probes.</div></div>';
        } else {
          ovList.innerHTML = currentFindings.slice(0, 3).map(function(f) {
            var isCrit = f.severity === 'CRITICAL' || (f.cvss_score && f.cvss_score >= 9.0);
            var isHigh = f.severity === 'HIGH' || (f.cvss_score && f.cvss_score >= 7.0);
            var sc = isCrit ? 'sev-critical' : (isHigh ? 'sev-high' : 'sev-medium');
            return '<div class="finding-compact-item" onclick="openFindingModal(\'' + escapeHtml(f.id) + '\')" style="cursor:pointer">' +
              '<div style="display:flex;justify-content:space-between;align-items:center">' +
                '<div style="font-size:0.72rem;font-weight:700;color:#fff;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:0.4rem">' + escapeHtml(f.title) + '</div>' +
                '<span class="finding-tag ' + sc + '" style="font-size:0.58rem;padding:0.1rem 0.35rem;flex-shrink:0">CVSS ' + f.cvss_score + '</span>' +
              '</div>' +
              '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:0.15rem;font-size:0.62rem;color:var(--text-muted);font-family:var(--font-mono)">' +
                '<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:70%">' + escapeHtml(f.affected_component) + '</span>' +
                '<span style="color:var(--emerald);flex-shrink:0">&#10003; Live Trace</span>' +
              '</div>' +
            '</div>';
          }).join('');
        }
      }

      // Synchronize Executive Overview (legacy mount — no-op if element absent)
      var ovMount = document.getElementById('overview-findings-mount');
      if (ovMount) {
        if (count === 0) {
          ovMount.innerHTML = '<div style="color:var(--text-dark); padding:1.2rem; text-align:center; font-size:0.78rem;">No verified vulnerabilities detected for current target.</div>';
        } else {
          ovMount.innerHTML = currentFindings.slice(0, 3).map(f => {
            const isCrit = f.severity === 'CRITICAL' || (f.cvss_score && f.cvss_score >= 9.0);
            return `
              <div class="threat-row-item ${isCrit ? 'rose' : 'amber'}" onclick="openFindingModal('${f.id}')">
                <div class="threat-row-left">
                  <div class="threat-row-title">${escapeHtml(f.id)}: ${escapeHtml(f.title)}</div>
                  <div class="threat-row-meta">
                    <span class="comp">${escapeHtml(f.affected_component)}</span>
                    <span>&bull;</span>
                    <span style="color:${isCrit ? 'var(--rose)' : 'var(--amber)'};">CVSS ${f.cvss_score} (${f.severity})</span>
                    <span>&bull;</span>
                    <span style="color:var(--emerald);">&#10003; Live Trace Recorded</span>
                  </div>
                </div>
                <div class="threat-row-right">
                  <button class="btn" style="padding:0.2rem 0.48rem; font-size:0.65rem;">View PoC</button>
                </div>
              </div>
            `;
          }).join('');
        }
      }

      // Synchronize Main Findings Grid
      const mount = document.getElementById('findings-mount-grid');
      if (!mount) return;
      if (count === 0) {
        mount.innerHTML = '<div style="color:var(--text-dark); padding:2rem; text-align:center;">No findings recorded for this target scope.</div>';
        return;
      }

      mount.innerHTML = currentFindings.map(f => {
        const isRetested = f.retest_status === 'FIX_VERIFIED';
        return `
          <div class="finding-card ${isRetested ? 'retested' : ''}" onclick="openFindingModal('${f.id}')">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <div style="display:flex; gap:0.4rem; align-items:center;">
                <span class="tag tag-rose">${f.severity} (${f.cvss_score})</span>
                <span class="tag tag-amber">${f.status}</span>
                ${isRetested ? '<span class="tag tag-green">&#10003; FIX VERIFIED</span>' : ''}
              </div>
              <span style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-dark);">${f.id}</span>
            </div>

            <div>
              <div style="font-weight:700; font-size:0.84rem; color:#fff;">${escapeHtml(f.title)}</div>
              <div style="font-family:var(--font-mono); font-size:0.68rem; color:var(--cyan); margin-top:0.15rem;">${escapeHtml(f.affected_component)}</div>
            </div>

            <div class="stepper">
              <span class="stepper-node done">&#10003; Discovered</span>
              <span class="stepper-arrow">&rarr;</span>
              <span class="stepper-node done">&#10003; Candidate</span>
              <span class="stepper-arrow">&rarr;</span>
              <span class="stepper-node active">&#10003; Prover Verified</span>
              <span class="stepper-arrow">&rarr;</span>
              <span class="stepper-node ${isRetested ? 'done' : ''}">${isRetested ? '&#10003; Re-Test Passed' : 'Patch Ready'}</span>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.25rem; font-size:0.68rem; color:var(--text-dark);">
              <span>Confidence: ${Math.round(f.confidence * 100)}%</span>
              <button onclick="event.stopPropagation(); triggerRetest('${f.id}')" style="background:transparent; border:1px solid var(--emerald); color:#34d399; padding:0.2rem 0.5rem; border-radius:4px; cursor:pointer; font-size:0.65rem; font-weight:700;">
                &#9851; Re-Test Fix
              </button>
            </div>
          </div>
        `;
      }).join('');
    }

    function filterFindings() {
      const q = document.getElementById('finding-search-input').value.toLowerCase();
      const filtered = currentFindings.filter(f => f.title.toLowerCase().includes(q) || f.affected_component.toLowerCase().includes(q));
      renderFindings(filtered);
    }

    function upsertFinding(f) {
      const idx = currentFindings.findIndex(item => item.id === f.id);
      if (idx >= 0) currentFindings[idx] = f;
      else currentFindings.push(f);
      renderFindings(currentFindings);
    }

    function openFindingModal(id) {
      const f = currentFindings.find(item => item.id === id);
      if (!f) return;
      activeModalFindingId = id;

      document.getElementById('modal-title').innerText = `${f.id}: ${f.title}`;
      document.getElementById('modal-sev').innerText = `${f.severity} (CVSS ${f.cvss_score})`;
      document.getElementById('modal-status').innerText = f.status;
      document.getElementById('modal-desc').innerText = f.description;
      document.getElementById('modal-poc').innerText = f.poc_code || 'N/A';

      let ev = 'No trace.';
      if (f.evidence) {
        ev = `PROBE TRACE:\n${f.evidence.method} ${f.evidence.url}\nResponse Status: ${f.evidence.response_status} (${f.evidence.duration_ms} ms)\n\nResponse Body:\n${f.evidence.response_body}`;
      }
      document.getElementById('modal-evidence').innerText = ev;
      document.getElementById('modal-impact').innerText = f.business_impact;
      document.getElementById('modal-remed').innerText = f.remediation_recommendations;
      document.getElementById('modal-diff').innerText = f.remediation_diff || 'No diff.';

      document.getElementById('finding-modal').classList.add('open');
    }

    function closeModal(e) {
      if (e.target.id === 'finding-modal') closeModalDirect();
    }
    function closeModalDirect() {
      document.getElementById('finding-modal').classList.remove('open');
    }

    function triggerRetest(id) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        appendConsole('RETEST', `Executing automated Before vs After verification for ${id}...`);
        ws.send(JSON.stringify({ action: 'RUN_RETEST', finding_id: id }));
      }
    }

    function executeRetestModal() {
      if (activeModalFindingId) triggerRetest(activeModalFindingId);
    }

    async function togglePatch(findingId) {
      try {
        const resp = await fetch(`/api/target/toggle-fix/${findingId}`, { method: 'POST' });
        const data = await resp.json();
        appendConsole('PATCH', `Patch state for ${findingId} updated: ${data.patch_enabled ? 'ENABLED' : 'DISABLED'}`);
        triggerRetest(findingId);
      } catch (err) {
        appendConsole('PATCH', `Error toggling patch: ${err}`);
      }
    }

    async function recalcCvss() {
      const av = document.getElementById('cvss-av').value;
      const ac = document.getElementById('cvss-ac').value;
      const pr = document.getElementById('cvss-pr').value;
      const ui = document.getElementById('cvss-ui').value;
      const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:U/C:H/I:H/A:N`;
      document.getElementById('cvss-vector-display').innerText = vector;
      const res = await fetch(`/api/cvss/calculate?vector=${encodeURIComponent(vector)}`);
      const data = await res.json();
      document.getElementById('cvss-score-display').innerText = data.score.toFixed(1);
      document.getElementById('cvss-sev-display').innerText = data.severity;
    }

    function escapeHtml(str) {
      return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    
    function fitOverviewNetwork() {
      if (overviewNetwork) overviewNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
    }
    function rebalanceOverviewGraph() {
      if (currentMapData) renderNetwork(currentMapData, true);
    }
    function zoomInOverview() {
      if (overviewNetwork) {
        const scale = overviewNetwork.getScale() * 1.3;
        overviewNetwork.moveTo({ scale: scale, animation: true });
      }
    }
    function zoomOutOverview() {
      if (overviewNetwork) {
        const scale = overviewNetwork.getScale() * 0.75;
        overviewNetwork.moveTo({ scale: scale, animation: true });
      }
    }

    window.addEventListener('DOMContentLoaded', () => {
      checkAuthSession();
      initWebSocket();

      // Initialize Target Input state (Locked on World Monitor Core, editable on custom)
      const targetPresetSelect = document.getElementById('target-preset-select');
      if (targetPresetSelect) {
        applyTargetPreset(targetPresetSelect.value);
      }
      const targetInput = document.getElementById('target-url-input');
      const protoBadge = document.getElementById('target-protocol-badge');
      if (targetInput) {
        targetInput.addEventListener('input', () => {
          const select = document.getElementById('target-preset-select');
          let val = targetInput.value;

          // If user pastes or types a full URL with scheme, auto-strip the scheme and set badge
          if (val.startsWith('https://')) {
            if (protoBadge) protoBadge.innerText = 'https://';
            val = val.substring(8);
            targetInput.value = val;
          } else if (val.startsWith('http://')) {
            if (protoBadge) protoBadge.innerText = 'http://';
            val = val.substring(7);
            targetInput.value = val;
          }

          if (select) {
            if (select.value === 'https://www.worldmonitor.app') {
              targetInput.value = 'www.worldmonitor.app';
            } else if (select.value !== 'custom' && val !== '127.0.0.1:8000/target') {
              select.value = 'custom';
            }
          }
        });
      }

      fetch('/api/assessment/state').then(r => r.json()).then(d => {
        updateStats(d.stats);
        if (d.findings) renderFindings(d.findings);
      });
      fetch('/api/assessment/attack-surface').then(r => r.json()).then(map => {
        currentMapData = map;
        setTimeout(() => renderNetwork(map, true), 80);
      });

      const ovMount = document.getElementById('overview-graph-mount');
      if (ovMount && window.ResizeObserver) {
        const ro = new ResizeObserver(() => {
          if (overviewNetwork) {
            overviewNetwork.setSize('100%', '100%');
            overviewNetwork.redraw();
          }
        });
        ro.observe(ovMount);
      }
    });

    window.addEventListener('resize', () => {
      if (surfaceNetwork) {
        surfaceNetwork.setSize('100%', '100%');
        surfaceNetwork.fit();
      }
      if (overviewNetwork) {
        overviewNetwork.setSize('100%', '100%');
        overviewNetwork.fit();
      }
    });