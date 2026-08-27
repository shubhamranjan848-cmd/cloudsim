/**
 * Server Traffic & Cloudflare Analytics Dashboard
 * Core Application Engine
 */

(function () {
  'use strict';

  // --- Configuration & State ---
  const state = {
    mode: 'simulation', // 'simulation' or 'live_api'
    scenario: 'normal',  // 'normal', 'surge', 'threat'
    isPaused: false,
    timerInterval: null,
    tickRateMs: 1000,
    
    // Aggregated Metrics
    totalRequests: 0,
    cfRequests: 0,
    cachedRequests: 0,
    originRequests: 0,
    threatsMitigated: 0,
    bandwidthSavedBytes: 0,
    bandwidthTotalBytes: 0,
    
    // HTTP Status Counters
    statusCodes: {
      '2xx': 0,
      '3xx': 0,
      '4xx': 0,
      '5xx': 0
    },

    // Protocol Weights
    protocols: {
      http3: 62,
      http2: 34,
      http1: 4,
      tls13: 99.4
    },

    // Chart Data History (rolling 25 ticks)
    maxHistoryPoints: 25,
    history: {
      labels: [],
      cfRps: [],
      cachedRps: [],
      originRps: []
    },

    // Cloudflare API Credentials
    apiCredentials: {
      zoneId: '',
      apiToken: ''
    }
  };

  // Sample Ray ID Datacenter codes
  const cfDatacenters = ['IAD', 'LHR', 'FRA', 'SJC', 'SIN', 'BOM', 'NRT', 'SYD', 'ORD', 'AMS'];
  
  const sampleEndpoints = [
    { path: '/api/v1/telemetry', method: 'POST', cacheable: false, originWeight: 0.9 },
    { path: '/assets/app.min.js', method: 'GET', cacheable: true, originWeight: 0.05 },
    { path: '/assets/theme.css', method: 'GET', cacheable: true, originWeight: 0.02 },
    { path: '/images/hero-banner.webp', method: 'GET', cacheable: true, originWeight: 0.03 },
    { path: '/api/v2/user/profile', method: 'GET', cacheable: false, originWeight: 0.8 },
    { path: '/fonts/inter-latin.woff2', method: 'GET', cacheable: true, originWeight: 0.01 },
    { path: '/api/v1/auth/session', method: 'GET', cacheable: false, originWeight: 0.7 },
    { path: '/healthz', method: 'GET', cacheable: false, originWeight: 0.5 },
    { path: '/static/icons/sprite.svg', method: 'GET', cacheable: true, originWeight: 0.02 }
  ];

  // DOM Elements Cache
  const dom = {
    kpiTotalRequests: document.getElementById('kpi-total-requests'),
    kpiRps: document.getElementById('kpi-rps'),
    kpiCfRequests: document.getElementById('kpi-cf-requests'),
    kpiCfPercentage: document.getElementById('kpi-cf-percentage'),
    kpiCacheRate: document.getElementById('kpi-cache-rate'),
    kpiCachedCount: document.getElementById('kpi-cached-count'),
    kpiOriginRequests: document.getElementById('kpi-origin-requests'),
    kpiOriginPercentage: document.getElementById('kpi-origin-percentage'),
    kpiBandwidthSaved: document.getElementById('kpi-bandwidth-saved'),
    kpiBandwidthTotal: document.getElementById('kpi-bandwidth-total'),
    kpiThreatsMitigated: document.getElementById('kpi-threats-mitigated'),
    kpiCleanTraffic: document.getElementById('kpi-clean-traffic'),
    
    // Progress Bar Fills
    barCfFill: document.getElementById('bar-cf-fill'),
    barCacheFill: document.getElementById('bar-cache-fill'),
    barOriginFill: document.getElementById('bar-origin-fill'),
    barBwFill: document.getElementById('bar-bw-fill'),
    barSecFill: document.getElementById('bar-sec-fill'),

    // Status Counters
    cnt2xx: document.getElementById('cnt-2xx'),
    cnt3xx: document.getElementById('cnt-3xx'),
    cnt4xx: document.getElementById('cnt-4xx'),
    cnt5xx: document.getElementById('cnt-5xx'),

    // Log Table
    trafficLogBody: document.getElementById('traffic-log-body'),

    // Buttons
    btnNormal: document.getElementById('btn-scenario-normal'),
    btnSurge: document.getElementById('btn-scenario-surge'),
    btnThreat: document.getElementById('btn-scenario-threat'),
    btnPausePlay: document.getElementById('btn-pause-play'),
    pauseIcon: document.getElementById('pause-icon'),
    btnResetStats: document.getElementById('btn-reset-stats'),

    // Modal
    openApiModalBtn: document.getElementById('open-api-modal-btn'),
    closeApiModalBtn: document.getElementById('close-api-modal-btn'),
    apiModal: document.getElementById('api-modal'),
    cfApiForm: document.getElementById('cf-api-form'),
    cfZoneIdInput: document.getElementById('cf-zone-id'),
    cfApiTokenInput: document.getElementById('cf-api-token'),
    btnUseSimMode: document.getElementById('btn-use-sim-mode'),
    apiStatusMessage: document.getElementById('api-status-message'),
    cfEdgeStatus: document.getElementById('cf-edge-status'),
    originServerStatus: document.getElementById('origin-server-status')
  };

  let trafficLineChart = null;
  let statusDoughnutChart = null;

  // --- Utilities ---
  function formatNumber(num) {
    return new Intl.NumberFormat().format(Math.round(num));
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  function generateRayId() {
    const hex = Math.random().toString(16).substring(2, 14);
    const dc = cfDatacenters[Math.floor(Math.random() * cfDatacenters.length)];
    return `${hex}-${dc}`.toUpperCase();
  }

  function generateMaskedIp() {
    const prefixes = ['198.51.100', '203.0.113', '192.0.2', '172.64.32', '104.28.14', '162.158.7'];
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const lastOctet = getRandomInt(10, 254);
    return `${prefix}.***`;
  }

  // --- Chart Initialization ---
  function initCharts() {
    // 1. Line Chart (Traffic Throughput)
    const ctxLine = document.getElementById('trafficLineChart').getContext('2d');
    
    // Initial blank history
    const now = new Date();
    for (let i = state.maxHistoryPoints; i > 0; i--) {
      const pastTime = new Date(now.getTime() - i * 1000);
      const timeStr = pastTime.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
      state.history.labels.push(timeStr);
      state.history.cfRps.push(0);
      state.history.cachedRps.push(0);
      state.history.originRps.push(0);
    }

    const cfGradient = ctxLine.createLinearGradient(0, 0, 0, 260);
    cfGradient.addColorStop(0, 'rgba(243, 128, 32, 0.35)');
    cfGradient.addColorStop(1, 'rgba(243, 128, 32, 0.0)');

    const cachedGradient = ctxLine.createLinearGradient(0, 0, 0, 260);
    cachedGradient.addColorStop(0, 'rgba(16, 185, 129, 0.25)');
    cachedGradient.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

    trafficLineChart = new Chart(ctxLine, {
      type: 'line',
      data: {
        labels: state.history.labels,
        datasets: [
          {
            label: 'Cloudflare Edge (Total)',
            data: state.history.cfRps,
            borderColor: '#f38020',
            backgroundColor: cfGradient,
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointRadius: 0,
            pointHoverRadius: 4
          },
          {
            label: 'CF Edge Cached (HIT)',
            data: state.history.cachedRps,
            borderColor: '#10b981',
            backgroundColor: cachedGradient,
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointRadius: 0,
            pointHoverRadius: 4
          },
          {
            label: 'Forwarded to Origin (MISS)',
            data: state.history.originRps,
            borderColor: '#8b5cf6',
            borderWidth: 2,
            borderDash: [4, 4],
            tension: 0.35,
            fill: false,
            pointRadius: 0,
            pointHoverRadius: 4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#111827',
            titleColor: '#f8fafc',
            bodyColor: '#94a3b8',
            borderColor: '#1e293b',
            borderWidth: 1,
            padding: 10,
            boxPadding: 4,
            callbacks: {
              label: function (context) {
                return `${context.dataset.label}: ${context.parsed.y} req/s`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: {
              color: '#64748b',
              font: { family: 'JetBrains Mono', size: 10 },
              maxTicksLimit: 6
            }
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: {
              color: '#64748b',
              font: { family: 'JetBrains Mono', size: 10 },
              callback: function (val) { return val + ' rps'; }
            }
          }
        }
      }
    });

    // 2. Status Donut Chart
    const ctxDonut = document.getElementById('statusDoughnutChart').getContext('2d');
    statusDoughnutChart = new Chart(ctxDonut, {
      type: 'doughnut',
      data: {
        labels: ['2xx Success', '3xx Redirect', '4xx Client Error', '5xx Server Error'],
        datasets: [{
          data: [1, 0, 0, 0],
          backgroundColor: ['#10b981', '#06b6d4', '#f59e0b', '#ef4444'],
          borderColor: '#111827',
          borderWidth: 2,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#111827',
            borderColor: '#1e293b',
            borderWidth: 1,
            bodyColor: '#f8fafc',
            callbacks: {
              label: function (context) {
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const val = context.parsed;
                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                return `${context.label}: ${formatNumber(val)} (${pct}%)`;
              }
            }
          }
        }
      }
    });
  }

  // --- Simulation Tick Generator ---
  function generateTrafficTick() {
    if (state.isPaused) return;

    let baseRps = 60;
    let cacheRate = 0.78; // 78% cache hit rate
    let threatRate = 0.002; // 0.2% threats

    if (state.scenario === 'normal') {
      baseRps = getRandomInt(45, 85);
      cacheRate = 0.76 + Math.random() * 0.08;
      threatRate = 0.002;
    } else if (state.scenario === 'surge') {
      baseRps = getRandomInt(320, 650);
      cacheRate = 0.82 + Math.random() * 0.08;
      threatRate = 0.008;
    } else if (state.scenario === 'threat') {
      baseRps = getRandomInt(1400, 2400);
      cacheRate = 0.65 + Math.random() * 0.10;
      threatRate = 0.45 + Math.random() * 0.15; // 45-60% volumetric threat mitigated
    }

    const currentTotalRps = baseRps;
    const threatsInTick = Math.round(currentTotalRps * threatRate);
    const cleanRps = currentTotalRps - threatsInTick;
    
    // Cloudflare Edge processes 99.8% of incoming traffic
    const cfProxiedRps = Math.round(currentTotalRps * 0.998);
    const cachedRps = Math.round(cleanRps * cacheRate);
    const originRps = Math.max(0, cleanRps - cachedRps);

    // Update cumulative state
    state.totalRequests += currentTotalRps;
    state.cfRequests += cfProxiedRps;
    state.cachedRequests += cachedRps;
    state.originRequests += originRps;
    state.threatsMitigated += threatsInTick;

    // Simulate bandwidth (average 28 KB per cached request, 42 KB for origin)
    const tickCachedBytes = cachedRps * getRandomInt(20000, 36000);
    const tickOriginBytes = originRps * getRandomInt(30000, 54000);
    state.bandwidthSavedBytes += tickCachedBytes;
    state.bandwidthTotalBytes += (tickCachedBytes + tickOriginBytes);

    // Status code distribution simulation
    let cnt2 = Math.round(cleanRps * 0.92);
    let cnt3 = Math.round(cleanRps * 0.04);
    let cnt4 = Math.round(cleanRps * 0.035);
    let cnt5 = cleanRps - (cnt2 + cnt3 + cnt4);
    if (cnt5 < 0) cnt5 = 0;

    // Threats add to 4xx (403 Forbidden / 429 Rate Limited)
    cnt4 += threatsInTick;

    state.statusCodes['2xx'] += cnt2;
    state.statusCodes['3xx'] += cnt3;
    state.statusCodes['4xx'] += cnt4;
    state.statusCodes['5xx'] += cnt5;

    // Update UI Elements
    updateDashboardUI(currentTotalRps, cfProxiedRps, cachedRps, originRps);

    // Add entries to live log table
    appendLogEntries(Math.min(3, Math.max(1, Math.floor(currentTotalRps / 30))));
  }

  // --- UI Update Function ---
  function updateDashboardUI(currentTotalRps, cfProxiedRps, cachedRps, originRps) {
    // 1. KPI Counters
    dom.kpiTotalRequests.textContent = formatNumber(state.totalRequests);
    dom.kpiRps.textContent = `${formatNumber(currentTotalRps)} req/s`;

    dom.kpiCfRequests.textContent = formatNumber(state.cfRequests);
    const cfPct = state.totalRequests > 0 ? ((state.cfRequests / state.totalRequests) * 100).toFixed(1) : 100;
    dom.kpiCfPercentage.textContent = `${cfPct}%`;
    dom.barCfFill.style.width = `${Math.min(100, cfPct)}%`;

    const overallCacheRate = state.totalRequests > 0 ? ((state.cachedRequests / (state.totalRequests - state.threatsMitigated || 1)) * 100).toFixed(1) : 0;
    dom.kpiCacheRate.textContent = `${overallCacheRate}%`;
    dom.kpiCachedCount.textContent = `${formatNumber(state.cachedRequests)} hits`;
    dom.barCacheFill.style.width = `${Math.min(100, overallCacheRate)}%`;

    dom.kpiOriginRequests.textContent = formatNumber(state.originRequests);
    const originPct = state.totalRequests > 0 ? ((state.originRequests / state.totalRequests) * 100).toFixed(1) : 0;
    dom.kpiOriginPercentage.textContent = `${originPct}%`;
    dom.barOriginFill.style.width = `${Math.min(100, originPct)}%`;

    dom.kpiBandwidthSaved.textContent = formatBytes(state.bandwidthSavedBytes);
    dom.kpiBandwidthTotal.textContent = `of ${formatBytes(state.bandwidthTotalBytes)} total`;
    const bwPct = state.bandwidthTotalBytes > 0 ? ((state.bandwidthSavedBytes / state.bandwidthTotalBytes) * 100).toFixed(1) : 0;
    dom.barBwFill.style.width = `${Math.min(100, bwPct)}%`;

    dom.kpiThreatsMitigated.textContent = formatNumber(state.threatsMitigated);
    const cleanPct = state.totalRequests > 0 ? (((state.totalRequests - state.threatsMitigated) / state.totalRequests) * 100).toFixed(1) : 100;
    dom.kpiCleanTraffic.textContent = `${cleanPct}% Clean`;
    dom.barSecFill.style.width = `${Math.min(100, cleanPct)}%`;

    // 2. Status Code Summary
    dom.cnt2xx.textContent = formatNumber(state.statusCodes['2xx']);
    dom.cnt3xx.textContent = formatNumber(state.statusCodes['3xx']);
    dom.cnt4xx.textContent = formatNumber(state.statusCodes['4xx']);
    dom.cnt5xx.textContent = formatNumber(state.statusCodes['5xx']);

    // 3. Update Chart.js (Line Chart)
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

    state.history.labels.push(timeStr);
    state.history.cfRps.push(cfProxiedRps);
    state.history.cachedRps.push(cachedRps);
    state.history.originRps.push(originRps);

    if (state.history.labels.length > state.maxHistoryPoints) {
      state.history.labels.shift();
      state.history.cfRps.shift();
      state.history.cachedRps.shift();
      state.history.originRps.shift();
    }

    if (trafficLineChart) {
      trafficLineChart.data.labels = state.history.labels;
      trafficLineChart.data.datasets[0].data = state.history.cfRps;
      trafficLineChart.data.datasets[1].data = state.history.cachedRps;
      trafficLineChart.data.datasets[2].data = state.history.originRps;
      trafficLineChart.update('none');
    }

    // 4. Update Doughnut Chart
    if (statusDoughnutChart) {
      statusDoughnutChart.data.datasets[0].data = [
        state.statusCodes['2xx'],
        state.statusCodes['3xx'],
        state.statusCodes['4xx'],
        state.statusCodes['5xx']
      ];
      statusDoughnutChart.update('none');
    }
  }

  // --- Live Table Log Appender ---
  function appendLogEntries(count) {
    const fragment = document.createDocumentFragment();

    for (let i = 0; i < count; i++) {
      const ep = sampleEndpoints[Math.floor(Math.random() * sampleEndpoints.length)];
      const rayId = generateRayId();
      const clientIp = generateMaskedIp();
      const isThreat = state.scenario === 'threat' && Math.random() < 0.5;

      let cacheStatus = 'HIT';
      let statusCode = 200;
      let latency = getRandomInt(2, 9) + 'ms';
      let edgeStatusClass = 'tag-hit';

      if (isThreat) {
        cacheStatus = 'BLOCKED (WAF)';
        statusCode = Math.random() > 0.5 ? 403 : 429;
        edgeStatusClass = 'tag-blocked';
        latency = '1ms';
      } else if (!ep.cacheable || Math.random() < ep.originWeight) {
        cacheStatus = 'MISS (ORIGIN)';
        edgeStatusClass = 'tag-miss';
        statusCode = Math.random() > 0.02 ? 200 : (Math.random() > 0.5 ? 404 : 502);
        latency = getRandomInt(28, 85) + 'ms';
      }

      let statusClass = 'status-2xx';
      if (statusCode >= 300 && statusCode < 400) statusClass = 'status-3xx';
      else if (statusCode >= 400 && statusCode < 500) statusClass = 'status-4xx';
      else if (statusCode >= 500) statusClass = 'status-5xx';

      const now = new Date();
      const timeStr = now.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) + '.' + String(now.getMilliseconds()).padStart(3, '0');

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${timeStr}</td>
        <td><span class="cf-ray-tag">${rayId}</span></td>
        <td>${clientIp}</td>
        <td><strong>${ep.method}</strong> ${ep.path}</td>
        <td><span class="cache-tag ${edgeStatusClass}">${cacheStatus}</span></td>
        <td><span class="status-badge ${statusClass}">${statusCode}</span></td>
        <td>${latency}</td>
      `;

      fragment.prepend(tr);
    }

    dom.trafficLogBody.insertBefore(fragment, dom.trafficLogBody.firstChild);

    // Keep only the last 30 rows
    while (dom.trafficLogBody.children.length > 30) {
      dom.trafficLogBody.removeChild(dom.trafficLogBody.lastChild);
    }
  }

  // --- Reset Statistics ---
  function resetStatistics() {
    state.totalRequests = 0;
    state.cfRequests = 0;
    state.cachedRequests = 0;
    state.originRequests = 0;
    state.threatsMitigated = 0;
    state.bandwidthSavedBytes = 0;
    state.bandwidthTotalBytes = 0;
    state.statusCodes = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };

    state.history.cfRps = state.history.cfRps.map(() => 0);
    state.history.cachedRps = state.history.cachedRps.map(() => 0);
    state.history.originRps = state.history.originRps.map(() => 0);

    dom.trafficLogBody.innerHTML = '';
    updateDashboardUI(0, 0, 0, 0);
  }

  // --- Cloudflare GraphQL Live Analytics API Connector ---
  async function testCloudflareLiveApi(zoneId, apiToken) {
    // Cloudflare GraphQL Analytics Query
    const query = `
      query GetZoneHttpRequests($zoneTag: string) {
        viewer {
          zones(filter: { zoneTag: $zoneTag }) {
            httpRequests1mGroups(limit: 1, orderBy: [datetimeMinute_DESC]) {
              dimensions {
                datetimeMinute
              }
              sum {
                requests
                cachedRequests
                bytes
                cachedBytes
                threats
              }
            }
          }
        }
      }
    `;

    try {
      const response = await fetch('https://api.cloudflare.com/client/v4/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiToken}`
        },
        body: JSON.stringify({
          query: query,
          variables: { zoneTag: zoneId }
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      if (data.errors && data.errors.length > 0) {
        throw new Error(data.errors[0].message);
      }

      return { success: true, data: data };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // --- Event Listeners ---
  function attachEventListeners() {
    // Simulation Scenarios
    dom.btnNormal.addEventListener('click', () => setScenario('normal', dom.btnNormal));
    dom.btnSurge.addEventListener('click', () => setScenario('surge', dom.btnSurge));
    dom.btnThreat.addEventListener('click', () => setScenario('threat', dom.btnThreat));

    function setScenario(scenario, activeBtn) {
      state.scenario = scenario;
      [dom.btnNormal, dom.btnSurge, dom.btnThreat].forEach(b => b.classList.remove('active'));
      activeBtn.classList.add('active');
    }

    // Pause / Resume Feed
    dom.btnPausePlay.addEventListener('click', () => {
      state.isPaused = !state.isPaused;
      if (state.isPaused) {
        dom.pauseIcon.className = 'fa-solid fa-play';
        dom.btnPausePlay.title = 'Resume Live Feed';
      } else {
        dom.pauseIcon.className = 'fa-solid fa-pause';
        dom.btnPausePlay.title = 'Pause Live Feed';
      }
    });

    // Reset Stats
    dom.btnResetStats.addEventListener('click', () => {
      if (confirm('Reset all aggregated server traffic counters?')) {
        resetStatistics();
      }
    });

    // API Modal Handlers
    dom.openApiModalBtn.addEventListener('click', () => {
      dom.apiModal.classList.add('show');
    });

    dom.closeApiModalBtn.addEventListener('click', () => {
      dom.apiModal.classList.remove('show');
    });

    dom.apiModal.addEventListener('click', (e) => {
      if (e.target === dom.apiModal) dom.apiModal.classList.remove('show');
    });

    dom.btnUseSimMode.addEventListener('click', () => {
      state.mode = 'simulation';
      dom.cfEdgeStatus.textContent = 'Proxied (Active)';
      dom.apiModal.classList.remove('show');
    });

    dom.cfApiForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const zoneId = dom.cfZoneIdInput.value.trim();
      const apiToken = dom.cfApiTokenInput.value.trim();

      if (!zoneId || !apiToken) {
        showApiStatus('Please provide both Zone ID and API Token.', 'error');
        return;
      }

      showApiStatus('Testing connection to Cloudflare GraphQL API...', '');

      const result = await testCloudflareLiveApi(zoneId, apiToken);
      if (result.success) {
        state.apiCredentials = { zoneId, apiToken };
        state.mode = 'live_api';
        dom.cfEdgeStatus.textContent = `Live Zone (${zoneId.substring(0, 6)}...)`;
        showApiStatus('Successfully connected to Cloudflare Analytics API!', 'success');
        setTimeout(() => dom.apiModal.classList.remove('show'), 1500);
      } else {
        showApiStatus(`Connection failed: ${result.error}. (Note: Direct browser calls to Cloudflare API may be subject to CORS; run via backend proxy or use simulated mode).`, 'error');
      }
    });

    function showApiStatus(msg, type) {
      dom.apiStatusMessage.textContent = msg;
      dom.apiStatusMessage.className = `modal-alert ${type}`;
      dom.apiStatusMessage.style.display = 'block';
    }
  }

  // --- Bootstrap Application ---
  function start() {
    initCharts();
    attachEventListeners();

    // Start live generator interval
    state.timerInterval = setInterval(generateTrafficTick, state.tickRateMs);
    // Initial burst
    generateTrafficTick();
  }

  // Run when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
