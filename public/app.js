/**
 * ScamShield — Dashboard Application Logic
 */

// ══════════════════════════════════════
// Sidebar Navigation
// ══════════════════════════════════════

const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');
const sidebar = document.getElementById('sidebar');
const hamburgerBtn = document.getElementById('hamburgerBtn');

let mapInitialized = false;

// Create overlay for mobile
const overlay = document.createElement('div');
overlay.className = 'sidebar-overlay';
document.body.appendChild(overlay);

function switchView(viewId) {
  // Update nav
  navItems.forEach(item => item.classList.remove('active'));
  document.querySelector(`[data-view="${viewId}"]`)?.classList.add('active');

  // Update views
  views.forEach(v => {
    v.classList.remove('active');
    // Reset animation
    v.style.animation = 'none';
    v.offsetHeight;
    v.style.animation = '';
  });
  document.getElementById('view' + viewId.charAt(0).toUpperCase() + viewId.slice(1))?.classList.add('active');

  // Init map on first dashboard visit
  if (viewId === 'dashboard' && !mapInitialized) {
    initMap();
    mapInitialized = true;
  }

  // Close mobile sidebar
  sidebar.classList.remove('open');
  overlay.classList.remove('active');

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'instant' });
}

navItems.forEach(item => {
  item.addEventListener('click', () => switchView(item.dataset.view));
});

// Mobile hamburger
hamburgerBtn.addEventListener('click', () => {
  sidebar.classList.toggle('open');
  overlay.classList.toggle('active');
});

overlay.addEventListener('click', () => {
  sidebar.classList.remove('open');
  overlay.classList.remove('active');
});

// ══════════════════════════════════════
// Dashboard — Leaflet Heatmap
// ══════════════════════════════════════

let map = null;

async function initMap() {
  try {
    // Fetch heatmap data + stats in parallel
    const [heatmapRes, statsRes] = await Promise.all([
      fetch('/api/heatmap'),
      fetch('/api/reports/stats'),
    ]);

    const heatmapData = await heatmapRes.json();
    const stats = await statsRes.json();

    // Populate stats bar
    document.getElementById('statTotalReports').textContent = stats.totalReports?.toLocaleString() || '—';
    document.getElementById('statCities').textContent = stats.citiesCovered || '—';
    document.getElementById('statTopCity').textContent = stats.topCity || '—';
    document.getElementById('statTopState').textContent = stats.mostAffectedState || '—';

    // Initialize Leaflet map
    map = L.map('indiaMap', {
      center: [22.5, 78.9],
      zoom: 5,
      minZoom: 4,
      maxZoom: 10,
      zoomControl: true,
      attributionControl: true,
    });

    // Dark tile layer
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19,
    }).addTo(map);

    // Prepare heat data: [lat, lng, intensity]
    const heatPoints = heatmapData.map(city => [
      city.lat,
      city.lng,
      city.intensity,
    ]);

    // Add heatmap layer
    L.heatLayer(heatPoints, {
      radius: 35,
      blur: 25,
      maxZoom: 8,
      max: 1.0,
      gradient: {
        0.0: '#3b82f6',
        0.3: '#6c5ce7',
        0.5: '#a855f7',
        0.7: '#f97316',
        1.0: '#ef4444',
      },
    }).addTo(map);

    // Add city markers with popups
    heatmapData.forEach(city => {
      const marker = L.circleMarker([city.lat, city.lng], {
        radius: 5,
        fillColor: getMarkerColor(city.intensity),
        color: 'rgba(255,255,255,0.3)',
        weight: 1,
        fillOpacity: 0.9,
      });

      marker.bindPopup(`
        <div class="popup-city">${city.city}</div>
        <div class="popup-state">${city.state}</div>
        <div class="popup-reports">📊 ${city.reports.toLocaleString()} Reports</div>
      `);

      marker.addTo(map);
    });

    // Fix map render on view switch
    setTimeout(() => map.invalidateSize(), 200);

  } catch (err) {
    console.error('Map init error:', err);
  }
}

function getMarkerColor(intensity) {
  if (intensity >= 0.8) return '#ef4444';
  if (intensity >= 0.6) return '#f97316';
  if (intensity >= 0.4) return '#a855f7';
  return '#6c5ce7';
}

// ══════════════════════════════════════
// Scam Detector — Message Analysis
// ══════════════════════════════════════

const messageInput = document.getElementById('messageInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const charCount = document.getElementById('charCount');
const resultsSection = document.getElementById('resultsSection');
const riskBadge = document.getElementById('riskBadge');
const gaugeFill = document.getElementById('gaugeFill');
const riskScore = document.getElementById('riskScore');
const riskSummary = document.getElementById('riskSummary');
const statWarnings = document.getElementById('statWarnings');
const statPatterns = document.getElementById('statPatterns');
const statRiskLevel = document.getElementById('statRiskLevel');
const warningsContainer = document.getElementById('warningsContainer');
const warningsGrid = document.getElementById('warningsGrid');
const warningsTitle = document.getElementById('warningsTitle');
const safeMessage = document.getElementById('safeMessage');
const exampleScam = document.getElementById('exampleScam');
const exampleSafe = document.getElementById('exampleSafe');

const EXAMPLES = {
  scam: `URGENT! CONGRATULATIONS! You've been selected as the winner of $1,000,000 in the International Lottery!

To claim your prize, you must act NOW before it expires today! Click here: bit.ly/claim-prize-now

We need you to verify your identity by providing your:
- Full Name
- Social Security Number
- Bank Account Details

Send a processing fee of $49.99 via gift cards to complete the transfer.

WARNING: Failure to respond within 24 hours will result in legal action and your winnings will be forfeited.

This is an official notice from the International Prize Commission.
Reply IMMEDIATELY - this is your LAST CHANCE!!!`,

  safe: `Hey! Are we still on for coffee tomorrow at 3pm? I was thinking we could try that new café on Main Street. Let me know if the time works for you. See you soon!`,
};

messageInput.addEventListener('input', () => {
  const len = messageInput.value.length;
  charCount.textContent = `${len.toLocaleString()} / 10,000`;
  charCount.style.color = len > 9000 ? '#ef4444' : '';
});

exampleScam.addEventListener('click', () => {
  messageInput.value = EXAMPLES.scam;
  messageInput.dispatchEvent(new Event('input'));
  messageInput.focus();
});

exampleSafe.addEventListener('click', () => {
  messageInput.value = EXAMPLES.safe;
  messageInput.dispatchEvent(new Event('input'));
  messageInput.focus();
});

analyzeBtn.addEventListener('click', () => analyzeMessage());

messageInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyzeMessage();
});

async function analyzeMessage() {
  const message = messageInput.value.trim();
  if (!message) {
    shakeElement(messageInput);
    messageInput.focus();
    return;
  }

  analyzeBtn.classList.add('loading');

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || 'Analysis failed');
    }

    const result = await response.json();
    renderResults(result);
  } catch (err) {
    console.error('Analysis error:', err);
    alert('Error: ' + err.message);
  } finally {
    analyzeBtn.classList.remove('loading');
  }
}

function renderResults(result) {
  resultsSection.style.display = 'block';

  setTimeout(() => {
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);

  const levelColors = {
    Low: '#34d399',
    Medium: '#f59e0b',
    High: '#f97316',
    Critical: '#ef4444',
  };

  const levelClass = result.riskLevel.toLowerCase();
  const color = levelColors[result.riskLevel] || '#34d399';

  riskBadge.textContent = result.riskLevel;
  riskBadge.className = 'risk-badge ' + levelClass;

  gaugeFill.style.width = '0%';
  gaugeFill.style.background = `linear-gradient(90deg, ${color}88, ${color})`;

  requestAnimationFrame(() => {
    setTimeout(() => {
      gaugeFill.style.width = result.riskScore + '%';
    }, 50);
  });

  const scoreNumber = riskScore.querySelector('.score-number');
  scoreNumber.style.color = color;
  animateNumber(scoreNumber, 0, result.riskScore, 1200);

  riskSummary.textContent = result.summary;
  riskSummary.style.borderLeftColor = color;

  statWarnings.textContent = result.warnings.length;
  statPatterns.textContent = result.totalPatterns || 0;
  statRiskLevel.textContent = result.riskLevel;
  statRiskLevel.style.color = color;

  if (result.warnings.length > 0) {
    warningsContainer.style.display = 'block';
    safeMessage.style.display = 'none';
    renderWarnings(result.warnings);
  } else {
    warningsContainer.style.display = 'none';
    safeMessage.style.display = 'block';
  }
}

function renderWarnings(warnings) {
  warningsGrid.innerHTML = '';
  warningsTitle.textContent = `${warnings.length} Warning Signal${warnings.length > 1 ? 's' : ''} Detected`;

  warnings.forEach((warning, index) => {
    const card = document.createElement('div');
    card.className = 'warning-card';
    card.style.animationDelay = `${index * 0.08}s`;

    const matchTags = warning.matchedTexts
      .map(text => `<span class="match-tag">"${escapeHtml(text)}"</span>`)
      .join('');

    card.innerHTML = `
      <div class="warning-card-header">
        <div class="warning-card-title">${escapeHtml(warning.category)}</div>
        <span class="severity-tag ${warning.severity}">${warning.severity}</span>
      </div>
      <div class="warning-card-desc">${escapeHtml(warning.description)}</div>
      <div class="warning-matches">${matchTags}</div>
    `;

    warningsGrid.appendChild(card);
  });
}

// ══════════════════════════════════════
// Scam Lookup
// ══════════════════════════════════════

const lookupInput = document.getElementById('lookupInput');
const lookupBtn = document.getElementById('lookupBtn');
const lookupResult = document.getElementById('lookupResult');
const lookupResultCard = document.getElementById('lookupResultCard');
const lookupResultIcon = document.getElementById('lookupResultIcon');
const lookupResultTitle = document.getElementById('lookupResultTitle');
const lookupResultQuery = document.getElementById('lookupResultQuery');
const lookupResultDesc = document.getElementById('lookupResultDesc');
const lookupResultMeta = document.getElementById('lookupResultMeta');

lookupBtn.addEventListener('click', () => performLookup());
lookupInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') performLookup();
});

document.querySelectorAll('.lookup-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    lookupInput.value = chip.dataset.lookup;
    lookupInput.focus();
    performLookup();
  });
});

async function performLookup() {
  const query = lookupInput.value.trim();
  if (!query) {
    shakeElement(lookupInput);
    lookupInput.focus();
    return;
  }

  lookupBtn.classList.add('loading');

  try {
    const response = await fetch('/api/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query }),
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || 'Lookup failed');
    }

    const result = await response.json();
    renderLookupResult(result);
  } catch (err) {
    console.error('Lookup error:', err);
    alert('Error: ' + err.message);
  } finally {
    lookupBtn.classList.remove('loading');
  }
}

function renderLookupResult(result) {
  lookupResult.style.display = 'block';

  lookupResult.style.animation = 'none';
  lookupResult.offsetHeight;
  lookupResult.style.animation = '';

  if (result.isScam) {
    lookupResultCard.className = 'lookup-result-card scam';
    lookupResultIcon.textContent = '🚨';
    lookupResultTitle.textContent = 'Reported as Scam';
    lookupResultQuery.textContent = result.query;
    lookupResultDesc.textContent = result.description;

    lookupResultMeta.innerHTML = `
      <span class="meta-tag category">${escapeHtml(result.category)}</span>
      <span class="meta-tag reports">📊 ${result.reports.toLocaleString()} Reports</span>
      <span class="meta-tag risk-${result.riskLevel.toLowerCase()}">${result.riskLevel} Risk</span>
    `;
  } else {
    lookupResultCard.className = 'lookup-result-card safe';
    lookupResultIcon.textContent = '✅';
    lookupResultTitle.textContent = 'Not Found in Database';
    lookupResultQuery.textContent = result.query;
    lookupResultDesc.textContent = result.message;

    lookupResultMeta.innerHTML = `
      <span class="meta-tag safe-tag">No Reports Found</span>
      <span class="meta-tag category">${result.type}</span>
    `;
  }

  setTimeout(() => {
    lookupResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, 100);
}

// ══════════════════════════════════════
// Report Scam Form
// ══════════════════════════════════════

const reportForm = document.getElementById('reportForm');
const reportSuccess = document.getElementById('reportSuccess');
const reportSubmitBtn = document.getElementById('reportSubmitBtn');
const reportNewBtn = document.getElementById('reportNewBtn');

reportForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  reportSubmitBtn.classList.add('loading');

  const data = {
    type: document.getElementById('reportType').value,
    contact: document.getElementById('reportContact').value.trim(),
    category: document.getElementById('reportCategory').value,
    description: document.getElementById('reportDescription').value.trim(),
  };

  try {
    const response = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      throw new Error(result.error || 'Failed to submit report');
    }

    // Show success
    reportForm.style.display = 'none';
    reportSuccess.style.display = 'block';

  } catch (err) {
    console.error('Report error:', err);
    alert('Error: ' + err.message);
  } finally {
    reportSubmitBtn.classList.remove('loading');
  }
});

reportNewBtn.addEventListener('click', () => {
  reportForm.reset();
  reportForm.style.display = 'flex';
  reportSuccess.style.display = 'none';
});

// ══════════════════════════════════════
// Utilities
// ══════════════════════════════════════

function animateNumber(element, start, end, duration) {
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easedProgress = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (end - start) * easedProgress);
    element.textContent = current;
    if (progress < 1) requestAnimationFrame(update);
  }

  requestAnimationFrame(update);
}

function shakeElement(element) {
  element.style.animation = 'none';
  element.offsetHeight;
  element.style.animation = 'shake 0.4s ease-out';
  setTimeout(() => { element.style.animation = ''; }, 400);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Add shake animation
const style = document.createElement('style');
style.textContent = `
  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    20% { transform: translateX(-6px); }
    40% { transform: translateX(6px); }
    60% { transform: translateX(-4px); }
    80% { transform: translateX(4px); }
  }
`;
document.head.appendChild(style);

// ══════════════════════════════════════
// Interactive Grid Background
// ══════════════════════════════════════
(function () {
  const canvas = document.getElementById('gridCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const CELL = 60;
  let mouse = { x: -1000, y: -1000 };
  const RADIUS = 180;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = document.documentElement.scrollHeight;
  }

  window.addEventListener('resize', resize);
  new ResizeObserver(resize).observe(document.documentElement);
  resize();

  document.addEventListener('mousemove', (e) => {
    mouse.x = e.pageX;
    mouse.y = e.pageY;
  });

  document.addEventListener('mouseleave', () => {
    mouse.x = -1000;
    mouse.y = -1000;
  });

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const cols = Math.ceil(canvas.width / CELL) + 1;
    const rows = Math.ceil(canvas.height / CELL) + 1;

    const scrollY = window.scrollY || window.pageYOffset;
    const scrollX = window.scrollX || window.pageXOffset;

    const mx = mouse.x - scrollX;
    const my = mouse.y - scrollY;

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const x = c * CELL;
        const y = r * CELL;

        const cx = x + CELL / 2;
        const cy = y + CELL / 2;

        const dx = mx - cx;
        const dy = my - cy;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < RADIUS) {
          const intensity = 1 - dist / RADIUS;
          const alpha = intensity * 0.18;

          ctx.fillStyle = `rgba(108, 92, 231, ${alpha})`;
          ctx.fillRect(x + 1, y + 1, CELL - 2, CELL - 2);

          ctx.strokeStyle = `rgba(138, 120, 255, ${intensity * 0.35})`;
          ctx.lineWidth = 1;
          ctx.strokeRect(x + 0.5, y + 0.5, CELL, CELL);
        } else {
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
          ctx.lineWidth = 1;
          ctx.strokeRect(x + 0.5, y + 0.5, CELL, CELL);
        }
      }
    }

    requestAnimationFrame(draw);
  }

  requestAnimationFrame(draw);
})();

// ══════════════════════════════════════
// Init — Load dashboard on page load
// ══════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  initMap();
  mapInitialized = true;
});
