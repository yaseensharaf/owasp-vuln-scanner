const startBtn = document.getElementById("startScanBtn");
const targetUrlInput = document.getElementById("targetUrl");
const confirmCheckbox = document.getElementById("confirmAuthorized");
const statusBadge = document.getElementById("statusBadge");
const summarySection = document.getElementById("summary");
const findingsSection = document.getElementById("findings");
const downloadReportLink = document.getElementById("downloadReport");

const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

function resetUI() {
  findingsSection.innerHTML = "";
  Object.keys(counts).forEach((k) => (counts[k] = 0));
  updateCounts();
  summarySection.style.display = "flex";
  downloadReportLink.style.display = "none";
}

function updateCounts() {
  document.getElementById("countCritical").textContent = counts.critical;
  document.getElementById("countHigh").textContent = counts.high;
  document.getElementById("countMedium").textContent = counts.medium;
  document.getElementById("countLow").textContent = counts.low;
  document.getElementById("countInfo").textContent = counts.info;
}

function renderFinding(f) {
  counts[f.severity] = (counts[f.severity] || 0) + 1;
  updateCounts();

  const div = document.createElement("div");
  div.className = `finding ${f.severity}`;
  div.innerHTML = `
    <div class="finding-title">[${f.severity.toUpperCase()}] ${f.title}</div>
    <div class="finding-meta">${f.check} &middot; ${f.url}</div>
    <div class="finding-desc">${f.description}</div>
    <div class="finding-remediation">Fix: ${f.remediation}</div>
  `;
  findingsSection.prepend(div);
}

async function startScan() {
  const url = targetUrlInput.value.trim();
  if (!url) {
    alert("Enter a target URL.");
    return;
  }
  if (!confirmCheckbox.checked) {
    alert("You must confirm authorization to scan this target.");
    return;
  }

  startBtn.disabled = true;
  statusBadge.textContent = "starting...";
  resetUI();

  let scanId;
  try {
    const resp = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, confirm_authorized: true }),
    });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.detail || "Failed to start scan");
    }
    const data = await resp.json();
    scanId = data.scan_id;
  } catch (e) {
    statusBadge.textContent = `error: ${e.message}`;
    startBtn.disabled = false;
    return;
  }

  const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${wsProtocol}://${location.host}/api/ws/${scanId}`);

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === "status") {
      statusBadge.textContent = msg.status;
      if (msg.status === "completed") {
        startBtn.disabled = false;
        downloadReportLink.style.display = "inline-block";
        downloadReportLink.href = `/api/scan/${scanId}/report.pdf`;
      }
      if (msg.status === "failed") {
        startBtn.disabled = false;
      }
    } else if (msg.type === "finding") {
      renderFinding(msg.finding);
    }
  };

  ws.onerror = () => {
    statusBadge.textContent = "connection error";
    startBtn.disabled = false;
  };
}

startBtn.addEventListener("click", startScan);
