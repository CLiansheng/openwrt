const state = {
  history: [],
  maxPoints: 40,
};

const $ = (selector) => document.querySelector(selector);

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB"];
  let n = Number(value) || 0;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatBps(value) {
  const units = ["bps", "Kbps", "Mbps", "Gbps"];
  let n = Number(value) || 0;
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i += 1;
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatTime(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleTimeString();
}

function drawChart(totalBps) {
  state.history.push(totalBps);
  if (state.history.length > state.maxPoints) state.history.shift();

  const canvas = $("#trafficChart");
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const pad = 34;
  const max = Math.max(1, ...state.history);

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#fbfdff";
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = "#e3ebf2";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = pad + ((height - pad * 2) * i) / 4;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(width - pad, y);
    ctx.stroke();
  }

  const gradient = ctx.createLinearGradient(0, pad, 0, height - pad);
  gradient.addColorStop(0, "rgba(31, 103, 210, 0.20)");
  gradient.addColorStop(1, "rgba(31, 103, 210, 0.02)");

  ctx.beginPath();
  state.history.forEach((value, index) => {
    const x = pad + ((width - pad * 2) * index) / Math.max(1, state.maxPoints - 1);
    const y = height - pad - ((height - pad * 2) * value) / max;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  if (state.history.length > 0) {
    const lastX = pad + ((width - pad * 2) * (state.history.length - 1)) / Math.max(1, state.maxPoints - 1);
    ctx.lineTo(lastX, height - pad);
    ctx.lineTo(pad, height - pad);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();
  }

  ctx.strokeStyle = "#175ddc";
  ctx.lineWidth = 3;
  ctx.beginPath();
  state.history.forEach((value, index) => {
    const x = pad + ((width - pad * 2) * index) / Math.max(1, state.maxPoints - 1);
    const y = height - pad - ((height - pad * 2) * value) / max;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.fillStyle = "#657383";
  ctx.font = "13px Segoe UI, Microsoft YaHei, sans-serif";
  ctx.fillText("0", pad, height - 10);
  ctx.fillText(formatBps(max), pad, 22);
  $("#chartScale").textContent = formatBps(max);
}

async function loadTraffic() {
  try {
    const res = await fetch("/api/traffic", { cache: "no-store" });
    const data = await res.json();
    const items = [...(data.items || [])].sort((a, b) => b.totalBytes - a.totalBytes).slice(0, 100);
    const totalBytes = items.reduce((sum, item) => sum + item.totalBytes, 0);
    const totalBps = items.reduce((sum, item) => sum + item.avg2sBps, 0);
    const peakBps = items.reduce((max, item) => Math.max(max, item.peakBps), 0);

    $("#status").textContent = "已连接";
    $("#statusDot").className = "dot ok";
    $("#lastUpdate").textContent = `更新时间 ${new Date().toLocaleTimeString()}`;
    $("#iface").textContent = data.interface || "-";
    $("#ipCount").textContent = String(items.length);
    $("#totalTraffic").textContent = formatBytes(totalBytes);
    $("#liveRate").textContent = formatBps(totalBps);
    $("#peakRate").textContent = formatBps(peakBps);
    drawChart(totalBps);

    if (items.length === 0) {
      $("#trafficRows").innerHTML = '<tr><td colspan="8" class="empty">暂无流量数据</td></tr>';
      return;
    }

    $("#trafficRows").innerHTML = items.map((item) => `
      <tr>
        <td>${item.ip}</td>
        <td>${formatBytes(item.rxBytes)}</td>
        <td>${formatBytes(item.txBytes)}</td>
        <td>${formatBps(item.peakBps)}</td>
        <td>${formatBps(item.avg2sBps)}</td>
        <td>${formatBps(item.avg10sBps)}</td>
        <td>${formatBps(item.avg40sBps)}</td>
        <td>${formatTime(item.lastSeen)}</td>
      </tr>
    `).join("");
  } catch (err) {
    $("#status").textContent = `连接失败：${err.message}`;
    $("#statusDot").className = "dot fail";
  }
}

async function postJSON(url, payload = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}

function showFirewallResult(data) {
  const prefix = data.ok ? "执行成功" : "执行失败";
  $("#firewallState").textContent = prefix;
  $("#firewallState").className = data.ok ? "ok" : "fail";
  $("#firewallOutput").textContent = `${prefix}\nexitCode=${data.exitCode}\n\n${data.output || ""}`;
}

async function refreshRules() {
  const res = await fetch("/api/firewall/list", { cache: "no-store" });
  showFirewallResult(await res.json());
}

function bindTabs() {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab, .panel").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      $(`#${button.dataset.tab}`).classList.add("active");
      if (button.dataset.tab === "firewall") refreshRules();
    });
  });
}

function bindFirewall() {
  $("#ruleForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const payload = Object.fromEntries(form.entries());
    payload.src = payload.src.trim() || "any";
    payload.dst = payload.dst.trim() || "any";
    payload.port = payload.port.trim();
    showFirewallResult(await postJSON("/api/firewall/add", payload));
    refreshRules();
  });

  $("#refreshRules").addEventListener("click", refreshRules);
  $("#clearRules").addEventListener("click", async () => {
    showFirewallResult(await postJSON("/api/firewall/clear"));
    refreshRules();
  });
  $("#deleteRule").addEventListener("click", async () => {
    const id = $("#deleteId").value.trim();
    showFirewallResult(await postJSON("/api/firewall/delete", { id }));
    refreshRules();
  });
}

bindTabs();
bindFirewall();
loadTraffic();
setInterval(loadTraffic, 1000);
