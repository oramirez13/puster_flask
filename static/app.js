let riskChartInstance = null;
let autoRefreshInterval = null;
let currentFilter = "all";

document.getElementById("scanBtn").addEventListener("click", async () => {
    const btn = document.getElementById("scanBtn");
    const info = document.getElementById("scanInfo");
    btn.disabled = true;
    btn.textContent = "Scanning...";
    info.textContent = "";
    info.className = "scan-info";
    try {
        const resp = await fetch("/scan");
        const result = await resp.json();
        if (resp.ok) {
            info.textContent = "Scan completed: " + (result.message || "");
            info.className = "scan-info success";
        } else {
            info.textContent = "Error: " + (result.message || "Unknown error");
            info.className = "scan-info error";
        }
    } catch (e) {
        info.textContent = "Network error: " + e.message;
        info.className = "scan-info error";
    }
    btn.disabled = false;
    btn.textContent = "Run Scan";
    loadData();
});

document.getElementById("pdfBtn").addEventListener("click", () => {
    window.location = "/export/pdf";
});

document.getElementById("csvBtn").addEventListener("click", () => {
    window.location = "/export/csv";
});

document.getElementById("autoRefresh").addEventListener("change", function () {
    if (this.checked) {
        autoRefreshInterval = setInterval(loadData, 30000);
    } else {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
        }
    }
});

document.querySelectorAll(".filter-btn").forEach((btn) => {
    btn.addEventListener("click", function () {
        document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
        this.classList.add("active");
        currentFilter = this.dataset.filter;
        loadData();
    });
});

async function loadData() {
    let url = "/api/alerts";
    if (currentFilter !== "all") {
        url += "?risk=" + currentFilter;
    }
    try {
        const response = await fetch(url);
        if (!response.ok) return;
        const data = await response.json();

        document.getElementById("total").innerText = data.summary.total_connections;
        document.getElementById("low").innerText = data.summary.low;
        document.getElementById("medium").innerText = data.summary.medium;
        document.getElementById("high").innerText = data.summary.high;

        const tableBody = document.getElementById("tableBody");
        tableBody.innerHTML = "";

        data.alerts.forEach((alert) => {
            const riskClass = (alert.risk || "").toLowerCase() + "-risk";
            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${escapeHtml(alert.process)}</td>
                <td>${escapeHtml(alert.pid)}</td>
                <td>${escapeHtml(alert.protocol)}</td>
                <td>${escapeHtml(alert.remote_ip)}</td>
                <td>${escapeHtml(alert.remote_port)}</td>
                <td>${escapeHtml(alert.local_ip)}</td>
                <td>${escapeHtml(alert.local_port)}</td>
                <td class="${riskClass}">${escapeHtml(alert.risk)}</td>
            `;
            tableBody.appendChild(row);
        });

        if (data.alerts.length === 0) {
            const row = document.createElement("tr");
            row.innerHTML = '<td colspan="8" style="text-align:center; color:#64748b;">No alerts match the current filter.</td>';
            tableBody.appendChild(row);
        }

        renderChart(data.summary.low, data.summary.medium, data.summary.high);
    } catch (e) {
        /* Silently fail on initial load if no data */
    }
}

function renderChart(low, medium, high) {
    const ctx = document.getElementById("riskChart").getContext("2d");
    if (riskChartInstance) {
        riskChartInstance.destroy();
    }
    riskChartInstance = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Low", "Medium", "High"],
            datasets: [{
                label: "Risk Levels",
                data: [low, medium, high],
                backgroundColor: ["#22c55e", "#facc15", "#ef4444"],
                borderRadius: 4,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { stepSize: 1 },
                },
            },
        },
    });
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text || "";
    return div.innerHTML;
}

loadData();
