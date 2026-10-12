/**
 * AuthGuard Modern Web Application Interface Logic
 * Fully asynchronous frontend coordinating API operations, live monitoring,
 * chart updates, assessment creation wizard, and lab toggles.
 */

let activePollInterval = null;
let currentMonitorId = null;

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    loadDashboardData();
    initWizard();
    checkLabStatus();
});

function initNavigation() {
    document.querySelectorAll(".nav-link").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const targetSection = link.getAttribute("data-section");
            switchSection(targetSection);
        });
    });
}

function switchSection(sectionId) {
    document.querySelectorAll(".content-section").forEach(sec => sec.style.display = "none");
    document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));

    const activeSec = document.getElementById(`section-${sectionId}`);
    if (activeSec) {
        activeSec.style.display = "block";
    }

    const activeLink = document.querySelector(`.nav-link[data-section="${sectionId}"]`);
    if (activeLink && activeLink.parentElement) {
        activeLink.parentElement.classList.add("active");
    }

    // Refresh data corresponding to view
    if (sectionId === "dashboard") {
        loadDashboardData();
    } else if (sectionId === "findings") {
        loadFindings();
    } else if (sectionId === "reports") {
        loadReportsList();
    } else if (sectionId === "admin") {
        loadAdminData();
    } else if (sectionId === "wizard") {
        loadTargetsForWizard();
    }
}

// ---------------- DASHBOARD DATA ----------------

async function loadDashboardData() {
    try {
        const res = await fetch("/api/dashboard/stats");
        if (!res.ok) return;
        const data = await res.json();

        // Populate counters
        document.getElementById("stat-total-assessments").innerText = data.assessments.total;
        document.getElementById("stat-running-assessments").innerText = data.assessments.running;
        document.getElementById("stat-completed-assessments").innerText = data.assessments.completed;
        document.getElementById("stat-total-findings").innerText = data.findings.total;

        // Findings Breakdown
        const sev = data.findings.by_severity;
        document.getElementById("sev-critical").innerText = sev.Critical || 0;
        document.getElementById("sev-high").innerText = sev.High || 0;
        document.getElementById("sev-medium").innerText = sev.Medium || 0;
        document.getElementById("sev-low").innerText = sev.Low || 0;

        // Recent assessments table
        const tbody = document.getElementById("table-recent-assessments");
        tbody.innerHTML = "";
        data.recent_assessments.forEach(asm => {
            const tr = document.createElement("tr");
            const badgeClass = asm.status === "completed" ? "badge-success" : (asm.status === "running" ? "badge-running" : "badge-medium");
            tr.innerHTML = `
                <td>#${asm.id}</td>
                <td><strong>${asm.name}</strong></td>
                <td><code>${asm.target}</code></td>
                <td><span class="badge ${badgeClass}">${asm.status.toUpperCase()}</span></td>
                <td>${new Date(asm.created_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="viewAssessmentMonitor(${asm.id})">Inspect</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

    } catch (err) {
        console.error("Failed loading dashboard metrics:", err);
    }
}

// ---------------- WIZARD CONTROLLER ----------------

let wizardStep = 1;

function initWizard() {
    const nextBtn = document.getElementById("btn-wizard-next");
    const prevBtn = document.getElementById("btn-wizard-prev");
    const submitBtn = document.getElementById("btn-wizard-submit");

    if (nextBtn) {
        nextBtn.addEventListener("click", () => {
            if (wizardStep < 3) {
                wizardStep++;
                updateWizardView();
            }
        });
    }
    if (prevBtn) {
        prevBtn.addEventListener("click", () => {
            if (wizardStep > 1) {
                wizardStep--;
                updateWizardView();
            }
        });
    }
    if (submitBtn) {
        submitBtn.addEventListener("click", submitAssessmentFromWizard);
    }
}

function updateWizardView() {
    document.querySelectorAll(".wizard-panel").forEach(p => p.style.display = "none");
    document.querySelectorAll(".wizard-step").forEach((ws, idx) => {
        ws.classList.toggle("active", idx + 1 === wizardStep);
        ws.classList.toggle("completed", idx + 1 < wizardStep);
    });

    const currPanel = document.getElementById(`wizard-step-${wizardStep}`);
    if (currPanel) currPanel.style.display = "block";

    const prevBtn = document.getElementById("btn-wizard-prev");
    const nextBtn = document.getElementById("btn-wizard-next");
    const submitBtn = document.getElementById("btn-wizard-submit");

    if (prevBtn) prevBtn.style.display = wizardStep > 1 ? "inline-flex" : "none";
    if (nextBtn) nextBtn.style.display = wizardStep < 3 ? "inline-flex" : "none";
    if (submitBtn) submitBtn.style.display = wizardStep === 3 ? "inline-flex" : "none";
}

async function loadTargetsForWizard() {
    try {
        const res = await fetch("/api/targets");
        if (!res.ok) return;
        const targets = await res.json();
        const select = document.getElementById("wizard-target-select");
        select.innerHTML = "";
        targets.forEach(t => {
            const opt = document.createElement("option");
            opt.value = t.id;
            opt.innerText = `${t.name} (${t.base_url})`;
            select.appendChild(opt);
        });
    } catch (e) {
        console.error(e);
    }
}

async function submitAssessmentFromWizard() {
    const name = document.getElementById("wizard-asm-name").value;
    const targetId = parseInt(document.getElementById("wizard-target-select").value);
    const budget = parseInt(document.getElementById("wizard-asm-budget").value) || 250;

    const modules = [];
    if (document.getElementById("mod-otp").checked) modules.push("otp");
    if (document.getElementById("mod-ratelimit").checked) modules.push("rate_limit");
    if (document.getElementById("mod-captcha").checked) modules.push("captcha");

    try {
        const res = await fetch("/api/assessments", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: name || "Security Assessment",
                target_id: targetId,
                request_budget: budget,
                modules: modules,
            })
        });

        if (!res.ok) {
            const err = await res.json();
            alert("Submission error: " + (err.detail || "Failed to launch assessment"));
            return;
        }

        const asm = await res.json();
        wizardStep = 1;
        updateWizardView();
        viewAssessmentMonitor(asm.id);
    } catch (e) {
        alert("Failed to create assessment: " + e.message);
    }
}

// ---------------- MONITOR CONTROLLER ----------------

function viewAssessmentMonitor(assessmentId) {
    currentMonitorId = assessmentId;
    switchSection("monitor");
    pollMonitor();

    if (activePollInterval) clearInterval(activePollInterval);
    activePollInterval = setInterval(pollMonitor, 1500);
}

async function pollMonitor() {
    if (!currentMonitorId) return;
    try {
        const res = await fetch(`/api/assessments/${currentMonitorId}`);
        if (!res.ok) return;
        const data = await res.json();
        const a = data.assessment;

        document.getElementById("mon-id").innerText = `#${a.id}`;
        document.getElementById("mon-name").innerText = a.name;
        document.getElementById("mon-target").innerText = `${a.target.name} (${a.target.base_url})`;
        document.getElementById("mon-phase").innerText = a.current_phase;
        document.getElementById("mon-status").innerText = a.status.toUpperCase();
        document.getElementById("mon-progress").innerText = `${a.completed_tests} / ${a.total_tests || '...'}`;
        document.getElementById("mon-budget").innerText = `${a.requests_used} / ${a.request_budget}`;

        // Tests list
        const testList = document.getElementById("mon-testcases");
        testList.innerHTML = "";
        data.test_cases.forEach(tc => {
            const li = document.createElement("li");
            li.style.padding = "8px 0";
            li.style.borderBottom = "1px solid #243247";
            li.style.display = "flex";
            li.style.justifyContent = "space-between";
            const col = tc.status === "passed" ? "#10b981" : "#ef4444";
            li.innerHTML = `<span><strong>[${tc.test_code}]</strong> ${tc.name}</span><span style="color:${col}; font-weight:bold;">${tc.status.toUpperCase()}</span>`;
            testList.appendChild(li);
        });

        // If completed or failed, stop polling
        if (a.status === "completed" || a.status === "failed" || a.status === "cancelled") {
            clearInterval(activePollInterval);
            activePollInterval = null;
        }
    } catch (e) {
        console.error("Monitor poll error:", e);
    }
}

async function cancelCurrentAssessment() {
    if (!currentMonitorId) return;
    if (!confirm("Are you sure you want to halt this running assessment?")) return;
    await fetch(`/api/assessments/${currentMonitorId}/cancel`, { method: "POST" });
    pollMonitor();
}

// ---------------- FINDINGS EXPLORER ----------------

async function loadFindings() {
    const sev = document.getElementById("filter-severity").value;
    const mod = document.getElementById("filter-module").value;

    let url = "/api/findings?";
    if (sev) url += `severity=${sev}&`;
    if (mod) url += `module=${mod}&`;

    const res = await fetch(url);
    if (!res.ok) return;
    const findings = await res.json();

    const tbody = document.getElementById("table-findings");
    tbody.innerHTML = "";

    findings.forEach(f => {
        const tr = document.createElement("tr");
        const bClass = `badge-${f.severity.toLowerCase()}`;
        tr.innerHTML = `
            <td>#${f.id}</td>
            <td><strong>${f.title}</strong></td>
            <td><span class="badge ${bClass}">${f.severity}</span></td>
            <td><code>${f.affected_endpoint}</code></td>
            <td>${f.module.toUpperCase()}</td>
            <td><span class="badge badge-medium">${f.validation_status}</span></td>
            <td>
                <button class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="openFindingDetailModal(${JSON.stringify(f).replace(/"/g, '&quot;')})">Details</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function openFindingDetailModal(f) {
    document.getElementById("modal-f-title").innerText = `${f.title} (${f.severity} - CVSS ${f.cvss_score})`;
    document.getElementById("modal-f-endpoint").innerText = f.affected_endpoint;
    document.getElementById("modal-f-desc").innerText = f.description;
    document.getElementById("modal-f-actual").innerText = f.actual_behavior;
    document.getElementById("modal-f-expected").innerText = f.expected_behavior;
    document.getElementById("modal-f-remediation").innerText = f.remediation;
    document.getElementById("modal-finding-id").value = f.id;

    document.getElementById("finding-modal").classList.add("active");
}

function closeFindingModal() {
    document.getElementById("finding-modal").classList.remove("active");
}

async function updateFindingStatusFromModal(newStatus) {
    const fid = document.getElementById("modal-finding-id").value;
    await fetch(`/api/findings/${fid}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ validation_status: newStatus })
    });
    closeFindingModal();
    loadFindings();
}

// ---------------- REPORTS LIST ----------------

async function loadReportsList() {
    const res = await fetch("/api/assessments");
    if (!res.ok) return;
    const assessments = await res.json();
    const tbody = document.getElementById("table-reports");
    tbody.innerHTML = "";

    assessments.forEach(a => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>#${a.id}</td>
            <td><strong>${a.name}</strong></td>
            <td>${a.status.toUpperCase()}</td>
            <td>${new Date(a.created_at).toLocaleDateString()}</td>
            <td>
                <a class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" href="/api/reports/${a.id}/html" target="_blank">HTML</a>
                <a class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" href="/api/reports/${a.id}/pdf" target="_blank">PDF</a>
                <a class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" href="/api/reports/${a.id}/json" target="_blank">JSON</a>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ---------------- DEMO LAB TOGGLE ----------------

async function checkLabStatus() {
    try {
        const res = await fetch("http://127.0.0.1:8001/api/config");
        if (res.ok) {
            const data = await res.json();
            const badge = document.getElementById("lab-mode-badge");
            if (badge) {
                badge.innerText = `LAB MODE: ${data.mode.toUpperCase()}`;
                badge.className = data.mode === "vulnerable" ? "badge badge-critical" : "badge badge-success";
            }
        }
    } catch (e) {
        // Lab may not be started on 8001
    }
}

async function toggleLabMode(mode) {
    try {
        await fetch(`http://127.0.0.1:8001/api/mode/${mode}`, { method: "POST" });
        checkLabStatus();
        alert(`Lab switched to ${mode.toUpperCase()} mode!`);
    } catch (e) {
        alert("Failed to communicate with Lab application on port 8001.");
    }
}
