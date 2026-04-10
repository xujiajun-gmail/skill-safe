const UI_STRINGS = {
  zh: {
    title: "Skill Scanner Web App",
    subtitle: "上传目录、压缩包或 URL，调用 skill_safe 的扫描能力并输出中英文可读报告。",
    scanFormTitle: "开始扫描",
    uiLangLabel: "界面语言",
    reportLangLabel: "报告语言",
    inputModeLabel: "输入方式",
    archiveLabel: "上传压缩包",
    directoryLabel: "上传目录",
    directoryHint: "浏览器会保留目录内相对路径。",
    urlLabel: "Skill URL",
    pathLabel: "服务器本地路径",
    dynamicLabel: "启用动态观察模式",
    submitButton: "开始扫描",
    resultTitle: "扫描结果",
    emptyText: "提交一个 Skill 之后，这里会显示可读报告、结构化结果和原始 JSON。",
    headlineTitle: "摘要",
    findingTitle: "关键发现",
    flowTitle: "关键攻击链",
    actionTitle: "建议动作",
    textTitle: "文字版报告",
    jsonTitle: "原始 JSON",
    historyTitle: "扫描历史",
    historyHint: "最近扫描结果会保存在当前服务进程的内存中。",
    refreshHistoryButton: "刷新",
    downloadReportJson: "下载报告 JSON",
    downloadExplanationJson: "下载解释 JSON",
    downloadExplanationText: "下载文字报告",
    statusIdle: "空闲",
    statusRunning: "扫描中",
    statusDone: "已完成",
    statusError: "出错",
    inputArchive: "压缩包",
    inputDirectory: "目录",
    inputUrl: "URL",
    inputPath: "服务器本地路径",
    summaryTarget: "目标",
    summaryDecision: "决策",
    summaryFindings: "发现数",
    summaryOverall: "总体等级",
    summaryLanguage: "输出语言",
    findingWhy: "为什么重要",
    findingRemediation: "建议",
    flowRoute: "路径",
    flowTaxonomy: "触发分类",
    noFindings: "无关键发现",
    noFlows: "无关键攻击链",
    noActions: "暂无建议动作",
    noHistory: "暂无历史记录",
    missingArchive: "请先选择压缩包。",
    missingDirectory: "请先选择目录。",
    missingUrl: "请输入 URL。",
    missingPath: "请输入服务器本地路径。",
    apiError: "请求失败",
    historyLoadError: "读取历史失败",
    historySource: "来源",
    historyDecision: "决策",
    historyFindings: "发现",
    historyTime: "时间",
  },
  en: {
    title: "Skill Scanner Web App",
    subtitle: "Upload a directory, archive, or URL and run skill_safe scans with human-readable bilingual reports.",
    scanFormTitle: "Start Scan",
    uiLangLabel: "UI Language",
    reportLangLabel: "Report Language",
    inputModeLabel: "Input Mode",
    archiveLabel: "Upload Archive",
    directoryLabel: "Upload Directory",
    directoryHint: "The browser preserves relative paths inside the selected folder.",
    urlLabel: "Skill URL",
    pathLabel: "Server-local Path",
    dynamicLabel: "Enable dynamic observation mode",
    submitButton: "Run Scan",
    resultTitle: "Scan Result",
    emptyText: "After you submit a skill, this area shows a readable report, structured output, and raw JSON.",
    headlineTitle: "Summary",
    findingTitle: "Key Findings",
    flowTitle: "Key Flows",
    actionTitle: "Recommended Actions",
    textTitle: "Text Report",
    jsonTitle: "Raw JSON",
    historyTitle: "Scan History",
    historyHint: "Recent scan results are kept in the current service process memory.",
    refreshHistoryButton: "Refresh",
    downloadReportJson: "Download Report JSON",
    downloadExplanationJson: "Download Explanation JSON",
    downloadExplanationText: "Download Text Report",
    statusIdle: "Idle",
    statusRunning: "Running",
    statusDone: "Done",
    statusError: "Error",
    inputArchive: "Archive",
    inputDirectory: "Directory",
    inputUrl: "URL",
    inputPath: "Server-local Path",
    summaryTarget: "Target",
    summaryDecision: "Decision",
    summaryFindings: "Findings",
    summaryOverall: "Overall",
    summaryLanguage: "Output Language",
    findingWhy: "Why it matters",
    findingRemediation: "What to do",
    flowRoute: "Route",
    flowTaxonomy: "Triggered taxonomy",
    noFindings: "No key findings",
    noFlows: "No key flows",
    noActions: "No recommended actions",
    noHistory: "No history yet",
    missingArchive: "Please choose an archive first.",
    missingDirectory: "Please choose a directory first.",
    missingUrl: "Please enter a URL.",
    missingPath: "Please enter a server-local path.",
    apiError: "Request failed",
    historyLoadError: "Failed to load history",
    historySource: "Source",
    historyDecision: "Decision",
    historyFindings: "Findings",
    historyTime: "Time",
  },
};

const form = document.getElementById("scanForm");
const inputMode = document.getElementById("inputMode");
const uiLanguage = document.getElementById("uiLanguage");
const reportLanguage = document.getElementById("reportLanguage");
const statusBadge = document.getElementById("statusBadge");
const resultEmpty = document.getElementById("resultEmpty");
const resultContent = document.getElementById("resultContent");
const historyList = document.getElementById("historyList");
const refreshHistoryButton = document.getElementById("refreshHistoryButton");
const downloadReportJsonButton = document.getElementById("downloadReportJson");
const downloadExplanationJsonButton = document.getElementById("downloadExplanationJson");
const downloadExplanationTextButton = document.getElementById("downloadExplanationText");

let currentScanId = null;
let currentPayload = null;

function activeUiLang() {
  const value = uiLanguage.value;
  if (value === "zh" || value === "en") {
    return value;
  }
  return (navigator.language || "").toLowerCase().startsWith("en") ? "en" : "zh";
}

function t(key) {
  const lang = activeUiLang();
  return UI_STRINGS[lang][key] || key;
}

function setStatus(kind) {
  statusBadge.textContent = t(`status${kind[0].toUpperCase()}${kind.slice(1)}`);
  statusBadge.dataset.state = kind;
}

function refreshUiText() {
  const lang = activeUiLang();
  const strings = UI_STRINGS[lang];
  for (const [id, key] of [
    ["title", "title"],
    ["subtitle", "subtitle"],
    ["scanFormTitle", "scanFormTitle"],
    ["uiLangLabel", "uiLangLabel"],
    ["reportLangLabel", "reportLangLabel"],
    ["inputModeLabel", "inputModeLabel"],
    ["archiveLabel", "archiveLabel"],
    ["directoryLabel", "directoryLabel"],
    ["directoryHint", "directoryHint"],
    ["urlLabel", "urlLabel"],
    ["pathLabel", "pathLabel"],
    ["dynamicLabel", "dynamicLabel"],
    ["submitButton", "submitButton"],
    ["resultTitle", "resultTitle"],
    ["emptyText", "emptyText"],
    ["headlineTitle", "headlineTitle"],
    ["findingTitle", "findingTitle"],
    ["flowTitle", "flowTitle"],
    ["actionTitle", "actionTitle"],
    ["textTitle", "textTitle"],
    ["jsonTitle", "jsonTitle"],
    ["historyTitle", "historyTitle"],
    ["historyHint", "historyHint"],
  ]) {
    document.getElementById(id).textContent = strings[key];
  }
  refreshHistoryButton.textContent = strings.refreshHistoryButton;
  downloadReportJsonButton.textContent = strings.downloadReportJson;
  downloadExplanationJsonButton.textContent = strings.downloadExplanationJson;
  downloadExplanationTextButton.textContent = strings.downloadExplanationText;
  const options = inputMode.options;
  options[0].text = strings.inputArchive;
  options[1].text = strings.inputDirectory;
  options[2].text = strings.inputUrl;
  options[3].text = strings.inputPath;
  setStatus(statusBadge.dataset.state || "idle");
  renderHistoryFromDomState();
}

function toggleModePanels() {
  const mode = inputMode.value;
  document.querySelectorAll("[data-mode-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.modePanel !== mode);
  });
}

function ensureInput(mode) {
  if (mode === "archive" && !document.getElementById("archiveFile").files.length) {
    throw new Error(t("missingArchive"));
  }
  if (mode === "directory" && !document.getElementById("directoryFile").files.length) {
    throw new Error(t("missingDirectory"));
  }
  if (mode === "url" && !document.getElementById("skillUrl").value.trim()) {
    throw new Error(t("missingUrl"));
  }
  if (mode === "path" && !document.getElementById("skillPath").value.trim()) {
    throw new Error(t("missingPath"));
  }
}

async function submitScan(event) {
  event.preventDefault();
  const mode = inputMode.value;
  try {
    ensureInput(mode);
    setStatus("running");
    const response = await sendRequest(mode);
    renderResult(response);
    renderHistory(response.history?.items || []);
    setStatus("done");
  } catch (error) {
    renderError(error);
    setStatus("error");
  }
}

async function sendRequest(mode) {
  const lang = reportLanguage.value;
  const dynamic = document.getElementById("dynamicMode").checked;
  if (mode === "archive" || mode === "directory") {
    const formData = new FormData();
    formData.append("input_mode", mode);
    formData.append("lang", lang);
    formData.append("dynamic", String(dynamic));
    if (mode === "archive") {
      const file = document.getElementById("archiveFile").files[0];
      formData.append("archive", file, file.name);
    } else {
      const files = Array.from(document.getElementById("directoryFile").files);
      for (const file of files) {
        const relativePath = file.webkitRelativePath || file.name;
        formData.append("files", file, relativePath);
      }
    }
    return fetchJson("/api/v1/scan/upload", { method: "POST", body: formData });
  }
  if (mode === "url") {
    return fetchJson("/api/v1/scan/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: document.getElementById("skillUrl").value.trim(),
        lang,
        dynamic,
      }),
    });
  }
  return fetchJson("/api/v1/scan/path", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      path: document.getElementById("skillPath").value.trim(),
      lang,
      dynamic,
    }),
  });
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) {
    const message = payload?.error?.message || t("apiError");
    throw new Error(message);
  }
  return payload;
}

function renderResult(payload) {
  currentPayload = payload;
  currentScanId = payload?.history?.item?.scan_id || currentScanId;
  updateDownloadButtons();
  resultEmpty.classList.add("hidden");
  resultContent.classList.remove("hidden");
  const explanation = payload.explanation || {};
  const report = payload.scan_report || {};

  document.getElementById("headlineText").textContent = explanation.headline || "";
  renderSummary(report);
  renderList("narrativeList", explanation.narrative || []);
  renderFindings(explanation.key_findings || []);
  renderFlows(explanation.key_flows || []);
  renderList("actionsList", explanation.recommended_actions || [], t("noActions"));
  document.getElementById("explanationText").textContent = payload.explanation_text || "";
  document.getElementById("rawJson").textContent = JSON.stringify(payload, null, 2);
}

function renderSummary(report) {
  const summary = report.summary || {};
  const scores = report.scores || {};
  const items = [
    [t("summaryTarget"), report.target || "-"],
    [t("summaryDecision"), report.decision || "-"],
    [t("summaryFindings"), String(summary.finding_count ?? 0)],
    [t("summaryOverall"), scores.overall || "-"],
    [t("summaryLanguage"), report.output_language || "-"],
  ];
  const container = document.getElementById("summaryGrid");
  container.innerHTML = "";
  for (const [label, value] of items) {
    const card = document.createElement("div");
    card.className = "summary-card";
    card.innerHTML = `<span class="summary-label">${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>`;
    container.appendChild(card);
  }
}

function renderFindings(items) {
  const container = document.getElementById("findingsList");
  container.innerHTML = "";
  if (!items.length) {
    container.innerHTML = `<p class="muted">${escapeHtml(t("noFindings"))}</p>`;
    return;
  }
  for (const item of items) {
    const block = document.createElement("article");
    block.className = "card";
    block.innerHTML = `
      <h4>${escapeHtml(item.taxonomy_id || "-")} · ${escapeHtml(item.title || "-")}</h4>
      <p><strong>${escapeHtml(t("findingWhy"))}:</strong> ${escapeHtml(item.why_it_matters || "-")}</p>
      <p><strong>${escapeHtml(t("findingRemediation"))}:</strong> ${escapeHtml(item.what_to_do || "-")}</p>
    `;
    container.appendChild(block);
  }
}

function renderFlows(items) {
  const container = document.getElementById("flowsList");
  container.innerHTML = "";
  if (!items.length) {
    container.innerHTML = `<p class="muted">${escapeHtml(t("noFlows"))}</p>`;
    return;
  }
  for (const item of items) {
    const source = item.source_node || {};
    const sink = item.sink_node || {};
    const route = `${source.capability_type || "?"}(${source.taxonomy_id || "-"}) → ${sink.capability_type || "?"}(${sink.taxonomy_id || "-"})`;
    const block = document.createElement("article");
    block.className = "card";
    block.innerHTML = `
      <h4>${escapeHtml(item.id || "-")}</h4>
      <p>${escapeHtml(item.summary || "-")}</p>
      <p><strong>${escapeHtml(t("flowTaxonomy"))}:</strong> ${escapeHtml((item.triggered_taxonomy_ids || []).join(", ") || "-")}</p>
      <p><strong>${escapeHtml(t("flowRoute"))}:</strong> ${escapeHtml(route)}</p>
    `;
    container.appendChild(block);
  }
}

function renderList(elementId, items, emptyText = "") {
  const container = document.getElementById(elementId);
  container.innerHTML = "";
  if (!items.length && emptyText) {
    const li = document.createElement("li");
    li.textContent = emptyText;
    container.appendChild(li);
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    container.appendChild(li);
  }
}

function renderError(error) {
  currentPayload = null;
  currentScanId = null;
  updateDownloadButtons();
  resultEmpty.classList.add("hidden");
  resultContent.classList.remove("hidden");
  document.getElementById("headlineText").textContent = error.message || t("apiError");
  document.getElementById("summaryGrid").innerHTML = "";
  renderList("narrativeList", []);
  renderFindings([]);
  renderFlows([]);
  renderList("actionsList", []);
  document.getElementById("explanationText").textContent = error.stack || String(error);
  document.getElementById("rawJson").textContent = JSON.stringify({ error: error.message }, null, 2);
}

async function loadHistory() {
  try {
    const payload = await fetchJson("/api/v1/history", { method: "GET" });
    renderHistory(payload.items || []);
  } catch (error) {
    historyList.innerHTML = `<p class="muted">${escapeHtml(`${t("historyLoadError")}: ${error.message}`)}</p>`;
  }
}

function renderHistory(items) {
  historyList.dataset.items = JSON.stringify(items);
  renderHistoryFromDomState();
}

function renderHistoryFromDomState() {
  const raw = historyList.dataset.items;
  const items = raw ? JSON.parse(raw) : [];
  historyList.innerHTML = "";
  if (!items.length) {
    historyList.innerHTML = `<p class="muted">${escapeHtml(t("noHistory"))}</p>`;
    return;
  }
  for (const item of items) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = `history-card${currentScanId === item.scan_id ? " active" : ""}`;
    card.innerHTML = `
      <span class="history-id">${escapeHtml(item.scan_id || "-")}</span>
      <strong>${escapeHtml(item.decision || "-")} · ${escapeHtml(item.overall || "-")}</strong>
      <span>${escapeHtml(t("historySource"))}: ${escapeHtml(item.source_hint || "-")}</span>
      <span>${escapeHtml(t("historyFindings"))}: ${escapeHtml(String(item.finding_count ?? 0))}</span>
      <span>${escapeHtml(t("historyTime"))}: ${escapeHtml(item.created_at || "-")}</span>
    `;
    card.addEventListener("click", () => loadHistoryItem(item.scan_id));
    historyList.appendChild(card);
  }
}

async function loadHistoryItem(scanId) {
  try {
    const payload = await fetchJson(`/api/v1/history/${encodeURIComponent(scanId)}`, { method: "GET" });
    currentScanId = scanId;
    renderResult(payload);
    renderHistoryFromDomState();
    setStatus("done");
  } catch (error) {
    renderError(error);
    setStatus("error");
  }
}

function updateDownloadButtons() {
  const disabled = !currentScanId;
  downloadReportJsonButton.disabled = disabled;
  downloadExplanationJsonButton.disabled = disabled;
  downloadExplanationTextButton.disabled = disabled;
}

function downloadArtifact(artifact, format) {
  if (!currentScanId) {
    return;
  }
  const url = `/api/v1/history/${encodeURIComponent(currentScanId)}/download?artifact=${encodeURIComponent(artifact)}&format=${encodeURIComponent(format)}`;
  window.open(url, "_blank", "noopener");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

uiLanguage.addEventListener("change", refreshUiText);
inputMode.addEventListener("change", toggleModePanels);
form.addEventListener("submit", submitScan);
refreshHistoryButton.addEventListener("click", loadHistory);
downloadReportJsonButton.addEventListener("click", () => downloadArtifact("scan_report", "json"));
downloadExplanationJsonButton.addEventListener("click", () => downloadArtifact("explanation", "json"));
downloadExplanationTextButton.addEventListener("click", () => downloadArtifact("explanation", "text"));

refreshUiText();
toggleModePanels();
setStatus("idle");
updateDownloadButtons();
loadHistory();
