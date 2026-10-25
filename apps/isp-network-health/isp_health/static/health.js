"use strict";

const updateSuiteClocks = () => {
  const now = new Date();
  const parts = new Intl.DateTimeFormat("pt-BR", {
    weekday: "long", day: "2-digit", month: "long", year: "numeric",
    hour: "2-digit", minute: "2-digit", hour12: false,
  }).formatToParts(now).reduce((values, part) => ({ ...values, [part.type]: part.value }), {});
  const weekday = parts.weekday ? parts.weekday.charAt(0).toUpperCase() + parts.weekday.slice(1) : "";
  const label = `${weekday}, ${parts.day} de ${parts.month} de ${parts.year} - ${parts.hour}:${parts.minute}`;
  document.querySelectorAll("[data-suite-clock]").forEach((clock) => {
    clock.textContent = label;
    clock.dateTime = now.toISOString();
  });
};
updateSuiteClocks();
window.setInterval(updateSuiteClocks, 30000);

const touchSuitePresence = () => {
  if (document.body.dataset.healthAuthenticated !== "true") return;
  fetch("/api/presence", { credentials: "same-origin", cache: "no-store" }).catch(() => {});
};
touchSuitePresence();
window.setInterval(touchSuitePresence, 60000);

const localDateTimeFormatters = {
  date: new Intl.DateTimeFormat("pt-BR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", hour12: false,
  }),
  time: new Intl.DateTimeFormat("pt-BR", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }),
};

const formatLocalDateTime = (value, format = "date") => {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return (localDateTimeFormatters[format] || localDateTimeFormatters.date).format(date);
};

const updateBrowserDateTimes = () => {
  document.querySelectorAll("[data-local-datetime]").forEach((element) => {
    const value = element.dataset.localDatetime;
    if (!value) return;
    element.textContent = formatLocalDateTime(value, element.dataset.localFormat || "date");
  });
};
updateBrowserDateTimes();

const executionModal = document.querySelector("[data-execution-modal]");
const executionContent = executionModal?.querySelector("[data-execution-content]");
const executionTitle = executionModal?.querySelector("[data-execution-title]");
let activeExecutionSource = null;
const activeScanPollers = new Map();
const fragmentRequestOptions = { headers: { "X-Requested-With": "XMLHttpRequest", Accept: "text/html" }, cache: "no-store" };

const openCompletedReport = (liveScan) => {
  const reportUrl = liveScan?.dataset.reportUrl;
  if (!reportUrl || liveScan.dataset.reportOpened === "true") return;
  liveScan.dataset.reportOpened = "true";
  const reportWindow = window.open(reportUrl, "_blank", "noopener,noreferrer");
  if (!reportWindow) {
    const liveIndicator = liveScan.querySelector("[data-live-indicator]");
    if (liveIndicator) liveIndicator.textContent = "Concluída. Expanda a análise no histórico para abrir o relatório.";
  }
};

const closeExecutionModal = () => {
  if (!executionModal) return;
  const source = activeExecutionSource;
  executionModal.hidden = true;
  executionModal.setAttribute("aria-hidden", "true");
  source?.setAttribute?.("aria-expanded", "false");
  activeExecutionSource = null;
  source?.focus?.();
};

const openExecutionModal = (liveScan, title = "Acompanhamento da análise", source = null, extraContent = null) => {
  if (!executionModal || !executionContent || !liveScan) return;
  activeExecutionSource = source;
  executionTitle.textContent = title;
  liveScan.querySelector("[data-execution-background]")?.remove();
  executionContent.replaceChildren(liveScan);
  if (extraContent) executionContent.append(extraContent);
  executionModal.hidden = false;
  executionModal.removeAttribute("aria-hidden");
  executionModal.querySelector("[data-execution-background]:not(.execution-modal-backdrop)")?.focus();
  startLiveScan(liveScan);
};

const startLiveScan = (liveScan) => {
  if (!liveScan || liveScan.dataset.polling === "true") return;
  liveScan.dataset.polling = "true";
  const statusUrl = liveScan.dataset.statusUrl;
  const previousPoller = activeScanPollers.get(statusUrl);
  previousPoller?.stop();
  const progressBar = liveScan.querySelector("[data-progress-bar]");
  const progressPercent = liveScan.querySelector("[data-progress-percent]");
  const progressCount = liveScan.querySelector("[data-progress-count]");
  const progressEta = liveScan.querySelector("[data-progress-eta]");
  const progressElapsed = liveScan.querySelector("[data-progress-elapsed]");
  const progressTrack = liveScan.querySelector("[role=progressbar]");
  const eventList = liveScan.querySelector("[data-scan-events]");
  const liveIndicator = liveScan.querySelector("[data-live-indicator]");
  let lastEventSignature = "";
  let pollTimer = null;
  let stopped = false;

  const stopPolling = () => {
    stopped = true;
    if (pollTimer !== null) window.clearTimeout(pollTimer);
    pollTimer = null;
    liveScan.dataset.polling = "false";
    if (activeScanPollers.get(statusUrl)?.liveScan === liveScan) activeScanPollers.delete(statusUrl);
  };

  activeScanPollers.set(statusUrl, { liveScan, stop: stopPolling });

  const formatEventTime = (value) => formatLocalDateTime(value, "time");

  const renderEvents = (events) => {
    const safeEvents = Array.isArray(events) ? events : [];
    const signature = safeEvents.map((event) => `${event.id}:${event.message}:${event.created_at}`).join("|");
    if (signature === lastEventSignature) return;
    lastEventSignature = signature;
    eventList?.replaceChildren();
    if (!eventList) return;
    if (!safeEvents.length) {
      const empty = document.createElement("li");
      empty.className = "scan-event-empty";
      empty.textContent = "Aguardando o início do worker.";
      eventList.append(empty);
      return;
    }
    safeEvents.forEach((event) => {
      const item = document.createElement("li");
      const time = document.createElement("time");
      time.dataset.localDatetime = event.created_at || "";
      time.dataset.localFormat = "time";
      time.dateTime = event.created_at || "";
      time.textContent = formatEventTime(event.created_at);
      const message = document.createElement("span");
      message.textContent = event.message || "Atividade registrada.";
      item.append(time, message);
      eventList.append(item);
    });
    eventList.scrollTop = eventList.scrollHeight;
  };

  const renderScan = (scan) => {
    const percent = Math.max(0, Math.min(100, Number(scan.progress_percent) || 0));
    const completed = Number(scan.completed_checks) || 0;
    const total = Number(scan.total_checks) || 0;
    if (progressBar) progressBar.style.width = `${percent}%`;
    if (progressPercent) progressPercent.textContent = `${percent}%`;
    if (progressTrack) progressTrack.setAttribute("aria-valuenow", String(percent));
    if (progressCount) progressCount.textContent = total ? `${completed} de ${total} consultas concluídas` : "Preparando consultas…";
    if (progressEta) progressEta.textContent = scan.eta_label || "Calculando tempo restante";
    if (progressElapsed) progressElapsed.textContent = `Tempo decorrido: ${scan.elapsed_label || "0s"}`;
    renderEvents(scan.events);
  };

  const pollScan = async () => {
    if (stopped) return;
    try {
      const response = await fetch(statusUrl, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!response.ok) {
        if (response.status === 429) {
          if (liveIndicator) liveIndicator.textContent = "Atualização temporariamente limitada; nova tentativa em 15 segundos.";
          pollTimer = window.setTimeout(pollScan, 15000);
          return;
        }
        throw new Error(`HTTP ${response.status}`);
      }
      const scan = await response.json();
      renderScan(scan);
      if (["succeeded", "failed", "canceled"].includes(scan.status)) {
        stopPolling();
        if (scan.status === "succeeded") openCompletedReport(liveScan);
        window.setTimeout(() => window.location.reload(), 350);
        return;
      }
      if (liveIndicator) liveIndicator.textContent = `Atualizado às ${formatEventTime(new Date().toISOString())}`;
    } catch (_error) {
      if (liveIndicator) liveIndicator.textContent = "Reconectando…";
    }
    if (!stopped) pollTimer = window.setTimeout(pollScan, 2000);
  };

  if (eventList) eventList.scrollTop = eventList.scrollHeight;
  pollScan();
};

const initialLiveScan = document.querySelector("[data-scan-live]");
if (initialLiveScan) {
  const sourceReport = initialLiveScan.closest(".report-card");
  sourceReport?.setAttribute("data-live-report", "true");
  const sourceTitle = sourceReport?.querySelector(".report-heading h2")?.textContent?.trim() || "Acompanhamento da análise";
  openExecutionModal(initialLiveScan, sourceTitle, null, sourceReport?.querySelector(".detail-actions"));
}

document.querySelectorAll("[data-execution-background]").forEach((button) => {
  button.addEventListener("click", closeExecutionModal);
});

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-execution-background]")) closeExecutionModal();
});

executionModal?.addEventListener("click", (event) => {
  if (event.target === executionModal || event.target.closest("[data-execution-background].execution-modal-backdrop")) {
    closeExecutionModal();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && executionModal && !executionModal.hidden) closeExecutionModal();
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-delete-scan]");
  if (button) {
    const label = button.dataset.scanLabel || "esta análise";
    if (!window.confirm(`Excluir ${label}? Os resultados e eventos deste scan serão removidos.`)) {
      event.preventDefault();
    }
  }
});

document.querySelectorAll("[data-scan-toggle]").forEach((button) => {
  button.addEventListener("click", async () => {
    const preview = document.getElementById(button.getAttribute("aria-controls"));
    if (!preview) return;
    const entry = button.closest("[data-scan-entry]");
    const isLiveEntry = entry?.classList.contains("scan-history-entry-live");
    if (isLiveEntry) {
      if (executionModal && !executionModal.hidden) {
        closeExecutionModal();
        return;
      }
      button.setAttribute("aria-expanded", "true");
      try {
        const response = await fetch(button.dataset.scanUrl, fragmentRequestOptions);
        if (!response.ok) throw new Error("Execução indisponível");
        const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
        const live = parsed.querySelector("[data-scan-live]");
        if (!live) throw new Error("Execução indisponível");
        const title = parsed.querySelector(".report-heading h2")?.textContent?.trim() || entry.querySelector(".scan-target")?.textContent?.trim() || "Acompanhamento da análise";
        openExecutionModal(live.cloneNode(true), title, button, parsed.querySelector(".detail-actions")?.cloneNode(true));
      } catch (_error) {
        window.location.assign(button.dataset.scanUrl);
      }
      return;
    }
    const open = button.getAttribute("aria-expanded") !== "true";
    button.setAttribute("aria-expanded", String(open));
    if (!open && executionModal && !executionModal.hidden) {
      closeExecutionModal();
      return;
    }
    preview.hidden = !open;
    if (!open || preview.dataset.loaded) return;
    preview.textContent = "Carregando relatório…";
    try {
      const response = await fetch(button.dataset.scanUrl, fragmentRequestOptions);
      if (!response.ok) throw new Error("Relatório indisponível");
      const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
      const report = parsed.querySelector("#scan-report");
      if (!report) throw new Error("Relatório indisponível");
      report.removeAttribute("id");
      preview.replaceChildren(report);
      preview.dataset.loaded = "true";
      updateBrowserDateTimes();
    } catch (_error) {
      preview.textContent = "Não foi possível carregar o relatório. Recolha e expanda para tentar novamente.";
    }
  });
});

document.querySelectorAll("[data-scan-entry-live]").forEach((entry) => {
  entry.addEventListener("click", (event) => {
    if (event.target.closest("button,form,a")) return;
    entry.querySelector("[data-scan-toggle]")?.click();
  });
});


const appLauncher = document.querySelector("[data-app-launcher]");
if (appLauncher) {
  const trigger = appLauncher.querySelector("[data-launcher-trigger]");
  const search = appLauncher.querySelector("[data-launcher-search]");
  const items = [...appLauncher.querySelectorAll("[data-launcher-item]")];
  const empty = appLauncher.querySelector("[data-launcher-empty]");
  const filterApplications = () => {
    const query = search?.value.trim().toLocaleLowerCase("pt-BR") || "";
    let visible = 0;
    items.forEach((item) => {
      const matches = !query || (item.dataset.appLabel || "").toLocaleLowerCase("pt-BR").includes(query);
      item.hidden = !matches;
      if (matches) visible += 1;
    });
    if (empty) empty.hidden = visible > 0;
  };
  search?.addEventListener("input", filterApplications);
  appLauncher.querySelector("[data-launcher-close]")?.addEventListener("click", () => {
    appLauncher.removeAttribute("open");
    trigger?.focus();
  });
  appLauncher.addEventListener("toggle", () => {
    const open = appLauncher.open;
    trigger?.setAttribute("aria-expanded", String(open));
    if (open) window.requestAnimationFrame(() => search?.focus());
    else if (search) search.value = "";
    if (!open) filterApplications();
  });
  document.addEventListener("click", (event) => {
    if (!appLauncher.contains(event.target)) appLauncher.removeAttribute("open");
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && appLauncher.open) {
      appLauncher.removeAttribute("open");
      trigger?.focus();
    }
  });
}

const reportSections = () => [...document.querySelectorAll("details[data-report-section]")];

document.addEventListener("toggle", async (event) => {
  const section = event.target.closest?.("details[data-report-block]");
  if (!section || !section.open || section.dataset.blockLoaded === "true" || section.dataset.blockLoading === "true") return;
  const body = section.querySelector("[data-report-block-body]");
  if (!body) return;
  section.dataset.blockLoading = "true";
  body.innerHTML = '<p class="muted">Carregando endereços IP…</p>';
  try {
    const response = await fetch(section.dataset.blockUrl, { headers: { Accept: "text/html" }, cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    body.innerHTML = await response.text();
    section.dataset.blockLoaded = "true";
  } catch (_error) {
    body.innerHTML = '<p class="report-note report-note-error">Não foi possível carregar os endereços deste bloco. Feche e tente novamente.</p>';
  } finally {
    delete section.dataset.blockLoading;
  }
}, true);

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-report-expand],[data-report-collapse]");
  if (!button) return;
  const card = button.closest(".report-card");
  card?.querySelectorAll("details[data-report-section]").forEach((section) => {
    section.open = button.hasAttribute("data-report-expand");
  });
});
document.querySelector("[data-report-print]")?.addEventListener("click", () => window.print());

let printSectionState = [];
window.addEventListener("beforeprint", () => {
  const sections = reportSections();
  printSectionState = sections.map((section) => section.open);
  sections.forEach((section) => {
    section.open = true;
  });
});
window.addEventListener("afterprint", () => {
  reportSections().forEach((section, index) => {
    section.open = Boolean(printSectionState[index]);
  });
  printSectionState = [];
});
