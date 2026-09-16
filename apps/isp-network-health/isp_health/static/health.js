"use strict";

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
const setReportSections = (open) => {
  reportSections().forEach((section) => {
    section.open = open;
  });
};

document.querySelector("[data-report-expand]")?.addEventListener("click", () => setReportSections(true));
document.querySelector("[data-report-collapse]")?.addEventListener("click", () => setReportSections(false));
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
