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
