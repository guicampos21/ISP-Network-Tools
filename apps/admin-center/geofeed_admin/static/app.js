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

document.querySelectorAll("form[data-confirm]").forEach((form) => form.addEventListener("submit", (event) => {
  if (!window.confirm(form.dataset.confirm || "Confirmar esta operação?")) event.preventDefault();
}));
document.querySelectorAll("button[data-confirm]").forEach((button) => button.addEventListener("click", (event) => {
  if (!window.confirm(button.dataset.confirm || "Confirmar esta operação?")) event.preventDefault();
}));

const changeReviewDialog = document.querySelector("[data-change-review-dialog]");
if (changeReviewDialog) {
  let pendingChangeForm = null;
  const reviewList = changeReviewDialog.querySelector("[data-change-review-list]");
  const reviewIntro = changeReviewDialog.querySelector("[data-change-review-intro]");
  const reviewPublication = changeReviewDialog.querySelector("[data-change-review-publication]");
  const confirmButton = changeReviewDialog.querySelector("[data-change-review-confirm]");
  const fieldNames = {company_id: "Empresa", asn: "ASN", description: "Descrição", active: "Status", alpha2code: "País", region: "Região", city: "Cidade", postal_code: "Código postal", cidr: "Bloco CIDR", filename: "Arquivo CSV", prefix: "Prefixo CIDR", sort_order: "Ordem"};
  const initialValue = (control) => {
    if (control.type === "checkbox") return control.defaultChecked;
    if (control instanceof HTMLSelectElement) return [...control.options].find((option) => option.defaultSelected)?.value ?? control.options[0]?.value ?? "";
    return control.defaultValue;
  };
  const readableValue = (control, value) => {
    if (control instanceof HTMLSelectElement) return [...control.options].find((option) => option.value === String(value))?.textContent?.trim() || value || "—";
    if (control.type === "checkbox") return value ? "Ativo" : "Inativo";
    return String(value || "").trim() || "—";
  };
  const fieldLabel = (control) => control.closest("label")?.querySelector("span")?.textContent?.replace(/\s*\*\s*$/, "").trim() || control.getAttribute("aria-label") || fieldNames[control.name] || control.name;
  const addReviewItem = (label, before, after) => {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt"); const detail = document.createElement("dd");
    term.textContent = label; detail.textContent = before === null ? after : `${before} → ${after}`;
    wrapper.append(term, detail); reviewList.append(wrapper);
  };
  const buildReview = (form) => {
    reviewList.replaceChildren();
    const isBulk = form.hasAttribute("data-bulk-form");
    const kind = form.dataset.changeKind || (form.querySelector('[name="entry_ids"]') ? "entradas" : form.querySelector('[name="block_ids"]') ? "blocos" : "registro");
    if (isBulk) {
      const selected = [...form.querySelectorAll("[data-select-item]:checked")];
      if (!selected.length) { window.alert("Selecione ao menos um item para revisar."); return false; }
      addReviewItem("Itens selecionados", null, `${selected.length} ${kind}`);
      const examples = selected.slice(0, 4).map((item) => item.getAttribute("aria-label")?.replace(/^Selecionar\s+/, "") || item.value);
      addReviewItem("Seleção", null, examples.join(", ") + (selected.length > examples.length ? ` e mais ${selected.length - examples.length}` : ""));
      const enabledFields = new Set([...form.querySelectorAll('input[name="fields"]:checked')].map((control) => control.value));
      [...form.elements].filter((control) => control.name && !["csrf_token", "confirm_changes", "block_ids", "entry_ids", "notes", "fields"].includes(control.name) && !control.disabled).forEach((control) => {
        if (enabledFields.size && !enabledFields.has(control.name)) return;
        if (String(control.value).trim()) addReviewItem(fieldLabel(control), null, readableValue(control, control.value));
      });
    } else {
      [...form.elements].filter((control) => control.name && !["csrf_token", "confirm_changes", "notes"].includes(control.name) && !control.disabled && !["submit", "button", "file"].includes(control.type)).forEach((control) => {
        const initial = initialValue(control); const current = control.type === "checkbox" ? control.checked : control.value;
        if (String(initial) === String(current)) return;
        addReviewItem(fieldLabel(control), readableValue(control, initial), readableValue(control, current));
      });
    }
    if (!reviewList.children.length) addReviewItem("Resultado", null, "Nenhuma alteração identificada");
    reviewIntro.textContent = `Confira o resumo da alteração em ${kind} antes de prosseguir.`;
    const isEditor = changeReviewDialog.dataset.currentRole === "editor";
    const action = form.dataset.changeAction || (isEditor ? "Enviar para aprovação" : "Confirmar e publicar");
    confirmButton.textContent = action;
    reviewPublication.textContent = isEditor ? "Após confirmar, a alteração será enviada para análise de outro administrador." : "Após confirmar, os arquivos públicos serão atualizados e o monitoramento será executado.";
    return true;
  };
  document.querySelectorAll("form[data-change-review],form[data-bulk-form]").forEach((form) => form.addEventListener("submit", (event) => {
    let confirmation = form.querySelector('input[name="confirm_changes"]');
    if (!confirmation) { confirmation = document.createElement("input"); confirmation.type = "hidden"; confirmation.name = "confirm_changes"; form.append(confirmation); }
    if (confirmation.value === "yes") return;
    event.preventDefault();
    if (!buildReview(form)) return;
    pendingChangeForm = form;
    if (changeReviewDialog.showModal) changeReviewDialog.showModal(); else changeReviewDialog.setAttribute("open", "");
  }));
  confirmButton?.addEventListener("click", () => {
    if (!pendingChangeForm) return;
    pendingChangeForm.querySelector('input[name="confirm_changes"]').value = "yes";
    changeReviewDialog.close();
    pendingChangeForm.requestSubmit();
  });
  changeReviewDialog.querySelectorAll("[data-change-review-cancel]").forEach((button) => button.addEventListener("click", () => { pendingChangeForm = null; changeReviewDialog.close(); }));
  changeReviewDialog.addEventListener("click", (event) => { if (event.target === changeReviewDialog) { pendingChangeForm = null; changeReviewDialog.close(); } });
}

const navButton = document.querySelector("[data-nav-toggle]");
const nav = document.querySelector("[data-nav]");
if (navButton && nav) navButton.addEventListener("click", () => {
  const open = nav.classList.toggle("is-open");
  navButton.setAttribute("aria-expanded", String(open));
});
const appSidebar = document.querySelector("[data-app-sidebar]");
const appSidebarOpen = document.querySelector("[data-app-sidebar-open]");
const appSidebarClose = document.querySelector("[data-app-sidebar-close]");
const setAppSidebar = (open) => {
  if (!appSidebar) return;
  appSidebar.classList.toggle("is-open", open);
  appSidebarOpen?.setAttribute("aria-expanded", String(open));
};
appSidebarOpen?.addEventListener("click", () => setAppSidebar(true));
appSidebarClose?.addEventListener("click", () => setAppSidebar(false));
document.addEventListener("click", (event) => {
  if (appSidebar?.classList.contains("is-open") && !event.target.closest("[data-app-sidebar],[data-app-sidebar-open]")) setAppSidebar(false);
});
const appLauncher = document.querySelector("[data-app-launcher]");
if (appLauncher) {
  const trigger = appLauncher.querySelector("[data-launcher-trigger]");
  const search = appLauncher.querySelector("[data-launcher-search]");
  const items = [...appLauncher.querySelectorAll("[data-launcher-item]")];
  const empty = appLauncher.querySelector("[data-launcher-empty]");
  const resetSearch = () => {
    if (search) search.value = "";
    items.forEach((item) => { item.hidden = false; });
    if (empty) empty.hidden = true;
  };
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
    else resetSearch();
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
document.querySelectorAll("[data-rfc-toggle]").forEach((toggle) => {
  const popover = document.getElementById(toggle.getAttribute("aria-controls"));
  if (!popover) return;
  const close = () => { popover.hidden = true; toggle.setAttribute("aria-expanded", "false"); };
  toggle.addEventListener("click", () => {
    const open = popover.hidden;
    document.querySelectorAll("[data-rfc-popover]").forEach((item) => { item.hidden = true; });
    document.querySelectorAll("[data-rfc-toggle]").forEach((item) => { item.setAttribute("aria-expanded", "false"); });
    popover.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
  });
  popover.querySelector("[data-rfc-close]")?.addEventListener("click", () => { close(); toggle.focus(); });
  document.addEventListener("click", (event) => { if (!popover.contains(event.target) && event.target !== toggle) close(); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !popover.hidden) { close(); toggle.focus(); } });
});
document.querySelectorAll("select[data-auto-submit]").forEach((select) => select.addEventListener("change", () => select.form.submit()));
const accessSchedule = document.querySelector("[data-access-schedule]");
if (accessSchedule) {
  const list = accessSchedule.querySelector("[data-window-list]");
  const template = accessSchedule.querySelector("[data-window-template]");
  const count = accessSchedule.querySelector("[data-window-count]");
  const alwaysOpen = accessSchedule.querySelector("[data-access-24h]");
  const addWindow = accessSchedule.querySelector("[data-add-window]");
  const renumberWindows = () => {
    const rows = [...(list?.querySelectorAll("[data-access-window]") || [])];
    rows.forEach((row, index) => {
      const title = row.querySelector(".window-heading strong");
      if (title) title.textContent = `Janela ${index + 1}`;
      row.querySelectorAll("input[type=checkbox]").forEach((input) => { input.name = `window_${index}_days`; if (!input.value) input.value = input.dataset.dayValue || ""; });
      const times = row.querySelectorAll("input[type=time]");
      if (times[0]) times[0].name = `window_${index}_start`;
      if (times[1]) times[1].name = `window_${index}_end`;
    });
    if (count) count.value = String(rows.length);
    return rows;
  };
  const removeWindow = (row) => { row.remove(); renumberWindows(); };
  const bindRow = (row) => row.querySelector("[data-remove-window]")?.addEventListener("click", () => removeWindow(row));
  list?.querySelectorAll("[data-access-window]").forEach(bindRow);
  addWindow?.addEventListener("click", () => {
    if (!template || alwaysOpen?.checked) return;
    const row = template.content.cloneNode(true).firstElementChild;
    list.append(row); bindRow(row); renumberWindows();
  });
  alwaysOpen?.addEventListener("change", () => {
    if (alwaysOpen.checked) { list.replaceChildren(); if (count) count.value = "0"; if (addWindow) addWindow.disabled = true; }
    else if (addWindow) addWindow.disabled = false;
  });
  renumberWindows();
  if (alwaysOpen?.checked && addWindow) addWindow.disabled = true;
}
document.querySelectorAll("[data-select-all]").forEach((master) => master.addEventListener("change", () => {
  const form = master.closest("form");
  form?.querySelectorAll("[data-select-item]").forEach((item) => { item.checked = master.checked; });
}));
document.querySelectorAll("[data-dismiss-suggestion]").forEach((button) => button.addEventListener("click", () => {
  button.closest("[data-subnet-suggestion]")?.remove();
}));
const firstName = document.querySelector("[name=first_name]");
const lastName = document.querySelector("[name=last_name]");
const displayName = document.querySelector("[name=display_name]");
if (firstName && lastName && displayName) {
  let displayEdited = Boolean(displayName.value);
  displayName.addEventListener("input", () => { displayEdited = true; });
  const updateDisplayName = () => { if (!displayEdited) displayName.value = [firstName.value, lastName.value].filter(Boolean).join(" "); };
  firstName.addEventListener("input", updateDisplayName);
  lastName.addEventListener("input", updateDisplayName);
  updateDisplayName();
}
document.querySelectorAll("[data-logo-drop]").forEach((drop) => {
  const input = drop.querySelector("input[type=file]");
  ["dragenter", "dragover"].forEach((eventName) => drop.addEventListener(eventName, (event) => { event.preventDefault(); drop.classList.add("is-dragging"); }));
  ["dragleave", "drop"].forEach((eventName) => drop.addEventListener(eventName, (event) => { event.preventDefault(); drop.classList.remove("is-dragging"); }));
  drop.addEventListener("drop", (event) => { if (input && event.dataTransfer.files.length) input.files = event.dataTransfer.files; });
});
const authType = document.querySelector("[data-auth-type]");
const localPasswordFields = document.querySelector("[data-local-passwords]");
const authUsernameField = document.querySelector("[data-auth-username]");
if (authType) {
  const updateLocalFields = () => {
    const isLocal = authType.value === "local";
    if (localPasswordFields) {
      localPasswordFields.hidden = !isLocal;
      localPasswordFields.querySelectorAll("input").forEach((input) => { input.disabled = !isLocal; });
    }
    if (authUsernameField) {
      authUsernameField.hidden = !isLocal;
      const input = authUsernameField.querySelector("input");
      if (input) { input.disabled = !isLocal; input.required = isLocal; }
    }
  };
  authType.addEventListener("change", updateLocalFields); updateLocalFields();
}
const dicebearSeed = () => `avatar-${window.crypto?.randomUUID?.() || Math.random().toString(36).slice(2)}`;
const dicebearDefault = () => ({type: "custom", style: "avataaars", seed: dicebearSeed(), options: {}});
const dicebearLabels = {accessoriesVariant: "Acessórios", accessoriesColor: "Cor dos acessórios", beardVariant: "Barba", clothesVariant: "Roupas", clothesColor: "Cor da roupa", clothesGraphicVariant: "Estampa", detailsVariant: "Detalhes", earringsVariant: "Brincos", eyebrowsVariant: "Sobrancelhas", eyesVariant: "Olhos", glassesVariant: "Óculos", hairVariant: "Cabelo", hairColor: "Cor do cabelo", headVariant: "Formato da cabeça", mouthVariant: "Boca", moustacheVariant: "Bigode", noseVariant: "Nariz", skinColor: "Tom de pele", topVariant: "Cabelo / topo", backgroundColor: "Cor de fundo", borderRadius: "Formato"};
const dicebearColor = (value) => `#${String(value).replace(/^#/, "")}`;
const dicebearSafeConfig = (raw, catalog) => {
  const fallback = dicebearDefault(); const source = raw && typeof raw === "object" ? raw : fallback; const style = catalog[source.style] ? source.style : fallback.style; const styleData = catalog[style]; const options = {};
  Object.entries({...styleData.components, ...styleData.colors}).forEach(([key, choices]) => { const value = source.options?.[key]; const selected = Array.isArray(value) ? value[0] : value; if (choices.includes(selected)) options[key] = [selected]; });
  if (source.options?.backgroundColor) options.backgroundColor = [String(source.options.backgroundColor).replace(/^#/, "").slice(0, 6)];
  const radius = Number(source.options?.borderRadius); if (Number.isInteger(radius) && radius >= 0 && radius <= 50) options.borderRadius = radius;
  return {type: source.type === "preset" ? "preset" : "custom", style, seed: /^[A-Za-z0-9_-]{1,80}$/.test(String(source.seed || "")) ? String(source.seed) : fallback.seed, options};
};
document.querySelectorAll("[data-avatar-picker]").forEach((picker) => {
  const catalog = JSON.parse(picker.dataset.dicebearCatalog || "{}"); const dialog = picker.querySelector("[data-avatar-dialog]"); const preview = picker.querySelector("[data-avatar-preview]"); const kind = picker.querySelector("[data-avatar-kind]"); const configField = picker.querySelector("[data-avatar-config]"); const upload = picker.querySelector("[data-avatar-upload]"); const photoPreview = picker.querySelector("[data-photo-preview]"); let draft = dicebearDefault(); let currentObjectUrl = ""; let committedKind = kind.value; let committedConfig = configField.value || "{}";
  const loadCommittedDraft = () => { try { const saved = JSON.parse(committedConfig || "{}"); draft = saved.type === "preset" || saved.type === "custom" ? dicebearSafeConfig(saved, catalog) : dicebearDefault(); } catch (_) { draft = dicebearDefault(); } };
  loadCommittedDraft();
  const setImage = (target, src, alt) => { target.replaceChildren(Object.assign(document.createElement("img"), {src, alt})); };
  const previewDicebear = async (target, config) => { if (!target) return; target.setAttribute("aria-busy", "true"); try { const response = await fetch(`/avatars/dicebear-preview?config=${encodeURIComponent(JSON.stringify(config))}`, {credentials: "same-origin"}); if (!response.ok) return; const url = URL.createObjectURL(await response.blob()); const old = target.dataset.objectUrl; if (old) URL.revokeObjectURL(old); target.dataset.objectUrl = url; setImage(target, url, "Pré-visualização do avatar DiceBear"); } finally { target.removeAttribute("aria-busy"); } };
  const renderDraft = () => { configField.value = JSON.stringify(draft); const target = picker.querySelector("[data-dicebear-preview]"); const customTarget = picker.querySelector("[data-dicebear-custom-preview]"); if (target) previewDicebear(target, draft); if (customTarget) previewDicebear(customTarget, draft); };
  const selected = (key, value) => { const selectedValue = draft.options?.[key]; return String(Array.isArray(selectedValue) ? selectedValue[0] : selectedValue) === String(value); };
  const makeOptionButton = (key, value, color = false) => { const button = document.createElement("button"); button.type = "button"; button.className = `dicebear-option${selected(key, value) ? " is-selected" : ""}`; button.dataset.dicebearOption = key; button.dataset.dicebearValue = value; button.setAttribute("aria-pressed", String(selected(key, value))); if (color) { const swatch = document.createElement("span"); swatch.className = "dicebear-swatch"; swatch.style.background = dicebearColor(value); button.append(swatch); } const label = document.createElement("small"); label.textContent = value; button.append(label); button.addEventListener("click", () => { draft.options[key] = key === "borderRadius" ? Number(value) : [value]; renderControls(); renderDraft(); }); return button; };
  const renderControls = () => { const controls = picker.querySelector("[data-dicebear-controls]"); if (!controls) return; controls.replaceChildren(); const styleData = catalog[draft.style]; Object.entries(styleData.components).forEach(([key, values]) => { const field = document.createElement("fieldset"); const legend = document.createElement("legend"); legend.textContent = dicebearLabels[key] || key.replace(/Variant$/, ""); field.append(legend); const grid = document.createElement("div"); grid.className = "dicebear-choice-grid"; values.slice(0, 18).forEach((value) => grid.append(makeOptionButton(key, value))); field.append(grid); controls.append(field); }); Object.entries(styleData.colors).forEach(([key, values]) => { const field = document.createElement("fieldset"); const legend = document.createElement("legend"); legend.textContent = dicebearLabels[key] || key.replace(/Color$/, ""); field.append(legend); const grid = document.createElement("div"); grid.className = "dicebear-choice-grid"; values.slice(0, 18).forEach((value) => grid.append(makeOptionButton(key, value, true))); field.append(grid); controls.append(field); }); const shapeField = document.createElement("fieldset"); const shapeLegend = document.createElement("legend"); shapeLegend.textContent = "Formato"; shapeField.append(shapeLegend); const shapeGrid = document.createElement("div"); shapeGrid.className = "dicebear-choice-grid"; [["0", "Quadrado"], ["18", "Arredondado"], ["35", "Pílula"], ["50", "Circular"]].forEach(([value, label]) => { const button = makeOptionButton("borderRadius", value); button.querySelector("small").textContent = label; shapeGrid.append(button); }); shapeField.append(shapeGrid); controls.append(shapeField); const field = document.createElement("fieldset"); const legend = document.createElement("legend"); legend.textContent = "Cor de fundo"; field.append(legend); const grid = document.createElement("div"); grid.className = "dicebear-choice-grid"; ["b6e3f4", "e1d7f5", "ffd5dc", "c0ebd7", "f5f3f7", "1b1724"].forEach((value) => grid.append(makeOptionButton("backgroundColor", value, true))); field.append(grid); controls.append(field); };
  const renderStyles = (container) => { if (!container) return; container.replaceChildren(); Object.entries(catalog).forEach(([style, data]) => { const button = document.createElement("button"); button.type = "button"; button.className = `dicebear-style-tab${draft.style === style ? " is-selected" : ""}`; button.setAttribute("aria-selected", String(draft.style === style)); const name = document.createElement("strong"); name.textContent = data.label; const license = document.createElement("small"); license.textContent = data.license; button.append(name, license); button.addEventListener("click", () => { draft.style = style; draft.options = {}; renderStyles(picker.querySelector("[data-dicebear-style-tabs]")); renderStyles(picker.querySelector("[data-dicebear-custom-tabs]")); renderControls(); renderDraft(); }); container.append(button); }); };
  const renderPresetGallery = () => { const gallery = picker.querySelector("[data-dicebear-gallery]"); if (!gallery) return; gallery.replaceChildren(); Object.entries(catalog).forEach(([style, data]) => { ["01", "02", "03"].forEach((suffix) => { const button = document.createElement("button"); button.type = "button"; button.className = "dicebear-preset-card"; button.dataset.style = style; const image = document.createElement("div"); image.className = "dicebear-preset-image"; const label = document.createElement("strong"); label.textContent = data.label; const license = document.createElement("small"); license.textContent = data.attribution; button.append(image, label, license); const config = {type: "preset", style, seed: `gallery-${style}-${suffix}`, options: {}}; previewDicebear(image, config); button.addEventListener("click", () => { draft = config; configField.value = JSON.stringify(draft); gallery.querySelectorAll(".dicebear-preset-card").forEach((item) => item.classList.toggle("is-selected", item === button)); previewDicebear(picker.querySelector("[data-dicebear-preview]"), draft); }); gallery.append(button); }); }); };
  const selectMode = (mode) => { picker.querySelectorAll("[data-avatar-mode]").forEach((button) => { const active = button.dataset.avatarMode === mode; button.classList.toggle("is-active", active); button.setAttribute("aria-selected", String(active)); }); picker.querySelectorAll("[data-avatar-mode-panel]").forEach((panel) => { panel.hidden = panel.dataset.avatarModePanel !== mode; }); if (mode !== "photo") { renderStyles(picker.querySelector("[data-dicebear-style-tabs]")); renderStyles(picker.querySelector("[data-dicebear-custom-tabs]")); renderControls(); renderDraft(); if (mode === "preset") renderPresetGallery(); } };
  picker.querySelector("[data-avatar-open]")?.addEventListener("click", () => { committedKind = kind.value; committedConfig = configField.value || "{}"; loadCommittedDraft(); selectMode(kind.value === "photo" ? "photo" : kind.value === "custom" ? "custom" : "preset"); if (dialog?.showModal) dialog.showModal(); else dialog?.setAttribute("open", ""); });
  picker.querySelectorAll("[data-avatar-mode]").forEach((button) => button.addEventListener("click", () => selectMode(button.dataset.avatarMode)));
  picker.querySelectorAll("[data-avatar-apply]").forEach((button) => button.addEventListener("click", () => { kind.value = button.closest('[data-avatar-mode-panel]').dataset.avatarModePanel; draft.type = kind.value; configField.value = JSON.stringify(draft); committedKind = kind.value; committedConfig = configField.value; previewDicebear(preview, draft); dialog?.close(); }));
  picker.querySelectorAll("[data-dicebear-random]").forEach((button) => button.addEventListener("click", () => { draft.seed = dicebearSeed(); renderDraft(); }));
  picker.querySelector("[data-dicebear-reset]")?.addEventListener("click", () => { draft = dicebearDefault(); renderStyles(picker.querySelector("[data-dicebear-custom-tabs]")); renderControls(); renderDraft(); });
  const restoreCommitted = () => { kind.value = committedKind; configField.value = committedConfig; if (upload) upload.value = ""; if (photoPreview) photoPreview.hidden = true; };
  picker.querySelector("[data-avatar-cancel]")?.addEventListener("click", () => { restoreCommitted(); dialog?.close(); }); picker.querySelector("[data-avatar-close]")?.addEventListener("click", () => { restoreCommitted(); dialog?.close(); }); dialog?.addEventListener("click", (event) => { if (event.target === dialog) { restoreCommitted(); dialog.close(); } });
  picker.querySelector("[data-avatar-remove]")?.addEventListener("click", () => { if (!window.confirm("Remover o avatar atual e usar as iniciais?")) return; kind.value = "initials"; configField.value = JSON.stringify({}); committedKind = kind.value; committedConfig = configField.value; preview.replaceChildren(Object.assign(document.createElement("span"), {textContent: "A"})); dialog?.close(); });
  upload?.addEventListener("change", (event) => { const file = event.target.files?.[0]; if (!file) return; if (kind.value === "photo" && !window.confirm("Substituir a foto atual?")) { upload.value = ""; return; } if (!file.type.startsWith("image/") || file.size > 2 * 1024 * 1024) { window.alert("A foto deve ser JPG, PNG ou WEBP e ter no máximo 2 MB."); upload.value = ""; return; } const image = new Image(); image.onload = () => { const size = Math.min(image.naturalWidth, image.naturalHeight); const canvas = document.createElement("canvas"); canvas.width = 512; canvas.height = 512; canvas.getContext("2d").drawImage(image, (image.naturalWidth - size) / 2, (image.naturalHeight - size) / 2, size, size, 0, 0, 512, 512); canvas.toBlob((blob) => { const cropped = new File([blob], "avatar.jpg", {type: "image/jpeg"}); const transfer = new DataTransfer(); transfer.items.add(cropped); upload.files = transfer.files; if (currentObjectUrl) URL.revokeObjectURL(currentObjectUrl); currentObjectUrl = URL.createObjectURL(blob); photoPreview.hidden = false; setImage(photoPreview.querySelector("img"), currentObjectUrl, "Pré-visualização da foto recortada"); kind.value = "photo"; configField.value = JSON.stringify({}); }); }; image.src = URL.createObjectURL(file); });
  picker.querySelector("[data-photo-cancel]")?.addEventListener("click", () => { upload.value = ""; photoPreview.hidden = true; kind.value = committedKind; configField.value = committedConfig; });
});
document.querySelectorAll(".account-menu").forEach((menu) => document.addEventListener("click", (event) => { if (!event.target.closest(".account-menu")) menu.removeAttribute("open"); }));
const settingsSections = document.querySelectorAll("[data-settings-section]");
const settingsPanels = document.querySelectorAll("[data-settings-panel]");
const settingsSectionField = document.querySelector("[data-settings-section-field]");
const settingsTabField = document.querySelector("[data-settings-tab-field]");
const emailSettingsPanel = document.querySelector('[data-settings-panel="email"]');
const senderSettingsFields = document.querySelector("[data-email-sender-fields]");
const legacySenderFieldset = document.querySelector("input[name=smtp_from]")?.closest("fieldset");
if (emailSettingsPanel && senderSettingsFields) {
  emailSettingsPanel.insertBefore(senderSettingsFields, legacySenderFieldset || emailSettingsPanel.querySelector(".email-test-box"));
  senderSettingsFields.hidden = false;
  if (legacySenderFieldset) legacySenderFieldset.hidden = true;
}
if (settingsSections.length && settingsPanels.length) {
  const selectSettingsSection = (name) => {
    settingsSections.forEach((button) => { const active = button.dataset.settingsSection === name; button.setAttribute("aria-selected", String(active)); });
    settingsPanels.forEach((panel) => { panel.hidden = panel.dataset.settingsPanel !== name; });
    if (settingsSectionField) settingsSectionField.value = name;
    if (settingsTabField) {
      const activeTab = document.querySelector(`[data-${name === "access" ? "access" : name === "general" ? "general" : "auth"}-tab][aria-selected="true"]`);
      settingsTabField.value = ["access", "general", "auth"].includes(name) ? (activeTab?.dataset[`${name}Tab`] || "") : "";
    }
  };
  settingsSections.forEach((button) => button.addEventListener("click", () => selectSettingsSection(button.dataset.settingsSection)));
  selectSettingsSection(new URLSearchParams(window.location.search).get("section") || "auth");
}
const accessTabs = document.querySelectorAll("[data-access-tab]");
const accessPanels = document.querySelectorAll("[data-access-panel]");
if (accessTabs.length && accessPanels.length) {
  const selectAccessTab = (name) => {
    accessTabs.forEach((button) => button.setAttribute("aria-selected", String(button.dataset.accessTab === name)));
    accessPanels.forEach((panel) => { panel.hidden = panel.dataset.accessPanel !== name; });
    if (settingsTabField && settingsSectionField?.value === "access") settingsTabField.value = name;
  };
  accessTabs.forEach((button) => button.addEventListener("click", () => selectAccessTab(button.dataset.accessTab)));
  selectAccessTab(new URLSearchParams(window.location.search).get("tab") || "users");
}
const authTabs = document.querySelectorAll("[data-auth-tab]");
const authPanels = document.querySelectorAll("[data-auth-panel]");
if (authTabs.length && authPanels.length) {
  const selectAuthTab = (name) => {
    authTabs.forEach((button) => button.setAttribute("aria-selected", String(button.dataset.authTab === name)));
    authPanels.forEach((panel) => { panel.hidden = panel.dataset.authPanel !== name; });
    if (settingsTabField && settingsSectionField?.value === "auth") settingsTabField.value = name;
  };
  authTabs.forEach((button) => button.addEventListener("click", () => selectAuthTab(button.dataset.authTab)));
  selectAuthTab(new URLSearchParams(window.location.search).get("tab") || "m365");
}
const generalTabs = document.querySelectorAll("[data-general-tab]");
const generalPanels = document.querySelectorAll("[data-general-panel]");
if (generalTabs.length && generalPanels.length) {
  const selectGeneralTab = (name) => {
    generalTabs.forEach((button) => button.setAttribute("aria-selected", String(button.dataset.generalTab === name)));
    generalPanels.forEach((panel) => { panel.hidden = panel.dataset.generalPanel !== name; });
    if (settingsTabField && settingsSectionField?.value === "general") settingsTabField.value = name;
  };
  generalTabs.forEach((button) => button.addEventListener("click", () => selectGeneralTab(button.dataset.generalTab)));
  selectGeneralTab(new URLSearchParams(window.location.search).get("tab") || "preferences");
}
const procedureDialog = document.querySelector("[data-procedure-dialog]");
const procedureTitle = procedureDialog?.querySelector("[data-procedure-title]");
const procedureContent = procedureDialog?.querySelector("[data-procedure-content]");
const providerDiagram = (provider, accent, steps) => `<div class="procedure-content provider-procedure"><div class="provider-banner" style="--provider-accent:${accent}"><strong>${provider}</strong><span>Configuração no provedor de identidade</span></div><svg class="procedure-diagram" viewBox="0 0 900 150" role="img" aria-label="Fluxo de configuração"><path d="M125 76h170M365 76h170M605 76h170" stroke="${accent}" stroke-width="4" stroke-linecap="round"/><g fill="#181220" stroke="${accent}" stroke-width="2"><rect x="25" y="35" width="200" height="82" rx="12"/><rect x="265" y="35" width="200" height="82" rx="12"/><rect x="505" y="35" width="200" height="82" rx="12"/><rect x="745" y="35" width="130" height="82" rx="12"/></g><g fill="#f4edf9" font-family="Arial" text-anchor="middle"><text x="125" y="68" font-size="15">1. Criar aplicativo</text><text x="125" y="91" font-size="12">Registro OAuth/OIDC</text><text x="365" y="68" font-size="15">2. Redirecionamento</text><text x="365" y="91" font-size="12">Callback HTTPS</text><text x="605" y="68" font-size="15">3. Permissões</text><text x="605" y="91" font-size="12">Perfil e e-mail</text><text x="810" y="68" font-size="15">4. Copiar</text><text x="810" y="91" font-size="12">IDs e segredo</text></g></svg><ol>${steps.map((step) => `<li>${step}</li>`).join("")}</ol><p class="muted">O segundo fator continua sob responsabilidade do ${provider}. O portal nunca recebe a senha do usuário.</p></div>`;
const procedures = {
  m365: {title: "Microsoft 365 · Microsoft Entra ID", html: providerDiagram("Microsoft 365", "#6f2dbd", ["Abra <strong>Microsoft Entra admin center → Applications → App registrations → New registration</strong>.", "Defina o nome, selecione <strong>Accounts in this organizational directory only</strong> e registre. Copie o <strong>Directory (tenant) ID</strong> e o <strong>Application (client) ID</strong>.", "Em <strong>Authentication → Add a platform → Web</strong>, inclua exatamente <code>https://admin.example.com/auth/callback</code> e mantenha os fluxos de código de autorização habilitados.", "Em <strong>Certificates & secrets → New client secret</strong>, escolha a validade, copie o campo <strong>Value</strong> imediatamente e guarde-o no cofre. Ele não será exibido novamente.", "Em <strong>API permissions → Microsoft Graph → Delegated permissions</strong>, confirme <code>openid</code>, <code>profile</code>, <code>email</code> e <code>User.Read</code> para sincronizar nome e foto. Conceda consentimento administrativo se solicitado.", "Retorne ao portal, informe os três valores, habilite o método e salve. Teste em uma janela anônima antes de restringir o acesso aos usuários autorizados."])},
  google: {title: "Google Workspace · Google Cloud", html: providerDiagram("Google Workspace", "#4285f4", ["Abra o <strong>Google Cloud Console</strong>, selecione ou crie um projeto e configure <strong>APIs & Services → OAuth consent screen</strong>. Para usuários do domínio, prefira <strong>Internal</strong>.", "Em <strong>Credentials → Create credentials → OAuth client ID</strong>, escolha <strong>Web application</strong> e dê um nome identificável.", "Em <strong>Authorized redirect URIs</strong>, inclua exatamente <code>https://admin.example.com/auth/google/callback</code>. Não use HTTP nem uma URL com barra adicional.", "Copie o <strong>Client ID</strong> e o <strong>Client Secret</strong>. Se a aplicação estiver em teste, confira os usuários de teste e os escopos publicados.", "No <strong>Admin Console → Security → Access and data control → API controls</strong>, autorize o Client ID caso a política do Workspace bloqueie apps não confiáveis.", "Retorne ao portal, informe os valores, habilite o método e salve. Valide o login com uma conta do domínio e confirme o redirecionamento HTTPS."]) }
};
document.querySelectorAll("[data-provider-procedure]").forEach((button) => button.addEventListener("click", () => {
  const procedure = procedures[button.dataset.providerProcedure];
  if (!procedure || !procedureDialog) return;
  procedureTitle.textContent = procedure.title; procedureContent.innerHTML = procedure.html;
  if (procedureDialog.showModal) procedureDialog.showModal(); else procedureDialog.setAttribute("open", "");
}));
document.querySelector("[data-procedure-close]")?.addEventListener("click", () => procedureDialog?.close());
procedureDialog?.addEventListener("click", (event) => { if (event.target === procedureDialog) procedureDialog.close(); });
const timezoneSelect = document.querySelector("[data-timezone]");
const timeDisplay = document.querySelector("[data-time-display]");
if (timezoneSelect && timeDisplay) {
  const updateTime = () => { try { timeDisplay.textContent = new Intl.DateTimeFormat("pt-BR", {timeZone: timezoneSelect.value, dateStyle: "full", timeStyle: "medium"}).format(new Date()); } catch (_) { timeDisplay.textContent = "Fuso inválido"; } };
  timezoneSelect.addEventListener("change", updateTime); updateTime(); window.setInterval(updateTime, 1000);
}
const emailProvider = document.querySelector("[data-email-provider]");
const emailHost = document.querySelector("[data-email-host]");
const emailPort = document.querySelector("[data-email-port]");
const emailSecurity = document.querySelector("[data-email-security]");
const emailAuth = document.querySelector("[data-email-auth]");
const emailSendTestButton = document.querySelector('button[name="action"][value="test_email"]');
if (emailSendTestButton) emailSendTestButton.textContent = "Enviar e-mail de teste";
const emailUsernameField = document.querySelector("[data-email-username-field]");
const emailSecretField = document.querySelector("[data-email-secret-field]");
const emailProviderDefaults = {
  microsoft365: {host: "smtp.office365.com", port: "587", security: "starttls", auth: "password"},
  google: {host: "smtp.gmail.com", port: "587", security: "starttls", auth: "password"},
  amazon: {host: "email-smtp.us-east-1.amazonaws.com", port: "587", security: "starttls", auth: "password"},
  sendgrid: {host: "smtp.sendgrid.net", port: "587", security: "starttls", auth: "password"},
  mailgun: {host: "smtp.mailgun.org", port: "587", security: "starttls", auth: "password"},
  other: {host: "", port: "587", security: "starttls", auth: "password"},
};
const updateEmailAuthFields = () => {
  if (!emailAuth) return;
  const disabled = emailAuth.value === "none";
  [emailUsernameField, emailSecretField].forEach((field) => { if (field) { field.hidden = disabled; field.querySelectorAll("input").forEach((input) => { input.disabled = disabled; }); } });
};
emailAuth?.addEventListener("change", updateEmailAuthFields); updateEmailAuthFields();
emailProvider?.addEventListener("change", () => {
  const preset = emailProviderDefaults[emailProvider.value]; if (!preset) return;
  if (emailHost?.value && emailHost.value !== preset.host && !window.confirm("Substituir servidor, porta e segurança pelos valores sugeridos?")) return;
  if (emailHost) emailHost.value = preset.host;
  if (emailPort) emailPort.value = preset.port;
  if (emailSecurity) emailSecurity.value = preset.security;
  if (emailAuth) { emailAuth.value = preset.auth; updateEmailAuthFields(); }
});
const primaryColor = document.querySelector("[data-primary-color]");
const secondaryColor = document.querySelector("[data-secondary-color]");
document.querySelectorAll("[data-palette-primary]").forEach((button) => button.addEventListener("click", () => {
  if (primaryColor) primaryColor.value = button.dataset.palettePrimary;
  if (secondaryColor) secondaryColor.value = button.dataset.paletteSecondary;
  const primaryPicker = document.querySelector('[data-color-picker="primary"]');
  const secondaryPicker = document.querySelector('[data-color-picker="secondary"]');
  if (primaryPicker) primaryPicker.value = button.dataset.palettePrimary;
  if (secondaryPicker) secondaryPicker.value = button.dataset.paletteSecondary;
}));
document.querySelector('[data-color-picker="primary"]')?.addEventListener("input", (event) => { if (primaryColor) primaryColor.value = event.target.value; });
document.querySelector('[data-color-picker="secondary"]')?.addEventListener("input", (event) => { if (secondaryColor) secondaryColor.value = event.target.value; });
primaryColor?.addEventListener("input", () => { const picker = document.querySelector('[data-color-picker="primary"]'); if (/^#[0-9a-f]{6}$/i.test(primaryColor.value)) picker.value = primaryColor.value; });
secondaryColor?.addEventListener("input", () => { const picker = document.querySelector('[data-color-picker="secondary"]'); if (/^#[0-9a-f]{6}$/i.test(secondaryColor.value)) picker.value = secondaryColor.value; });
const colorFields = {primary: document.querySelector("[data-primary-color]"), secondary: document.querySelector("[data-secondary-color]"), accent: document.querySelector("[data-accent-color]"), background_start: document.querySelector("[data-background-start]"), background_end: document.querySelector("[data-background-end]")};
const applyThemePreview = (theme) => {
  Object.entries({primary: "primary", secondary: "secondary", accent: "accent", background_start: "background_start", background_end: "background_end"}).forEach(([key, fieldKey]) => {
    const field = colorFields[key]; const picker = document.querySelector(`[data-color-picker="${key}"]`);
    if (field && theme[fieldKey]) field.value = theme[fieldKey]; if (picker && theme[fieldKey]) picker.value = theme[fieldKey];
  });
  const gradient = document.querySelector("[name=background_gradient]"); if (gradient && typeof theme.gradient === "boolean") gradient.checked = theme.gradient;
  const company = document.querySelector("[name=company_name]"); if (company && theme.company_name) company.value = theme.company_name;
  document.body.style.setProperty("--brand", theme.primary); document.body.style.setProperty("--brand-2", theme.secondary); document.body.style.setProperty("--brand-light", theme.accent); document.body.style.setProperty("--portal-bg-start", theme.background_start); document.body.style.setProperty("--portal-bg-end", theme.background_end);
};
const themeDialog = document.querySelector("[data-theme-dialog]"); const themeTitle = themeDialog?.querySelector("[data-theme-title]"); const themePreview = themeDialog?.querySelector("[data-theme-preview]"); let pendingTheme = null;
document.querySelectorAll("[data-theme-preset]").forEach((button) => button.addEventListener("click", () => {
  try { pendingTheme = JSON.parse(button.dataset.themePreset); } catch (_) { pendingTheme = null; }
  if (!pendingTheme || !themeDialog) return; if (themeTitle) themeTitle.textContent = `Visualização · ${pendingTheme.name || "Tema"}`;
  if (themePreview) themePreview.innerHTML = `<svg class="theme-large-preview" viewBox="0 0 720 260"><defs><linearGradient id="theme-preview-gradient" x1="0" x2="1"><stop stop-color="${pendingTheme.background_start}"/><stop offset="1" stop-color="${pendingTheme.background_end}"/></linearGradient></defs><rect width="720" height="260" rx="18" fill="${pendingTheme.gradient ? "url(#theme-preview-gradient)" : pendingTheme.background_start}"/><circle cx="590" cy="0" r="240" fill="${pendingTheme.primary}" opacity=".7"/><rect x="42" y="48" width="220" height="26" rx="13" fill="${pendingTheme.primary}"/><rect x="42" y="100" width="470" height="16" rx="8" fill="${pendingTheme.accent}" opacity=".9"/><rect x="42" y="154" width="180" height="48" rx="10" fill="${pendingTheme.secondary}"/><rect x="250" y="154" width="180" height="48" rx="10" fill="${pendingTheme.primary}"/></svg>`;
  if (themeDialog.showModal) themeDialog.showModal(); else themeDialog.setAttribute("open", "");
}));
themeDialog?.querySelector("[data-theme-apply]")?.addEventListener("click", () => { if (pendingTheme) applyThemePreview(pendingTheme); themeDialog.close(); });
themeDialog?.querySelector("[data-theme-close]")?.addEventListener("click", () => themeDialog.close());
themeDialog?.addEventListener("click", (event) => { if (event.target === themeDialog) themeDialog.close(); });
const settingsForm = document.querySelector("#settings-form");
const settingsWorkspace = document.querySelector(".settings-layout");
if (settingsForm && settingsWorkspace) {
  let settingsDirty = false;
  settingsWorkspace.addEventListener("input", () => { settingsDirty = true; }); settingsWorkspace.addEventListener("change", () => { settingsDirty = true; });
  settingsForm.addEventListener("submit", () => { settingsDirty = false; });
  settingsWorkspace.querySelectorAll("form").forEach((form) => form.addEventListener("submit", () => { settingsDirty = false; }));
  document.querySelectorAll("[data-settings-section]").forEach((button) => button.addEventListener("click", (event) => {
    if (settingsDirty && !window.confirm("Existem configurações não salvas. Deseja continuar e descartá-las?")) { event.stopImmediatePropagation(); }
    else if (settingsDirty) settingsDirty = false;
  }));
  document.querySelectorAll("a").forEach((link) => link.addEventListener("click", (event) => {
    if (!settingsDirty || link.closest(".settings-nav") || link.href.includes("#")) return;
    if (!window.confirm("Existem configurações não salvas. Deseja sair e descartá-las?")) event.preventDefault();
  }));
  window.addEventListener("beforeunload", (event) => { if (settingsDirty) { event.preventDefault(); event.returnValue = ""; } });
}
const closeWarning = (event) => {
  if (!event.target.closest("[data-warning], .warning-popover")) document.querySelectorAll(".warning-popover").forEach((item) => item.remove());
};
document.addEventListener("click", closeWarning);
document.querySelectorAll("[data-warning]").forEach((button) => button.addEventListener("click", (event) => {
  event.stopPropagation();
  document.querySelectorAll(".warning-popover").forEach((item) => item.remove());
  const message = document.createElement("div");
  message.className = "warning-popover";
  message.textContent = button.dataset.warningMessage || "Este registro precisa ser revisado.";
  document.body.appendChild(message);
  const rect = button.getBoundingClientRect();
  message.style.left = `${Math.min(window.innerWidth - message.offsetWidth - 16, Math.max(16, rect.left))}px`;
  message.style.top = `${Math.min(window.innerHeight - message.offsetHeight - 16, rect.bottom + 8)}px`;
}));
const notificationToggle = document.querySelector("[data-notification-toggle]");
const notificationPopup = document.querySelector("[data-notification-popup]");
const notificationList = document.querySelector("[data-notification-list]");
if (notificationToggle && notificationPopup && notificationList) {
  notificationToggle.addEventListener("click", async (event) => {
    event.stopPropagation();
    const opening = notificationPopup.hidden;
    notificationPopup.hidden = !opening;
    notificationToggle.setAttribute("aria-expanded", String(opening));
    if (!opening) return;
    try {
      const response = await fetch("/notifications/feed", {credentials: "same-origin"});
      const data = await response.json();
      notificationList.replaceChildren();
      if (!data.notifications?.length) { notificationList.innerHTML = '<p class="muted notification-empty">Nenhuma notificação.</p>'; return; }
      data.notifications.forEach((item) => {
        const wrapper = document.createElement(item.link ? "a" : "div");
        wrapper.className = `notification-popup-item${item.read ? "" : " notification-unread"}`;
        if (item.link) wrapper.href = item.link;
        const title = document.createElement("strong"); title.textContent = item.title;
        const message = document.createElement("p"); message.textContent = item.message;
        const date = document.createElement("small"); date.textContent = new Date(item.created_at).toLocaleString("pt-BR");
        wrapper.append(title, message, date); notificationList.appendChild(wrapper);
      });
    } catch (_) { notificationList.innerHTML = '<p class="muted notification-empty">Não foi possível carregar as notificações.</p>'; }
  });
  document.addEventListener("click", (event) => {
    if (!event.target.closest(".notification-menu")) { notificationPopup.hidden = true; notificationToggle.setAttribute("aria-expanded", "false"); }
  });
}
const rememberToggle = document.querySelector("[data-remember-toggle]");
const rememberLinks = document.querySelectorAll("[data-remember-link]");
if (rememberToggle && rememberLinks.length) {
  const updateRememberLink = () => { rememberLinks.forEach((link) => { link.href = `${link.dataset.rememberLink}${rememberToggle.checked ? "?remember=1" : ""}`; }); };
  rememberToggle.addEventListener("change", updateRememberLink);
  updateRememberLink();
}

(() => {
  const container = document.querySelector("[data-ip-map]");
  const card = document.querySelector("[data-ip-map-card]");
  if (!container || !card || !window.L) return;
  const loading = card.querySelector("[data-map-loading]");
  let mapData;
  try { mapData = JSON.parse(document.getElementById("map-data")?.textContent || "{}"); } catch (_) { return; }
  const toBigInt = (value) => { try { return BigInt(value || "0"); } catch (_) { return 0n; } };
  const format = (value) => toBigInt(value).toLocaleString("pt-BR");
  const escapeHtml = (value) => String(value).replace(/[&<>\"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]));
  const normalize = (value) => String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();
  const ufCodes = {"11":"RO","12":"AC","13":"AM","14":"RR","15":"PA","16":"AP","17":"TO","21":"MA","22":"PI","23":"CE","24":"RN","25":"PB","26":"PE","27":"AL","28":"SE","29":"BA","31":"MG","32":"ES","33":"RJ","35":"SP","41":"PR","42":"SC","43":"RS","50":"MS","51":"MT","52":"GO","53":"DF"};
  const map = L.map(container, {scrollWheelZoom: true, zoomControl: true, attributionControl: false, minZoom: 2, maxZoom: 19});
  L.control.attribution({prefix: false, position: "bottomright"}).addTo(map);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
  }).addTo(map);
  const stateData = new Map((mapData.states || []).map((item) => [item.region, item]));
  const macroCoordinates = {"Norte": [-5.5, -60], "Nordeste": [-8.5, -42], "Centro-Oeste": [-15, -55], "Sudeste": [-20.5, -44], "Sul": [-27, -52]};
  const cityCoordinates = new Map();
  let stateLayer;
  const markerGroup = L.layerGroup().addTo(map);
  const locationGroup = L.layerGroup().addTo(map);
  const markerIcon = (label, size) => L.divIcon({className: "map-count-marker-wrap", html: `<span class="map-count-marker" style="--marker-size:${size}px">${escapeHtml(label)}</span>`, iconSize: [size, size], iconAnchor: [size / 2, size / 2]});

  const currentLevel = () => map.getZoom() < 4 ? "macroregions" : (map.getZoom() < 7 ? "states" : "cities");
  const drawMarkers = () => {
    markerGroup.clearLayers();
    locationGroup.clearLayers();
    const level = currentLevel();
    const items = (mapData[level] || []).map((item) => {
      let latlng = macroCoordinates[item.region];
      let label = item.region;
      if (level === "states") {
        const state = stateLayer?.getLayers().find((layer) => layer.feature.properties.sigla === item.region);
        latlng = state?.getBounds().getCenter(); label = item.region;
      } else if (level === "cities") {
        const coordinates = cityCoordinates.get(`${item.region}:${normalize(item.city)}`);
        latlng = coordinates || stateLayer?.getLayers().find((layer) => layer.feature.properties.sigla === item.region)?.getBounds().getCenter();
        label = item.city;
      }
      return latlng ? {...item, latlng, label} : null;
    }).filter(Boolean);
    const threshold = level === "cities" ? 36 : 70;
    const clusters = [];
    items.forEach((item) => {
      const point = map.latLngToLayerPoint(item.latlng);
      let cluster = clusters.find((candidate) => point.distanceTo(candidate.point) < threshold);
      if (!cluster) { cluster = {point, latlng: item.latlng, items: []}; clusters.push(cluster); }
      cluster.items.push(item);
    });
    clusters.forEach((cluster) => {
      const total = cluster.items.reduce((sum, item) => sum + toBigInt(item.blocks), 0n);
      const names = cluster.items.map((item) => item.label).join(", ");
      const companies = new Map();
      cluster.items.forEach((item) => (item.companies || []).forEach((company) => {
        const current = companies.get(company.name) || {name: company.name, ipv4: 0n, ipv6: 0n};
        current.ipv4 += toBigInt(company.ipv4);
        current.ipv6 += toBigInt(company.ipv6);
        companies.set(company.name, current);
      }));
      const companySummary = [...companies.values()].sort((left, right) => left.name.localeCompare(right.name, "pt-BR")).map((company) => `<div class="map-tooltip-company"><strong>${escapeHtml(company.name)}</strong><span>IPv4: ${format(company.ipv4)} · IPv6: ${format(company.ipv6)}</span></div>`).join("");
      const markerSize = Math.min(60, 30 + Math.round(Math.log10(Number(total > 0n ? total : 1n)) * 1.6));
      const marker = L.marker(cluster.latlng, {icon: markerIcon(format(total), markerSize), keyboard: true});
      marker.bindTooltip(`<div class="map-tooltip-summary"><strong>${escapeHtml(names)}</strong><div class="map-tooltip-total">${format(total)} blocos</div>${companySummary}</div>`, {direction: "top", opacity: .96});
      marker.addTo(markerGroup);
    });
    (mapData.locations || []).forEach((location) => {
      const marker = L.circleMarker([location.latitude, location.longitude], {radius: 7, color: "#f4c95d", weight: 2, fillColor: "#7c32c7", fillOpacity: .95});
      const details = [location.address && `Endereço: ${location.address}`, location.customer && `Cliente: ${location.customer}`, location.pop && `POP/DC: ${location.pop}`, location.equipment && `Equipamento: ${location.equipment}`].filter(Boolean).map(escapeHtml).join("<br>");
      const detailedZoom = map.getZoom() >= 11;
      const tooltip = `<strong>${escapeHtml(location.prefix)}</strong>${details ? `<br>${details}` : "<br>Endereço operacional não informado"}`;
      marker.bindTooltip(tooltip, {direction: "top", opacity: .96, permanent: detailedZoom, className: "map-location-tooltip", offset: [0, -6]});
      marker.bindPopup(tooltip, {maxWidth: 360});
      marker.addTo(locationGroup);
    });
    const title = level === "macroregions" ? "Macroregiões" : (level === "states" ? "Estados" : "Cidades");
    const levelElement = card.querySelector("[data-map-level]");
    if (levelElement) levelElement.textContent = `Visualização: ${title}`;
  };
  Promise.all([fetch("/static/brazil-states.geojson", {credentials: "same-origin"}).then((response) => response.json()), fetch("/static/brazil-cities-coordinates.json", {credentials: "same-origin"}).then((response) => response.json())]).then(([geo, cities]) => {
    cities.forEach((city) => cityCoordinates.set(`${ufCodes[city.uf] || city.uf}:${normalize(city.n)}`, [city.lat, city.lon]));
    stateLayer = L.geoJSON(geo, {
      style: (feature) => { const item = stateData.get(feature.properties.sigla); return {color: "#b187ea", weight: 1, fillColor: item ? "#7c32c7" : "#241a31", fillOpacity: item ? .52 : .18}; },
      onEachFeature: (feature, layer) => { const item = stateData.get(feature.properties.sigla) || {blocks: "0"}; layer.bindTooltip(`<strong>${escapeHtml(feature.properties.name)} (${feature.properties.sigla})</strong><br>${format(item.blocks)} blocos`, {sticky: true}); }
    }).addTo(map);
    map.fitBounds(stateLayer.getBounds(), {padding: [12, 12]});
    map.setZoom(Math.min(3.5, map.getZoom()));
    loading?.remove(); drawMarkers();
  }).catch(() => { if (loading) loading.textContent = "Não foi possível carregar o mapa."; });
  map.on("zoomend moveend", drawMarkers);
})();

const initServicePicker = (picker) => {
  if (!picker || picker.dataset.servicePickerReady) return;
  const panel = picker.querySelector("[data-service-picker-panel]");
  const selected = picker.querySelector("[data-selected-services]");
  const empty = picker.querySelector("[data-no-selected-services]");
  const toggle = picker.querySelector("[data-open-service-picker]");
  const search = picker.querySelector("[data-service-search]");
  const options = [...picker.querySelectorAll("[data-service-option]")];
  const updateEmpty = () => { if (empty) empty.hidden = Boolean(selected?.querySelector("[data-selected-service]")); };
  const addSelected = (checkbox) => {
    if (!selected || selected.querySelector(`[data-selected-service][data-service-id="${CSS.escape(checkbox.value)}"]`)) return;
    const option = checkbox.closest("[data-service-option]");
    const title = option?.querySelector("strong")?.textContent?.trim() || "Serviço";
    const row = document.createElement("div");
    row.className = "selected-service-row"; row.dataset.selectedService = ""; row.dataset.serviceId = checkbox.value;
    row.innerHTML = `<input type="hidden" name="service_ids" value="${checkbox.value}"><strong></strong><label><span class="sr-only"></span><select name="service_status_${checkbox.value}"><option value="suspended">Suspenso</option><option value="active" selected>Ativo</option><option value="canceled">Cancelado</option></select></label><button class="icon-button" type="button" data-remove-service aria-label="Remover serviço">×</button>`;
    row.querySelector("strong").textContent = title; row.querySelector(".sr-only").textContent = `Status de ${title}`;
    row.querySelector("select").setAttribute("aria-label", `Status de ${title}`);
    row.querySelector("[data-remove-service]").addEventListener("click", () => { checkbox.checked = false; row.remove(); updateEmpty(); });
    selected.append(row); updateEmpty();
  };
  options.forEach((option) => { const checkbox = option.querySelector("[data-service-checkbox]"); checkbox?.addEventListener("change", () => checkbox.checked ? addSelected(checkbox) : (selected.querySelector(`[data-selected-service][data-service-id="${CSS.escape(checkbox.value)}"]`)?.remove(), updateEmpty())); });
  selected?.querySelectorAll("[data-remove-service]").forEach((button) => button.addEventListener("click", () => { const row = button.closest("[data-selected-service]"); const checkbox = picker.querySelector(`[data-service-checkbox][value="${CSS.escape(row.dataset.serviceId)}"]`); if (checkbox) checkbox.checked = false; row.remove(); updateEmpty(); }));
  if (panel && toggle) {
    panel.hidden = true;
    toggle.setAttribute("aria-expanded", "false");
    toggle.addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      toggle.setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) search?.focus();
    });
  }
  search?.addEventListener("input", () => { const query = search.value.trim().toLocaleLowerCase(); options.forEach((option) => { option.hidden = Boolean(query) && !option.dataset.serviceName.includes(query); }); });
  picker.dataset.servicePickerReady = "1"; updateEmpty();
};

// A service picker is used both in the page form and in dynamically loaded
// quick-entry dialogs. Delegation keeps the behavior identical in both places:
// clicking anywhere outside the picker closes only its option panel and keeps
// the selected hidden inputs and status controls intact.
document.addEventListener("click", (event) => {
  document.querySelectorAll("[data-service-picker]").forEach((picker) => {
    const panel = picker.querySelector("[data-service-picker-panel]");
    const toggle = picker.querySelector("[data-open-service-picker]");
    if (panel && !panel.hidden && !panel.contains(event.target) && !toggle?.contains(event.target)) {
      panel.hidden = true;
      toggle?.setAttribute("aria-expanded", "false");
    }
  });
});

document.querySelectorAll("[data-service-picker]").forEach(initServicePicker);
window.initQuickServicePicker = initServicePicker;

window.applyFieldExamples = (scope = document) => {
  const examples = {name: "Ex.: Razão social ou nome identificável", code: "Ex.: POP-SP-01 ou serviço-link-ip-100", cnpj: "00.000.000/0000-00", address: "Ex.: Av. Paulista, 1000, 8º andar", city: "Ex.: São Paulo", state: "Ex.: SP", postal_code: "Ex.: 01310-100", contact_name: "Ex.: Maria Silva", contact_email: "Ex.: contato@empresa.com.br", email: "Ex.: usuario@empresa.com.br", contact_phone: "Ex.: (11) 3333-4444", phone: "Ex.: (11) 3333-4444", notes: "Ex.: Observações relevantes para a operação.", description: "Ex.: Descreva o recurso e sua finalidade.", prefix: "Ex.: 203.0.113.0/24", allocation_address: "Ex.: Rack 04, posição 12, sala técnica", latitude: "Ex.: -23.5505", longitude: "Ex.: -46.6333", default_asn: "Ex.: 64500", asn: "Ex.: 64500", vlan: "Ex.: 120", vrf: "Ex.: CLIENTES-SP"};
  scope.querySelectorAll?.("form input, form textarea")?.forEach((field) => { if (field.placeholder || field.type === "hidden" || field.type === "checkbox" || field.type === "radio" || field.type === "file" || field.type === "submit") return; const key = field.name?.toLowerCase() || ""; const match = Object.keys(examples).find((candidate) => key === candidate || key.includes(candidate)); if (match) field.placeholder = examples[match]; });
};

const markMissingRequired = (field) => {
  if (!field || field.disabled || field.type === "hidden") return;
  const missing = !String(field.value || "").trim();
  field.classList.toggle("is-required-missing", missing);
  field.closest("label")?.classList.toggle("required-missing", missing);
};
window.highlightMissingRequired = (scope = document) => {
  scope.querySelectorAll?.("form [required]")?.forEach(markMissingRequired);
};
document.addEventListener("invalid", (event) => markMissingRequired(event.target), true);
document.addEventListener("input", (event) => {
  if (event.target?.matches?.("[required]")) markMissingRequired(event.target);
});
document.addEventListener("change", (event) => {
  if (event.target?.matches?.("[required]")) markMissingRequired(event.target);
});

(() => {
  const examples = {
    name: "Ex.: Razão social ou nome identificável",
    code: "Ex.: POP-SP-01 ou serviço-link-ip-100",
    cnpj: "00.000.000/0000-00",
    address: "Ex.: Av. Paulista, 1000, 8º andar",
    city: "Ex.: São Paulo",
    state: "Ex.: SP",
    postal_code: "Ex.: 01310-100",
    contact_name: "Ex.: Maria Silva",
    contact_email: "Ex.: contato@empresa.com.br",
    email: "Ex.: usuario@empresa.com.br",
    contact_phone: "Ex.: (11) 3333-4444",
    phone: "Ex.: (11) 3333-4444",
    notes: "Ex.: Observações relevantes para a operação.",
    description: "Ex.: Descreva o recurso e sua finalidade.",
    prefix: "Ex.: 203.0.113.0/24",
    allocation_address: "Ex.: Rack 04, posição 12, sala técnica",
    latitude: "Ex.: -23.5505",
    longitude: "Ex.: -46.6333",
    default_asn: "Ex.: 64500",
    asn: "Ex.: 64500",
    vlan: "Ex.: 120",
    vrf: "Ex.: CLIENTES-SP",
  };
  document.querySelectorAll("form input, form textarea").forEach((field) => {
    if (field.placeholder || field.type === "hidden" || field.type === "checkbox" || field.type === "radio" || field.type === "file" || field.type === "submit") return;
    const key = field.name?.toLowerCase() || "";
    const match = Object.keys(examples).find((candidate) => key === candidate || key.includes(candidate));
    if (match) field.placeholder = examples[match];
  });
})();

(() => {
  const tables = document.querySelectorAll("main table");
  const normalize = (value) => value.replace(/\s+/g, " ").trim().toLocaleLowerCase();
  const funnelIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16l-6.5 7.2v5.3l-3 1.5v-6.8z"></path></svg>';
  const closeFilterPopovers = (except = null) => {
    document.querySelectorAll(".table-filter-popover:not([hidden])").forEach((popover) => {
      if (popover === except) return;
      popover.hidden = true;
      popover._filterButton?.setAttribute("aria-expanded", "false");
    });
  };
  tables.forEach((table) => {
    const headers = [...table.querySelectorAll("thead th")];
    const body = table.tBodies[0];
    if (!body || !headers.length) return;
    headers.forEach((header, index) => {
      if (header.dataset.noTableEnhance === "true") return;
      if (header.querySelector(".table-header-inner")) return;
      const label = header.textContent.trim();
      if (!label) return;
      const allowFilter = header.dataset.noTableFilter !== "true";
      const wrapper = document.createElement("span");
      wrapper.className = "table-header-inner";
      wrapper.innerHTML = `<button class="table-sort-button" type="button" title="Ordenar por ${label}"></button><span class="table-header-label"></span><button class="table-filter-button" type="button" title="Filtrar por ${label}" aria-label="Filtrar por ${label}">⌄</button><div class="table-filter-popover" hidden><input type="search" placeholder="Filtrar ${label}" aria-label="Filtrar ${label}"><button type="button" class="table-filter-clear">Limpar</button></div>`;
      wrapper.querySelector(".table-header-label").textContent = label;
      const filterMarkup = allowFilter ? `<button class="table-filter-button" type="button" title="Filtrar por ${label}" aria-label="Filtrar por ${label}" aria-expanded="false">${funnelIcon}</button><div class="table-filter-popover" hidden><div class="table-filter-box"><label class="table-filter-label">Filtrar por <span></span></label><input type="search" placeholder="Digite para filtrar" autocomplete="off"><div class="table-filter-actions"><button type="button" class="table-filter-apply">Aplicar</button><button type="button" class="table-filter-clear">Limpar</button></div></div></div>` : "";
      wrapper.innerHTML = `<button class="table-sort-button" type="button" title="Ordenar por ${label}" aria-label="Ordenar por ${label}"></button><span class="table-header-label"></span>${filterMarkup}`;
      wrapper.querySelector(".table-header-label").textContent = label;
      if (allowFilter) {
        wrapper.querySelector(".table-filter-label span").textContent = label;
        wrapper.querySelector(".table-filter-popover input").setAttribute("aria-label", `Filtrar por ${label}`);
      }
      header.textContent = "";
      header.append(wrapper);
      const sort = wrapper.querySelector(".table-sort-button");
      let direction = 1;
      sort.addEventListener("click", () => {
        const rows = [...body.rows].filter((row) => row.cells.length > index);
        rows.sort((left, right) => normalize(left.cells[index].textContent).localeCompare(normalize(right.cells[index].textContent), "pt-BR", {numeric: true}) * direction);
        rows.forEach((row) => body.append(row));
        direction *= -1;
      });
      if (!allowFilter) return;
      const filter = wrapper.querySelector(".table-filter-button");
      const popover = wrapper.querySelector(".table-filter-popover");
      const input = popover.querySelector("input");
      const applyButton = popover.querySelector(".table-filter-apply");
      const clearButton = popover.querySelector(".table-filter-clear");
      document.body.append(popover);
      popover._filterButton = filter;
      let appliedQuery = "";
      const positionPopover = () => {
        if (popover.hidden) return;
        const buttonBox = filter.getBoundingClientRect();
        const popoverBox = popover.getBoundingClientRect();
        const margin = 12;
        const left = Math.min(Math.max(margin, buttonBox.right - popoverBox.width), window.innerWidth - popoverBox.width - margin);
        const below = buttonBox.bottom + 8;
        const above = buttonBox.top - popoverBox.height - 8;
        const top = below + popoverBox.height + margin <= window.innerHeight || above < margin ? below : above;
        popover.style.left = `${Math.round(left)}px`;
        popover.style.top = `${Math.round(Math.max(margin, top))}px`;
      };
      const applyFilter = () => {
        const query = normalize(appliedQuery);
        [...body.rows].forEach((row) => { row.hidden = Boolean(query) && !normalize(row.cells[index]?.textContent || "").includes(query); });
        filter.classList.toggle("is-active", Boolean(query));
        filter.setAttribute("aria-pressed", String(Boolean(query)));
      };
      const closePopover = () => {
        popover.hidden = true;
        filter.setAttribute("aria-expanded", "false");
      };
      filter.addEventListener("click", (event) => {
        event.stopPropagation();
        closeFilterPopovers(popover);
        popover.hidden = !popover.hidden;
        filter.setAttribute("aria-expanded", String(!popover.hidden));
        if (!popover.hidden) {
          input.value = appliedQuery;
          input.focus();
          requestAnimationFrame(positionPopover);
        }
      });
      window.addEventListener("resize", positionPopover);
      window.addEventListener("scroll", positionPopover, true);
      applyButton.addEventListener("click", () => {
        appliedQuery = input.value;
        applyFilter();
        closePopover();
      });
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          applyButton.click();
        }
      });
      clearButton.addEventListener("click", () => {
        input.value = "";
        appliedQuery = "";
        applyFilter();
        closePopover();
      });
    });
  });
  document.addEventListener("click", (event) => {
    if (event.target.closest(".table-filter-popover, .table-filter-button")) return;
    closeFilterPopovers();
  });
})();

(() => {
  const table = document.querySelector("[data-ipam-tree]");
  if (!table) return;
  const expanded = new Set();
  const loaded = new Set();
  const rows = () => [...table.querySelectorAll("[data-ipam-row], [data-ipam-child-toolbar]")];
  const rowMap = () => new Map([...table.querySelectorAll("[data-ipam-row]")].map((row) => [row.dataset.nodeKey, row]));
  const isVisible = (row, byKey) => {
    let parentKey = row.dataset.parentKey || "";
    while (parentKey) {
      if (!expanded.has(parentKey)) return false;
      const parent = byKey.get(parentKey);
      if (!parent) break;
      parentKey = parent.dataset.parentKey || "";
    }
    return true;
  };
  const render = () => {
    const byKey = rowMap();
    rows().forEach((row) => {
      row.classList.toggle("ipam-tree-hidden", !isVisible(row, byKey));
      const button = row.querySelector("[data-ipam-tree-toggle]");
      if (!button || button.dataset.ipamHasChildren !== "true") return;
      const open = expanded.has(row.dataset.nodeKey);
      button.setAttribute("aria-expanded", String(open));
      button.title = open ? "Recolher itens filhos" : "Abrir itens filhos";
      const chevron = button.querySelector(".ipam-tree-chevron");
      if (chevron) chevron.textContent = open ? "⌄" : "›";
    });
  };
  table.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-ipam-tree-toggle]");
    if (!button) return;
    if (button.dataset.ipamHasChildren !== "true") {
      if (button.dataset.ipamResourceAction) {
        const link = document.createElement("a");
        link.href = button.dataset.ipamResourceAction;
        link.dataset.quickCreate = "";
        link.hidden = true;
        document.body.append(link);
        link.click();
        window.setTimeout(() => link.remove(), 0);
      }
      return;
    }
    const row = button.closest("[data-ipam-row]");
    const key = row?.dataset.nodeKey;
    if (!key) return;
    if (expanded.has(key)) {
      expanded.delete(key);
      render();
      return;
    }
    if (!loaded.has(key)) {
      button.classList.add("is-loading");
      button.setAttribute("aria-busy", "true");
      const url = new URL(table.dataset.ipamTreeUrl, window.location.href);
      url.searchParams.set("owner_id", row.dataset.ownerId);
      url.searchParams.set("parent_prefix", row.dataset.prefix);
      url.searchParams.set("parent_key", key);
      url.searchParams.set("depth", row.dataset.depth || "0");
      try {
        const response = await fetch(url, {credentials: "same-origin", headers: {Accept: "text/html"}});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const template = document.createElement("template");
        template.innerHTML = await response.text();
        row.after(template.content);
        loaded.add(key);
      } catch (_error) {
        window.alert("Não foi possível carregar os itens filhos. Tente novamente.");
        return;
      } finally {
        button.classList.remove("is-loading");
        button.removeAttribute("aria-busy");
      }
    }
    expanded.add(key);
    render();
  });
  render();

  const openPlanner = async (button) => {
    const parentPrefix = button.dataset.parentPrefix;
    const parentLength = Number(parentPrefix.split("/").pop());
    const dialog = document.createElement("dialog");
    dialog.className = "quick-entry-dialog subnet-planner-dialog";
    const options = Array.from({length: Math.max(0, 32 - parentLength)}, (_item, index) => parentLength + index + 1)
      .map((length) => `<option value="${length}">/${length} · ${2 ** (32 - length)} endereços</option>`).join("");
    dialog.innerHTML = `<div class="quick-entry-dialog-inner"><header class="quick-entry-dialog-header"><div><p class="eyebrow">Cálculo de sub-rede</p><h2>Criar bloco filho em ${parentPrefix}</h2></div><button class="dialog-close" type="button" aria-label="Fechar">×</button></header><div class="subnet-planner-body"><label><span>Tamanho do novo bloco</span><select data-subnet-size>${options}</select></label><div class="subnet-planner-status" data-subnet-status>Calculando faixas disponíveis…</div><div class="subnet-suggestions" data-subnet-suggestions></div><div class="form-actions"><button class="button button-secondary" type="button" data-planner-cancel>Cancelar</button><a class="button button-primary is-disabled" aria-disabled="true" data-planner-create>Cadastrar bloco</a></div></div></div>`;
    document.body.append(dialog);
    const size = dialog.querySelector("[data-subnet-size]");
    const status = dialog.querySelector("[data-subnet-status]");
    const suggestions = dialog.querySelector("[data-subnet-suggestions]");
    const create = dialog.querySelector("[data-planner-create]");
    const load = async () => {
      status.textContent = "Calculando faixas disponíveis…";
      suggestions.replaceChildren();
      create.classList.add("is-disabled");
      create.setAttribute("aria-disabled", "true");
      create.removeAttribute("href");
      const url = new URL(table.dataset.ipamSuggestionsUrl, window.location.href);
      url.searchParams.set("owner_id", button.dataset.ownerId);
      url.searchParams.set("parent_prefix", parentPrefix);
      url.searchParams.set("prefixlen", size.value);
      try {
        const response = await fetch(url, {credentials: "same-origin", headers: {Accept: "application/json"}});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        status.textContent = payload.suggestions.length
          ? `${payload.suggestions.length} faixa(s) alinhada(s) disponível(is). Prefixos idênticos já existentes foram excluídos; IPs e grupos menores podem ser reunidos.`
          : "Não há faixa livre deste tamanho dentro do bloco selecionado.";
        payload.suggestions.forEach((prefix, index) => {
          const label = document.createElement("label");
          label.className = "subnet-suggestion";
          label.innerHTML = `<input type="radio" name="subnet_suggestion" value="${prefix}" ${index === 0 ? "checked" : ""}><span><strong>${prefix}</strong><small>Alinhamento validado</small></span>`;
          suggestions.append(label);
        });
        const updateCreate = () => {
          const selected = suggestions.querySelector("input:checked")?.value;
          if (!selected) return;
          const target = new URL("/ipam/allocations/new", window.location.origin);
          target.searchParams.set("resource_kind", "block");
          target.searchParams.set("prefix", selected);
          target.searchParams.set("parent_id", button.dataset.parentId);
          if (button.dataset.companyId) target.searchParams.set("company_id", button.dataset.companyId);
          if (button.dataset.sourceBlockId) target.searchParams.set("source_block_id", button.dataset.sourceBlockId);
          create.href = target.toString();
          create.dataset.quickCreate = "";
          create.classList.remove("is-disabled");
          create.removeAttribute("aria-disabled");
        };
        suggestions.addEventListener("change", updateCreate);
        updateCreate();
      } catch (_error) {
        status.textContent = "Não foi possível calcular as sub-redes. Tente novamente.";
      }
    };
    size.addEventListener("change", load);
    dialog.querySelector(".dialog-close").addEventListener("click", () => dialog.close());
    dialog.querySelector("[data-planner-cancel]").addEventListener("click", () => dialog.close());
    dialog.addEventListener("close", () => dialog.remove());
    dialog.showModal();
    await load();
  };
  table.addEventListener("click", (event) => {
    const button = event.target.closest("[data-subnet-planner]");
    if (button) openPlanner(button);
  });
})();

window.initIpamEquipmentForm = (form) => {
  if (!form || form.dataset.equipmentInitialized === "1") return;
  form.dataset.equipmentInitialized = "1";
  const type = form.elements.equipment_type;
  const pop = form.elements.pop_id;
  const customer = form.elements.customer_id;
  const updateOptions = () => {
    const typeValue = type?.value || "";
    const popValue = pop?.value || "";
    const customerValue = customer?.value || "";
    form.querySelectorAll("select[name=router_id], select[name=secondary_router_id]").forEach((select) => {
      select.querySelectorAll("option[data-pop-id]").forEach((option) => {
        option.hidden = Boolean(popValue && option.dataset.popId && option.dataset.popId !== popValue);
      });
      if (select.selectedOptions[0]?.hidden) select.value = "";
    });
    form.querySelectorAll("select[name=cpe_id]").forEach((select) => {
      select.querySelectorAll("option[data-customer-id]").forEach((option) => {
        option.hidden = Boolean(customerValue && option.dataset.customerId && option.dataset.customerId !== customerValue);
      });
      if (select.selectedOptions[0]?.hidden) select.value = "";
    });
    form.querySelectorAll("select[name=access_point_id]").forEach((select) => {
      select.querySelectorAll("option[data-pop-id]").forEach((option) => {
        option.hidden = Boolean(popValue && option.dataset.popId && option.dataset.popId !== popValue) || Boolean(customerValue && option.dataset.customerId && option.dataset.customerId !== customerValue);
      });
      if (select.selectedOptions[0]?.hidden) select.value = "";
    });
    const accessPoint = form.elements.access_point_id;
    if (typeValue === "radio_st" && accessPoint?.selectedOptions[0]?.dataset.popId && pop) {
      pop.value = accessPoint.selectedOptions[0].dataset.popId;
      pop.disabled = true;
    } else if (pop) {
      pop.disabled = false;
    }
  };
  const updateVisibility = () => {
    const typeValue = type?.value || "";
    const show = (selector, visible, required = false) => {
      const wrapper = form.querySelector(selector);
      if (!wrapper) return;
      wrapper.hidden = !visible;
      const field = wrapper.querySelector("select, input, textarea");
      if (field) field.required = Boolean(visible && required);
    };
    show("[data-equipment-pop-field]", typeValue !== "radio_st", ["router", "switch", "edge_router", "radio_ap"].includes(typeValue));
    show("[data-equipment-secondary-pop-field]", typeValue === "cpe");
    show("[data-equipment-customer-field]", ["cpe", "radio_ap", "radio_st"].includes(typeValue), ["cpe", "radio_ap", "radio_st"].includes(typeValue));
    show("[data-equipment-router-field]", typeValue === "cpe");
    show("[data-equipment-secondary-router-field]", typeValue === "cpe");
    show("[data-equipment-cpe-field]", typeValue === "radio_st", true);
    show("[data-equipment-ap-field]", typeValue === "radio_st", true);
    updateOptions();
  };
  type?.addEventListener("change", updateVisibility);
  pop?.addEventListener("change", updateOptions);
  customer?.addEventListener("change", updateOptions);
  updateVisibility();
};

window.initIpamAllocationForm = (form) => {
  if (!form || form.dataset.ipamAllocationInitialized === "1") return;
  form.dataset.ipamAllocationInitialized = "1";
  const summary = form.querySelector("[data-ipam-data-summary]");
  const valueOrFallback = (value, fallback = "Não informado") => String(value ?? "").trim() || fallback;
  const parentContexts = (() => {
    try { return JSON.parse(form.dataset.ipamParentContexts || "{}"); } catch (_) { return {}; }
  })();
  const inheritedFields = ["company_id", "geofeed_region", "vlan", "vrf", "customer_id", "pop_id", "pop_2_id", "access_type", "access_type_2", "router_id", "router_2_id", "switch_id", "switch_2_id", "cpe_id", "access_point_id", "access_point_2_id", "st_id", "st_2_id"];
  const updateParentRequirement = () => {
    const kind = form.elements.resource_kind?.value || "block";
    const raw = form.elements.prefix?.value?.trim() || "";
    const match = raw.match(/\/(\d+)$/);
    const prefixLength = match ? Number(match[1]) : (kind === "ip" ? 32 : 0);
    const version = raw.includes(":") ? 6 : 4;
    const required = kind === "ip" || (version === 4 && prefixLength > 24) || (version === 6 && prefixLength > 32);
    const field = form.elements.parent_id;
    if (field) {
      field.required = required;
      field.closest("label")?.classList.toggle("is-conditionally-required", required);
      const mark = form.querySelector("[data-ipam-parent-required-mark]");
      if (mark) mark.hidden = !required;
      markMissingRequired(field);
    }
  };
  const updateSummary = () => {
    if (!summary) return;
    const prefixOutput = summary.querySelector("[data-summary-prefix]");
    if (prefixOutput) prefixOutput.textContent = valueOrFallback(form.elements.prefix?.value);
    summary.querySelectorAll("[data-summary-field]").forEach((output) => {
      const field = form.elements[output.dataset.summaryField];
      output.textContent = valueOrFallback(field?.value, "—");
    });
    summary.querySelectorAll("[data-summary-select]").forEach((output) => {
      const field = form.elements[output.dataset.summarySelect];
      output.textContent = field?.selectedOptions?.[0]?.textContent?.trim() || "Não informado";
    });
  };
  const targetIsPublic = () => {
    const raw = String(form.elements.prefix?.value || "").trim().split("/")[0];
    if (!raw) return false;
    if (raw.includes(":")) {
      const normalized = raw.toLowerCase();
      return !normalized.startsWith("fc") && !normalized.startsWith("fd") && !normalized.startsWith("fe8") && normalized !== "::1";
    }
    const octets = raw.split(".").map(Number);
    if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return false;
    const [first, second] = octets;
    const reservedTestNetwork = (first === 192 && second === 0) || (first === 198 && second === 51) || (first === 203 && second === 0);
    return first !== 10 && !(first === 172 && second >= 16 && second <= 31) && !(first === 192 && second === 168)
      && !(first === 169 && second === 254) && !reservedTestNetwork
      && first !== 127 && first !== 0 && first < 224;
  };
  const filterOptions = () => {
    const customerId = form.elements.customer_id?.value || "";
    [1, 2].forEach((approach) => {
      const pop = form.querySelector(`[name="${approach === 1 ? "pop_id" : "pop_2_id"}"]`);
      const popId = pop?.value || "";
      const router = form.querySelector(`[name="${approach === 1 ? "router_id" : "router_2_id"}"]`);
      const switchField = form.querySelector(`[name="${approach === 1 ? "switch_id" : "switch_2_id"}"]`);
      const ap = form.querySelector(`[name="${approach === 1 ? "access_point_id" : "access_point_2_id"}"]`);
      const st = form.querySelector(`[name="${approach === 1 ? "st_id" : "st_2_id"}"]`);
      [router, switchField].forEach((field) => {
        field?.querySelectorAll("option[data-pop-id]").forEach((option) => { option.hidden = Boolean(popId && option.dataset.popId && option.dataset.popId !== popId); });
        if (field?.selectedOptions[0]?.hidden) field.value = "";
      });
      ap?.querySelectorAll("option[data-pop-id]").forEach((option) => {
        option.hidden = Boolean(popId && option.dataset.popId && option.dataset.popId !== popId) || Boolean(customerId && option.dataset.customerId && option.dataset.customerId !== customerId);
      });
      if (ap?.selectedOptions[0]?.hidden) ap.value = "";
      st?.querySelectorAll("option[data-pop-id]").forEach((option) => {
        option.hidden = Boolean(popId && option.dataset.popId && option.dataset.popId !== popId) || Boolean(customerId && option.dataset.customerId && option.dataset.customerId !== customerId) || Boolean(form.elements.cpe_id?.value && option.dataset.cpeId && option.dataset.cpeId !== form.elements.cpe_id.value) || Boolean(ap?.value && option.dataset.accessPointId && option.dataset.accessPointId !== ap.value);
      });
      if (st?.selectedOptions[0]?.hidden) st.value = "";
      const type = form.querySelector(`[name="${approach === 1 ? "access_type" : "access_type_2"}"]`);
      form.querySelectorAll(`[data-ipam-radio-field="${approach}"]`).forEach((field) => {
        field.hidden = type?.value !== "radio";
        const input = field.querySelector("select");
        if (input) {
          input.required = type?.value === "radio";
          if (type?.value !== "radio" && !input.disabled) input.value = "";
        }
      });
      const routerRequired = Boolean(popId);
      if (router) router.required = routerRequired;
      form.querySelector(`[data-required-for-pop="${approach}"]`)?.toggleAttribute("hidden", !routerRequired);
    });
  };
  const updateQuickLinks = () => {
    form.querySelectorAll("[data-ipam-equipment-quick], [data-ipam-pop-quick]").forEach((link) => {
      const url = new URL(link.href, window.location.href);
      const resultName = link.dataset.resultName || url.searchParams.get("result_name") || "";
      url.searchParams.set("result_name", resultName);
      if (link.dataset.ipamPopQuick) {
        const field = form.elements[resultName];
        if (field?.value) url.searchParams.set(resultName, field.value);
      } else {
        const approach = resultName.endsWith("_2_id") ? 2 : 1;
        const popName = approach === 1 ? "pop_id" : "pop_2_id";
        const routerName = approach === 1 ? "router_id" : "router_2_id";
        const params = {pop_id: form.elements[popName]?.value, secondary_pop_id: form.elements.pop_2_id?.value, customer_id: form.elements.customer_id?.value, router_id: form.elements.router_id?.value, secondary_router_id: form.elements.router_2_id?.value, cpe_id: form.elements.cpe_id?.value, access_point_id: form.elements[approach === 1 ? "access_point_id" : "access_point_2_id"]?.value};
        Object.entries(params).forEach(([key, value]) => value ? url.searchParams.set(key, value) : url.searchParams.delete(key));
        url.searchParams.set("equipment_type", link.dataset.equipmentType || "other");
      }
      link.href = url.toString();
    });
  };
  const updateInheritedFields = () => {
    const parentId = form.elements.parent_id?.value || "";
    const context = parentContexts[parentId] || {values: {}, sources: {}};
    const inheritedValues = targetIsPublic()
      ? Object.fromEntries(Object.entries(context.values || {}).filter(([fieldName]) => ["company_id", "geofeed_region"].includes(fieldName)))
      : (context.values || {});
    inheritedFields.forEach((fieldName) => {
      const field = form.elements[fieldName];
      if (!field) return;
      const wasInherited = field.dataset.ipamInherited === "1";
      const isInherited = Object.prototype.hasOwnProperty.call(inheritedValues, fieldName);
      const value = isInherited ? inheritedValues[fieldName] : "";
      if (field.tagName === "SELECT") {
        if (isInherited || wasInherited) field.value = value == null ? "" : String(value);
      } else if (isInherited || !field.value || field.dataset.ipamInherited === "1") {
        field.value = value == null ? "" : String(value);
      }
      field.disabled = isInherited;
      field.dataset.ipamInherited = isInherited ? "1" : "0";
      const help = form.querySelector(`[data-inherited-help="${fieldName}"]`);
      if (help) help.textContent = isInherited ? `Herdado de ${context.sources?.[fieldName] || "bloco pai"}.` : "";
    });
    const locationTrigger = form.querySelector("[data-location-picker-trigger], [data-ipam-location-trigger]");
    if (locationTrigger) locationTrigger.disabled = false;
    updateSummary();
  };
  form.addEventListener("input", updateSummary);
  form.addEventListener("change", (event) => {
    if (event.target?.name === "parent_id" || event.target?.name === "prefix") updateInheritedFields();
    else { filterOptions(); updateQuickLinks(); updateSummary(); }
  });
  form.addEventListener("ipam:coordinates-updated", updateSummary);
  form.addEventListener("ipam:inheritance-updated", updateInheritedFields);
  form.addEventListener("input", updateParentRequirement);
  form.addEventListener("change", updateParentRequirement);
  updateInheritedFields();
  updateParentRequirement();
  filterOptions();
  updateQuickLinks();
  updateSummary();
  form.querySelector("[data-ipam-vlan-quick]")?.addEventListener("click", () => {
    const dialog = document.createElement("dialog");
    dialog.className = "quick-entry-dialog ipam-vlan-dialog";
    dialog.innerHTML = `<div class="quick-entry-dialog-inner"><header class="quick-entry-dialog-header"><div><p class="eyebrow">Cadastro rápido</p><h2>Registrar VLAN</h2></div><button class="dialog-close" type="button" aria-label="Fechar">×</button></header><div class="form-grid"><label><span>Identificação da VLAN *</span><input data-vlan-value required inputmode="numeric" placeholder="Ex.: 120"></label><label class="full"><span>Descrição</span><input data-vlan-description placeholder="Ex.: Clientes corporativos Curitiba"></label></div><div class="form-actions"><button class="button button-secondary" type="button" data-vlan-cancel>Cancelar</button><button class="button button-primary" type="button" data-vlan-apply>Adicionar VLAN</button></div></div>`;
    document.body.append(dialog);
    const close = () => dialog.close();
    dialog.querySelector(".dialog-close").addEventListener("click", close);
    dialog.querySelector("[data-vlan-cancel]").addEventListener("click", close);
    dialog.querySelector("[data-vlan-apply]").addEventListener("click", () => {
      const value = dialog.querySelector("[data-vlan-value]").value.trim();
      if (!value) { dialog.querySelector("[data-vlan-value]").classList.add("is-required-missing"); return; }
      const description = dialog.querySelector("[data-vlan-description]").value.trim();
      const input = form.elements.vlan;
      if (input) { input.value = description ? `${value} · ${description}` : value; input.dispatchEvent(new Event("input", {bubbles: true})); }
      close();
    });
    dialog.addEventListener("close", () => dialog.remove(), {once: true});
    dialog.showModal();
  });
};

document.querySelectorAll("form[data-ipam-allocation-form]").forEach((form) => window.initIpamAllocationForm(form));
document.querySelectorAll("form[data-equipment-form]").forEach((form) => window.initIpamEquipmentForm(form));

(() => {
  const isFormRoute = (href) => /\/(?:new|edit)(?:[/?#]|$)/.test(new URL(href, window.location.href).pathname);
  const extractForm = (html, url) => {
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const form = parsed.querySelector("main form.form-card, main form[data-quick-form], main form");
    if (!form) return null;
    if (!form.getAttribute("action")) form.setAttribute("action", url);
    const flashes = parsed.querySelector(".flash-stack");
    return {form, flashes};
  };
  const attachForm = (dialog, form) => {
    const body = dialog.querySelector("[data-quick-dialog-body]");
    body.replaceChildren(form);
    form.classList.add("quick-entry-form");
    window.applyFieldExamples?.(body);
    window.initIpamAllocationForm?.(form);
    window.initIpamEquipmentForm?.(form);
    form.querySelectorAll("[data-service-picker]").forEach((picker) => window.initQuickServicePicker?.(picker));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = form.querySelector("button[type=submit]");
      if (submit) { submit.disabled = true; submit.dataset.previousLabel = submit.textContent; submit.textContent = "Salvando…"; }
      const response = await fetch(form.action || window.location.href, {method: form.method || "POST", body: new FormData(form), credentials: "same-origin", headers: {"X-Requested-With": "XMLHttpRequest", Accept: "text/html"}});
      if (response.redirected || !isFormRoute(response.url)) {
        const resultName = form.dataset.quickResultName;
        const resultUrl = new URL(response.url, window.location.href);
        const resultId = resultUrl.searchParams.get("equipment_created") || resultUrl.searchParams.get("pop_created");
        if (resultName && resultId) {
          const isPop = resultUrl.searchParams.has("pop_created");
          const resultLabel = resultUrl.searchParams.get(isPop ? "pop_name" : "equipment_name") || `${isPop ? "POP/DC" : "Equipamento"} ${resultId}`;
          document.querySelectorAll(`[name="${CSS.escape(resultName)}"]`).forEach((select) => {
            if (![...select.options].some((option) => option.value === resultId)) select.add(new Option(resultLabel, resultId));
            select.value = resultId;
            select.dispatchEvent(new Event("change", {bubbles: true}));
          });
          dialog.close();
          return;
        }
        dialog.close(); window.location.reload(); return;
      }
      const extracted = extractForm(await response.text(), response.url);
      if (extracted) {
        const flash = extracted.flashes;
        attachForm(dialog, extracted.form);
        if (flash) {
          flash.classList.add("quick-entry-errors");
          body.append(flash);
          window.highlightMissingRequired?.(body);
        }
      }
    });
    form.querySelectorAll("input, textarea").forEach((field) => { if (!field.placeholder && field.name) field.dispatchEvent(new Event("input")); });
    form.querySelectorAll("[data-service-picker]").forEach((picker) => window.initQuickServicePicker?.(picker));
  };
  const openQuickLink = async (link, event) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    const response = await fetch(link.href, {credentials: "same-origin", headers: {"X-Requested-With": "XMLHttpRequest", Accept: "text/html"}});
    const extracted = extractForm(await response.text(), link.href);
    if (!extracted) { window.location.assign(link.href); return; }
    const quickResultName = new URL(link.href, window.location.href).searchParams.get("result_name");
    if (quickResultName) extracted.form.dataset.quickResultName = quickResultName;
    const dialog = document.createElement("dialog");
    dialog.className = "quick-entry-dialog";
    dialog.innerHTML = `<div class="quick-entry-dialog-inner"><header class="quick-entry-dialog-header"><div><p class="eyebrow">Cadastro rápido</p><h2>${link.textContent.trim() || "Editar registro"}</h2></div><button class="dialog-close" type="button" aria-label="Fechar">×</button></header><div data-quick-dialog-body></div></div>`;
    document.body.append(dialog);
    dialog.querySelector(".dialog-close").addEventListener("click", () => dialog.close());
    dialog.addEventListener("close", () => dialog.remove());
    attachForm(dialog, extracted.form);
    dialog.showModal();
  };
  document.querySelectorAll("a[data-quick-create], main a[href]").forEach((link) => {
    if (!link.matches("[data-quick-create]") && !isFormRoute(link.href)) return;
    link.dataset.quickCreateBound = "1";
    link.addEventListener("click", (event) => openQuickLink(link, event));
  });
  document.addEventListener("click", (event) => {
    const link = event.target.closest("a[data-quick-create]");
    if (link && !link.dataset.quickCreateBound) openQuickLink(link, event);
  });
})();

(() => {
  let dialog;
  let map;
  let marker;
  let form;
  let addressField;
  let latitudeField;
  let longitudeField;
  let searchField;
  let status;
  const brazilCenter = [-15.78, -47.93];
  const readCoordinate = (field) => {
    const value = Number.parseFloat(String(field?.value || "").replace(",", "."));
    return Number.isFinite(value) ? value : null;
  };
  const updateCoordinates = (lat, lng) => {
    if (!latitudeField || !longitudeField) return;
    latitudeField.value = Number(lat).toFixed(7).replace(/0+$/, "").replace(/\.$/, "");
    longitudeField.value = Number(lng).toFixed(7).replace(/0+$/, "").replace(/\.$/, "");
    latitudeField.dispatchEvent(new Event("input", {bubbles: true}));
    longitudeField.dispatchEvent(new Event("input", {bubbles: true}));
    form?.dispatchEvent(new Event("ipam:coordinates-updated"));
    if (status) status.textContent = `Marcador em ${latitudeField.value}, ${longitudeField.value}.`;
  };
  const placeMarker = (lat, lng, center = true) => {
    if (!map) return;
    const point = [lat, lng];
    if (!marker) {
      marker = L.marker(point, {draggable: true, icon: L.divIcon({className: "ipam-map-pin-wrap", html: '<span class="ipam-map-pin" aria-hidden="true"></span>', iconSize: [24, 32], iconAnchor: [12, 31]})}).addTo(map);
      marker.on("dragend", () => { const position = marker.getLatLng(); updateCoordinates(position.lat, position.lng); });
    } else marker.setLatLng(point);
    if (center) map.setView(point, Math.max(map.getZoom(), 14));
    updateCoordinates(lat, lng);
  };
  const close = () => {
    if (!dialog) return;
    if (map) map.remove();
    map = null; marker = null; dialog.remove(); dialog = null; form = null;
    addressField = null; latitudeField = null; longitudeField = null; searchField = null; status = null;
  };
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-location-picker-trigger], [data-ipam-location-trigger]");
    if (!trigger) return;
    event.preventDefault();
    form = trigger.closest("form");
    const field = (name, fallback) => form?.elements?.namedItem(name || fallback) || null;
    addressField = field(trigger.dataset.locationAddressField, "allocation_address");
    latitudeField = field(trigger.dataset.locationLatitudeField, "latitude");
    longitudeField = field(trigger.dataset.locationLongitudeField, "longitude");
    const title = trigger.dataset.locationTitle || "Definir endereço exato";
    dialog = document.createElement("dialog");
    dialog.className = "ipam-location-dialog";
    dialog.innerHTML = `<div class="ipam-location-dialog-inner"><header class="quick-entry-dialog-header"><div><p class="eyebrow">Localização operacional</p><h2>${title}</h2><p class="muted">Pesquise o endereço e ajuste o marcador no mapa.</p></div><button class="dialog-close" type="button" aria-label="Fechar">×</button></header><div class="ipam-location-tools"><label><span>Endereço para localizar</span><div class="field-with-action"><input data-ipam-location-search type="search" placeholder="Ex.: Av. Paulista, 1000, São Paulo/SP"><button class="button button-secondary" type="button" data-ipam-location-search-button>Localizar</button></div></label><p class="muted" data-ipam-location-status>Você também pode clicar no mapa ou arrastar o marcador.</p></div><div class="ipam-location-map" data-ipam-location-map></div><footer class="ipam-location-footer"><span class="muted" data-ipam-location-coordinates>Coordenadas ainda não definidas.</span><div><button class="button button-secondary" type="button" data-ipam-location-cancel>Cancelar</button><button class="button button-primary" type="button" data-ipam-location-apply>Aplicar localização</button></div></footer></div>`;
    document.body.append(dialog);
    searchField = dialog.querySelector("[data-ipam-location-search]");
    status = dialog.querySelector("[data-ipam-location-status]");
    const coordinates = dialog.querySelector("[data-ipam-location-coordinates]");
    if (addressField?.value) searchField.value = addressField.value;
    const syncCoordinatesLabel = () => { if (coordinates) coordinates.textContent = latitudeField?.value && longitudeField?.value ? `Coordenadas: ${latitudeField.value}, ${longitudeField.value}` : "Coordenadas ainda não definidas."; };
    dialog.querySelector("[data-ipam-location-search-button]").addEventListener("click", async () => {
      const query = searchField.value.trim();
      if (!query) { status.textContent = "Digite um endereço para localizar."; return; }
      status.textContent = "Localizando endereço…";
      try {
        const url = new URL("/geocode", window.location.origin);
        url.searchParams.set("q", query);
        const response = await fetch(url, {credentials: "same-origin", headers: {Accept: "application/json"}});
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.error || "O serviço de localização está indisponível no momento.");
        const results = Array.isArray(payload.results) ? payload.results : [];
        if (!results.length) throw new Error("Endereço não encontrado.");
        placeMarker(Number(results[0].lat), Number(results[0].lon));
        status.textContent = results[0].display_name || "Endereço localizado.";
        syncCoordinatesLabel();
      } catch (error) { status.textContent = error.message || "Não foi possível localizar o endereço. Ajuste o marcador manualmente."; }
    });
    searchField.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      dialog.querySelector("[data-ipam-location-search-button]").click();
    });
    dialog.querySelector("[data-ipam-location-map]");
    dialog.querySelector("[data-ipam-location-cancel]").addEventListener("click", close);
    dialog.querySelector(".dialog-close").addEventListener("click", close);
    dialog.querySelector("[data-ipam-location-apply]").addEventListener("click", () => {
      if (addressField && searchField.value.trim()) addressField.value = searchField.value.trim();
      addressField?.dispatchEvent(new Event("input", {bubbles: true}));
      close();
    });
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); close(); });
    dialog.addEventListener("close", close);
    dialog.showModal();
    map = L.map(dialog.querySelector("[data-ipam-location-map]"), {scrollWheelZoom: true, zoomControl: true}).setView(brazilCenter, 4);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {maxZoom: 19, attribution: '&copy; OpenStreetMap'}).addTo(map);
    map.on("click", (mapEvent) => { placeMarker(mapEvent.latlng.lat, mapEvent.latlng.lng, false); syncCoordinatesLabel(); });
    const existingLat = readCoordinate(latitudeField);
    const existingLng = readCoordinate(longitudeField);
    if (existingLat !== null && existingLng !== null) placeMarker(existingLat, existingLng);
    setTimeout(() => map?.invalidateSize(), 50);
  });
})();
document.querySelectorAll("[data-dashboard-datetime]").forEach((element) => {
  const date = new Date(element.dataset.dashboardDatetime);
  if (!Number.isNaN(date.getTime())) {
    element.textContent = new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short" }).format(date);
  }
});

(() => {
  const dashboard = document.querySelector("[data-dashboard-operations]");
  if (!dashboard) return;
  const onlineCount = document.querySelector("[data-dashboard-online-count]");
  const runningCount = document.querySelector("[data-dashboard-running-scan-count]");
  const recentList = document.querySelector("[data-dashboard-recent-list]");
  const emptyState = document.querySelector("[data-dashboard-recent-empty]");
  const dateFormatter = new Intl.DateTimeFormat("pt-BR", {dateStyle: "short", timeStyle: "short"});
  const formatDate = (value) => {
    const date = new Date(value || "");
    return Number.isNaN(date.getTime()) ? String(value || "") : dateFormatter.format(date);
  };
  const badgeClass = (slug) => slug === "listed" || slug === "failed" ? "badge badge-error" : slug === "clean" ? "badge badge-ok" : "badge badge-warning";
  const renderRecent = (scans) => {
    if (!recentList) return;
    recentList.replaceChildren();
    const items = Array.isArray(scans) ? scans : [];
    recentList.hidden = items.length === 0;
    if (emptyState) emptyState.hidden = items.length > 0;
    items.forEach((scan) => {
      const item = document.createElement("li");
      item.className = "scanned-item";
      const link = document.createElement("a");
      link.className = "scanned-item-link";
      link.href = scan.scan_url || "#";
      const details = document.createElement("div");
      const target = document.createElement("strong");
      target.textContent = scan.target || "Alvo não informado";
      const actor = document.createElement("small");
      actor.textContent = `${scan.requester_name || "Usuário"} · ${scan.requester_email || ""}`;
      const reference = document.createElement("small");
      reference.textContent = `${scan.reference || ""} · ${formatDate(scan.created_at)}`;
      details.append(target, actor, reference);
      const badge = document.createElement("span");
      badge.className = badgeClass(scan.result_slug);
      badge.textContent = scan.result_label || "Sem resultado";
      link.append(details, badge);
      item.append(link);
      recentList.append(item);
    });
  };
  const refreshDashboardOperations = async () => {
    try {
      const response = await fetch(dashboard.dataset.dashboardOperationsUrl, {credentials: "same-origin", cache: "no-store", headers: {Accept: "application/json"}});
      if (!response.ok) return;
      const payload = await response.json();
      if (onlineCount) onlineCount.textContent = String(payload.online_user_count ?? 0);
      if (runningCount) runningCount.textContent = String(payload.running_scan_count ?? 0);
      renderRecent(payload.recent_health_scans);
    } catch (_) {
      // The server-rendered values remain visible if a background refresh fails.
    }
  };
  refreshDashboardOperations();
  window.setInterval(refreshDashboardOperations, 10000);
})();
