"use strict";

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
document.querySelectorAll("select[data-auto-submit]").forEach((select) => select.addEventListener("change", () => select.form.submit()));
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
  const map = L.map(container, {scrollWheelZoom: true, zoomControl: true, attributionControl: false, minZoom: 2, maxZoom: 12});
  L.control.attribution({prefix: false, position: "bottomright"}).addTo(map);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
  }).addTo(map);
  const stateData = new Map((mapData.states || []).map((item) => [item.region, item]));
  const macroCoordinates = {"Norte": [-5.5, -60], "Nordeste": [-8.5, -42], "Centro-Oeste": [-15, -55], "Sudeste": [-20.5, -44], "Sul": [-27, -52]};
  const cityCoordinates = new Map();
  let stateLayer;
  const markerGroup = L.layerGroup().addTo(map);
  const markerIcon = (label, size) => L.divIcon({className: "map-count-marker-wrap", html: `<span class="map-count-marker" style="--marker-size:${size}px">${escapeHtml(label)}</span>`, iconSize: [size, size], iconAnchor: [size / 2, size / 2]});

  const currentLevel = () => map.getZoom() < 4 ? "macroregions" : (map.getZoom() < 7 ? "states" : "cities");
  const drawMarkers = () => {
    markerGroup.clearLayers();
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
