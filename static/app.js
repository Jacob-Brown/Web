const state = {
  user: null,
  presets: [],
  output: "",
};

const elements = {
  authArea: document.getElementById("authArea"),
  signedOutPanel: document.getElementById("signedOutPanel"),
  workspacePanel: document.getElementById("workspacePanel"),
  source: document.getElementById("source"),
  output: document.getElementById("output"),
  preset: document.getElementById("preset"),
  seed: document.getElementById("seed"),
  compression: document.getElementById("compression"),
  antiTamper: document.getElementById("antiTamper"),
  injectInvite: document.getElementById("injectInvite"),
  discordInvite: document.getElementById("discordInvite"),
  fileInput: document.getElementById("fileInput"),
  clearSource: document.getElementById("clearSource"),
  obfuscateButton: document.getElementById("obfuscateButton"),
  copyOutput: document.getElementById("copyOutput"),
  downloadOutput: document.getElementById("downloadOutput"),
  metrics: document.getElementById("metrics"),
  diagnostics: document.getElementById("diagnostics"),
  status: document.getElementById("status"),
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Request failed.");
  }
  return data;
}

function setStatus(message, isError = false) {
  elements.status.textContent = message;
  elements.status.style.color = isError ? "#f87171" : "#9fb0c9";
}

function renderAuth() {
  if (state.user) {
    elements.authArea.innerHTML = `
      <span class="muted">${escapeHtml(state.user.global_name)}</span>
      <a class="button secondary" href="/auth/logout">Sign out</a>
    `;
    elements.signedOutPanel.classList.add("hidden");
    elements.workspacePanel.classList.remove("hidden");
  } else {
    elements.authArea.innerHTML = `<a class="button secondary" href="/auth/discord">Sign in with Discord</a>`;
    elements.signedOutPanel.classList.remove("hidden");
    elements.workspacePanel.classList.add("hidden");
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function loadSession() {
  try {
    state.user = await api("/api/me", { method: "GET" });
  } catch {
    state.user = null;
  }
  renderAuth();
}

async function loadPresets() {
  try {
    const data = await api("/api/presets", { method: "GET" });
    state.presets = data.presets || [];
    elements.preset.innerHTML = state.presets.map((preset) => `<option value="${preset}">${preset}</option>`).join("");
    const preferred = state.presets.includes("maximum") ? "maximum" : state.presets[0];
    if (preferred) elements.preset.value = preferred;
  } catch (error) {
    setStatus(error.message, true);
  }
}

elements.fileInput.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  elements.source.value = await file.text();
  setStatus(`Loaded ${file.name}.`);
});

elements.clearSource.addEventListener("click", () => {
  elements.source.value = "";
  elements.output.value = "";
  elements.metrics.innerHTML = "";
  elements.diagnostics.textContent = "";
  state.output = "";
  setStatus("Workspace cleared.");
});

elements.obfuscateButton.addEventListener("click", async () => {
  if (!state.user) {
    setStatus("Sign in with Discord first.", true);
    return;
  }
  const source = elements.source.value;
  if (!source.trim()) {
    setStatus("Source is empty.", true);
    return;
  }

  const antiTamperValue = elements.antiTamper.value;
  const payload = {
    source,
    preset: elements.preset.value,
    seed: elements.seed.value.trim() || null,
    compression: elements.compression.value.trim() || null,
    anti_tamper: antiTamperValue === "" ? null : antiTamperValue === "true",
    discord_invite: elements.discordInvite.value.trim() || null,
    inject_discord_invite: elements.injectInvite.checked,
  };

  elements.obfuscateButton.disabled = true;
  setStatus("Obfuscating...");
  try {
    const result = await api("/api/obfuscate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.output = result.output;
    elements.output.value = result.output;
    elements.metrics.innerHTML = `
      <div><span>Input</span><strong>${result.input_bytes} B</strong></div>
      <div><span>Output</span><strong>${result.output_bytes} B</strong></div>
      <div><span>Time</span><strong>${result.duration_ms} ms</strong></div>
    `;
    elements.diagnostics.textContent = (result.diagnostics || []).join("\n");
    setStatus(`Completed with preset ${result.preset} and seed ${result.seed}.`);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    elements.obfuscateButton.disabled = false;
  }
});

elements.copyOutput.addEventListener("click", async () => {
  if (!state.output) return;
  await navigator.clipboard.writeText(state.output);
  setStatus("Output copied.");
});

elements.downloadOutput.addEventListener("click", () => {
  if (!state.output) return;
  const blob = new Blob([state.output], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "obfuscated.lua";
  link.click();
  URL.revokeObjectURL(url);
});

Promise.all([loadSession(), loadPresets()]);
EOF