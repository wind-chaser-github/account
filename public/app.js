const app = document.getElementById("app");

const state = {
  auth: "checking",
  user: null,
  token: localStorage.getItem("vault_token") || "",
  vaultEnvelope: null,
  vault: null,
  unlocked: false,
  passphrase: "",
  selectedId: null,
  search: "",
  category: "All",
  notice: {
    text: "正在验证登录状态。",
    tone: "info",
  },
  syncStatus: "idle",
  syncing: false,
  dirty: false,
  lastSyncAt: null,
  vaultMode: "locked",
  creatingVault: false,
  importError: "",
};

const iterations = 310000;
let syncTimer = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function randomId() {
  return crypto.randomUUID();
}

function nowIso() {
  return new Date().toISOString();
}

function setNotice(text, tone = "info") {
  state.notice = { text, tone };
  render();
}

function setSyncStatus(syncStatus, message) {
  state.syncStatus = syncStatus;
  if (typeof message === "string") {
    state.notice = {
      text: message,
      tone: syncStatus === "error" ? "error" : syncStatus === "synced" ? "success" : "info",
    };
  }
  render();
}

function visibleRecords() {
  const records = state.vault?.records || [];
  const query = state.search.trim().toLowerCase();
  return records.filter((record) => {
    const matchesCategory =
      state.category === "All" || record.category === state.category;
    const haystack = [record.title, record.category, record.username, record.url, record.notes]
      .join(" ")
      .toLowerCase();
    const matchesQuery = !query || haystack.includes(query);
    return matchesCategory && matchesQuery;
  });
}

function categoryList() {
  const categories = new Set(["All"]);
  for (const record of state.vault?.records || []) {
    if (record.category) categories.add(record.category);
  }
  return Array.from(categories);
}

function stats() {
  const records = state.vault?.records || [];
  const categories = categoryList().length - 1;
  const dirty = state.dirty ? "待同步" : "已同步";
  return {
    entries: records.length,
    categories,
    sync: dirty,
  };
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, {
    ...options,
    headers,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP_${response.status}`);
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function deriveKey(passphrase, saltBytes, iter = iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: iter,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(vault, passphrase, meta = {}) {
  const salt = meta.saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const iv = meta.ivBytes || crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, meta.iterations || iterations);
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return {
    version: 1,
    iterations: meta.iterations || iterations,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptVault(envelope, passphrase) {
  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const key = await deriveKey(passphrase, salt, envelope.iterations || iterations);
  const cipherBytes = base64ToBytes(envelope.ciphertext);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBytes);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function emptyVault() {
  return {
    version: 1,
    updatedAt: nowIso(),
    records: [],
  };
}

function maskedPassword(value) {
  if (!value) return "未设置";
  return "•".repeat(Math.max(8, Math.min(18, value.length)));
}

function formatDate(iso) {
  if (!iso) return "刚刚";
  try {
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

function selectedRecord() {
  return state.vault?.records?.find((item) => item.id === state.selectedId) || null;
}

function updateVault(nextVault, { silent = false } = {}) {
  state.vault = nextVault;
  state.dirty = true;
  state.lastSyncAt = state.lastSyncAt || null;
  if (!state.selectedId && nextVault.records.length) {
    state.selectedId = nextVault.records[0].id;
  }
  if (!silent) {
    setNotice("本地已更新，准备同步到云端。", "info");
    scheduleSync();
  } else {
    render();
  }
}

function scheduleSync() {
  if (!state.unlocked || !state.token || !state.passphrase) return;
  window.clearTimeout(syncTimer);
  syncTimer = window.setTimeout(() => {
    syncVault().catch((error) => {
      console.error(error);
      setSyncStatus("error", "同步失败，数据仍保留在本地。");
    });
  }, 650);
}

async function syncVault() {
  if (!state.unlocked || !state.vault || !state.passphrase) return;
  state.syncing = true;
  render();
  const envelope = await encryptVault(state.vault, state.passphrase, {
    iterations,
    saltBytes: state.vaultEnvelope ? base64ToBytes(state.vaultEnvelope.salt) : undefined,
    ivBytes: crypto.getRandomValues(new Uint8Array(12)),
    iterations: state.vaultEnvelope?.iterations || iterations,
  });
  const payload = await api("/api/vault", {
    method: "PUT",
    body: JSON.stringify({ vault: envelope }),
  });
  state.vaultEnvelope = payload.vault;
  state.dirty = false;
  state.syncing = false;
  state.lastSyncAt = nowIso();
  setSyncStatus("synced", "密文保险库已同步到云端。");
}

function updateStatsPanel() {
  const visible = visibleRecords();
  const info = stats();
  return `
    <div class="hero">
      <section class="panel hero-copy">
        <span class="kicker">Zero-knowledge vault</span>
        <h2>把账号密码锁进本地，只把密文放上云。</h2>
        <p>
          这是一个可部署的安全密码柜原型：登录由服务端验证，保险库在本地解锁和加密。
          云端只保存密文，浏览器负责分类、查看、更新、删除和备份。
        </p>
        <div class="hero-grid">
          <div class="metric">
            <span>条目</span>
            <strong>${info.entries}</strong>
          </div>
          <div class="metric">
            <span>分类</span>
            <strong>${info.categories}</strong>
          </div>
          <div class="metric">
            <span>同步</span>
            <strong>${escapeHtml(info.sync)}</strong>
          </div>
        </div>
      </section>
      <aside class="panel security-card">
        <div>
          <h3>安全边界</h3>
          <p class="helper">服务器不接触保险库明文。浏览器输入的解锁口令只用于本地推导密钥。</p>
        </div>
        <div class="security-rows">
          <div class="security-row">
            <div>
              <strong>${state.auth === "signedIn" ? "账号已登录" : "需要登录"}</strong>
              <small>云端身份与本地解锁分离</small>
            </div>
            <span class="state-badge ${state.auth === "signedIn" ? "" : "warn"}">${state.auth === "signedIn" ? "在线" : "未登录"}</span>
          </div>
          <div class="security-row">
            <div>
              <strong>${state.unlocked ? "保险库已解锁" : "保险库已锁定"}</strong>
              <small>${state.unlocked ? "仅当前会话持有明文" : "需要输入本地口令"}</small>
            </div>
            <span class="state-badge ${state.unlocked ? "" : "warn"}">${state.unlocked ? "本地" : "锁定"}</span>
          </div>
          <div class="security-row">
            <div>
              <strong>${state.syncing ? "正在同步" : state.dirty ? "待同步" : "已同步"}</strong>
              <small>${state.lastSyncAt ? `最近同步 ${formatDate(state.lastSyncAt)}` : "尚未完成同步"}</small>
            </div>
            <span class="state-badge ${state.dirty ? "info" : ""}">${state.dirty ? "待写入" : "稳定"}</span>
          </div>
        </div>
      </aside>
    </div>
    <div class="content">
      <section class="panel card">
        <div class="form-head">
          <div>
            <h3 class="section-title">保险库条目</h3>
            <div class="helper">自由分类、搜索、更新和删除。当前列表会实时保留在本地并同步密文到云端。</div>
          </div>
          <button class="primary" data-action="new-record">新建条目</button>
        </div>
        <div class="toolbar">
          <input id="search" placeholder="搜索站点、用户名、备注..." value="${escapeHtml(state.search)}" />
          <select id="category">
            ${categoryList()
              .map((category) => `<option value="${escapeHtml(category)}" ${category === state.category ? "selected" : ""}>${escapeHtml(category)}</option>`)
              .join("")}
          </select>
          <button class="secondary" data-action="generate-password">生成密码</button>
          <button class="secondary" data-action="export-backup">导出密文备份</button>
        </div>
        <div class="tags">
          ${categoryList()
            .map((category) => `<button class="tag ${category === state.category ? "active" : ""}" data-category="${escapeHtml(category)}">${escapeHtml(category)}</button>`)
            .join("")}
        </div>
        <div style="height: 16px"></div>
        <div class="record-list">
          ${visible.length
            ? visible
                .map(
                  (record) => `
                  <button class="record ${record.id === state.selectedId ? "active" : ""}" data-select="${record.id}">
                    <div>
                      <div class="record-title">
                        <strong>${escapeHtml(record.title)}</strong>
                        <span class="state-badge info">${escapeHtml(record.category || "未分类")}</span>
                      </div>
                      <div class="record-meta">
                        <div>${escapeHtml(record.username || "无用户名")}</div>
                        <div>${escapeHtml(record.url || "无网址")}</div>
                        <div>${escapeHtml(maskedPassword(record.password))}</div>
                      </div>
                    </div>
                    <div class="record-actions">
                      <span>${formatDate(record.updatedAt)}</span>
                    </div>
                  </button>
                `
                )
                .join("")
            : `<div class="empty-state">还没有条目。点击“新建条目”开始保存第一条账号信息。</div>`}
        </div>
      </section>
      <aside class="sidebar">
        <section class="panel card">
          <div class="form-head">
            <div>
              <h3 class="section-title">${selectedRecord() ? "编辑条目" : "新建条目"}</h3>
              <div class="helper">字段变化只会在本地更新，点击保存后才会重新加密并同步。</div>
            </div>
            <span class="state-badge ${state.unlocked ? "" : "warn"}">${state.unlocked ? "可编辑" : "已锁定"}</span>
          </div>
          ${state.unlocked ? recordForm() : `<div class="empty-state">先解锁保险库，才能查看或编辑条目。</div>`}
        </section>
        <section class="panel card">
          <div class="form-head">
            <div>
              <h3 class="section-title">同步与备份</h3>
              <div class="helper">云端仅保存密文。导出的备份同样是加密后的数据包。</div>
            </div>
          </div>
          <div class="stack">
            <div class="notice ${state.notice.tone}">${escapeHtml(state.notice.text)}</div>
            <div class="footer-row">
              <button class="primary" data-action="force-sync" ${state.unlocked && state.token ? "" : "disabled"}>立即同步</button>
              <button class="secondary" data-action="download-backup" ${state.unlocked ? "" : "disabled"}>下载备份</button>
              <button class="secondary" data-action="import-backup">导入备份</button>
            </div>
            <div class="subtle">
              最近同步：${state.lastSyncAt ? formatDate(state.lastSyncAt) : "尚未同步"}。
              服务器不保存解锁口令。
            </div>
          </div>
        </section>
      </aside>
    </div>
  `;
}

function recordForm() {
  const record = selectedRecord();
  const formTitle = record ? "编辑当前条目" : "保存新凭据";
  const value = (field) => escapeHtml(record?.[field] || "");
  return `
    <form id="record-form" class="form-grid">
      <div class="helper">${formTitle}。分类字段支持自由输入，筛选标签会自动跟随记录内容。</div>
      <div class="field-grid">
        <input name="title" placeholder="站点 / 服务名称" autocomplete="organization" value="${value("title")}" required />
        <input name="category" placeholder="分类，例如 工作 / 个人 / 金融" autocomplete="off" value="${value("category")}" />
      </div>
      <div class="field-grid">
        <input name="username" placeholder="用户名 / 邮箱" autocomplete="username" value="${value("username")}" />
        <input name="url" placeholder="网址 / App 名称" autocomplete="url" value="${value("url")}" />
      </div>
      <input name="password" placeholder="密码" autocomplete="new-password" value="${value("password")}" required />
      <textarea name="notes" placeholder="备注、恢复码、提醒等">${value("notes")}</textarea>
      <div class="footer-row">
        <button class="primary" type="submit">${record ? "更新条目" : "保存条目"}</button>
        <button class="secondary" type="button" data-action="fill-generated">填入生成密码</button>
        <button class="danger" type="button" data-action="delete-record" ${record ? "" : "disabled"}>删除条目</button>
      </div>
    </form>
  `;
}

function renderAuthScreen() {
  return `
    <div class="auth-wrap">
      <section class="panel auth-card">
        <div class="auth-hero">
          <span class="kicker">Encrypted vault</span>
          <h2>把敏感账号交给本地，把云端留给密文。</h2>
          <p>
            这是一个可部署的零知识保险库原型。登录用于识别用户，保险库口令只在浏览器里推导密钥。
            云端可同步、可备份，但无法读取明文密码。
          </p>
        </div>
        <div class="auth-panels">
          <div class="panel card">
            <h3>登录 / 注册</h3>
            <p class="helper">先创建云端身份，再进入本地保险库。</p>
            <form id="auth-form" class="form-grid">
              <input name="email" type="email" placeholder="邮箱地址" autocomplete="email" required />
              <input name="password" type="password" placeholder="登录密码" autocomplete="current-password" required />
              <div class="split">
                <button class="primary" name="mode" value="login" type="submit">登录</button>
                <button class="secondary" name="mode" value="register" type="submit">注册</button>
              </div>
            </form>
          </div>
          <div class="panel card">
            <h3>安全说明</h3>
            <div class="stack">
              <div class="notice info">登录密码只用于服务器认证，保险库解锁口令不会上传。</div>
              <div class="notice info">云端保存的是 AES-GCM 密文和随机盐值。</div>
              <div class="notice info">导出的备份文件依旧是加密包，可以离线保存。</div>
            </div>
          </div>
        </div>
      </section>
    </div>
  `;
}

function renderUnlockScreen() {
  const vaultExists = Boolean(state.vaultEnvelope);
  const title = vaultExists ? "解锁本地保险库" : "创建你的第一把保险库口令";
  const description = vaultExists
    ? "输入曾经用于加密这份云端密文的口令。服务端不会知道这段明文。"
    : "为新保险库设置一个强口令。之后每次登录后，都用同一口令在本地解锁。";
  return `
    <div class="unlock-wrap">
      <section class="panel auth-card">
        <div class="auth-hero">
          <span class="kicker">Local unlock</span>
          <h2>${title}</h2>
          <p>${description}</p>
        </div>
        <div class="auth-panels">
          <div class="panel card">
            <h3>保险库口令</h3>
            <p class="helper">口令只用于本地解密。忘记口令后，服务器无法帮你恢复明文。</p>
            <form id="unlock-form" class="form-grid">
              <input name="passphrase" type="password" placeholder="输入保险库口令" autocomplete="new-password" required />
              <div class="split">
                <button class="primary" type="submit">${vaultExists ? "解锁并同步" : "创建并加密"}</button>
                <button class="secondary" type="button" data-action="logout">退出登录</button>
              </div>
            </form>
            <div style="height: 10px"></div>
            <div class="notice ${state.importError ? "error" : "info"}">${escapeHtml(state.importError || "如果你已经有导出的加密备份，也可以稍后通过同步面板导入。")}</div>
          </div>
          <div class="panel card">
            <h3>提示</h3>
            <div class="stack">
              <div class="notice info">建议使用长度高于 16 位的口令。</div>
              <div class="notice info">创建成功后，第一版保险库会自动生成空白密文并同步云端。</div>
              <div class="notice info">后续可自由新增、修改、删除和分类条目。</div>
            </div>
          </div>
        </div>
      </section>
    </div>
  `;
}

function render() {
  if (state.auth === "checking") {
    app.innerHTML = `
      <div class="auth-wrap">
        <section class="panel auth-card">
          <div class="auth-hero">
            <span class="kicker">Loading</span>
            <h2>正在验证会话和密文保险库。</h2>
            <p>请稍候，浏览器正在确认登录状态与云端数据。</p>
          </div>
          <div class="auth-panels">
            <div class="panel card">
              <div class="empty-state">初始化中...</div>
            </div>
          </div>
        </section>
      </div>
    `;
    bindGlobal();
    return;
  }

  if (state.auth !== "signedIn") {
    app.innerHTML = renderAuthScreen();
    bindAuth();
    return;
  }

  if (!state.unlocked) {
    app.innerHTML = renderUnlockScreen();
    bindUnlock();
    return;
  }

  app.innerHTML = `
    <div class="shell">
      <header class="topbar">
        <div class="brand">
          <div class="brand-mark">VK</div>
          <div class="brand-copy">
            <h1>密钥柜 Vault</h1>
            <p>${escapeHtml(state.user?.email || "未登录")} · 云端密文同步已启用</p>
          </div>
        </div>
        <div class="status-pills">
          <div class="pill"><strong>会话</strong> ${state.user?.email || ""}</div>
          <div class="pill"><strong>解锁</strong> 本地</div>
          <div class="pill"><strong>同步</strong> ${state.dirty ? "待写入" : state.syncing ? "进行中" : "稳定"}</div>
          <button class="secondary" data-action="logout">退出</button>
        </div>
      </header>
      ${updateStatsPanel()}
    </div>
  `;
  bindVault();
}

function bindGlobal() {
  // No-op placeholder for loading state.
}

function bindAuth() {
  const form = document.getElementById("auth-form");
  form?.addEventListener("submit", handleAuthSubmit);
}

function bindUnlock() {
  const form = document.getElementById("unlock-form");
  form?.addEventListener("submit", handleUnlockSubmit);
  document.querySelector('[data-action="logout"]')?.addEventListener("click", handleLogout);
}

function bindVault() {
  document.querySelector('[data-action="new-record"]')?.addEventListener("click", () => {
    state.selectedId = null;
    render();
  });
  document.querySelector('[data-action="generate-password"]')?.addEventListener("click", () => {
    const generated = generatePassword();
    navigator.clipboard?.writeText(generated).catch(() => {});
    setNotice(`已生成强密码并复制到剪贴板：${generated}`, "success");
  });
  document.querySelector('[data-action="export-backup"]')?.addEventListener("click", exportBackup);
  document.querySelector('[data-action="download-backup"]')?.addEventListener("click", exportBackup);
  document.querySelector('[data-action="import-backup"]')?.addEventListener("click", () => {
    importBackup().catch((error) => {
      console.error(error);
      setNotice("导入失败，请检查备份文件格式。", "error");
    });
  });
  document.querySelector('[data-action="force-sync"]')?.addEventListener("click", () => {
    syncVault().catch((error) => {
      console.error(error);
      setNotice("同步失败，请稍后重试。", "error");
    });
  });
  document.querySelector('[data-action="fill-generated"]')?.addEventListener("click", () => {
    const input = document.querySelector('#record-form input[name="password"]');
    if (input) {
      const generated = generatePassword();
      input.value = generated;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      setNotice("已填入生成密码。", "success");
    }
  });
  document.querySelector('[data-action="delete-record"]')?.addEventListener("click", handleDeleteRecord);
  document.querySelector('[data-action="logout"]')?.addEventListener("click", handleLogout);
  document.querySelectorAll("[data-select]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedId = button.getAttribute("data-select");
      render();
    });
  });
  document.querySelectorAll("[data-category]").forEach((button) => {
    button.addEventListener("click", () => {
      state.category = button.getAttribute("data-category");
      render();
    });
  });
  const search = document.getElementById("search");
  search?.addEventListener("input", (event) => {
    state.search = event.target.value;
    render();
  });
  const category = document.getElementById("category");
  category?.addEventListener("change", (event) => {
    state.category = event.target.value;
    render();
  });
  const form = document.getElementById("record-form");
  form?.addEventListener("submit", handleRecordSubmit);
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const email = String(formData.get("email") || "").trim().toLowerCase();
  const password = String(formData.get("password") || "");
  const mode = String(event.submitter?.value || "login");
  try {
    const payload =
      mode === "register"
        ? await api("/api/register", {
            method: "POST",
            body: JSON.stringify({ email, password }),
          })
        : await api("/api/login", {
            method: "POST",
            body: JSON.stringify({ email, password }),
          });
    state.token = payload.token;
    localStorage.setItem("vault_token", payload.token);
    state.user = payload.user;
    state.auth = "signedIn";
    state.importError = "";
    setNotice(mode === "register" ? "账号已创建，接下来解锁保险库。" : "登录成功，正在加载保险库。", "success");
    await loadVaultEnvelope();
  } catch (error) {
    console.error(error);
    setNotice(
      error?.message === "ACCOUNT_EXISTS"
        ? "这个邮箱已经注册过了，请直接登录。"
        : error?.message === "INVALID_CREDENTIALS"
          ? "邮箱或密码不正确。"
          : "登录失败，请稍后重试。",
      "error"
    );
  }
}

async function handleUnlockSubmit(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const passphrase = String(formData.get("passphrase") || "");
  state.passphrase = passphrase;
  try {
    if (state.vaultEnvelope) {
      state.vault = await decryptVault(state.vaultEnvelope, passphrase);
      state.unlocked = true;
      state.vaultMode = "locked";
      state.selectedId = state.vault.records[0]?.id || null;
      setNotice("保险库已解锁。", "success");
      render();
      scheduleSync();
      return;
    }
    state.vault = emptyVault();
    state.unlocked = true;
    state.vaultMode = "created";
    state.selectedId = null;
    setNotice("新保险库已创建，正在生成加密密文。", "success");
    render();
    await syncVault();
  } catch (error) {
    console.error(error);
    state.passphrase = "";
    setNotice("解锁失败。请检查口令是否正确。", "error");
  }
}

async function handleRecordSubmit(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const title = String(formData.get("title") || "").trim();
  const category = String(formData.get("category") || "").trim();
  const username = String(formData.get("username") || "").trim();
  const url = String(formData.get("url") || "").trim();
  const password = String(formData.get("password") || "").trim();
  const notes = String(formData.get("notes") || "").trim();

  if (!title || !password) {
    setNotice("标题和密码不能为空。", "error");
    return;
  }

  const existing = selectedRecord();
  const record = {
    id: existing?.id || randomId(),
    title,
    category: category || "未分类",
    username,
    url,
    password,
    notes,
    createdAt: existing?.createdAt || nowIso(),
    updatedAt: nowIso(),
  };

  const records = [...(state.vault?.records || [])];
  const index = records.findIndex((item) => item.id === record.id);
  if (index >= 0) {
    records[index] = record;
  } else {
    records.unshift(record);
  }
  updateVault({ ...state.vault, updatedAt: nowIso(), records });
  state.selectedId = record.id;
  render();
}

async function handleDeleteRecord() {
  const record = selectedRecord();
  if (!record) return;
  const confirmed = confirm(`删除条目“${record.title}”？此操作会同步到云端。`);
  if (!confirmed) return;
  const records = (state.vault?.records || []).filter((item) => item.id !== record.id);
  state.selectedId = records[0]?.id || null;
  updateVault({ ...state.vault, updatedAt: nowIso(), records });
  setNotice("条目已删除。", "success");
  render();
}

async function handleLogout() {
  try {
    if (state.token) {
      await fetch("/api/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${state.token}` },
      });
    }
  } catch {
    // Ignore logout failures.
  }
  localStorage.removeItem("vault_token");
  state.auth = "signedOut";
  state.user = null;
  state.token = "";
  state.vault = null;
  state.vaultEnvelope = null;
  state.unlocked = false;
  state.passphrase = "";
  state.selectedId = null;
  state.dirty = false;
  state.lastSyncAt = null;
  state.notice = {
    text: "你已退出登录。",
    tone: "info",
  };
  render();
}

async function loadSession() {
  if (!state.token) {
    state.auth = "signedOut";
    render();
    return;
  }
  try {
    const payload = await api("/api/me", { method: "GET" });
    state.user = payload.user;
    state.auth = "signedIn";
    await loadVaultEnvelope();
  } catch (error) {
    console.error(error);
    localStorage.removeItem("vault_token");
    state.token = "";
    state.auth = "signedOut";
    render();
  }
}

async function loadVaultEnvelope() {
  try {
    const response = await fetch("/api/vault", {
      method: "GET",
      headers: state.token ? { Authorization: `Bearer ${state.token}` } : {},
    });
    if (response.status === 404) {
      state.vaultEnvelope = null;
      state.vaultMode = "empty";
      state.unlocked = false;
      state.passphrase = "";
      state.vault = null;
      state.selectedId = null;
      state.importError = "";
      render();
      return;
    }
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `HTTP_${response.status}`);
    }
    state.vaultEnvelope = payload.vault;
    state.vaultMode = payload.exists ? "locked" : "empty";
    state.unlocked = false;
    state.passphrase = "";
    state.vault = null;
    state.selectedId = null;
    state.importError = "";
    render();
  } catch (error) {
    console.error(error);
    if (error?.message === "UNAUTHENTICATED") {
      state.auth = "signedOut";
      render();
      return;
    }
    state.vaultEnvelope = null;
    state.vaultMode = "empty";
    render();
  }
}

function generatePassword(length = 20) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*";
  const values = new Uint32Array(length);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => chars[value % chars.length]).join("");
}

async function exportBackup() {
  if (!state.vaultEnvelope) {
    setNotice("当前没有可导出的密文备份。", "error");
    return;
  }
  const payload = {
    app: "encrypted-vault",
    exportedAt: nowIso(),
    vault: state.vaultEnvelope,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  setNotice("密文备份已导出。", "success");
}

async function importBackup() {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = "application/json";
  input.click();
  const file = await new Promise((resolve) => {
    input.addEventListener("change", () => resolve(input.files?.[0] || null), { once: true });
  });
  if (!file) return;
  const text = await file.text();
  const payload = JSON.parse(text);
  if (!payload?.vault?.ciphertext) {
    throw new Error("INVALID_BACKUP");
  }
  state.vaultEnvelope = payload.vault;
  state.vaultMode = "locked";
  state.unlocked = false;
  state.passphrase = "";
  setNotice("备份已导入。请使用对应口令解锁。", "success");
  render();
  if (state.token) {
    await api("/api/vault", {
      method: "PUT",
      body: JSON.stringify({ vault: state.vaultEnvelope }),
    });
    setNotice("备份已导入并同步到云端。", "success");
  }
}

render();
loadSession().finally(() => {
  if (state.auth === "signedIn") {
    if (state.vaultMode === "empty" && !state.vaultEnvelope) {
      setNotice("尚未创建保险库，先输入一个本地口令开始。", "info");
    }
  }
});

