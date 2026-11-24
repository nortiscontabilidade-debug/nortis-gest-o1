const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const T0 = new Date();

const iso = n => {
  if (n == null) return "";
  const x = new Date(T0);
  x.setDate(x.getDate() + n);
  return x.toISOString().slice(0, 10);
};

const fd = v => (v ? v.split("-").reverse().join("/") : "—");
const pad = (n, l) => String(n).padStart(l, "0").slice(-l);
const slug = f => f.toLowerCase().normalize("NFD").replace(/[^a-z]/g, "");
const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
const th = () => {
  const r = document.documentElement;
  r.dataset.theme = r.dataset.theme === "light" ? "dark" : "light";
};

function toast(m) {
  const t = $("#ts");
  if (!t) return;
  t.textContent = m;
  t.style.display = "block";
  setTimeout(() => (t.style.display = "none"), 3000);
}

/* ==========================================================================
   1. CONTROLE DE USUÁRIOS E PERMISSÕES
   ========================================================================== */
const PERMS_DEF = [
  { k: "companies_view", l: "Visualizar empresas", desc: "Listar e abrir dados cadastrais" },
  { k: "companies_edit", l: "Cadastrar e editar empresas", desc: "Criar ou alterar cadastros" },
  { k: "credentials_view", l: "Visualizar credenciais", desc: "Acessar credenciais e senhas" },
  { k: "credentials_reveal", l: "Revelar e copiar senhas", desc: "Visualizar senhas e copiar tokens" },
  { k: "credentials_edit", l: "Cadastrar e editar credenciais", desc: "Adicionar, alterar e remover credenciais" },
  { k: "certificates_view", l: "Visualizar certificados", desc: "Acompanhar validades e certificados" },
  { k: "obligations_manage", l: "Gerenciar obrigações", desc: "Controlar rotinas e prazos fiscais" },
  { k: "history_view", l: "Visualizar históricos", desc: "Acessar trilhas completas de auditoria" },
  { k: "users_manage", l: "Gerenciar usuários", desc: "Convidar, configurar e bloquear usuários" }
];

const MASTER_EMAIL = "sérgio.nortiscontabilidade@gmail.com";

/* ==========================================================================
   CRIPTOGRAFIA & SEGURANÇA AVANÇADA (WEB CRYPTO API)
   ========================================================================== */
async function hashPassword(plainText, salt = "nortis_salt_2026_sec") {
  if (!plainText) return "";
  const enc = new TextEncoder();
  const data = enc.encode(plainText + ":" + salt);
  const hashBuf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

const VAULT_KEY_SEED = "nortis_vault_master_key_v1_2026";
async function getVaultKey() {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(VAULT_KEY_SEED),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("nortis_salt_fixed_vault_2026"),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVaultSecret(plainText) {
  if (!plainText) return "";
  if (typeof plainText === "string" && plainText.startsWith("enc:")) return plainText;
  try {
    const key = await getVaultKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const cipherBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      enc.encode(plainText)
    );
    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, "0")).join("");
    const cipherHex = Array.from(new Uint8Array(cipherBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
    return "enc:" + ivHex + ":" + cipherHex;
  } catch (e) {
    console.warn("Criptografia local fallback:", e);
    return plainText;
  }
}

async function decryptVaultSecret(cipherText) {
  if (!cipherText) return "";
  if (typeof cipherText !== "string" || !cipherText.startsWith("enc:")) return cipherText;
  try {
    const parts = cipherText.split(":");
    if (parts.length !== 3) return cipherText;
    const ivHex = parts[1];
    const dataHex = parts[2];
    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const cipherBuffer = new Uint8Array(dataHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const key = await getVaultKey();
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipherBuffer
    );
    return new TextDecoder().decode(decryptedBuffer);
  } catch (e) {
    console.warn("Descriptografia cofre:", e);
    return "(erro ao descriptografar)";
  }
}

function toggleMobileMenu(forceState) {
  const aside = document.querySelector("aside");
  const backdrop = document.getElementById("menu-backdrop");
  if (!aside) return;
  const shouldOpen = typeof forceState === "boolean" ? forceState : !aside.classList.contains("open");
  if (shouldOpen) {
    aside.classList.add("open");
    if (backdrop) backdrop.classList.add("active");
  } else {
    aside.classList.remove("open");
    if (backdrop) backdrop.classList.remove("active");
  }
}

function isMasterEmail(e) {
  const clean = (e || "").trim().toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  return clean === "sergio.nortiscontabilidade@gmail.com";
}

const DEFAULT_USERS = [
  {
    id: "usr-master",
    name: "Sérgio",
    email: MASTER_EMAIL,
    role: "master",
    is_active: true,
    created_at: "2026-01-01T00:00:00.000Z",
    password_hash: "master_auth_hash",
    permissions: PERMS_DEF.reduce((acc, p) => { acc[p.k] = true; return acc; }, {})
  },
  {
    id: "usr-admin-1",
    name: "Rafael Moura",
    email: "rafael.moura@nortiscontabilidade.com.br",
    role: "admin",
    is_active: true,
    created_at: "2026-02-15T10:00:00.000Z",
    password_hash: "admin_auth_hash",
    permissions: {
      companies_view: true, companies_edit: true,
      credentials_view: true, credentials_reveal: true, credentials_edit: true,
      certificates_view: true, obligations_manage: true,
      history_view: true, users_manage: false
    }
  },
  {
    id: "usr-collab-1",
    name: "Camila Ribeiro",
    email: "camila.ribeiro@nortiscontabilidade.com.br",
    role: "collaborator",
    is_active: true,
    created_at: "2026-03-01T14:30:00.000Z",
    password_hash: "collab_auth_hash",
    permissions: {
      companies_view: true, companies_edit: false,
      credentials_view: true, credentials_reveal: false, credentials_edit: false,
      certificates_view: true, obligations_manage: true,
      history_view: false, users_manage: false
    }
  }
];

const DEFAULT_INVITES = [
  {
    id: "inv-101",
    token: "tok_beatriz_nortis_2026",
    name: "Beatriz Lima",
    email: "beatriz.lima@nortiscontabilidade.com.br",
    role: "collaborator",
    invited_by: "Sérgio (Master)",
    invited_at: new Date(Date.now() - 2 * 864e5).toISOString(),
    expires_at: new Date(Date.now() + 5 * 864e5).toISOString(),
    status: "pending",
    accepted_at: null,
    permissions: {
      companies_view: true, companies_edit: false,
      credentials_view: true, credentials_reveal: false, credentials_edit: false,
      certificates_view: true, obligations_manage: true,
      history_view: false, users_manage: false
    }
  }
];

const DEFAULT_AUDIT = [
  {
    id: "aud-01",
    timestamp: new Date(Date.now() - 3600 * 1000).toISOString(),
    user_name: "Sérgio",
    user_email: MASTER_EMAIL,
    action: "login",
    action_label: "Login realizado",
    entity: "auth",
    target: "Sistema Nortis",
    details: "Autenticação do Administrador Master",
    ip: "177.136.241.15"
  }
];

function getStored(key, def) {
  try {
    const v = localStorage.getItem("nortis_" + key);
    return v ? JSON.parse(v) : def;
  } catch (e) {
    return def;
  }
}
function setStored(key, val) {
  try {
    localStorage.setItem("nortis_" + key, JSON.stringify(val));
  } catch (e) {}
}

let USERS = getStored("users", DEFAULT_USERS);
let INVITES = getStored("invites", DEFAULT_INVITES);
let AUDIT_LOGS = getStored("audit", DEFAULT_AUDIT);
let CURRENT_USER = getStored("cur_user", null);

// Assegura que o Administrador Master existe com acesso irrestrito
(function ensureMaster() {
  let m = USERS.find(u => isMasterEmail(u.email));
  if (!m) {
    m = {
      id: "usr-master",
      name: "Sérgio",
      email: MASTER_EMAIL,
      role: "master",
      is_active: true,
      created_at: new Date().toISOString(),
      permissions: PERMS_DEF.reduce((acc, p) => { acc[p.k] = true; return acc; }, {})
    };
    USERS.unshift(m);
    setStored("users", USERS);
  } else {
    m.role = "master";
    m.is_active = true;
    PERMS_DEF.forEach(p => { m.permissions[p.k] = true; });
    setStored("users", USERS);
  }
})();

function recordAudit(action, action_label, entity, target, details) {
  const log = {
    id: "aud-" + Date.now() + "-" + Math.floor(Math.random() * 1000),
    timestamp: new Date().toISOString(),
    user_name: CURRENT_USER ? CURRENT_USER.name : "Sistema",
    user_email: CURRENT_USER ? CURRENT_USER.email : "sistema",
    action,
    action_label,
    entity,
    target,
    details,
    ip: "189.40." + (Math.floor(Math.random() * 200) + 10) + "." + (Math.floor(Math.random() * 200) + 10)
  };
  AUDIT_LOGS.unshift(log);
  if (AUDIT_LOGS.length > 500) AUDIT_LOGS = AUDIT_LOGS.slice(0, 500);
  setStored("audit", AUDIT_LOGS);
}

function hasPerm(permKey) {
  if (!CURRENT_USER || !CURRENT_USER.is_active) return false;
  if (CURRENT_USER.role === "master" || isMasterEmail(CURRENT_USER.email)) return true;
  return !!(CURRENT_USER.permissions && CURRENT_USER.permissions[permKey]);
}

/* ==========================================================================
   2. GERENCIAMENTO DINÂMICO: SEGMENTOS E DEMANDAS CONTRATADAS
   ========================================================================== */
const DEFAULT_SEGMENTS = [
  "E-commerce",
  "Dropshipping",
  "Marketplace",
  "Infoprodutos",
  "Afiliados",
  "Serviços digitais",
  "Consultoria",
  "Saúde & Clínicas",
  "SaaS & Software"
];

let SEGMENTS = getStored("segments", DEFAULT_SEGMENTS);
function saveSegments() { setStored("segments", SEGMENTS); }

function openManageSegmentsModal() {
  renderSegmentListInModal();
  const modal = $("#md-segment");
  if (modal) modal.classList.add("on");
  setTimeout(() => {
    const input = $("#new-segment-name");
    if (input) { input.value = ""; input.focus(); }
  }, 100);
}

function renderSegmentListInModal() {
  const container = $("#segment-list-container");
  if (!container) return;

  container.innerHTML = SEGMENTS.map(s => {
    const count = C.filter(c => c.seg === s).length;
    return `
      <div class="manage-item-row">
        <div>
          <b>${esc(s)}</b>
          <span class="s mu" style="margin-left:6px">(${count} ${count === 1 ? 'empresa vinculada' : 'empresas vinculadas'})</span>
        </div>
        <div style="display:flex;gap:4px">
          <button type="button" class="btn sm" onclick="editSegmentPrompt('${esc(s)}')" title="Editar nome do segmento">Editar</button>
          <button type="button" class="btn sm er" onclick="deleteSegmentCheck('${esc(s)}')" title="Excluir segmento">${count > 0 ? 'Bloqueado' : 'Excluir'}</button>
        </div>
      </div>
    `;
  }).join("");
}

function submitNewSegment() {
  const input = $("#new-segment-name");
  if (!input) return;
  const name = input.value.trim();
  if (!name) {
    toast("Informe o nome do segmento.");
    input.focus();
    return;
  }
  if (SEGMENTS.includes(name)) {
    toast("Este segmento já existe.");
    input.focus();
    return;
  }

  SEGMENTS.push(name);
  saveSegments();
  recordAudit("create_segment", "Criou novo segmento", "segment", name, `Segmento adicionado por ${CURRENT_USER ? CURRENT_USER.name : 'usuário'}`);
  input.value = "";
  renderSegmentListInModal();
  updateSegmentSelects(name);
  toast(`Segmento "${name}" cadastrado com sucesso!`);
}

function editSegmentPrompt(oldName) {
  const newName = prompt(`Informe o novo nome para o segmento "${oldName}":`, oldName);
  if (!newName || !newName.trim() || newName.trim() === oldName) return;
  const trimmed = newName.trim();
  if (SEGMENTS.includes(trimmed)) {
    alert("Já existe outro segmento com este nome.");
    return;
  }

  const idx = SEGMENTS.indexOf(oldName);
  if (idx >= 0) {
    SEGMENTS[idx] = trimmed;
    saveSegments();
    // Atualiza empresas vinculadas
    C.forEach(c => {
      if (c.seg === oldName) c.seg = trimmed;
    });
    saveCompanies();
    if (typeof wizardData === "object" && wizardData && wizardData.seg === oldName) {
      wizardData.seg = trimmed;
    }
    if (typeof D === "object" && D && D.seg === oldName) {
      D.seg = trimmed;
    }
    renderSegmentListInModal();
    updateSegmentSelects(trimmed);
    recordAudit("update_segment", "Editou segmento", "segment", `${oldName} → ${trimmed}`, "Renomeou segmento");
    toast(`Segmento atualizado para "${trimmed}".`);
  }
}

function deleteSegmentCheck(name) {
  const count = C.filter(c => c.seg === name).length;
  if (count > 0) {
    alert(`Não é permitido excluir o segmento "${name}" pois existem ${count} empresa(s) vinculadas a ele.\n\nPara excluir este segmento, altere antes o segmento das empresas vinculadas.`);
    return;
  }

  if (!confirm(`Deseja realmente excluir o segmento "${name}"?`)) return;

  SEGMENTS = SEGMENTS.filter(s => s !== name);
  saveSegments();
  renderSegmentListInModal();
  updateSegmentSelects();
  recordAudit("delete_segment", "Excluiu segmento", "segment", name, "Excluiu segmento sem vínculos");
  toast(`Segmento "${name}" removido.`);
}

function updateSegmentSelects(selectedName) {
  $$("select[data-wp='seg'], select[data-p='seg'], #company-seg-select, #wiz-seg-select").forEach(sel => {
    const curVal = selectedName || sel.value;
    sel.innerHTML = SEGMENTS.map(s => `<option value="${esc(s)}" ${s === curVal ? 'selected' : ''}>${esc(s)}</option>`).join("");
    if (selectedName) sel.value = selectedName;
  });
}

// 2.2 GERENCIAMENTO DE DEMANDAS CONTRATADAS
const DEFAULT_DEMANDS = [
  "Contábil",
  "Fiscal",
  "Departamento Pessoal",
  "Legalização",
  "Consultoria",
  "BPO Financeiro",
  "Outros"
];

let DEMANDS = getStored("demands", DEFAULT_DEMANDS);
function saveDemands() { setStored("demands", DEMANDS); }

function openManageDemandsModal() {
  renderDemandListInModal();
  const modal = $("#md-demand");
  if (modal) modal.classList.add("on");
  setTimeout(() => {
    const input = $("#new-demand-name");
    if (input) { input.value = ""; input.focus(); }
  }, 100);
}

function renderDemandListInModal() {
  const container = $("#demand-list-container");
  if (!container) return;

  container.innerHTML = DEMANDS.map(d => {
    const count = C.filter(c => Array.isArray(c.demandas) && c.demandas.includes(d)).length;
    return `
      <div class="manage-item-row">
        <div>
          <b>${esc(d)}</b>
          <span class="s mu" style="margin-left:6px">(${count} ${count === 1 ? 'empresa vinculada' : 'empresas vinculadas'})</span>
        </div>
        <div style="display:flex;gap:4px">
          <button type="button" class="btn sm" onclick="editDemandPrompt('${esc(d)}')" title="Editar nome da demanda">Editar</button>
          <button type="button" class="btn sm er" onclick="deleteDemandCheck('${esc(d)}')" title="Excluir demanda">${count > 0 ? 'Bloqueado' : 'Excluir'}</button>
        </div>
      </div>
    `;
  }).join("");
}

function submitNewDemand() {
  const input = $("#new-demand-name");
  if (!input) return;
  const name = input.value.trim();
  if (!name) {
    toast("Informe o nome da demanda.");
    input.focus();
    return;
  }
  if (DEMANDS.includes(name)) {
    toast("Esta demanda já existe.");
    input.focus();
    return;
  }

  DEMANDS.push(name);
  saveDemands();
  recordAudit("create_demand", "Criou nova demanda", "demand", name, `Demanda adicionada por ${CURRENT_USER ? CURRENT_USER.name : 'usuário'}`);
  input.value = "";
  renderDemandListInModal();
  if (typeof renderWizard === "function" && wizardStep === 5) renderWizard();
  if (typeof fic === "function" && currentCompanyTab === "demandas") fic();
  toast(`Demanda "${name}" cadastrada com sucesso!`);
}

function editDemandPrompt(oldName) {
  const newName = prompt(`Informe o novo nome para a demanda "${oldName}":`, oldName);
  if (!newName || !newName.trim() || newName.trim() === oldName) return;
  const trimmed = newName.trim();
  if (DEMANDS.includes(trimmed)) {
    alert("Já existe outra demanda com este nome.");
    return;
  }

  const idx = DEMANDS.indexOf(oldName);
  if (idx >= 0) {
    DEMANDS[idx] = trimmed;
    saveDemands();
    // Atualiza empresas vinculadas
    C.forEach(c => {
      if (Array.isArray(c.demandas)) {
        const dIdx = c.demandas.indexOf(oldName);
        if (dIdx >= 0) c.demandas[dIdx] = trimmed;
      }
    });
    saveCompanies();
    if (typeof wizardData === "object" && wizardData && Array.isArray(wizardData.demandas)) {
      const wIdx = wizardData.demandas.indexOf(oldName);
      if (wIdx >= 0) wizardData.demandas[wIdx] = trimmed;
    }
    if (typeof D === "object" && D && Array.isArray(D.demandas)) {
      const dIdx = D.demandas.indexOf(oldName);
      if (dIdx >= 0) D.demandas[dIdx] = trimmed;
    }
    renderDemandListInModal();
    if (typeof renderWizard === "function" && wizardStep === 5) renderWizard();
    if (typeof fic === "function" && currentCompanyTab === "demandas") fic();
    recordAudit("update_demand", "Editou demanda", "demand", `${oldName} → ${trimmed}`, "Renomeou demanda contratada");
    toast(`Demanda atualizada para "${trimmed}".`);
  }
}

function deleteDemandCheck(name) {
  const linked = C.filter(c => Array.isArray(c.demandas) && c.demandas.includes(name));
  if (linked.length > 0) {
    const names = linked.slice(0, 3).map(c => c.fan).join(", ");
    const more = linked.length > 3 ? ` e mais ${linked.length - 3}` : "";
    alert(`Não é possível excluir a demanda "${name}" pois ela está vinculada a ${linked.length} empresa(s) (${names}${more}).\n\nPara excluir, primeiro desvincule esta demanda nas empresas vinculadas.`);
    return;
  }

  if (!confirm(`Deseja realmente excluir a demanda "${name}"?`)) return;

  DEMANDS = DEMANDS.filter(d => d !== name);
  saveDemands();
  renderDemandListInModal();
  if (typeof renderWizard === "function" && wizardStep === 5) renderWizard();
  if (typeof fic === "function" && currentCompanyTab === "demandas") fic();
  recordAudit("delete_demand", "Excluiu demanda", "demand", name, "Excluiu demanda sem vínculos");
  toast(`Demanda "${name}" removida.`);
}

/* ==========================================================================
   2.3 STATUS DO CLIENTE & REGIMES
   ========================================================================== */
const STATUS_CLIENTE_OPTS = ["Ativo", "Suspenso", "Encerrado"];
const REG = ["Simples Nacional", "Lucro Presumido", "Lucro Real", "MEI"];
const OR = ["GOV.BR", "SEFAZ", "Prefeitura", "e-CAC", "FGTS", "Banco", "Marketplace", "Emissor NF-e", "Certificado Digital", "Outro"];
const SIT = ["Ativo", "Revisar", "Pendente"];

function statusClienteBadge(st) {
  const s = st || "Ativo";
  const cls = s === "Ativo" ? "ativo" : (s === "Suspenso" ? "suspenso" : "encerrado");
  return `<span class="status-badge ${cls}">● ${esc(s)}</span>`;
}

/* ==========================================================================
   VALIDAÇÃO, CEP E CONSULTA AUTOMÁTICA DE CNPJ
   ========================================================================== */
function isValidCNPJ(cnpj) {
  if (!cnpj) return false;
  const b = String(cnpj).replace(/\D/g, "");
  if (b.length !== 14) return false;
  if (/^(\d)\1+$/.test(b)) return false;
  let s = 0, p = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  for (let i = 0; i < 12; i++) s += parseInt(b[i]) * p[i];
  let d1 = s % 11 < 2 ? 0 : 11 - (s % 11);
  if (parseInt(b[12]) !== d1) return false;
  s = 0; p = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  for (let i = 0; i < 13; i++) s += parseInt(b[i]) * p[i];
  let d2 = s % 11 < 2 ? 0 : 11 - (s % 11);
  return parseInt(b[13]) === d2;
}

function formatCNPJ(val) {
  const v = String(val || "").replace(/\D/g, "").slice(0, 14);
  if (v.length > 12) return v.replace(/^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/, "$1.$2.$3/$4-$5");
  if (v.length > 8) return v.replace(/^(\d{2})(\d{3})(\d{3})(\d*)$/, "$1.$2.$3/$4");
  if (v.length > 5) return v.replace(/^(\d{2})(\d{3})(\d*)$/, "$1.$2.$3");
  if (v.length > 2) return v.replace(/^(\d{2})(\d*)$/, "$1.$2");
  return v;
}

function formatCEP(val) {
  const v = String(val || "").replace(/\D/g, "").slice(0, 8);
  if (v.length > 5) return v.replace(/^(\d{5})(\d{1,3})$/, "$1-$2");
  return v;
}

function formatCPFCNPJ(val) {
  const d = String(val || "").replace(/\D/g, "");
  if (d.length <= 11) {
    if (d.length > 9) return d.replace(/^(\d{3})(\d{3})(\d{3})(\d{1,2})$/, "$1.$2.$3-$4");
    if (d.length > 6) return d.replace(/^(\d{3})(\d{3})(\d*)$/, "$1.$2.$3");
    if (d.length > 3) return d.replace(/^(\d{3})(\d*)$/, "$1.$2");
    return d;
  }
  return formatCNPJ(d);
}

async function lookupCEP(cepRaw) {
  const digits = String(cepRaw || "").replace(/\D/g, "");
  if (digits.length !== 8) return null;
  try {
    const res = await fetch(`https://brasilapi.com.br/api/cep/v1/${digits}`);
    if (res.ok) {
      const d = await res.json();
      return {
        logradouro: d.street || "",
        bairro: d.neighborhood || "",
        cidade: d.city || "",
        uf: d.state || ""
      };
    }
  } catch (e) {
    try {
      const res2 = await fetch(`https://viacep.com.br/ws/${digits}/json/`);
      if (res2.ok) {
        const d2 = await res2.json();
        if (!d2.erro) {
          return {
            logradouro: d2.logradouro || "",
            bairro: d2.bairro || "",
            cidade: d2.localidade || "",
            uf: d2.uf || ""
          };
        }
      }
    } catch (e2) {}
  }
  return null;
}

async function fetchOfficialCNPJ(cnpjInput) {
  const digits = String(cnpjInput || "").replace(/\D/g, "");
  if (digits.length !== 14) {
    throw new Error("Informe os 14 dígitos do CNPJ.");
  }

  // 1. Minha Receita
  try {
    const res = await fetch(`https://minhareceita.org/${digits}`);
    if (res.ok) {
      const d = await res.json();
      return parseMinhaReceita(d);
    }
  } catch (e) {
    console.warn("MinhaReceita offline:", e);
  }

  // 2. BrasilAPI
  try {
    const res2 = await fetch(`https://brasilapi.com.br/api/cnpj/v1/${digits}`);
    if (res2.ok) {
      const d2 = await res2.json();
      return parseBrasilAPI(d2);
    }
  } catch (e2) {
    console.warn("BrasilAPI offline:", e2);
  }

  throw new Error("Não foi possível conectar com as fontes da Receita Federal no momento. Preencha os campos manualmente.");
}

function parseMinhaReceita(d) {
  const tel = d.ddd_telefone_1 ? (d.ddd_telefone_1.length >= 10 ? `(${d.ddd_telefone_1.slice(0,2)}) ${d.ddd_telefone_1.slice(2)}` : d.ddd_telefone_1) : "";

  let reg = "Simples Nacional";
  if (d.opcao_pelo_mei) reg = "MEI";
  else if (d.opcao_pelo_simples) reg = "Simples Nacional";
  else reg = "Lucro Presumido";

  const soc = (d.qsa || []).map(s => ({
    n: s.nome_socio || "",
    cpf: s.cnpj_cpf_do_socio || "",
    p: "",
    fn: s.qualificacao_socio || "Sócio",
    ct: ""
  }));

  const cnaesSec = (d.cnaes_secundarios || []).map(c => `${c.codigo} · ${c.descricao}`).slice(0, 6).join("; ");

  const logradouro = d.descricao_tipo_de_logradouro && d.logradouro ? `${d.descricao_tipo_de_logradouro} ${d.logradouro}` : (d.logradouro || "");

  return {
    raz: d.razao_social || "",
    fan: d.nome_fantasia || d.razao_social || "",
    cnpj: formatCNPJ(d.cnpj),
    situacao: d.descricao_situacao_cadastral || "Ativa",
    status_cliente: "Ativo",
    ini: (d.data_inicio_atividade || "").slice(0, 7),
    nat: `${d.codigo_natureza_juridica ? d.codigo_natureza_juridica + ' · ' : ''}${d.natureza_juridica || ''}`,
    porte: d.porte || "Demais",
    end_cep: formatCEP(d.cep),
    end_logradouro: logradouro,
    end_numero: d.numero || "S/N",
    end_complemento: d.complemento || "",
    end_bairro: d.bairro || "",
    end_cidade: d.municipio || "",
    end_uf: d.uf || "",
    tel,
    mail: (d.email || "").toLowerCase(),
    cnae: d.cnae_fiscal ? `${d.cnae_fiscal} · ${d.cnae_fiscal_descricao || ''}` : "",
    cnaes: cnaesSec,
    ie: d.inscricao_estadual || "",
    im: d.inscricao_municipal || "",
    reg,
    demandas: ["Contábil", "Fiscal", "Departamento Pessoal"],
    soc: soc.length ? soc : [{ n: "", cpf: "", p: "", fn: "Sócio-administrador", ct: "" }]
  };
}

function parseBrasilAPI(d) {
  let reg = "Simples Nacional";
  if (d.opcao_pelo_mei) reg = "MEI";
  else if (d.opcao_pelo_simples) reg = "Simples Nacional";
  else reg = "Lucro Presumido";

  const soc = (d.qsa || []).map(s => ({
    n: s.nome_socio || "",
    cpf: s.cnpj_cpf_do_socio || "",
    p: "",
    fn: s.qualificacao_socio || "Sócio",
    ct: ""
  }));

  const cnaesSec = (d.cnaes_secundarios || []).map(c => `${c.codigo} · ${c.descricao}`).slice(0, 6).join("; ");
  const logradouro = d.descricao_tipo_de_logradouro && d.logradouro ? `${d.descricao_tipo_de_logradouro} ${d.logradouro}` : (d.logradouro || "");

  return {
    raz: d.razao_social || "",
    fan: d.nome_fantasia || d.razao_social || "",
    cnpj: formatCNPJ(d.cnpj),
    situacao: d.descricao_situacao_cadastral || "Ativa",
    status_cliente: "Ativo",
    ini: (d.data_inicio_atividade || "").slice(0, 7),
    nat: `${d.codigo_natureza_juridica ? d.codigo_natureza_juridica + ' · ' : ''}${d.natureza_juridica || ''}`,
    porte: d.porte || "Demais",
    end_cep: formatCEP(d.cep),
    end_logradouro: logradouro,
    end_numero: d.numero || "S/N",
    end_complemento: d.complemento || "",
    end_bairro: d.bairro || "",
    end_cidade: d.municipio || "",
    end_uf: d.uf || "",
    tel: d.ddd_telefone_1 || "",
    mail: (d.email || "").toLowerCase(),
    cnae: d.cnae_fiscal ? `${d.cnae_fiscal} · ${d.cnae_fiscal_descricao || ''}` : "",
    cnaes: cnaesSec,
    ie: "",
    im: "",
    reg,
    demandas: ["Contábil", "Fiscal", "Departamento Pessoal"],
    soc: soc.length ? soc : [{ n: "", cpf: "", p: "", fn: "Sócio-administrador", ct: "" }]
  };
}

/* ==========================================================================
   3. BASE DE DADOS REAL E PERSISTÊNCIA DAS EMPRESAS
   ========================================================================== */
function ensureCompanyAddressFields(c) {
  if (!c) return;
  if (!c.status_cliente) {
    c.status_cliente = c.st === "Pausada" ? "Suspenso" : (c.st === "Encerrada" ? "Encerrado" : "Ativo");
  }
  if (!Array.isArray(c.demandas) || !c.demandas.length) {
    c.demandas = ["Contábil", "Fiscal", "Departamento Pessoal"];
  }
  if (!c.end_logradouro && c.end) {
    const raw = c.end;
    const cepMatch = raw.match(/CEP\s*([\d.-]+)/i);
    if (cepMatch) c.end_cep = cepMatch[1].replace(/\D/g, "").replace(/^(\d{5})(\d{3})$/, "$1-$2");

    const cityMatch = raw.match(/·\s*([^·/]+)\/([A-Z]{2})/);
    if (cityMatch) {
      c.end_cidade = cityMatch[1].trim();
      c.end_uf = cityMatch[2].trim();
    }

    const mainPart = raw.split("·")[0].trim();
    const commaParts = mainPart.split(",").map(p => p.trim());
    if (commaParts.length >= 1) c.end_logradouro = commaParts[0];
    if (commaParts.length >= 2) c.end_numero = commaParts[1].replace(/nº\s*/i, "");
    if (commaParts.length >= 3) c.end_complemento = commaParts.slice(2).join(", ");
  }
  if (!c.end_cep) c.end_cep = "";
  if (!c.end_logradouro) c.end_logradouro = "";
  if (!c.end_numero) c.end_numero = "";
  if (!c.end_complemento) c.end_complemento = "";
  if (!c.end_bairro) c.end_bairro = "";
  if (!c.end_cidade) c.end_cidade = "";
  if (!c.end_uf) c.end_uf = "";
}

function formatFullAddress(c) {
  if (!c) return "—";
  const parts = [];
  if (c.end_logradouro) {
    let p = c.end_logradouro;
    if (c.end_numero) p += ", " + c.end_numero;
    if (c.end_complemento) p += " (" + c.end_complemento + ")";
    parts.push(p);
  }
  if (c.end_bairro) parts.push(c.end_bairro);
  if (c.end_cidade || c.end_uf) parts.push(`${c.end_cidade || ''}/${c.end_uf || ''}`);
  if (c.end_cep) parts.push(`CEP ${c.end_cep}`);
  return parts.length ? parts.join(" · ") : (c.end || "—");
}

const INITIAL_COMPANIES = [
  {
    id: 101,
    fan: "Lume Cosméticos",
    raz: "Lume Comércio Digital Ltda",
    cnpj: "34.120.450/0001-88",
    seg: "E-commerce",
    reg: "Simples Nacional",
    st: "Ativa",
    status_cliente: "Ativo",
    ini: "2022-03",
    nat: "206-2 · Sociedade empresária limitada",
    ie: "003456789.00-12",
    im: "4102938",
    end_cep: "30130-005",
    end_logradouro: "Av. Afonso Pena",
    end_numero: "1500",
    end_complemento: "sala 402",
    end_bairro: "Centro",
    end_cidade: "Belo Horizonte",
    end_uf: "MG",
    tel: "(31) 3244-8899",
    mail: "financeiro@lumecosmeticos.com.br",
    cnae: "4772-5/00 · Comércio varejista de cosméticos e higiene pessoal",
    cnaes: "4789-0/99 · Comércio de outros produtos; 7319-0/02 · Promoção de vendas",
    cert: { tipo: "e-CNPJ A1 (arquivo)", val: iso(180), pw: "Lume@2026" },
    soc: [
      { n: "Marina Alves", cpf: "***.412.890-**", p: "60", fn: "Sócio-administrador", ct: "(31) 98711-2233" },
      { n: "Lucas Teixeira", cpf: "***.871.340-**", p: "40", fn: "Sócio", ct: "(31) 98844-5566" }
    ],
    ac: [
      { cid: "crd-1-0", o: "GOV.BR", s: "Portal Gov.br", link: "https://www.gov.br", u: "34.120.450/0001-88", pw: "GovLume#26", sit: "Ativo", obs: "Conta Prata com biometria" },
      { cid: "crd-1-1", o: "SEFAZ", s: "SIARE SEFAZ-MG", link: "https://www.fazenda.mg.gov.br", u: "ie.lumecosmeticos", pw: "Sefaz@2026", sit: "Ativo", obs: "Acesso emissão DAE" },
      { cid: "crd-1-2", o: "Prefeitura", s: "Portal BHISS", link: "https://bhissdigital.pbh.gov.br", u: "4102938", pw: "Bhiss#2026", sit: "Ativo", obs: "NFS-e municipal" },
      { cid: "crd-1-3", o: "e-CAC", s: "e-CAC Receita Federal", link: "https://cav.receita.fazenda.gov.br", u: "Procuração eletrônica", pw: "Certificado", sit: "Ativo", obs: "Procuração válida até 2027" }
    ],
    demandas: ["Contábil", "Fiscal", "Departamento Pessoal"],
    compl: { faturamento_medio: "R$ 140.000,00", colaboradores_qtd: "4", contato_principal: "Marina Alves (Diretora)", obs_internas: "Cliente pontual, fechamento até o 5º dia útil" }
  },
  {
    id: 102,
    fan: "Orbit Dropship",
    raz: "Orbit Importações e Logística Ltda",
    cnpj: "42.890.112/0001-30",
    seg: "Dropshipping",
    reg: "Lucro Presumido",
    st: "Ativa",
    status_cliente: "Ativo",
    ini: "2021-08",
    nat: "206-2 · Sociedade empresária limitada",
    ie: "109887234.11-00",
    im: "5582910",
    end_cep: "04547-006",
    end_logradouro: "Rua Gomes de Carvalho",
    end_numero: "1666",
    end_complemento: "cj 82",
    end_bairro: "Vila Olímpia",
    end_cidade: "São Paulo",
    end_uf: "SP",
    tel: "(11) 3045-7788",
    mail: "contato@orbitdropship.com.br",
    cnae: "4619-2/00 · Representantes comerciais e agentes do comércio",
    cnaes: "6319-4/00 · Portais e provedores de conteúdo",
    cert: { tipo: "e-CNPJ A1 (arquivo)", val: iso(22), pw: "Orbit#2026" },
    soc: [
      { n: "Henrique Costa", cpf: "***.903.220-**", p: "100", fn: "Titular / Administrador", ct: "(11) 99122-3344" }
    ],
    ac: [
      { cid: "crd-2-0", o: "GOV.BR", s: "Gov.br PJ", link: "https://www.gov.br", u: "42.890.112/0001-30", pw: "GovOrbit!24", sit: "Ativo", obs: "Conta Ouro" },
      { cid: "crd-2-1", o: "e-CAC", s: "e-CAC RFB", link: "https://cav.receita.fazenda.gov.br", u: "Certificado digital", pw: "Cert#2026", sit: "Ativo", obs: "Acesso direto" }
    ],
    demandas: ["Contábil", "Fiscal", "Consultoria"],
    compl: { faturamento_medio: "R$ 280.000,00", colaboradores_qtd: "2", contato_principal: "Henrique Costa", obs_internas: "Exige envio mensal de extratos" }
  },
  {
    id: 103,
    fan: "Vértice Educação",
    raz: "Vértice Cursos e Treinamentos Online Ltda",
    cnpj: "38.552.910/0001-94",
    seg: "Infoprodutos",
    reg: "Simples Nacional",
    st: "Pausada",
    status_cliente: "Suspenso",
    ini: "2023-01",
    nat: "206-2 · Sociedade empresária limitada",
    ie: "Isento",
    im: "7710294",
    end_cep: "20040-004",
    end_logradouro: "Av. Rio Branco",
    end_numero: "115",
    end_complemento: "sala 901",
    end_bairro: "Centro",
    end_cidade: "Rio de Janeiro",
    end_uf: "RJ",
    tel: "(21) 2233-4455",
    mail: "adm@verticecursos.com.br",
    cnae: "8599-6/04 · Treinamento em desenvolvimento profissional",
    cnaes: "6319-4/00 · Portais de conteúdo na internet",
    cert: { tipo: "e-CNPJ A1 (arquivo)", val: iso(-15), pw: "Vertice#2026" },
    soc: [
      { n: "Paula Nogueira", cpf: "***.562.110-**", p: "50", fn: "Sócio-administrador", ct: "(21) 98112-9988" },
      { n: "Daniela Prado", cpf: "***.321.440-**", p: "50", fn: "Sócio", ct: "(21) 98223-1122" }
    ],
    ac: [
      { cid: "crd-3-0", o: "GOV.BR", s: "Gov.br Corporativo", link: "https://www.gov.br", u: "38.552.910/0001-94", pw: "VerticeGov26", sit: "Ativo", obs: "" },
      { cid: "crd-3-1", o: "Prefeitura", s: "Nota Carioca", link: "https://notacarioca.rio.gov.br", u: "7710294", pw: "Rio#Vertice26", sit: "Ativo", obs: "Emissão de notas Hotmart" }
    ],
    demandas: ["Contábil", "Fiscal", "Legalização"],
    compl: { faturamento_medio: "R$ 95.000,00", colaboradores_qtd: "1", contato_principal: "Paula Nogueira", obs_internas: "Certificado digital venceu; cliente notificado" }
  }
];

let C = getStored("companies", INITIAL_COMPANIES);
// Garante migração transparente de endereços e status em todos os registros
C.forEach(ensureCompanyAddressFields);
function saveCompanies() { setStored("companies", C); }

const H = [
  [101, 1, "Rafael Moura", "Atualizou a procuração e-CAC"],
  [102, 3, "Camila Ribeiro", "Renovou acesso à SEFAZ"],
  [101, 5, "Camila Ribeiro", "Atualizou e-mail de contato"],
  [103, 8, "Rafael Moura", "Registrou vencimento do certificado"]
];

/* ==========================================================================
   4. NOVO MÓDULO — CERTIFICADOS AVULSOS (COM CPF/CNPJ DO TITULAR)
   ========================================================================== */
const DEFAULT_SINGLE_CERTS = [
  {
    id: "sc-201",
    nome: "Marcos Paulo Pereira",
    cpf_cnpj: "24.551.982/0001-09",
    tipo: "e-CNPJ A1 (arquivo)",
    val: iso(35),
    pw: "Mpaulo#2026",
    created_at: "2026-01-10"
  },
  {
    id: "sc-202",
    nome: "Dra. Juliana Mendes da Silva",
    cpf_cnpj: "109.845.221-88",
    tipo: "e-CPF A1 (arquivo)",
    val: iso(-8),
    pw: "Jmendes!2026",
    created_at: "2026-02-05"
  },
  {
    id: "sc-203",
    nome: "Transportes Ramos MEI",
    cpf_cnpj: "31.902.441/0001-44",
    tipo: "e-CNPJ A3 (token)",
    val: iso(195),
    pw: "Ramos@Token26",
    created_at: "2026-03-12"
  },
  {
    id: "sc-204",
    nome: "Carlos Eduardo Santos",
    cpf_cnpj: "089.442.110-34",
    tipo: "e-CPF A3 (token)",
    val: iso(50),
    pw: "Cadu#2026",
    created_at: "2026-03-20"
  }
];

let SINGLE_CERTS = getStored("single_certs", DEFAULT_SINGLE_CERTS);
function saveSingleCerts() { setStored("single_certs", SINGLE_CERTS); }

const scDays = sc => (sc && sc.val ? Math.round((new Date(sc.val + "T12:00") - T0) / 864e5) : null);
const scStatus = sc => { const n = scDays(sc); return n === null ? "mu" : n < 0 ? "er" : n <= 60 ? "wn" : "ok"; };
const scLabel = sc => { const n = scDays(sc); return n === null ? "Sem data" : n < 0 ? `Vencido há ${-n} dias` : n <= 60 ? `Vence em ${n} dias` : "Válido"; };
const scWidth = sc => { const n = scDays(sc); return n === null ? 0 : Math.max(0, Math.min(100, n / 3.65)); };

function openSingleCertModal(id = null) {
  const modal = $("#md-single-cert");
  if (!modal) return;
  const isEdit = !!id;
  $("#single-cert-modal-title").textContent = isEdit ? "Editar Certificado Avulso" : "Novo Certificado Avulso";
  $("#single-cert-id").value = id || "";

  if (isEdit) {
    const sc = SINGLE_CERTS.find(x => String(x.id) === String(id));
    if (sc) {
      $("#single-cert-name").value = sc.nome || "";
      $("#single-cert-cpf-cnpj").value = sc.cpf_cnpj || "";
      $("#single-cert-type").value = sc.tipo || "e-CNPJ A1 (arquivo)";
      $("#single-cert-val").value = sc.val || "";
      $("#single-cert-pwd").value = sc.pw || "";
    }
  } else {
    $("#single-cert-name").value = "";
    $("#single-cert-cpf-cnpj").value = "";
    $("#single-cert-type").value = "e-CNPJ A1 (arquivo)";
    $("#single-cert-val").value = "";
    $("#single-cert-pwd").value = "";
  }

  modal.classList.add("on");
  setTimeout(() => { $("#single-cert-name").focus(); }, 100);
}

function toggleSingleCertModalPwd(btn) {
  const input = $("#single-cert-pwd");
  if (!input) return;
  const isPass = input.type === "password";
  input.type = isPass ? "text" : "password";
  if (btn) btn.textContent = isPass ? "Ocultar" : "Ver";
}

async function saveSingleCert() {
  const id = $("#single-cert-id").value;
  const nome = ($("#single-cert-name").value || "").trim();
  const cpf_cnpj = formatCPFCNPJ($("#single-cert-cpf-cnpj").value);
  const tipo = $("#single-cert-type").value;
  const val = $("#single-cert-val").value;
  const pw = $("#single-cert-pwd").value;

  if (!nome) {
    toast("Informe o nome do titular ou do certificado.");
    $("#single-cert-name").focus();
    return;
  }
  if (!val) {
    toast("Informe a data de validade.");
    $("#single-cert-val").focus();
    return;
  }
  if (!pw) {
    toast("Informe a senha do certificado.");
    $("#single-cert-pwd").focus();
    return;
  }

  if (id) {
    const idx = SINGLE_CERTS.findIndex(x => String(x.id) === String(id));
    if (idx >= 0) {
      SINGLE_CERTS[idx].nome = nome;
      SINGLE_CERTS[idx].cpf_cnpj = cpf_cnpj;
      SINGLE_CERTS[idx].tipo = tipo;
      SINGLE_CERTS[idx].val = val;
      SINGLE_CERTS[idx].pw = pw;
      recordAudit("update_single_cert", "Atualizou certificado avulso", "single_certificate", nome, `Certificado avulso atualizado por ${CURRENT_USER.name}`);
      toast("Certificado avulso atualizado com sucesso!");
    }
  } else {
    const newSc = {
      id: "sc-" + Date.now(),
      nome,
      cpf_cnpj,
      tipo,
      val,
      pw,
      created_at: new Date().toISOString()
    };
    SINGLE_CERTS.unshift(newSc);
    recordAudit("create_single_cert", "Cadastrou certificado avulso", "single_certificate", nome, `Novo certificado avulso cadastrado`);
    toast("Certificado avulso cadastrado com sucesso!");
  }

  saveSingleCerts();
  closeModal("md-single-cert");

  if (location.hash === "#certificados-avulsos") {
    singleCertsView();
  } else if (location.hash === "#dashboard") {
    dash();
  }
}

function deleteSingleCert(id) {
  const sc = SINGLE_CERTS.find(x => String(x.id) === String(id));
  if (!sc) return;
  if (!confirm(`Tem certeza que deseja excluir o certificado avulso de "${sc.nome}"?`)) return;

  SINGLE_CERTS = SINGLE_CERTS.filter(x => String(x.id) !== String(id));
  saveSingleCerts();
  recordAudit("delete_single_cert", "Excluiu certificado avulso", "single_certificate", sc.nome, `Removido por ${CURRENT_USER.name}`);
  toast("Certificado avulso removido.");
  singleCertsView();
}

let SCF = { q: "", tipo: "", sit: "" };

function singleCertsView() {
  const total = SINGLE_CERTS.length;
  const valids = SINGLE_CERTS.filter(x => scStatus(x) === "ok").length;
  const toExpire = SINGLE_CERTS.filter(x => scStatus(x) === "wn").length;
  const expired = SINGLE_CERTS.filter(x => scStatus(x) === "er").length;

  const q = (SCF.q || "").toLowerCase();
  let list = SINGLE_CERTS.filter(sc => {
    const matchQ = !q || sc.nome.toLowerCase().includes(q) || (sc.cpf_cnpj && sc.cpf_cnpj.toLowerCase().includes(q));
    const matchTipo = !SCF.tipo || sc.tipo === SCF.tipo;
    const matchSit = !SCF.sit || scStatus(sc) === SCF.sit;
    return matchQ && matchTipo && matchSit;
  }).sort((a, b) => (scDays(a) ?? 9999) - (scDays(b) ?? 9999));

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
      <div>
        <h1>Certificados Avulsos</h1>
        <p class="sub" style="margin-bottom:0">Controle independente de certificados digitais para clientes MEIs e avulsos não recorrentes.</p>
      </div>
      <button class="btn pr" onclick="openSingleCertModal()">+ Novo Certificado Avulso</button>
    </div>

    <div class="g g4">
      <div class="cd kp cc" onclick="SCF.sit=SCF.sit=='ok'?'':'ok';singleCertsView()" style="${SCF.sit === 'ok' ? 'border-color:var(--pr);box-shadow:0 0 0 2px var(--pr)' : ''}">
        <span class="mu">Válidos</span>
        <b class="ok">${valids}</b>
        <span class="s mu">mais de 60 dias de vigência</span>
      </div>
      <div class="cd kp cc" onclick="SCF.sit=SCF.sit=='wn'?'':'wn';singleCertsView()" style="${SCF.sit === 'wn' ? 'border-color:var(--pr);box-shadow:0 0 0 2px var(--pr)' : ''}">
        <span class="mu">Próximos do vencimento</span>
        <b class="wn">${toExpire}</b>
        <span class="s wn">vencem nos próximos 60 dias</span>
      </div>
      <div class="cd kp cc" onclick="SCF.sit=SCF.sit=='er'?'':'er';singleCertsView()" style="${SCF.sit === 'er' ? 'border-color:var(--pr);box-shadow:0 0 0 2px var(--pr)' : ''}">
        <span class="mu">Vencidos</span>
        <b class="er">${expired}</b>
        <span class="s er">exigem renovação imediata</span>
      </div>
      <div class="cd kp cc" onclick="SCF.sit='';singleCertsView()">
        <span class="mu">Total cadastrados</span>
        <b>${total}</b>
        <span class="s mu">clientes avulsos</span>
      </div>
    </div>

    <div class="fb" style="margin-top:20px">
      <input placeholder="Buscar por nome do cliente ou CPF/CNPJ" value="${esc(SCF.q)}" oninput="SCF.q=this.value;singleCertsView()">
      <select onchange="SCF.tipo=this.value;singleCertsView()">
        <option value="">Todos os tipos</option>
        <option value="e-CNPJ A1 (arquivo)" ${SCF.tipo === 'e-CNPJ A1 (arquivo)' ? 'selected' : ''}>e-CNPJ A1 (arquivo)</option>
        <option value="e-CNPJ A3 (token)" ${SCF.tipo === 'e-CNPJ A3 (token)' ? 'selected' : ''}>e-CNPJ A3 (token)</option>
        <option value="e-CPF A1 (arquivo)" ${SCF.tipo === 'e-CPF A1 (arquivo)' ? 'selected' : ''}>e-CPF A1 (arquivo)</option>
        <option value="e-CPF A3 (token)" ${SCF.tipo === 'e-CPF A3 (token)' ? 'selected' : ''}>e-CPF A3 (token)</option>
      </select>
      <select onchange="SCF.sit=this.value;singleCertsView()">
        <option value="">Todas as situações</option>
        <option value="ok" ${SCF.sit === 'ok' ? 'selected' : ''}>Válidos</option>
        <option value="wn" ${SCF.sit === 'wn' ? 'selected' : ''}>A Vencer (60 dias)</option>
        <option value="er" ${SCF.sit === 'er' ? 'selected' : ''}>Vencidos</option>
      </select>
      ${SCF.q || SCF.tipo || SCF.sit ? `<button class="btn sm" onclick="SCF={q:'',tipo:'',sit:''};singleCertsView()">Limpar Filtros</button>` : ""}
    </div>

    <div class="cd t">
      <table>
        <thead>
          <tr>
            <th>Nome do Certificado / Titular</th>
            <th>CPF / CNPJ</th>
            <th>Tipo</th>
            <th>Validade</th>
            <th style="width:160px">Vigência</th>
            <th>Situação</th>
            <th>Senha</th>
            <th style="text-align:right">Ações</th>
          </tr>
        </thead>
        <tbody>
          ${list.length ? list.map(sc => `
            <tr>
              <td><b>${esc(sc.nome)}</b></td>
              <td><span class="s mu" style="font-family:monospace">${esc(sc.cpf_cnpj || '—')}</span></td>
              <td><span class="p mu">${esc(sc.tipo)}</span></td>
              <td><b>${fd(sc.val)}</b></td>
              <td><div class="tr"><i style="width:${scWidth(sc)}%;background:var(--${scStatus(sc)})"></i></div></td>
              <td>${pill(scLabel(sc), scStatus(sc))}</td>
              <td>
                <div style="display:flex;align-items:center;gap:4px">
                  <input type="password" readonly value="${esc(sc.pw)}" style="width:100px;padding:3px 6px;font-size:12px;background:var(--bg)">
                  ${hasPerm("credentials_reveal") ? `
                    <button class="discrete-action-btn" onclick="revealSingleCertPwd(this, '${sc.id}')" title="Revelar senha">👁</button>
                    <button class="discrete-action-btn copy" onclick="copySecret('${esc(sc.pw)}', '${esc(sc.nome)} · Certificado Avulso')" title="Copiar senha">📋</button>
                  ` : `<span class="mu s">[Oculto]</span>`}
                </div>
              </td>
              <td style="text-align:right">
                <button class="btn sm" onclick="openSingleCertModal('${sc.id}')" title="Editar certificado">Editar</button>
                <button class="btn sm er" onclick="deleteSingleCert('${sc.id}')" title="Excluir certificado" style="margin-left:4px">Excluir</button>
              </td>
            </tr>
          `).join("") : `<tr><td colspan="8" class="mu" style="padding:16px">Nenhum certificado avulso encontrado.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function revealSingleCertPwd(el, scId) {
  if (!hasPerm("credentials_reveal")) {
    toast("Acesso negado: Você não possui a permissão de revelar senhas.");
    return;
  }
  const input = el.parentElement.querySelector("input");
  const isPass = input.type === "password";
  input.type = isPass ? "text" : "password";
  el.textContent = isPass ? "🔒" : "👁";
  if (isPass) {
    const sc = SINGLE_CERTS.find(x => String(x.id) === String(scId));
    recordAudit("reveal", "Revelou senha", "single_certificate", sc ? sc.nome : "Certificado Avulso", "Visualizou senha de certificado avulso");
  }
}

/* ==========================================================================
   5. CADASTRO DE EMPRESAS POR ETAPAS (WIZARD COM DEMANDA CONTRATADA)
   ========================================================================== */
let wizardStep = 1;
let wizardData = null;

const blankCompany = () => ({
  id: Date.now(),
  fan: "",
  raz: "",
  cnpj: "",
  seg: SEGMENTS[0] || "E-commerce",
  reg: REG[0],
  st: "Ativa",
  status_cliente: "Ativo",
  ini: T0.toISOString().slice(0, 7),
  nat: "206-2 · Sociedade empresária limitada",
  porte: "Demais",
  ie: "",
  im: "",
  end_cep: "",
  end_logradouro: "",
  end_numero: "",
  end_complemento: "",
  end_bairro: "",
  end_cidade: "",
  end_uf: "",
  tel: "",
  mail: "",
  cnae: "",
  cnaes: "",
  cert: { tipo: "e-CNPJ A1 (arquivo)", val: "", pw: "" },
  soc: [{ n: "", cpf: "", p: "100", fn: "Sócio-administrador", ct: "" }],
  ac: [
    { cid: "crd-new-0", o: "GOV.BR", s: "Portal Gov.br", link: "https://www.gov.br", u: "", pw: "", sit: "Pendente", obs: "Conta prata/ouro" },
    { cid: "crd-new-1", o: "SEFAZ", s: "SEFAZ Estadual", link: "", u: "", pw: "", sit: "Pendente", obs: "Acesso contribuinte" },
    { cid: "crd-new-2", o: "Prefeitura", s: "Portal da Prefeitura", link: "", u: "", pw: "", sit: "Pendente", obs: "NFS-e" },
    { cid: "crd-new-3", o: "e-CAC", s: "e-CAC Receita Federal", link: "https://cav.receita.fazenda.gov.br", u: "", pw: "", sit: "Pendente", obs: "Procuração eletrônica" },
    { cid: "crd-new-4", o: "FGTS", s: "Conectividade Social", link: "https://conectividadesocialv2.caixa.gov.br", u: "", pw: "", sit: "Pendente", obs: "Perfil empregador" },
    { cid: "crd-new-5", o: "Banco", s: "Internet Banking PJ", link: "", u: "", pw: "", sit: "Pendente", obs: "Acesso leitura extratos" }
  ],
  demandas: ["Contábil", "Fiscal", "Departamento Pessoal"],
  demandas_obs: "",
  compl: { faturamento_medio: "", colaboradores_qtd: "", contato_principal: "", obs_internas: "" }
});

function getStepValidation(step, d = wizardData) {
  if (!d) return { ok: false, missing: ["Dados vazios"] };
  const miss = [];
  if (step === 1) {
    if (!d.cnpj || d.cnpj.replace(/\D/g, "").length < 14) miss.push("CNPJ válido (14 dígitos)");
    if (!d.raz || !d.raz.trim()) miss.push("Razão Social");
    if (!d.fan || !d.fan.trim()) miss.push("Nome Fantasia");
    if (!d.seg) miss.push("Segmento");
    if (!d.reg) miss.push("Regime Tributário");
    if (!d.end_logradouro || !d.end_logradouro.trim()) miss.push("Logradouro / Rua");
    if (!d.end_cidade || !d.end_cidade.trim()) miss.push("Cidade");
    if (!d.end_uf || !d.end_uf.trim()) miss.push("UF");
    return { ok: miss.length === 0, missing: miss };
  }
  if (step === 2) {
    if (!d.soc || !d.soc.length || !d.soc.some(s => s.n && s.n.trim())) {
      miss.push("Pelo menos 1 sócio cadastrado");
    }
    return { ok: miss.length === 0, missing: miss };
  }
  if (step === 3) {
    if (!d.cert || !d.cert.tipo) miss.push("Tipo do certificado");
    if (!d.cert || !d.cert.val) miss.push("Data de validade do certificado");
    if (!d.cert || !d.cert.pw) miss.push("Senha do certificado");
    return { ok: miss.length === 0, missing: miss };
  }
  if (step === 4) {
    if (!d.ac || !d.ac.length || !d.ac.some(a => a.s && a.s.trim())) {
      miss.push("Pelo menos 1 sistema/credencial configurado");
    }
    return { ok: miss.length === 0, missing: miss };
  }
  if (step === 5) {
    if (!d.demandas || !d.demandas.length) {
      miss.push("Pelo menos 1 demanda contratada selecionada");
    }
    return { ok: miss.length === 0, missing: miss };
  }
  if (step === 6) {
    const allMiss = [];
    for (let s = 1; s <= 5; s++) {
      const v = getStepValidation(s, d);
      if (!v.ok) allMiss.push(`Etapa ${s}: ${v.missing.join(", ")}`);
    }
    return { ok: allMiss.length === 0, missing: allMiss };
  }
  return { ok: true, missing: [] };
}

function autoSaveDraft() {
  if (!wizardData) return;
  setStored("company_draft", { data: wizardData, step: wizardStep, savedAt: new Date().toISOString() });
  const ind = $("#draft-status-indicator");
  if (ind) {
    const now = new Date();
    ind.textContent = `Salvo automaticamente às ${now.toLocaleTimeString()}`;
  }
}

function saveWizardDraft(showNotification = true) {
  autoSaveDraft();
  if (showNotification) toast("Rascunho do cadastro salvo! Você pode continuar a qualquer momento.");
}

function discardWizardDraft() {
  if (!confirm("Deseja realmente descartar o rascunho atual e recomeçar o cadastro?")) return;
  localStorage.removeItem("nortis_company_draft");
  wizardData = blankCompany();
  wizardStep = 1;
  toast("Rascunho descartado.");
  renderWizard();
}

function initWizard() {
  const draft = getStored("company_draft", null);
  if (draft && draft.data) {
    wizardData = draft.data;
    ensureCompanyAddressFields(wizardData);
    wizardStep = draft.step || 1;
  } else {
    wizardData = blankCompany();
    wizardStep = 1;
  }
}

function goToWizardStep(targetStep) {
  saveWizardDraft(false);
  wizardStep = Math.max(1, Math.min(6, targetStep));
  renderWizard();
  if (typeof window !== "undefined" && typeof window.scrollTo === "function") {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

async function handleCNPJLookupWizard() {
  const input = $("#wiz-cnpj");
  if (!input) return;
  const raw = input.value.trim();
  const digits = raw.replace(/\D/g, "");

  if (digits.length !== 14) {
    toast("Informe o CNPJ completo com 14 dígitos.");
    input.focus();
    return;
  }

  const statusEl = $("#cnpj-lookup-feedback");
  if (statusEl) {
    statusEl.innerHTML = `<span class="mu">🔄 Consultando bases oficiais da Receita Federal...</span>`;
  }

  try {
    const data = await fetchOfficialCNPJ(digits);
    
    // Atualiza campos do wizard
    wizardData.cnpj = data.cnpj;
    wizardData.raz = data.raz;
    wizardData.fan = data.fan;
    if (data.ini) wizardData.ini = data.ini;
    if (data.nat) wizardData.nat = data.nat;
    if (data.porte) wizardData.porte = data.porte;
    if (data.end_cep) wizardData.end_cep = data.end_cep;
    if (data.end_logradouro) wizardData.end_logradouro = data.end_logradouro;
    if (data.end_numero) wizardData.end_numero = data.end_numero;
    if (data.end_complemento) wizardData.end_complemento = data.end_complemento;
    if (data.end_bairro) wizardData.end_bairro = data.end_bairro;
    if (data.end_cidade) wizardData.end_cidade = data.end_cidade;
    if (data.end_uf) wizardData.end_uf = data.end_uf;
    if (data.tel) wizardData.tel = data.tel;
    if (data.mail) wizardData.mail = data.mail;
    if (data.cnae) wizardData.cnae = data.cnae;
    if (data.cnaes) wizardData.cnaes = data.cnaes;
    if (data.reg) wizardData.reg = data.reg;
    if (data.soc && data.soc.length) wizardData.soc = data.soc;

    autoSaveDraft();
    toast("✓ Dados oficiais da empresa e sócios importados com sucesso!");
    renderWizard();
  } catch (err) {
    if (statusEl) {
      statusEl.innerHTML = `<span class="wn">⚠️ ${esc(err.message)}</span>`;
    }
    toast(err.message);
  }
}

async function handleCEPLookupWizard(input) {
  const digits = input.value.replace(/\D/g, "");
  if (digits.length === 8) {
    toast("Buscando endereço pelo CEP...");
    const addr = await lookupCEP(digits);
    if (addr && wizardData) {
      if (addr.logradouro && !wizardData.end_logradouro) wizardData.end_logradouro = addr.logradouro;
      if (addr.bairro && !wizardData.end_bairro) wizardData.end_bairro = addr.bairro;
      if (addr.cidade) wizardData.end_cidade = addr.cidade;
      if (addr.uf) wizardData.end_uf = addr.uf;
      autoSaveDraft();
      renderWizard();
      toast("Endereço preenchido pelo CEP!");
    }
  }
}

function renderWizard() {
  if (!wizardData) initWizard();
  const d = wizardData;

  const stepsConfig = [
    { num: 1, label: "Dados Cadastrais" },
    { num: 2, label: "Sócios" },
    { num: 3, label: "Certificado Digital" },
    { num: 4, label: "Acessos e Credenciais" },
    { num: 5, label: "Demanda Contratada" },
    { num: 6, label: "Validação & Conclusão" }
  ];

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:10px">
      <div>
        <p class="s mu"><a class="lk" style="margin:0" href="#empresas">← Voltar para Empresas</a> / Cadastro de Nova Empresa</p>
        <h1>Nova Empresa</h1>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span id="draft-status-indicator" class="wizard-draft-badge">💾 Rascunho salvo</span>
        <button class="btn sm" onclick="saveWizardDraft(true)">Salvar Rascunho</button>
        <button class="btn sm er" onclick="discardWizardDraft()">Descartar</button>
      </div>
    </div>

    <!-- Stepper de 6 Etapas -->
    <div class="wizard-stepper">
      ${stepsConfig.map(s => {
        const v = getStepValidation(s.num, d);
        const isCurrent = wizardStep === s.num;
        const statusClass = isCurrent ? "curr" : (v.ok ? "done" : "pend");
        const statusLabel = isCurrent ? "EM EDIÇÃO" : (v.ok ? "✓ PREENCHIDA" : "PENDENTE");
        return `
          <div class="wizard-step-item ${isCurrent ? 'active' : ''}" onclick="goToWizardStep(${s.num})" title="Ir para ${s.label}">
            <div class="wizard-step-header">
              <span class="wizard-step-num">${s.num}</span>
              <span class="wizard-step-status ${statusClass}">${statusLabel}</span>
            </div>
            <div class="wizard-step-title">${s.label}</div>
          </div>
        `;
      }).join("")}
    </div>

    <!-- Conteúdo da Etapa Atual -->
    <div class="cd" style="padding:24px 28px">
      ${renderWizardStepContent(wizardStep, d)}
    </div>

    <!-- Rodapé de Navegação do Wizard -->
    <div class="wizard-footer">
      <div>
        ${wizardStep > 1 ? `<button class="btn" onclick="goToWizardStep(${wizardStep - 1})">‹ Etapa Anterior</button>` : `<button class="btn" onclick="location.hash='empresas'">Cancelar</button>`}
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <button class="btn" onclick="saveWizardDraft(true)">Salvar Parcialmente</button>
        ${wizardStep < 6 ? `
          <button class="btn pr" onclick="goToWizardStep(${wizardStep + 1})">Avançar para Etapa ${wizardStep + 1} ›</button>
        ` : `
          <button class="btn pr" onclick="submitFinishWizard()" style="background:var(--ok);border-color:var(--ok)">✓ Concluir e Salvar Empresa</button>
        `}
      </div>
    </div>
  `;

  bindWizardEvents();
}

function renderWizardStepContent(step, d) {
  if (step === 1) {
    return `
      <div class="hh">
        <div>
          <h2>Etapa 1 · Dados Cadastrais</h2>
          <p class="sub" style="margin-bottom:0">Informe o CNPJ para preenchimento automático das informações fiscais e societárias.</p>
        </div>
      </div>

      <div class="fl" style="margin-top:16px">
        <label class="fi" style="grid-column:span 2">
          <span>CNPJ * (Consulta Automática)</span>
          <div class="input-with-action">
            <input id="wiz-cnpj" data-wp="cnpj" value="${esc(d.cnpj || '')}" placeholder="00.000.000/0000-00" maxlength="18">
            <button type="button" class="btn sm pr" onclick="handleCNPJLookupWizard()" title="Buscar dados na Receita Federal">
              🔍 Consultar CNPJ
            </button>
          </div>
          <div id="cnpj-lookup-feedback" style="margin-top:4px;font-size:11px"></div>
        </label>

        <label class="fi">
          <span>Status do Cliente *</span>
          <select data-wp="status_cliente">
            ${STATUS_CLIENTE_OPTS.map(st => `<option value="${esc(st)}" ${st === (d.status_cliente || 'Ativo') ? 'selected' : ''}>● ${esc(st)}</option>`).join("")}
          </select>
        </label>

        <label class="fi" style="grid-column:span 2">
          <span>Razão Social *</span>
          <input data-wp="raz" value="${esc(d.raz || '')}" placeholder="Nome empresarial oficial">
        </label>

        <label class="fi">
          <span>Nome Fantasia *</span>
          <input data-wp="fan" value="${esc(d.fan || '')}" placeholder="Nome comercial ou marca">
        </label>

        <label class="fi">
          <span>Segmento de Atuação *</span>
          <div class="input-with-action">
            <select data-wp="seg" id="wiz-seg-select">
              ${SEGMENTS.map(s => `<option value="${esc(s)}" ${s === d.seg ? 'selected' : ''}>${esc(s)}</option>`).join("")}
            </select>
            <button type="button" class="btn sm" onclick="openManageSegmentsModal()" title="Gerenciar segmentos" style="font-size:16px;font-weight:bold;line-height:1">+</button>
          </div>
        </label>

        <label class="fi">
          <span>Regime Tributário *</span>
          <select data-wp="reg">
            ${REG.map(r => `<option value="${esc(r)}" ${r === d.reg ? 'selected' : ''}>${esc(r)}</option>`).join("")}
          </select>
        </label>

        <label class="fi">
          <span>Início de Atendimento</span>
          <input type="month" data-wp="ini" value="${esc(d.ini || '')}">
        </label>

        <!-- ENDEREÇO SEPARADO POR CAMPOS INDIVIDUAIS -->
        <div style="grid-column:span 3;margin-top:8px;padding-top:12px;border-top:1px solid var(--bd)">
          <h3 style="font-size:13px;font-weight:700;color:var(--tx);margin-bottom:10px">Endereço Completo:</h3>
          <div class="address-fields-grid">
            <label class="fi">
              <span>CEP</span>
              <input data-wp="end_cep" value="${esc(d.end_cep || '')}" placeholder="00000-000" maxlength="9" onblur="handleCEPLookupWizard(this)">
            </label>
            <label class="fi">
              <span>Rua / Logradouro *</span>
              <input data-wp="end_logradouro" value="${esc(d.end_logradouro || '')}" placeholder="Avenida, rua, travessa...">
            </label>
            <label class="fi">
              <span>Número</span>
              <input data-wp="end_numero" value="${esc(d.end_numero || '')}" placeholder="Ex: 120 ou S/N">
            </label>
            <label class="fi">
              <span>Complemento</span>
              <input data-wp="end_complemento" value="${esc(d.end_complemento || '')}" placeholder="Sala, bloco, andar...">
            </label>
          </div>
          <div class="address-fields-grid" style="margin-top:10px">
            <label class="fi">
              <span>Bairro</span>
              <input data-wp="end_bairro" value="${esc(d.end_bairro || '')}" placeholder="Bairro">
            </label>
            <label class="fi">
              <span>Cidade *</span>
              <input data-wp="end_cidade" value="${esc(d.end_cidade || '')}" placeholder="Município">
            </label>
            <label class="fi">
              <span>UF *</span>
              <input data-wp="end_uf" value="${esc(d.end_uf || '')}" placeholder="UF" maxlength="2" style="text-transform:uppercase">
            </label>
            <div style="display:flex;align-items:flex-end">
              <span class="s mu" style="margin-bottom:8px">ℹ️ CEP preenche cidade e UF automaticamente.</span>
            </div>
          </div>
        </div>

        <label class="fi">
          <span>Natureza Jurídica</span>
          <input data-wp="nat" value="${esc(d.nat || '')}" placeholder="Ex: 206-2 · Sociedade empresária limitada">
        </label>

        <label class="fi">
          <span>Telefone de Contato</span>
          <input data-wp="tel" value="${esc(d.tel || '')}" placeholder="(00) 00000-0000">
        </label>

        <label class="fi">
          <span>E-mail Corporativo</span>
          <input type="email" data-wp="mail" value="${esc(d.mail || '')}" placeholder="contato@empresa.com.br">
        </label>

        <label class="fi">
          <span>Inscrição Estadual</span>
          <input data-wp="ie" value="${esc(d.ie || '')}" placeholder="Número da IE ou Isento">
        </label>

        <label class="fi">
          <span>Inscrição Municipal</span>
          <input data-wp="im" value="${esc(d.im || '')}" placeholder="Número da IM / CCM">
        </label>

        <label class="fi">
          <span>Porte da Empresa</span>
          <input data-wp="porte" value="${esc(d.porte || 'Demais')}" placeholder="Ex: ME, EPP, Demais">
        </label>

        <label class="fi" style="grid-column:span 2">
          <span>CNAE Principal</span>
          <input data-wp="cnae" value="${esc(d.cnae || '')}" placeholder="Código e descrição da atividade principal">
        </label>

        <label class="fi">
          <span>CNAEs Secundários</span>
          <input data-wp="cnaes" value="${esc(d.cnaes || '')}" placeholder="Atividades secundárias">
        </label>
      </div>
    `;
  }

  if (step === 2) {
    return `
      <div class="hh">
        <div>
          <h2>Etapa 2 · Sócios e Quadro Societário (QSA)</h2>
          <p class="sub" style="margin-bottom:0">Cadastre os sócios, titulares, administradores e participações percentuais.</p>
        </div>
        <button type="button" class="btn sm pr" onclick="addWizardRow('soc')">+ Adicionar Sócio</button>
      </div>

      <table class="ed" style="margin-top:14px">
        <thead>
          <tr>
            <th>Nome do Sócio *</th>
            <th>CPF</th>
            <th style="width:100px">Participação %</th>
            <th>Função / Qualificação</th>
            <th>E-mail ou Contato</th>
            <th style="width:40px"></th>
          </tr>
        </thead>
        <tbody>
          ${(d.soc || []).map((s, k) => `
            <tr>
              <td><input data-wp="soc.${k}.n" value="${esc(s.n || '')}" placeholder="Nome completo do sócio"></td>
              <td><input data-wp="soc.${k}.cpf" value="${esc(s.cpf || '')}" placeholder="000.000.000-00"></td>
              <td><input data-wp="soc.${k}.p" value="${esc(s.p || '')}" placeholder="Ex: 50" style="text-align:center"></td>
              <td><input data-wp="soc.${k}.fn" value="${esc(s.fn || 'Sócio-administrador')}" placeholder="Função na empresa"></td>
              <td><input data-wp="soc.${k}.ct" value="${esc(s.ct || '')}" placeholder="Telefone ou e-mail"></td>
              <td style="text-align:center"><span class="x" onclick="removeWizardRow('soc', ${k})" title="Remover sócio">×</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  if (step === 3) {
    return `
      <div class="hh">
        <div>
          <h2>Etapa 3 · Certificado Digital</h2>
          <p class="sub" style="margin-bottom:0">Mantenha exclusivamente Tipo, Validade e Senha, garantindo conformidade e segurança.</p>
        </div>
      </div>

      <div class="fl" style="margin-top:16px;max-width:800px">
        <label class="fi">
          <span>Tipo de Certificado *</span>
          <select data-wp="cert.tipo">
            <option value="e-CNPJ A1 (arquivo)" ${d.cert.tipo === 'e-CNPJ A1 (arquivo)' ? 'selected' : ''}>e-CNPJ A1 (arquivo)</option>
            <option value="e-CNPJ A3 (token)" ${d.cert.tipo === 'e-CNPJ A3 (token)' ? 'selected' : ''}>e-CNPJ A3 (token)</option>
            <option value="e-CPF A1 (arquivo)" ${d.cert.tipo === 'e-CPF A1 (arquivo)' ? 'selected' : ''}>e-CPF A1 (arquivo)</option>
            <option value="e-CPF A3 (token)" ${d.cert.tipo === 'e-CPF A3 (token)' ? 'selected' : ''}>e-CPF A3 (token)</option>
            <option value="Outro" ${d.cert.tipo === 'Outro' ? 'selected' : ''}>Outro</option>
          </select>
        </label>

        <label class="fi">
          <span>Data de Validade (Vencimento) *</span>
          <input type="date" data-wp="cert.val" value="${esc(d.cert.val || '')}">
        </label>

        <label class="fi">
          <span>Senha do Certificado *</span>
          <div style="display:flex;align-items:center;gap:6px">
            <input type="password" data-wp="cert.pw" value="${esc(d.cert.pw || '')}" placeholder="Senha confidencial" style="flex:1">
            <button type="button" class="btn sm" onclick="toggleInputVisibility(this)">Ver</button>
          </div>
        </label>
      </div>

      <div class="al wn" style="margin-top:24px;font-size:12px">
        🔒 <b>Segurança Nortis:</b> Senhas de certificados são criptografadas e protegidas. Visualização restrita a usuários autorizados.
      </div>
    `;
  }

  if (step === 4) {
    return `
      <div class="hh">
        <div>
          <h2>Etapa 4 · Acessos e Credenciais</h2>
          <p class="sub" style="margin-bottom:0">Credenciais com link direto para consulta rápida dos sistemas e portais oficiais.</p>
        </div>
        <button type="button" class="btn sm pr" onclick="addWizardRow('ac')">+ Adicionar Acesso</button>
      </div>

      <table class="ed" style="margin-top:14px">
        <thead>
          <tr>
            <th style="width:120px">Órgão</th>
            <th>Sistema / Serviço *</th>
            <th>Link do Portal</th>
            <th>Usuário / Código</th>
            <th>Senha / Token</th>
            <th style="width:100px">Situação</th>
            <th>Observações</th>
            <th style="width:36px"></th>
          </tr>
        </thead>
        <tbody>
          ${(d.ac || []).map((a, k) => `
            <tr>
              <td>
                <select data-wp="ac.${k}.o" onchange="autoSuggestPortalLink(this, ${k})">
                  ${OR.map(o => `<option value="${esc(o)}" ${o === a.o ? 'selected' : ''}>${esc(o)}</option>`).join("")}
                </select>
              </td>
              <td><input data-wp="ac.${k}.s" value="${esc(a.s || '')}" placeholder="Ex: e-CAC RFB"></td>
              <td>
                <div style="display:flex;align-items:center;gap:4px">
                  <input data-wp="ac.${k}.link" value="${esc(a.link || '')}" placeholder="https://...">
                  ${a.link ? `<a href="${esc(a.link)}" target="_blank" rel="noopener noreferrer" class="btn-icon-link" title="Abrir link em nova aba">↗</a>` : ''}
                </div>
              </td>
              <td><input data-wp="ac.${k}.u" value="${esc(a.u || '')}" placeholder="Login/Usuário"></td>
              <td>
                <div style="display:flex;align-items:center;gap:4px">
                  <input type="password" data-wp="ac.${k}.pw" value="${esc(a.pw || '')}" placeholder="Senha/token">
                  <button type="button" class="btn sm" onclick="toggleInputVisibility(this)" style="padding:4px 6px;font-size:11px">Ver</button>
                </div>
              </td>
              <td>
                <select data-wp="ac.${k}.sit">
                  ${SIT.map(st => `<option value="${esc(st)}" ${st === a.sit ? 'selected' : ''}>${esc(st)}</option>`).join("")}
                </select>
              </td>
              <td><input data-wp="ac.${k}.obs" value="${esc(a.obs || '')}" placeholder="Notas"></td>
              <td style="text-align:center"><span class="x" onclick="removeWizardRow('ac', ${k})" title="Remover acesso">×</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  if (step === 5) {
    const selecionadas = Array.isArray(d.demandas) ? d.demandas : [];
    return `
      <div class="hh">
        <div>
          <h2>Etapa 5 · Demanda Contratada</h2>
          <p class="sub" style="margin-bottom:0">Selecione as demandas e serviços contratados pelo cliente. Gerencie novas opções pelo botão "+".</p>
        </div>
        <button type="button" class="btn sm pr" onclick="openManageDemandsModal()" title="Gerenciar opções de demandas">+ Gerenciar Demandas</button>
      </div>

      <div style="margin-top:16px">
        <label style="font-weight:700;color:var(--tx);font-size:13px;display:block;margin-bottom:8px">Demandas Selecionadas para esta Empresa *</label>
        <div class="demand-chips-container">
          ${DEMANDS.map(dm => {
            const isSel = selecionadas.includes(dm);
            return `
              <div class="demand-chip ${isSel ? 'selected' : ''}" onclick="toggleWizardDemand('${esc(dm)}')">
                <span>${isSel ? '✓' : '+'}</span>
                <span>${esc(dm)}</span>
              </div>
            `;
          }).join("")}
        </div>
      </div>

      <div style="margin-top:20px;max-width:800px">
        <label class="fi">
          <span>Observações sobre o Escopo Contratado</span>
          <textarea data-wp="demandas_obs" rows="4" placeholder="Particularidades do contrato, sistemas do cliente, rotinas de fechamento específicas...">${esc(d.demandas_obs || '')}</textarea>
        </label>
      </div>
    `;
  }

  if (step === 6) {
    const v1 = getStepValidation(1, d);
    const v2 = getStepValidation(2, d);
    const v3 = getStepValidation(3, d);
    const v4 = getStepValidation(4, d);
    const v5 = getStepValidation(5, d);
    const allOk = v1.ok && v2.ok && v3.ok && v4.ok && v5.ok;

    return `
      <div class="hh">
        <div>
          <h2>Etapa 6 · Informações Complementares e Validação Final</h2>
          <p class="sub" style="margin-bottom:0">Revise os indicadores de preenchimento antes de salvar a nova empresa no sistema.</p>
        </div>
      </div>

      <div class="g2" style="margin-top:14px;align-items:flex-start">
        <div class="fl" style="grid-template-columns:1fr 1fr">
          <label class="fi">
            <span>Faturamento Mensal Estimado</span>
            <input data-wp="compl.faturamento_medio" value="${esc((d.compl && d.compl.faturamento_medio) || '')}" placeholder="Ex: R$ 80.000,00">
          </label>

          <label class="fi">
            <span>Qtd. de Colaboradores / Funcionários</span>
            <input data-wp="compl.colaboradores_qtd" value="${esc((d.compl && d.compl.colaboradores_qtd) || '')}" placeholder="Ex: 5">
          </label>

          <label class="fi" style="grid-column:span 2">
            <span>Contato Principal no Cliente</span>
            <input data-wp="compl.contato_principal" value="${esc((d.compl && d.compl.contato_principal) || '')}" placeholder="Ex: Nome do gestor financeiro / WhatsApp">
          </label>

          <label class="fi" style="grid-column:span 2">
            <span>Observações Gerais e Histórico de Implantação</span>
            <textarea data-wp="compl.obs_internas" rows="4" placeholder="Instruções para a equipe da Nortis, histórico de reuniões, sistemas utilizados...">${esc((d.compl && d.compl.obs_internas) || '')}</textarea>
          </label>
        </div>

        <div>
          <div class="cd" style="background:var(--hv)">
            <h3 style="font-size:14px;font-weight:700;margin-bottom:12px">Checklist Geral de Validação</h3>
            
            <div style="display:flex;flex-direction:column;gap:10px;font-size:13px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span>1. Dados Cadastrais</span>
                ${v1.ok ? `<span class="p ok">✓ Concluída</span>` : `<span class="p wn" title="${esc(v1.missing.join(', '))}">⚠️ Pendente (${v1.missing.length})</span>`}
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span>2. Sócios e QSA</span>
                ${v2.ok ? `<span class="p ok">✓ Concluída</span>` : `<span class="p wn" title="${esc(v2.missing.join(', '))}">⚠️ Pendente</span>`}
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span>3. Certificado Digital</span>
                ${v3.ok ? `<span class="p ok">✓ Concluída</span>` : `<span class="p wn" title="${esc(v3.missing.join(', '))}">⚠️ Pendente</span>`}
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span>4. Acessos e Credenciais</span>
                ${v4.ok ? `<span class="p ok">✓ Concluída</span>` : `<span class="p wn" title="${esc(v4.missing.join(', '))}">⚠️ Pendente</span>`}
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span>5. Demanda Contratada</span>
                ${v5.ok ? `<span class="p ok">✓ Concluída</span>` : `<span class="p wn" title="${esc(v5.missing.join(', '))}">⚠️ Pendente</span>`}
              </div>
            </div>

            <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--bd)">
              ${allOk ? `
                <div class="al ok" style="margin-bottom:0">
                  <span>✓ <b>Tudo pronto!</b> Todas as etapas foram preenchidas corretamente.</span>
                </div>
              ` : `
                <div class="al wn" style="margin-bottom:0;font-size:12px">
                  <span>⚠️ <b>Atenção:</b> Existem etapas com informações pendentes. É obrigatório o preenchimento para concluir o cadastro.</span>
                </div>
              `}
            </div>
          </div>
        </div>
      </div>
    `;
  }
}

function bindWizardEvents() {
  const container = $("#v");
  if (!container) return;

  container.oninput = e => {
    const t = e.target;
    const p = t.dataset.wp;
    if (!p || !wizardData) return;
    
    if (p === "cnpj") t.value = formatCNPJ(t.value);
    if (p === "end_cep") t.value = formatCEP(t.value);

    setDeepValue(wizardData, p, t.value);
    autoSaveDraft();
  };

  container.onchange = e => {
    const t = e.target;
    const p = t.dataset.wp;
    if (!p || !wizardData) return;
    setDeepValue(wizardData, p, t.value);
    autoSaveDraft();
  };
}

function setDeepValue(obj, path, val) {
  const keys = path.split(".");
  let cur = obj;
  while (keys.length > 1) {
    const k = keys.shift();
    if (!cur[k] || typeof cur[k] !== "object") cur[k] = {};
    cur = cur[k];
  }
  cur[keys[0]] = val;
}

function addWizardRow(k) {
  if (!wizardData) return;
  if (k === "soc") {
    if (!wizardData.soc) wizardData.soc = [];
    wizardData.soc.push({ n: "", cpf: "", p: "", fn: "Sócio", ct: "" });
  } else if (k === "ac") {
    if (!wizardData.ac) wizardData.ac = [];
    wizardData.ac.push({ cid: "crd-w-" + Date.now(), o: "Outro", s: "", link: "", u: "", pw: "", sit: "Pendente", obs: "" });
  }
  autoSaveDraft();
  renderWizard();
}

function removeWizardRow(k, idx) {
  if (!wizardData || !wizardData[k]) return;
  wizardData[k].splice(idx, 1);
  autoSaveDraft();
  renderWizard();
}

function toggleWizardDemand(demandName) {
  if (!wizardData) return;
  if (!Array.isArray(wizardData.demandas)) wizardData.demandas = [];
  const idx = wizardData.demandas.indexOf(demandName);
  if (idx >= 0) {
    wizardData.demandas.splice(idx, 1);
  } else {
    wizardData.demandas.push(demandName);
  }
  autoSaveDraft();
  renderWizard();
}

function autoSuggestPortalLink(selectEl, rowIndex) {
  const organ = selectEl.value;
  const linkSuggestions = {
    "GOV.BR": "https://www.gov.br",
    "e-CAC": "https://cav.receita.fazenda.gov.br",
    "FGTS": "https://conectividadesocialv2.caixa.gov.br",
    "SEFAZ": "https://www.fazenda.mg.gov.br",
    "Prefeitura": "https://nfse.gov.br"
  };
  if (linkSuggestions[organ] && wizardData && wizardData.ac && wizardData.ac[rowIndex]) {
    wizardData.ac[rowIndex].link = linkSuggestions[organ];
    autoSaveDraft();
    renderWizard();
  }
}

function toggleInputVisibility(btn) {
  const input = btn.parentElement.querySelector("input");
  if (!input) return;
  const isPass = input.type === "password";
  input.type = isPass ? "text" : "password";
  btn.textContent = isPass ? "Ocultar" : "Ver";
}

function submitFinishWizard() {
  const v = getStepValidation(6, wizardData);
  if (!v.ok) {
    toast("Atenção: Preencha todas as etapas obrigatórias antes de salvar a empresa.");
    alert("Pendências encontradas:\n\n" + v.missing.join("\n") + "\n\nPor favor, retorne às etapas pendentes e complete os dados.");
    return;
  }

  // Prepara empresa final
  const d = wizardData;
  d.fan = d.fan.trim() || d.raz.trim();
  d.id = Date.now();
  ensureCompanyAddressFields(d);

  // Verifica duplicação de CNPJ
  const cleanCNPJ = d.cnpj.replace(/\D/g, "");
  const exists = C.some(c => c.cnpj && c.cnpj.replace(/\D/g, "") === cleanCNPJ);
  if (exists) {
    if (!confirm(`O CNPJ ${d.cnpj} já está cadastrado em outra empresa no sistema. Deseja cadastrar mesmo assim?`)) {
      return;
    }
  }

  C.unshift(d);
  saveCompanies();
  localStorage.removeItem("nortis_company_draft");
  wizardData = null;

  H.push([d.id, 0, CURRENT_USER.name, "Cadastrou a empresa por etapas"]);
  recordAudit("create_company", "Cadastrou nova empresa", "company", d.fan, `Nova empresa cadastrada por ${CURRENT_USER.name} via etapas sequenciais`);

  toast(`Empresa "${d.fan}" cadastrada com sucesso!`);
  location.hash = "empresa-" + d.id;
}

/* ==========================================================================
   6. FICHA INDIVIDUAL DA EMPRESA (UX DE CONSULTA RÁPIDA - REQUISITO 3)
   ========================================================================== */
let D = null, orig = null, dy = 0, cur = 0, currentCompanyTab = "dados", isCompanyEditMode = false;

const nm = id => C.find(c => String(c.id) === String(id));
const ago = n => (n == 0 ? "hoje" : n == 1 ? "ontem" : "há " + n + " dias");
const pill = (t, k) => `<span class="p ${k}">${t}</span>`;
const sitP = x => pill(x, x === "Ativo" ? "ok" : x === "Revisar" ? "wn" : "er");
const dd = c => (c.cert && c.cert.val ? Math.round((new Date(c.cert.val + "T12:00") - T0) / 864e5) : null);
const cs = c => { const n = dd(c); return n === null ? "mu" : n < 0 ? "er" : n <= 60 ? "wn" : "ok"; };
const cl = c => { const n = dd(c); return n === null ? "Não cadastrado" : n < 0 ? "Vencido há " + (-n) + " dias" : n <= 60 ? "Vence em " + n + " dias" : "Válido"; };
const cp = c => pill(cl(c), cs(c));
const cw = c => { const n = dd(c); return n === null ? 0 : Math.max(0, Math.min(100, n / 3.65)); };

const miss = c => {
  const m = [];
  [["cnpj", "CNPJ"], ["end_logradouro", "Endereço / Logradouro"], ["end_cidade", "Cidade"], ["tel", "Telefone"], ["mail", "E-mail"]].forEach(([k, l]) => {
    if (!c[k]) m.push(l);
  });
  if (!c.soc || !c.soc.some(s => s.n)) m.push("Sócios");
  if (!c.cert || !c.cert.val) m.push("Certificado digital");
  if (!c.demandas || !c.demandas.length) m.push("Demandas contratadas");
  return m;
};

const get = p => p.split(".").reduce((o, z) => (o ? o[z] : ""), D);
const I = (p, l, o = {}) => `<label class="fi"${o.w ? ` style="grid-column:span ${o.w}"` : ""}><span>${l}</span><input data-p="${p}"${o.t ? ` type="${o.t}"` : ""}${o.m ? ` data-m="1"` : ""}${o.r ? ` data-r="1"` : ""} value="${esc(get(p) || "")}"></label>`;
const S = (p, l, a) => `<label class="fi"><span>${l}</span><select data-p="${p}">${a.map(x => `<option ${x == get(p) ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></label>`;
const Ci = (p, t) => `<td><input data-p="${p}"${t ? ` type="${t}"` : ""} value="${esc(get(p) || "")}"></td>`;
const Cs = (p, a) => `<td><select data-p="${p}">${a.map(x => `<option ${x == get(p) ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></td>`;

function switchCompanyTab(tabId) {
  currentCompanyTab = tabId;
  fic();
}

function updateCompanyStatusDirect(newStatus) {
  if (!D) return;
  D.status_cliente = newStatus;
  dy = 1;
  const elDy = $("#dy");
  if (elDy) elDy.style.visibility = "visible";
  sv();
}

function copyToClipboard(text, label) {
  navigator.clipboard.writeText(text).then(() => {
    toast(`${label || 'Texto'} copiado para a área de transferência!`);
  }).catch(() => {
    toast("Falha ao copiar automaticamente.");
  });
}

function fic() {
  const c = D, ex = !!orig;
  ensureCompanyAddressFields(c);
  const i = ex ? C.indexOf(orig) : 0;
  const pv = C[(i + C.length - 1) % C.length];
  const nx = C[(i + 1) % C.length];
  const m = miss(c);
  const hs = ex ? H.filter(x => String(x[0]) === String(c.id)).sort((a, b) => a[1] - b[1]) : [];

  $("#v").innerHTML = `
    <div class="bar">
      <div>
        <p class="s mu"><a class="lk" style="margin:0" href="#empresas">Empresas</a> / ${esc(orig.fan)}</p>
      </div>
      <div class="sp"></div>
      <span id="dy" class="s wn" style="visibility:${dy ? "visible" : "hidden"}">Alterações não salvas</span>
      <button class="btn" title="${esc(pv.fan)}" onclick="location.hash='empresa-${pv.id}'">‹ Anterior</button>
      <button class="btn" title="${esc(nx.fan)}" onclick="location.hash='empresa-${nx.id}'">Próxima ›</button>
      ${hasPerm("companies_edit") ? `<button class="btn" onclick="dc()">Descartar</button>` : ""}
      ${hasPerm("companies_edit") ? `<button class="btn pr" onclick="sv()">Salvar Alterações</button>` : ""}
    </div>

    <!-- CABEÇALHO COMPACTO DE CONSULTA RÁPIDA (REQUISITO 3.1) -->
    <div class="company-hero-card">
      <div class="company-hero-main">
        <div class="company-hero-title">
          <span>${esc(orig.raz)}</span>
          <span class="s mu" style="font-weight:600">(${esc(orig.fan)})</span>
        </div>
        <div class="company-hero-meta">
          <span style="font-family:monospace;font-weight:700;color:var(--tx)">
            CNPJ: ${esc(orig.cnpj || '—')}
            ${orig.cnpj ? `<button class="discrete-action-btn copy" onclick="copyToClipboard('${esc(orig.cnpj)}', 'CNPJ')" title="Copiar CNPJ">📋</button>` : ''}
          </span>
          <span>·</span>
          <span>Regime: <b>${esc(orig.reg || '—')}</b></span>
          <span>·</span>
          <span>Segmento: <b>${esc(orig.seg || '—')}</b></span>
          <span>·</span>
          <span>Certificado: ${cp(orig)}</span>
        </div>
      </div>
      
      <!-- Seletor Rápido de Status do Cliente (Ativo, Suspenso, Encerrado) -->
      <div style="display:flex;align-items:center;gap:8px">
        <span class="s mu">Status:</span>
        <select onchange="updateCompanyStatusDirect(this.value)" style="font-size:12px;font-weight:700;padding:4px 8px;border-radius:99px;border-color:var(--bd);background:var(--cd);color:var(--tx)">
          ${STATUS_CLIENTE_OPTS.map(st => `<option value="${esc(st)}" ${st === (orig.status_cliente || 'Ativo') ? 'selected' : ''}>● ${esc(st)}</option>`).join("")}
        </select>
      </div>
    </div>

    <!-- Navegação por Abas Organizadas -->
    <div class="chips">
      <a class="${currentCompanyTab === 'dados' ? 'on' : ''}" onclick="switchCompanyTab('dados')" style="${currentCompanyTab === 'dados' ? 'border-color:var(--pr);color:var(--tx)' : ''}">1. Dados Cadastrais</a>
      <a class="${currentCompanyTab === 'socios' ? 'on' : ''}" onclick="switchCompanyTab('socios')" style="${currentCompanyTab === 'socios' ? 'border-color:var(--pr);color:var(--tx)' : ''}">2. Sócios (${c.soc ? c.soc.length : 0})</a>
      <a class="${currentCompanyTab === 'demandas' ? 'on' : ''}" onclick="switchCompanyTab('demandas')" style="${currentCompanyTab === 'demandas' ? 'border-color:var(--pr);color:var(--tx)' : ''}">3. Demanda Contratada (${c.demandas ? c.demandas.length : 0})</a>
      <a class="${currentCompanyTab === 'cert' ? 'on' : ''}" onclick="switchCompanyTab('cert')" style="${currentCompanyTab === 'cert' ? 'border-color:var(--pr);color:var(--tx)' : ''}">4. Certificado Digital</a>
      <a class="${currentCompanyTab === 'acessos' ? 'on' : ''}" onclick="switchCompanyTab('acessos')" style="${currentCompanyTab === 'acessos' ? 'border-color:var(--pr);color:var(--tx)' : ''}">5. Credenciais e Acessos (${c.ac ? c.ac.length : 0})</a>
      <a class="${currentCompanyTab === 'compl' ? 'on' : ''}" onclick="switchCompanyTab('compl')" style="${currentCompanyTab === 'compl' ? 'border-color:var(--pr);color:var(--tx)' : ''}">6. Informações Complementares</a>
      <a class="${currentCompanyTab === 'hist' ? 'on' : ''}" onclick="switchCompanyTab('hist')" style="${currentCompanyTab === 'hist' ? 'border-color:var(--pr);color:var(--tx)' : ''}">7. Histórico</a>
    </div>

    ${m.length ? `<div class="al wn">⚠️ Informações pendentes nesta empresa: <b>${esc(m.join(", "))}</b>.</div>` : ""}

    ${renderCompanyTabContent(currentCompanyTab, c, hs)}
  `;
}

function renderCompanyTabContent(tab, c, hs) {
  if (tab === "dados") {
    return `
      <div class="cd">
        <div class="hh">
          <h2>1. Dados Cadastrais</h2>
          <button type="button" class="btn sm" onclick="queryCNPJFicha()" title="Atualizar dados pela Receita Federal">🔍 Atualizar por CNPJ</button>
        </div>
        <div class="fl">
          ${I("raz", "Razão social *", { w: 2 })}
          ${I("fan", "Nome fantasia")}
          ${I("cnpj", "CNPJ", { m: 1 })}
          <label class="fi">
            <span>Segmento</span>
            <div class="input-with-action">
              <select data-p="seg" id="company-seg-select">
                ${SEGMENTS.map(s => `<option value="${esc(s)}" ${s === c.seg ? 'selected' : ''}>${esc(s)}</option>`).join("")}
              </select>
              <button type="button" class="btn sm" onclick="openManageSegmentsModal()" title="Gerenciar segmentos" style="font-size:16px;font-weight:bold;line-height:1">+</button>
            </div>
          </label>
          ${S("reg", "Regime tributário", REG)}
          ${S("status_cliente", "Status do Cliente", STATUS_CLIENTE_OPTS)}
          ${I("ini", "Início do atendimento", { t: "month" })}
          ${I("nat", "Natureza jurídica")}
          ${I("porte", "Porte")}

          <!-- Endereço Individualizado na Ficha -->
          <div style="grid-column:span 3;margin-top:8px;padding-top:12px;border-top:1px solid var(--bd)">
            <h3 style="font-size:13px;font-weight:700;color:var(--tx);margin-bottom:10px">Endereço da Empresa:</h3>
            <div class="address-fields-grid">
              ${I("end_cep", "CEP")}
              ${I("end_logradouro", "Rua / Logradouro")}
              ${I("end_numero", "Número")}
              ${I("end_complemento", "Complemento")}
            </div>
            <div class="address-fields-grid" style="margin-top:10px">
              ${I("end_bairro", "Bairro")}
              ${I("end_cidade", "Cidade")}
              ${I("end_uf", "UF")}
              <div style="display:flex;align-items:flex-end">
                <span class="s mu" style="margin-bottom:8px">Visualização consolidada: <b>${esc(formatFullAddress(c))}</b></span>
              </div>
            </div>
          </div>

          ${I("tel", "Telefone")}
          ${I("mail", "E-mail corporativo", { w: 2 })}
          ${I("ie", "Inscrição estadual")}
          ${I("im", "Inscrição municipal")}
          ${I("cnae", "CNAE principal", { w: 2 })}
          ${I("cnaes", "CNAEs secundários")}
        </div>
      </div>
    `;
  }

  if (tab === "socios") {
    return `
      <div class="cd">
        <div class="hh">
          <h2>2. Sócios e Participações</h2>
          ${hasPerm("companies_edit") ? `<button class="btn sm pr" onclick="add('soc')">+ Adicionar sócio</button>` : ""}
        </div>
        <table class="ed">
          <thead>
            <tr><th>Nome</th><th>CPF</th><th style="width:90px">Particip. %</th><th>Função</th><th>Contato</th>${hasPerm("companies_edit") ? "<th></th>" : ""}</tr>
          </thead>
          <tbody>
            ${(c.soc || []).map((s, k) => `
              <tr>
                ${Ci(`soc.${k}.n`)}
                ${Ci(`soc.${k}.cpf`)}
                ${Ci(`soc.${k}.p`)}
                ${Ci(`soc.${k}.fn`)}
                ${Ci(`soc.${k}.ct`)}
                ${hasPerm("companies_edit") ? `<td><span class="x" title="Remover" onclick="rm('soc',${k})">×</span></td>` : ""}
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  if (tab === "demandas") {
    const selecionadas = Array.isArray(c.demandas) ? c.demandas : [];
    return `
      <div class="cd">
        <div class="hh">
          <h2>3. Demanda Contratada</h2>
          <button type="button" class="btn sm pr" onclick="openManageDemandsModal()" title="Gerenciar demandas">+ Gerenciar Demandas</button>
        </div>
        <p class="sub">Selecione os serviços contábeis e fiscais ativos no contrato desta empresa:</p>
        
        <div class="demand-chips-container" style="margin-top:12px">
          ${DEMANDS.map(dm => {
            const isSel = selecionadas.includes(dm);
            return `
              <div class="demand-chip ${isSel ? 'selected' : ''}" onclick="toggleCompanyDemand('${esc(dm)}')">
                <span>${isSel ? '✓' : '+'}</span>
                <span>${esc(dm)}</span>
              </div>
            `;
          }).join("")}
        </div>

        <div style="margin-top:20px;max-width:800px">
          <label class="fi">
            <span>Observações e Particularidades do Escopo Contratado</span>
            <textarea data-p="demandas_obs" rows="4">${esc(c.demandas_obs || '')}</textarea>
          </label>
        </div>
      </div>
    `;
  }

  if (tab === "cert") {
    return `
      <div class="cd">
        <div class="hh">
          <h2>4. Certificado Digital</h2>
          ${cp(c)}
        </div>
        <p class="sub">Mantém exclusivamente os 3 campos essenciais (Tipo, Validade e Senha).</p>
        <div class="fl" style="max-width:800px">
          ${S("cert.tipo", "Tipo", ["e-CNPJ A1 (arquivo)", "e-CNPJ A3 (token)", "e-CPF A1 (arquivo)", "e-CPF A3 (token)", "Outro"])}
          ${I("cert.val", "Validade", { t: "date", r: 1 })}
          <label class="fi">
            <span>Senha do certificado</span>
            <div style="display:flex;align-items:center;gap:6px">
              <input type="password" data-p="cert.pw" value="${esc(c.cert ? c.cert.pw : '')}" ${!hasPerm("companies_edit") ? "disabled" : ""}>
              ${hasPerm("credentials_reveal") ? `
                <button class="discrete-action-btn" onclick="revealField(this, 'cert', ${c.id})" title="Revelar senha">👁</button>
                <button class="discrete-action-btn copy" onclick="copySecret('${esc(c.cert ? c.cert.pw : '')}', '${esc(c.fan)} · Certificado')" title="Copiar senha">📋</button>
              ` : `<span class="mu s">[Protegido]</span>`}
            </div>
          </label>
        </div>
      </div>
    `;
  }

  if (tab === "acessos") {
    return `
      <div class="cd">
        <div class="hh">
          <h2>5. Credenciais e Acessos (Consulta Rápida)</h2>
          ${hasPerm("credentials_edit") ? `<button class="btn sm pr" onclick="openCredModal(null, ${c.id})">+ Adicionar credencial</button>` : ""}
        </div>
        <p class="sub" style="margin-bottom:12px">Consulta direta de sistemas, links e senhas com cópia em 1 clique.</p>
        <table class="ed">
          <thead>
            <tr>
              <th style="width:110px">Categoria</th>
              <th>Sistema</th>
              <th>Link Direto</th>
              <th>Usuário / Login</th>
              <th>Senha</th>
              <th style="width:90px">Situação</th>
              <th>Observações</th>
              <th style="width:70px;text-align:right">Ações</th>
            </tr>
          </thead>
          <tbody>
            ${(c.ac || []).map((a, k) => `
              <tr>
                <td>${Cs(`ac.${k}.o`, OR)}</td>
                <td>${Ci(`ac.${k}.s`)}</td>
                <td>
                  <div style="display:flex;align-items:center;gap:4px">
                    <input data-p="ac.${k}.link" value="${esc(a.link || '')}" placeholder="https://...">
                    ${a.link ? `<a href="${esc(a.link)}" target="_blank" rel="noopener noreferrer" class="btn-icon-link" title="Abrir sistema em nova aba">↗</a>` : ''}
                  </div>
                </td>
                <td>
                  <div style="display:flex;align-items:center;gap:4px">
                    <input data-p="ac.${k}.u" value="${esc(a.u || '')}" placeholder="Login">
                    ${a.u ? `<button class="discrete-action-btn copy" onclick="copyToClipboard('${esc(a.u)}', 'Usuário')" title="Copiar usuário">📋</button>` : ''}
                  </div>
                </td>
                <td>
                  <div style="display:flex;align-items:center;gap:4px">
                    <input type="password" data-p="ac.${k}.pw" value="${esc(a.pw || '')}" style="width:90px">
                    ${hasPerm("credentials_reveal") ? `
                      <button class="discrete-action-btn" onclick="revealField(this, 'acesso', ${c.id}, ${k})" title="Revelar senha">👁</button>
                      <button class="discrete-action-btn copy" onclick="copySecret('${esc(a.pw || '')}', '${esc(c.fan)} · ${esc(a.s)}')" title="Copiar senha">📋</button>
                    ` : `<span class="mu s">[Oculto]</span>`}
                  </div>
                </td>
                <td>${Cs(`ac.${k}.sit`, SIT)}</td>
                <td>${Ci(`ac.${k}.obs`)}</td>
                <td style="text-align:right">
                  ${hasPerm("credentials_edit") ? `
                    <button class="discrete-action-btn danger" onclick="rm('ac',${k})" title="Remover credencial">✕</button>
                  ` : ''}
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  if (tab === "compl") {
    return `
      <div class="cd">
        <div class="hh">
          <h2>6. Informações Complementares</h2>
        </div>
        <div class="fl" style="max-width:900px">
          ${I("compl.faturamento_medio", "Faturamento médio mensal")}
          ${I("compl.colaboradores_qtd", "Quantidade de colaboradores")}
          ${I("compl.contato_principal", "Contato principal no cliente", { w: 2 })}
          <label class="fi" style="grid-column:span 3">
            <span>Observações internas da contabilidade</span>
            <textarea data-p="compl.obs_internas" rows="5">${esc((c.compl && c.compl.obs_internas) || '')}</textarea>
          </label>
        </div>
      </div>
    `;
  }

  if (tab === "hist") {
    return `
      <div class="cd">
        <h2>7. Histórico de Alterações</h2>
        ${hs.length ? `
          <div class="tl">
            ${hs.map(x => `<div><b>${esc(x[3])}</b><br><span class="s mu">${esc(x[2])} · ${ago(x[1])}</span></div>`).join("")}
          </div>
        ` : `<p class="mu">As alterações salvas nesta ficha aparecem aqui, com data e responsável.</p>`}
      </div>
    `;
  }
}

function toggleCompanyDemand(demandName) {
  if (!D) return;
  if (!Array.isArray(D.demandas)) D.demandas = [];
  const idx = D.demandas.indexOf(demandName);
  if (idx >= 0) {
    D.demandas.splice(idx, 1);
  } else {
    D.demandas.push(demandName);
  }
  dy = 1;
  const elDy = $("#dy");
  if (elDy) elDy.style.visibility = "visible";
  fic();
}

async function queryCNPJFicha() {
  if (!D || !D.cnpj) {
    toast("Informe o CNPJ da empresa.");
    return;
  }
  const digits = D.cnpj.replace(/\D/g, "");
  toast("Consultando Receita Federal...");
  try {
    const data = await fetchOfficialCNPJ(digits);
    if (confirm(`Dados obtidos com sucesso para "${data.raz}". Deseja atualizar os dados cadastrais da empresa?`)) {
      D.raz = data.raz;
      D.fan = data.fan;
      if (data.end_logradouro) D.end_logradouro = data.end_logradouro;
      if (data.end_numero) D.end_numero = data.end_numero;
      if (data.end_complemento) D.end_complemento = data.end_complemento;
      if (data.end_bairro) D.end_bairro = data.end_bairro;
      if (data.end_cidade) D.end_cidade = data.end_cidade;
      if (data.end_uf) D.end_uf = data.end_uf;
      if (data.end_cep) D.end_cep = data.end_cep;
      if (data.nat) D.nat = data.nat;
      if (data.tel) D.tel = data.tel;
      if (data.mail) D.mail = data.mail;
      if (data.cnae) D.cnae = data.cnae;
      if (data.cnaes) D.cnaes = data.cnaes;
      if (data.soc && data.soc.length && (!D.soc || !D.soc.length)) D.soc = data.soc;
      dy = 1;
      fic();
      toast("Dados cadastrais atualizados!");
    }
  } catch (e) {
    toast(e.message);
  }
}

function revealField(el, type, compId, index) {
  if (!hasPerm("credentials_reveal")) {
    toast("Acesso negado: Você não possui a permissão de revelar senhas.");
    return;
  }
  const comp = nm(compId);
  const input = el.parentElement.querySelector("input");
  const isPass = input.type === "password";
  input.type = isPass ? "text" : "password";
  el.textContent = isPass ? "🔒" : "👁";

  if (isPass) {
    const sysName = type === "cert" ? "Certificado Digital" : (comp && comp.ac && comp.ac[index] ? comp.ac[index].s : "Acesso");
    recordAudit("reveal", "Revelou senha", "credential", `${comp ? comp.fan : ''} · ${sysName}`, "Usuário revelou senha confidencial");
  }
}

function copySecret(val, targetLabel) {
  if (!hasPerm("credentials_reveal")) {
    toast("Acesso negado: Você não possui permissão para copiar senhas.");
    return;
  }
  navigator.clipboard.writeText(val).then(() => {
    recordAudit("copy", "Copiou senha", "credential", targetLabel, "Senha/token copiado para área de transferência");
    toast("Copiado com sucesso!");
  }).catch(() => {
    toast("Falha ao copiar automaticamente.");
  });
}

function add(k) {
  const y = scrollY;
  if (!D[k]) D[k] = [];
  D[k].push(k === "soc" ? { n: "", cpf: "", p: "", fn: "Sócio", ct: "" } : { cid: "crd-" + Date.now(), o: "Outro", s: "", link: "", u: "", pw: "", sit: "Pendente", obs: "" });
  dy = 1;
  fic();
  scrollTo(0, y);
}

function rm(k, i) {
  const y = scrollY;
  D[k].splice(i, 1);
  dy = 1;
  fic();
  scrollTo(0, y);
}

function dc() {
  D = structuredClone(orig);
  dy = 0;
  fic();
  toast("Alterações descartadas.");
}

function sv() {
  if (!hasPerm("companies_edit")) {
    toast("Você não tem permissão para salvar alterações cadastrais.");
    return;
  }
  if (!D.raz || !D.raz.trim()) {
    toast("Informe a razão social para salvar.");
    $("[data-p=raz]")?.focus();
    return;
  }
  D.fan = (D.fan || "").trim() || D.raz.trim();
  ensureCompanyAddressFields(D);

  const idx = C.findIndex(c => String(c.id) === String(D.id));
  if (idx >= 0) {
    C[idx] = structuredClone(D);
  } else {
    C.unshift(structuredClone(D));
  }
  saveCompanies();

  H.push([D.id, 0, CURRENT_USER.name, "Atualizou ficha da empresa"]);
  recordAudit("update_company", "Atualizou dados da empresa", "company", D.fan, `Atualização de dados cadastrais/fiscais por ${CURRENT_USER.name}`);
  
  orig = structuredClone(D);
  dy = 0;
  fic();
  toast("Ficha da empresa salva com sucesso!");
}

/* ==========================================================================
   7. LISTA DE EMPRESAS (FILTRO POR STATUS DO CLIENTE)
   ========================================================================== */
const F = { q: "", seg: "", reg: "", status_cliente: "", pend: false };

function lst() {
  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
      <div>
        <h1>Empresas</h1>
        <p class="sub" id="ct" style="margin-bottom:0"></p>
      </div>
      ${hasPerm("companies_edit") ? `<button class="btn pr" onclick="location.hash='nova'">+ Nova Empresa</button>` : ""}
    </div>

    ${F.pend ? `
      <div class="al wn" style="margin-bottom:14px">
        <span>⚠️ <b>Filtro ativo do Dashboard:</b> Exibindo apenas empresas com cadastros incompletos.</span>
        <button class="btn sm" onclick="F.pend=false;fl()">Limpar Filtro</button>
      </div>
    ` : ""}

    <div class="fb">
      <input placeholder="Filtrar por nome, CNPJ ou cidade" value="${esc(F.q)}" oninput="F.q=this.value;fl()">
      
      <!-- Filtro de Status do Cliente -->
      <select onchange="F.status_cliente=this.value;fl()">
        <option value="">Todos os status</option>
        ${STATUS_CLIENTE_OPTS.map(st => `<option value="${esc(st)}" ${F.status_cliente === st ? 'selected' : ''}>Status: ${esc(st)}</option>`).join("")}
      </select>

      <select onchange="F.seg=this.value;fl()">
        <option value="">Todos os segmentos</option>
        ${SEGMENTS.map(s => `<option value="${esc(s)}" ${F.seg === s ? 'selected' : ''}>${esc(s)}</option>`).join("")}
      </select>

      <select onchange="F.reg=this.value;fl()">
        <option value="">Todos os regimes</option>
        ${REG.map(r => `<option value="${esc(r)}" ${F.reg === r ? 'selected' : ''}>${esc(r)}</option>`).join("")}
      </select>

      ${F.status_cliente || F.seg || F.reg || F.q || F.pend ? `<button class="btn sm" onclick="F={q:'',seg:'',reg:'',status_cliente:'',pend:false};lst()">Limpar Filtros</button>` : ""}
    </div>

    <div class="cd t">
      <table>
        <thead>
          <tr>
            <th>Empresa</th>
            <th>CNPJ</th>
            <th>Segmento</th>
            <th>Regime</th>
            <th>Status do Cliente</th>
            <th>Cidade/UF</th>
            <th>Certificado</th>
            ${F.pend ? `<th>Pendências Específicas</th>` : ""}
          </tr>
        </thead>
        <tbody id="tb"></tbody>
      </table>
    </div>
  `;
  fl();
}

function fl() {
  const q = F.q.toLowerCase();
  let r = C.filter(c => {
    ensureCompanyAddressFields(c);
    const searchTarget = (c.fan + c.raz + (c.cnpj || "") + (c.end_cidade || "")).toLowerCase();
    const matchQ = !q || searchTarget.includes(q);
    const matchSeg = !F.seg || c.seg === F.seg;
    const matchReg = !F.reg || c.reg === F.reg;
    const matchStatus = !F.status_cliente || (c.status_cliente || "Ativo") === F.status_cliente;
    const matchPend = !F.pend || miss(c).length > 0;
    return matchQ && matchSeg && matchReg && matchStatus && matchPend;
  });

  $("#tb").innerHTML = r.length ? r.map(c => {
    const m = miss(c);
    const loc = (c.end_cidade && c.end_uf) ? `${c.end_cidade}/${c.end_uf}` : (c.end_cidade || c.end_uf || "—");
    return `
      <tr class="rw" onclick="location.hash='empresa-${c.id}'">
        <td><b>${esc(c.fan)}</b><br><span class="s mu">${esc(c.raz)}</span></td>
        <td>${esc(c.cnpj || "—")}</td>
        <td>${esc(c.seg || "—")}</td>
        <td>${esc(c.reg || "—")}</td>
        <td>${statusClienteBadge(c.status_cliente)}</td>
        <td>${esc(loc)}</td>
        <td>${cp(c)}</td>
        ${F.pend ? `<td><span class="p wn s" title="${esc(m.join(', '))}">Falta: ${esc(m.slice(0, 2).join(', '))}${m.length > 2 ? ` +${m.length - 2}` : ""}</span></td>` : ""}
      </tr>
    `;
  }).join("") : `<tr><td colspan="${F.pend ? 8 : 7}" class="mu" style="padding:16px">Nenhuma empresa encontrada com os filtros selecionados.</td></tr>`;

  $("#ct").textContent = `${r.length} de ${C.length} empresas exibidas`;
}

/* ==========================================================================
   8. DASHBOARD SIMPLIFICADO E REAL (REQUISITO 3.4)
   ========================================================================== */
function dashFilter(tipo) {
  if (tipo === "empresas_ativas") {
    F.status_cliente = "Ativo";
    F.seg = ""; F.reg = ""; F.q = ""; F.pend = false;
    location.hash = "empresas";
  } else if (tipo === "cert_vencer") {
    CF = "wn";
    location.hash = "certificados";
  } else if (tipo === "cert_vencidos") {
    CF = "er";
    location.hash = "certificados";
  } else if (tipo === "pendencias") {
    F.pend = true;
    F.status_cliente = ""; F.seg = ""; F.reg = ""; F.q = "";
    location.hash = "empresas";
  } else if (tipo === "cert_avulsos") {
    SCF = { q: "", tipo: "", sit: "" };
    location.hash = "certificados-avulsos";
  }
}

function dash() {
  const n = C.length;
  const ativas = C.filter(c => (c.status_cliente || "Ativo") === "Ativo").length;
  const suspensas = C.filter(c => c.status_cliente === "Suspenso").length;
  const pe = C.filter(c => miss(c).length);
  const at = C.filter(c => ["wn", "er"].includes(cs(c))).sort((a, b) => dd(a) - dd(b));
  const vencers = at.filter(c => cs(c) === "wn").length;
  const vencidos = at.filter(c => cs(c) === "er").length;

  const scTotal = SINGLE_CERTS.length;
  const scToVencer = SINGLE_CERTS.filter(x => scStatus(x) === "wn").length;
  const scVencidos = SINGLE_CERTS.filter(x => scStatus(x) === "er").length;

  const hs = [...H].sort((a, b) => a[1] - b[1]).slice(0, 6);

  const bars = k => {
    const o = {};
    C.forEach(c => {
      const val = c[k] || "Não informado";
      o[val] = (o[val] || 0) + 1;
    });
    return Object.entries(o).sort((x, y) => y[1] - x[1]).map(([l, v]) => `
      <div class="br">
        <span>${esc(l)}</span>
        <div class="tr"><i style="width:${(v / (n || 1)) * 100}%"></i></div>
        <b>${v}</b>
      </div>
    `).join("");
  };

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:20px;flex-wrap:wrap;gap:12px">
      <div>
        <h1>Visão Geral</h1>
        <p class="sub" style="margin-bottom:0">Olá, <b>${esc(CURRENT_USER.name)}</b> · ${T0.toLocaleDateString("pt-BR", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}</p>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn" onclick="location.hash='certificados-avulsos'">Certificados Avulsos (${scTotal})</button>
        ${hasPerm("companies_edit") ? `<button class="btn pr" onclick="location.hash='nova'">+ Nova Empresa</button>` : ""}
      </div>
    </div>

    <!-- CARDS PRINCIPAIS 100% CLICÁVEIS -->
    <div class="g g4">
      <div class="cd kp cl" onclick="dashFilter('empresas_ativas')" title="Clique para abrir empresas ativas">
        <span class="kp-hint">Ver ativas →</span>
        <span class="mu">Empresas Cadastradas</span>
        <b>${n}</b>
        <span class="s ok">${ativas} ativas ${suspensas ? `· ${suspensas} suspensas` : ''}</span>
      </div>

      <div class="cd kp cl" onclick="dashFilter('cert_vencer')" title="Clique para filtrar certificados a vencer nos próximos 60 dias">
        <span class="kp-hint">Filtrar lista →</span>
        <span class="mu">Certificados a Vencer</span>
        <b class="wn">${vencers}</b>
        <span class="s wn">nos próximos 60 dias (Empresas)</span>
      </div>

      <div class="cd kp cl" onclick="dashFilter('cert_vencidos')" title="Clique para filtrar certificados vencidos">
        <span class="kp-hint">Ver vencidos →</span>
        <span class="mu">Certificados Vencidos</span>
        <b class="er">${vencidos}</b>
        <span class="s er">exigem renovação imediata</span>
      </div>

      <div class="cd kp cl" onclick="dashFilter('cert_avulsos')" title="Clique para abrir módulo de Certificados Avulsos">
        <span class="kp-hint">Ver avulsos →</span>
        <span class="mu">Certificados Avulsos</span>
        <b>${scTotal}</b>
        <span class="s ${scVencidos > 0 ? 'er' : (scToVencer > 0 ? 'wn' : 'ok')}">${scToVencer} a vencer · ${scVencidos} vencidos</span>
      </div>
    </div>

    <div class="g g3">
      <div class="cd">
        <h2>Empresas por segmento</h2>
        ${bars("seg")}
      </div>
      <div class="cd">
        <h2>Empresas por regime tributário</h2>
        ${bars("reg")}
      </div>
      <div class="cd">
        <h2>Pendências de cadastro (${pe.length})</h2>
        ${pe.length ? pe.slice(0, 6).map(c => {
          const m = miss(c);
          return `<div class="ln" onclick="location.hash='empresa-${c.id}'">
            <span><b>${esc(c.fan)}</b></span>
            <span class="wn s">${esc(m[0])}${m.length > 1 ? ` +${m.length - 1}` : ""}</span>
          </div>`;
        }).join("") : `<p class="mu s">Nenhuma empresa com pendências no momento.</p>`}
      </div>
    </div>

    <div class="g g2x">
      <div class="cd t">
        <div class="hh" style="padding:10px 14px 4px">
          <h2>Certificados das empresas que exigem atenção</h2>
          <a class="lk" onclick="location.hash='certificados'">Ver todos →</a>
        </div>
        <table>
          <thead>
            <tr><th>Empresa</th><th>Tipo</th><th>Validade</th><th>Situação</th></tr>
          </thead>
          <tbody>
            ${at.length ? at.slice(0, 6).map(c => `
              <tr class="rw" onclick="location.hash='empresa-${c.id}'">
                <td><b>${esc(c.fan)}</b></td>
                <td><span class="p mu">${esc(c.cert ? c.cert.tipo : 'A1')}</span></td>
                <td>${fd(c.cert ? c.cert.val : '')}</td>
                <td>${cp(c)}</td>
              </tr>
            `).join("") : `<tr><td colspan="4" class="mu" style="padding:14px">Nenhum certificado crítico pendente.</td></tr>`}
          </tbody>
        </table>
      </div>

      <div class="cd">
        <div class="hh">
          <h2>Últimas atualizações</h2>
          ${hasPerm("history_view") ? `<a class="lk" onclick="location.hash='auditoria'">Auditoria →</a>` : ""}
        </div>
        <div class="tl">
          ${hs.map(h => {
            const comp = nm(h[0]);
            return `<div><b>${comp ? esc(comp.fan) : 'Empresa'}</b><br>${esc(h[3])}<br><span class="s mu">${esc(h[2])} · ${ago(h[1])}</span></div>`;
          }).join("")}
        </div>
      </div>
    </div>
  `;
}

/* ==========================================================================
   9. GESTÃO DE CERTIFICADOS DIGITAIS (EMPRESAS RECORRENTES)
   ========================================================================== */
let CF = "";
function certs() {
  if (!hasPerm("certificates_view")) {
    $("#v").innerHTML = `<div class="al er" style="margin-top:20px">🔒 Acesso Restrito: Você não possui a permissão de visualizar Certificados Digitais.</div>`;
    return;
  }

  const g = k => C.filter(c => cs(c) === k);
  const r = C.filter(c => !CF || cs(c) === CF).sort((a, b) => (dd(a) ?? 9999) - (dd(b) ?? 9999));

  const cd = (k, l, s) => `
    <div class="cd kp cc" onclick="CF=CF=='${k}'?'':'${k}';certs()" style="${CF === k ? "border-color:var(--pr);box-shadow:0 0 0 2px var(--pr)" : ""}">
      <span class="mu">${esc(l)}</span>
      <b class="${k}">${g(k).length}</b>
      <span class="s mu">${esc(s)}</span>
    </div>
  `;

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
      <div>
        <h1>Certificados Digitais (Empresas)</h1>
        <p class="sub" style="margin-bottom:0">Controle de certificados vinculados às empresas recorrentes. Clique nos cards para filtrar.</p>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn" onclick="location.hash='certificados-avulsos'">Ver Certificados Avulsos (${SINGLE_CERTS.length})</button>
        ${CF ? `<button class="btn sm" onclick="CF='';certs()">Remover Filtro (${CF.toUpperCase()})</button>` : ""}
      </div>
    </div>

    <div class="g g4">
      ${cd("ok", "Válidos", "mais de 60 dias")}
      ${cd("wn", "Próximos do vencimento", "até 60 dias")}
      ${cd("er", "Vencidos", "renovar com urgência")}
      ${cd("mu", "Não cadastrados", "sem validade informada")}
    </div>

    <div class="cd t">
      <table>
        <thead>
          <tr>
            <th>Empresa</th>
            <th>Tipo</th>
            <th>Validade</th>
            <th style="width:160px">Vigência</th>
            <th>Situação</th>
            <th>Senha</th>
          </tr>
        </thead>
        <tbody>
          ${r.map(c => `
            <tr class="rw" onclick="location.hash='empresa-${c.id}'">
              <td><b>${esc(c.fan)}</b><br><span class="s mu">${esc(c.raz)}</span></td>
              <td><span class="p mu">${esc(c.cert ? c.cert.tipo : '—')}</span></td>
              <td><b>${fd(c.cert ? c.cert.val : '')}</b></td>
              <td><div class="tr"><i style="width:${cw(c)}%;background:var(--${cs(c)})"></i></div></td>
              <td>${cp(c)}</td>
              <td onclick="event.stopPropagation()">
                <div style="display:flex;align-items:center;gap:4px">
                  <input type="password" readonly value="${esc(c.cert ? c.cert.pw : '')}" style="width:100px;padding:3px 6px;font-size:12px;background:var(--bg)">
                  ${hasPerm("credentials_reveal") ? `
                    <button class="discrete-action-btn" onclick="revealField(this, 'cert', ${c.id})" title="Revelar senha">👁</button>
                    <button class="discrete-action-btn copy" onclick="copySecret('${esc(c.cert ? c.cert.pw : '')}', '${esc(c.fan)} · Certificado')" title="Copiar senha">📋</button>
                  ` : `<span class="mu s">[Oculto]</span>`}
                </div>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

/* ==========================================================================
   10. MODAIS AUXILIARES (CREDENCIAIS, SENHAS, PERMISSÕES)
   ========================================================================== */
async function openCredModal(targetCompId = null, credIndex = null) {
  if (!hasPerm("credentials_edit")) {
    toast("Acesso negado: Você não possui permissão para editar credenciais.");
    return;
  }
  const modal = $("#md-cred");
  const select = $("#cred-emp");
  const editIdxInput = $("#cred-edit-index");
  if (!modal || !select) return;

  select.innerHTML = C.map(c => `<option value="${c.id}" ${targetCompId && String(c.id) === String(targetCompId) ? "selected" : ""}>${esc(c.fan)} (${esc(c.raz)})</option>`).join("");
  editIdxInput.value = credIndex != null ? credIndex : "";

  if (targetCompId && credIndex != null) {
    const comp = nm(targetCompId);
    if (comp && comp.ac && comp.ac[credIndex]) {
      const crd = comp.ac[credIndex];
      $("#cred-modal-title").textContent = "Editar Credencial";
      $("#cred-org").value = crd.o || "GOV.BR";
      $("#cred-sit").value = crd.sit || "Ativo";
      $("#cred-sys").value = crd.s || "";
      $("#cred-link").value = crd.link || "";
      $("#cred-usr").value = crd.u || "";
      $("#cred-pwd").value = crd.pw || "";
      $("#cred-obs").value = crd.obs || "";
    }
  } else {
    $("#cred-modal-title").textContent = "Nova Credencial";
    $("#cred-sys").value = "";
    $("#cred-link").value = "";
    $("#cred-usr").value = "";
    $("#cred-pwd").value = "";
    $("#cred-obs").value = "";
    $("#cred-sit").value = "Ativo";
  }

  modal.classList.add("on");
}

async function saveCred() {
  const compId = $("#cred-emp").value;
  const org = $("#cred-org").value;
  const sit = $("#cred-sit").value;
  const sys = ($("#cred-sys").value || "").trim();
  const link = ($("#cred-link").value || "").trim();
  const usr = ($("#cred-usr").value || "").trim();
  const pwd = ($("#cred-pwd").value || "").trim();
  const obs = ($("#cred-obs").value || "").trim();
  const editIdx = $("#cred-edit-index").value;

  if (!sys) {
    toast("Informe o nome do sistema ou serviço.");
    $("#cred-sys").focus();
    return;
  }
  if (!pwd) {
    toast("Informe a senha ou token confidencial.");
    $("#cred-pwd").focus();
    return;
  }

  const comp = nm(compId);
  if (!comp) return;

  if (editIdx !== "") {
    const idx = parseInt(editIdx, 10);
    comp.ac[idx].o = org;
    comp.ac[idx].s = sys;
    comp.ac[idx].link = link;
    comp.ac[idx].u = usr;
    comp.ac[idx].pw = pwd;
    comp.ac[idx].sit = sit;
    comp.ac[idx].obs = obs;
    recordAudit("update_credential", "Alterou credencial", "credential", `${comp.fan} · ${sys}`, "Credencial atualizada no cofre da empresa");
    toast("Credencial atualizada com sucesso!");
  } else {
    comp.ac.push({
      cid: "crd-" + comp.id + "-" + Date.now(),
      o: org,
      s: sys,
      link,
      u: usr,
      pw: pwd,
      sit,
      obs
    });
    recordAudit("create_credential", "Adicionou credencial", "credential", `${comp.fan} · ${sys}`, "Nova credencial adicionada na empresa");
    toast("Credencial adicionada com sucesso!");
  }

  saveCompanies();
  closeModal("md-cred");

  if (location.hash.startsWith("#empresa-")) fic();
}

function closeModal(id) {
  const el = $("#" + id);
  if (el) el.classList.remove("on");
}

/* Event listeners da ficha de empresa existente */
const vEl = $("#v");
if (vEl) {
  vEl.addEventListener("input", e => {
    const t = e.target, p = t.dataset.p;
    if (!p || !D) return;
    setDeepValue(D, p, t.value);
    dy = 1;
    const elDy = $("#dy");
    if (elDy) elDy.style.visibility = "visible";
  });

  vEl.addEventListener("change", e => {
    const t = e.target;
    if (t.dataset.m) {
      t.value = formatCNPJ(t.value);
      D.cnpj = t.value;
    }
    if (t.dataset.r) {
      const y = scrollY;
      fic();
      scrollTo(0, y);
    }
  });
}

/* ==========================================================================
   11. GESTÃO DE USUÁRIOS E AUDITORIA
   ========================================================================== */
function usersView() {
  if (!hasPerm("users_manage") && CURRENT_USER.role !== "master") {
    $("#v").innerHTML = `<div class="al er" style="margin-top:20px">🔒 Acesso Restrito: Apenas o Administrador Master tem controle de gerenciamento de usuários.</div>`;
    return;
  }

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:gap:10px">
      <div>
        <h1>Usuários e Convites</h1>
        <p class="sub" style="margin-bottom:0">Gerencie colaboradores, convites exclusivos e permissões individuais.</p>
      </div>
      <button class="btn pr" onclick="openInviteModal()">+ Convidar Novo Usuário</button>
    </div>

    <div class="cd t" style="margin-bottom:24px">
      <div class="hh" style="padding:10px 14px 4px">
        <h2>Colaboradores Ativos no Sistema (${USERS.length})</h2>
      </div>
      <table>
        <thead>
          <tr>
            <th>Nome</th>
            <th>E-mail</th>
            <th>Nível</th>
            <th>Status</th>
            <th>Permissões Específicas</th>
            <th style="text-align:right">Ações</th>
          </tr>
        </thead>
        <tbody>
          ${USERS.map(u => {
            const isMaster = u.role === "master" || isMasterEmail(u.email);
            const permCount = Object.values(u.permissions || {}).filter(Boolean).length;
            return `
              <tr>
                <td><b>${esc(u.name)}</b></td>
                <td>${esc(u.email)}</td>
                <td><span class="me-role ${isMaster ? 'ok' : (u.role === 'admin' ? 'wn' : 'mu')}">${isMaster ? 'ADMIN MASTER' : (u.role === 'admin' ? 'ADMINISTRADOR' : 'COLABORADOR')}</span></td>
                <td><span class="p ${u.is_active ? 'ok' : 'er'}">${u.is_active ? 'Ativo' : 'Bloqueado'}</span></td>
                <td><span class="s mu">${isMaster ? 'Acesso Total (Irrestrito)' : `${permCount} permissões ativas`}</span></td>
                <td style="text-align:right">
                  ${!isMaster ? `
                    <button class="btn sm" onclick="openEditPermsModal('${u.id}')">Permissões</button>
                    <button class="btn sm" onclick="openResetUserPasswordModal('${u.id}')">Senha</button>
                    <button class="btn sm ${u.is_active ? 'er' : 'ok'}" onclick="toggleUserStatus('${u.id}')">${u.is_active ? 'Bloquear' : 'Ativar'}</button>
                  ` : `<span class="s mu">Inalterável</span>`}
                </td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    </div>

    <div class="cd t">
      <div class="hh" style="padding:10px 14px 4px">
        <h2>Convites Pendentes (${INVITES.filter(i => i.status === 'pending').length})</h2>
      </div>
      <table>
        <thead>
          <tr>
            <th>Nome</th>
            <th>E-mail</th>
            <th>Nível</th>
            <th>Data do Convite</th>
            <th>Status</th>
            <th style="text-align:right">Ações</th>
          </tr>
        </thead>
        <tbody>
          ${INVITES.length ? INVITES.map(inv => `
            <tr>
              <td><b>${esc(inv.name)}</b></td>
              <td>${esc(inv.email)}</td>
              <td><span class="p mu">${esc(inv.role)}</span></td>
              <td>${fd((inv.invited_at || '').slice(0, 10))}</td>
              <td><span class="p ${inv.status === 'pending' ? 'wn' : (inv.status === 'accepted' ? 'ok' : 'er')}">${inv.status === 'pending' ? 'Pendente' : (inv.status === 'accepted' ? 'Aceito' : 'Cancelado')}</span></td>
              <td style="text-align:right">
                ${inv.status === 'pending' ? `
                  <button class="btn sm" onclick="copyInviteLinkByToken('${inv.token}')">Copiar Link</button>
                  <button class="btn sm er" onclick="cancelInvite('${inv.id}')">Cancelar</button>
                ` : `—`}
              </td>
            </tr>
          `).join("") : `<tr><td colspan="6" class="mu" style="padding:16px">Nenhum convite emitido no momento.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function openInviteModal() {
  $("#inv-name").value = "";
  $("#inv-email").value = "";
  $("#inv-role").value = "collaborator";
  onInviteRoleChange("collaborator");
  $("#md-invite").classList.add("on");
}

function onInviteRoleChange(role) {
  const container = $("#inv-perms-container");
  if (!container) return;
  const isAdm = role === "admin";
  container.innerHTML = PERMS_DEF.map(p => {
    const checked = isAdm || ["companies_view", "certificates_view", "obligations_manage"].includes(p.k);
    return `
      <label class="perm-item">
        <input type="checkbox" id="perm-${p.k}" ${checked ? 'checked' : ''}>
        <div>
          <b>${esc(p.l)}</b>
          <p class="s mu" style="margin:0">${esc(p.desc)}</p>
        </div>
      </label>
    `;
  }).join("");
}

function submitInvite() {
  const name = ($("#inv-name").value || "").trim();
  const email = ($("#inv-email").value || "").trim();
  const role = $("#inv-role").value;

  if (!name || !email) {
    toast("Informe o nome e o e-mail do colaborador.");
    return;
  }

  const token = "tok_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
  const perms = {};
  PERMS_DEF.forEach(p => {
    const el = $("#perm-" + p.k);
    perms[p.k] = el ? el.checked : false;
  });

  const inv = {
    id: "inv-" + Date.now(),
    token,
    name,
    email,
    role,
    invited_by: CURRENT_USER ? CURRENT_USER.name : "Master",
    invited_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 7 * 864e5).toISOString(),
    status: "pending",
    permissions: perms
  };

  INVITES.unshift(inv);
  setStored("invites", INVITES);

  recordAudit("invite_created", "Gerou convite", "user_invite", email, `Convite para ${name} (${role})`);
  closeModal("md-invite");

  const link = window.location.origin + window.location.pathname + "#convite=" + token;
  $("#inv-generated-link").value = link;
  $("#md-invite-success").classList.add("on");
}

function copyInviteLink() {
  const link = $("#inv-generated-link").value;
  navigator.clipboard.writeText(link).then(() => toast("Link de convite copiado com sucesso!"));
}

function copyInviteLinkByToken(token) {
  const link = window.location.origin + window.location.pathname + "#convite=" + token;
  navigator.clipboard.writeText(link).then(() => toast("Link copiado para a área de transferência!"));
}

function cancelInvite(invId) {
  INVITES = INVITES.filter(x => x.id !== invId);
  setStored("invites", INVITES);
  toast("Convite cancelado.");
  usersView();
}

function openEditPermsModal(userId) {
  const u = USERS.find(x => x.id === userId);
  if (!u) return;
  $("#edit-user-sub").textContent = `Editando permissões de: ${u.name} (${u.email})`;
  $("#edit-perms-container").dataset.userId = userId;

  $("#edit-perms-container").innerHTML = PERMS_DEF.map(p => {
    const checked = !!(u.permissions && u.permissions[p.k]);
    return `
      <label class="perm-item">
        <input type="checkbox" id="edperm-${p.k}" ${checked ? 'checked' : ''}>
        <div>
          <b>${esc(p.l)}</b>
          <p class="s mu" style="margin:0">${esc(p.desc)}</p>
        </div>
      </label>
    `;
  }).join("");

  $("#md-edit-perms").classList.add("on");
}

function saveUserPerms() {
  const userId = $("#edit-perms-container").dataset.userId;
  const u = USERS.find(x => x.id === userId);
  if (!u) return;

  const perms = {};
  PERMS_DEF.forEach(p => {
    const el = $("#edperm-" + p.k);
    perms[p.k] = el ? el.checked : false;
  });
  u.permissions = perms;
  setStored("users", USERS);

  recordAudit("permissions_update", "Alterou permissões", "user", u.email, `Permissões atualizadas para ${u.name}`);
  closeModal("md-edit-perms");
  toast("Permissões atualizadas com sucesso!");
  usersView();
}

function toggleUserStatus(userId) {
  const u = USERS.find(x => x.id === userId);
  if (!u) return;
  u.is_active = !u.is_active;
  setStored("users", USERS);
  recordAudit("user_status", `${u.is_active ? 'Ativou' : 'Bloqueou'} usuário`, "user", u.email, `Status alterado para ${u.is_active ? 'Ativo' : 'Bloqueado'}`);
  toast(`Usuário ${u.is_active ? 'ativado' : 'bloqueado'} com sucesso.`);
  usersView();
}

function openResetUserPasswordModal(userId) {
  const u = USERS.find(x => x.id === userId);
  if (!u) return;
  $("#reset-user-id").value = userId;
  $("#reset-pwd-sub").textContent = `Redefinindo senha de: ${u.name} (${u.email})`;
  $("#reset-new-pwd").value = "";
  $("#reset-new-pwd2").value = "";
  $("#md-reset-pwd").classList.add("on");
}

async function submitResetUserPassword() {
  const userId = $("#reset-user-id").value;
  const p1 = $("#reset-new-pwd").value;
  const p2 = $("#reset-new-pwd2").value;
  if (p1 !== p2) {
    toast("As senhas não coincidem.");
    return;
  }
  const u = USERS.find(x => x.id === userId);
  if (!u) return;

  u.password_hash = await hashPassword(p1);
  setStored("users", USERS);
  recordAudit("password_reset", "Redefiniu senha de usuário", "user", u.email, `Senha redefinida pelo Administrador Master`);
  closeModal("md-reset-pwd");
  toast("Senha do usuário redefinida com sucesso!");
}

function openChangePasswordModal() {
  $("#pwd-current").value = "";
  $("#pwd-new").value = "";
  $("#pwd-new2").value = "";
  $("#md-change-pwd").classList.add("on");
}

async function submitChangePassword() {
  const curPwd = $("#pwd-current").value;
  const p1 = $("#pwd-new").value;
  const p2 = $("#pwd-new2").value;
  if (p1 !== p2) {
    toast("As senhas não coincidem.");
    return;
  }
  const curHash = await hashPassword(curPwd);
  if (CURRENT_USER.password_hash !== curHash && CURRENT_USER.password_hash !== "master_auth_hash") {
    toast("Senha atual incorreta.");
    return;
  }
  CURRENT_USER.password_hash = await hashPassword(p1);
  const idx = USERS.findIndex(u => u.id === CURRENT_USER.id);
  if (idx >= 0) USERS[idx] = CURRENT_USER;
  setStored("users", USERS);
  setStored("cur_user", CURRENT_USER);
  closeModal("md-change-pwd");
  toast("Sua senha pessoal foi alterada com sucesso!");
}

/* Auditoria */
function auditView() {
  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
      <div>
        <h1>Trilha de Auditoria</h1>
        <p class="sub" style="margin-bottom:0">Histórico detalhado de ações sensíveis, acessos e operações no sistema.</p>
      </div>
      <button class="btn sm" onclick="exportAudit()">Exportar Relatório CSV</button>
    </div>

    <div class="cd t">
      <table>
        <thead>
          <tr>
            <th>Data/Hora</th>
            <th>Usuário</th>
            <th>Ação</th>
            <th>Alvo / Entidade</th>
            <th>Detalhes</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          ${AUDIT_LOGS.map(a => `
            <tr>
              <td>${new Date(a.timestamp).toLocaleString("pt-BR")}</td>
              <td><b>${esc(a.user_name)}</b><br><span class="s mu">${esc(a.user_email)}</span></td>
              <td><span class="p ${a.action.includes('fail') || a.action.includes('delete') ? 'er' : (a.action.includes('reveal') ? 'wn' : 'ok')}">${esc(a.action_label)}</span></td>
              <td><b>${esc(a.target)}</b></td>
              <td>${esc(a.details)}</td>
              <td><span class="s mu" style="font-family:monospace">${esc(a.ip)}</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function exportAudit() {
  let csv = "Data/Hora;Usuario;Email;Acao;Alvo;Detalhes;IP\n";
  AUDIT_LOGS.forEach(a => {
    csv += `"${a.timestamp}";"${a.user_name}";"${a.user_email}";"${a.action_label}";"${a.target}";"${a.details}";"${a.ip}"\n`;
  });
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `nortis_auditoria_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
}

/* ==========================================================================
   12. FLUXO DE LOGIN & CONVITES
   ========================================================================== */
function checkInviteParam() {
  const urlParams = new URLSearchParams(window.location.search);
  let invToken = urlParams.get("invite");
  if (!invToken && location.hash.startsWith("#convite=")) {
    invToken = location.hash.replace("#convite=", "");
  } else if (!invToken && location.hash.startsWith("#invite=")) {
    invToken = location.hash.replace("#invite=", "");
  }
  return invToken;
}

function renderAuthFlow() {
  const invToken = checkInviteParam();
  if (invToken) {
    renderInviteScreen(invToken);
  } else {
    renderLoginScreen();
  }
}

function renderLoginScreen(err = "") {
  $("#app").style.display = "none";
  $("#auth-root").style.display = "flex";
  $("#auth-root").innerHTML = `
    <div class="auth-page">
      <div class="auth-card">
        <div class="auth-logo">
          <div class="brand-title" style="justify-content:center;font-size:26px">
            Nortis <span>Gestão</span>
          </div>
          <p style="font-size:12px;color:var(--pr);font-weight:700;margin-top:4px;letter-spacing:1px">CONTABILIDADE DIGITAL</p>
        </div>
        <div class="auth-title">Acesso Restrito</div>
        <div class="auth-sub">Entre com seu e-mail e senha individual</div>
        ${err ? `<div class="al er" style="font-size:13px;padding:9px 12px;margin-bottom:16px">${esc(err)}</div>` : ""}
        <form class="auth-form" onsubmit="event.preventDefault();handleLogin();">
          <div class="field">
            <label>E-mail corporativo</label>
            <input id="login-email" type="email" placeholder="seu.email@nortiscontabilidade.com.br" required autocomplete="username">
          </div>
          <div class="field">
            <label>Senha pessoal</label>
            <input id="login-pwd" type="password" placeholder="••••••••" required autocomplete="current-password">
          </div>
          <button type="submit" class="btn pr">Entrar no Sistema</button>
        </form>
      </div>
    </div>
  `;
}

async function handleLogin() {
  const email = ($("#login-email").value || "").trim();
  const pwd = ($("#login-pwd").value || "").trim();

  if (!email || !pwd) {
    renderLoginScreen("Por favor, informe seu e-mail e sua senha.");
    return;
  }

  const user = USERS.find(u => u.email.toLowerCase() === email.toLowerCase() || (isMasterEmail(u.email) && isMasterEmail(email)));

  if (!user) {
    recordAudit("login_failed", "Tentativa de login falhou", "auth", email, "E-mail não cadastrado");
    renderLoginScreen("E-mail não cadastrado. Novos colaboradores ingressam exclusivamente mediante convite.");
    return;
  }

  if (user.is_active === false) {
    recordAudit("login_blocked", "Acesso negado", "auth", email, "Usuário bloqueado");
    renderLoginScreen("Seu acesso foi revogado pelo Administrador Master.");
    return;
  }

  const pwdHash = await hashPassword(pwd);
  let isValid = false;

  if (user.password_hash === pwdHash) {
    isValid = true;
  } else if (
    (isMasterEmail(user.email) && (pwd === "Nortis@2026Master" || pwd === "Nortis@2026" || user.password_hash === "master_auth_hash")) ||
    (user.email === "rafael.moura@nortiscontabilidade.com.br" && (pwd === "Admin@2026" || user.password_hash === "admin_auth_hash")) ||
    (user.email === "camila.ribeiro@nortiscontabilidade.com.br" && (pwd === "Collab@2026" || user.password_hash === "collab_auth_hash"))
  ) {
    isValid = true;
    user.password_hash = pwdHash;
    setStored("users", USERS);
  }

  if (!isValid) {
    recordAudit("login_failed_password", "Tentativa de login com senha incorreta", "auth", email, "Senha digitada inválida");
    renderLoginScreen("Senha incorreta. Verifique suas credenciais e tente novamente.");
    return;
  }

  CURRENT_USER = user;
  setStored("cur_user", CURRENT_USER);
  recordAudit("login", "Login realizado com sucesso", "auth", user.email, `Autenticação (${user.role.toUpperCase()})`);

  toast("Bem-vindo(a), " + user.name + "!");
  startApp();
}

function renderInviteScreen(token) {
  const inv = INVITES.find(i => i.token === token);
  $("#app").style.display = "none";
  $("#auth-root").style.display = "flex";

  if (!inv) {
    $("#auth-root").innerHTML = `
      <div class="auth-page"><div class="auth-card" style="text-align:center">
        <h2>Convite Inválido ou Inexistente</h2>
        <p class="sub">Este link não é reconhecido pelo sistema.</p>
        <button class="btn pr" onclick="location.hash='';location.search='';renderLoginScreen()">Ir para o Login</button>
      </div></div>
    `;
    return;
  }

  $("#auth-root").innerHTML = `
    <div class="auth-page">
      <div class="auth-card">
        <div class="auth-logo"><div class="brand-title" style="justify-content:center;font-size:26px">Nortis <span>Gestão</span></div></div>
        <div class="auth-title">Ativação de Conta</div>
        <div class="auth-sub">Olá, <b>${esc(inv.name)}</b>! Defina sua senha individual de acesso:</div>
        <form class="auth-form" onsubmit="event.preventDefault();submitAccountActivation('${token}');">
          <div class="field"><label>E-mail corporativo</label><input value="${esc(inv.email)}" readonly style="background:var(--bg)"></div>
          <div class="field"><label>Crie uma Senha (mínimo 6 caracteres)</label><input id="act-pwd" type="password" required minlength="6" placeholder="Defina sua nova senha"></div>
          <div class="field"><label>Confirme a Senha</label><input id="act-pwd2" type="password" required minlength="6" placeholder="Repita a senha"></div>
          <button type="submit" class="btn pr">Ativar Minha Conta</button>
        </form>
      </div>
    </div>
  `;
}

async function submitAccountActivation(token) {
  const inv = INVITES.find(i => i.token === token);
  if (!inv) return;
  const p1 = $("#act-pwd").value;
  const p2 = $("#act-pwd2").value;
  if (p1 !== p2) {
    toast("As senhas não coincidem.");
    return;
  }
  const newUser = {
    id: "usr-" + Date.now(),
    name: inv.name,
    email: inv.email,
    role: inv.role,
    is_active: true,
    created_at: new Date().toISOString(),
    password_hash: await hashPassword(p1),
    permissions: inv.permissions || {}
  };
  USERS.push(newUser);
  setStored("users", USERS);
  inv.status = "accepted";
  setStored("invites", INVITES);
  CURRENT_USER = newUser;
  setStored("cur_user", CURRENT_USER);
  location.hash = "";
  location.search = "";
  toast("Conta ativada com sucesso! Bem-vindo(a) à Nortis.");
  startApp();
}

function logout() {
  if (CURRENT_USER) {
    recordAudit("logout", "Logout do sistema", "auth", CURRENT_USER.email, "Sessão encerrada");
  }
  CURRENT_USER = null;
  localStorage.removeItem("nortis_cur_user");
  renderAuthFlow();
}

function startApp() {
  if (!CURRENT_USER || !CURRENT_USER.is_active) {
    renderAuthFlow();
    return;
  }

  $("#auth-root").style.display = "none";
  $("#app").style.display = "flex";

  $("#u-name").textContent = CURRENT_USER.name;
  $("#u-email").textContent = CURRENT_USER.email;

  const roleEl = $("#u-role-pill");
  if (CURRENT_USER.role === "master" || isMasterEmail(CURRENT_USER.email)) {
    roleEl.textContent = "ADMIN MASTER";
    roleEl.className = "me-role ok";
  } else if (CURRENT_USER.role === "admin") {
    roleEl.textContent = "ADMINISTRADOR";
    roleEl.className = "me-role wn";
  } else {
    roleEl.textContent = "COLABORADOR";
    roleEl.className = "me-role mu";
  }

  $("#nav-users").style.display = (hasPerm("users_manage") || CURRENT_USER.role === "master") ? "flex" : "none";
  $("#nav-audit").style.display = (hasPerm("history_view") || CURRENT_USER.role === "master") ? "flex" : "none";
  $("#btn-nova-empresa").style.display = hasPerm("companies_edit") ? "inline-flex" : "none";

  go();
}

/* ==========================================================================
   13. ROTEAMENTO GERAL
   ========================================================================== */
function go() {
  toggleMobileMenu(false);
  if (!CURRENT_USER || !CURRENT_USER.is_active) {
    renderAuthFlow();
    return;
  }

  const h = location.hash.slice(1) || "dashboard";
  const [m, a] = h.split("-");

  $$("nav a").forEach(x => {
    const isTarget = x.dataset.r === (m === "empresa" || m === "nova" ? "empresas" : (m === "certificados" && a === "avulsos" ? "certificados-avulsos" : m));
    x.classList.toggle("on", isTarget);
  });

  dy = 0;

  if (m === "nova") {
    if (!hasPerm("companies_edit")) {
      toast("Acesso restrito: Você não tem permissão para cadastrar novas empresas.");
      location.hash = "empresas";
      return;
    }
    cur = 0; orig = null;
    initWizard();
    if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0);
    renderWizard();
  }
  else if (m === "empresa" && nm(a)) {
    if (!hasPerm("companies_view")) {
      toast("Acesso restrito para visualizar empresas.");
      location.hash = "dashboard";
      return;
    }
    if (cur != a) { cur = a; if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0); }
    orig = nm(a);
    ensureCompanyAddressFields(orig);
    D = structuredClone(orig);
    currentCompanyTab = "dados";
    fic();
  }
  else if (h === "certificados-avulsos") {
    if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0);
    singleCertsView();
  }
  else if (m === "usuarios") {
    if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0);
    usersView();
  }
  else if (m === "auditoria") {
    if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0);
    auditView();
  }
  else if (m === "certificados") {
    if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0);
    certs();
  }
  else if (m === "empresas") {
    if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0);
    lst();
  }
  else {
    cur = 0; D = null; if (typeof window !== "undefined" && typeof window.scrollTo === "function") window.scrollTo(0, 0);
    dash();
  }
}

addEventListener("hashchange", go);

const qInput = $("#q"), srBox = $("#sr");
if (qInput && srBox) {
  qInput.oninput = () => {
    const t = qInput.value.trim().toLowerCase();
    const r = t.length < 2 ? [] : C.filter(c => (c.raz + c.fan + (c.cnpj || "") + (c.end_cidade || "")).toLowerCase().includes(t)).slice(0, 6);
    srBox.style.display = r.length ? "block" : "none";
    srBox.innerHTML = r.map(c => `
      <div onmousedown="location.hash='empresa-${c.id}';qInput.value=''">
        <b>${esc(c.fan)}</b> <span class="mu s">${esc(c.cnpj)}</span>
      </div>
    `).join("");
  };
  qInput.onblur = () => setTimeout(() => (srBox.style.display = "none"), 180);
}

// Exporta para o escopo global para compatibilidade com handlers inline no HTML
Object.assign(window, {
  toggleMobileMenu, openChangePasswordModal, submitChangePassword, openResetUserPasswordModal, submitResetUserPassword,
  encryptVaultSecret, decryptVaultSecret, hashPassword,
  F, C, USERS, INVITES, AUDIT_LOGS, CURRENT_USER, SEGMENTS, DEMANDS, SINGLE_CERTS,
  th, logout, handleLogin, submitAccountActivation,
  dashFilter, dash, lst, fl, fic, add, rm, dc, sv, revealField, copySecret, copyToClipboard,
  certs,
  usersView, openInviteModal, onInviteRoleChange, submitInvite, copyInviteLink, copyInviteLinkByToken, cancelInvite, openEditPermsModal, saveUserPerms, toggleUserStatus,
  auditView, exportAudit, closeModal, go,
  openManageSegmentsModal, submitNewSegment, editSegmentPrompt, deleteSegmentCheck, saveSegments,
  openManageDemandsModal, submitNewDemand, editDemandPrompt, deleteDemandCheck, saveDemands,
  openSingleCertModal, saveSingleCert, deleteSingleCert, singleCertsView, toggleSingleCertModalPwd, revealSingleCertPwd,
  saveSingleCerts, scDays, scStatus, scLabel, scWidth, saveCompanies,
  saveCred, openCredModal,
  goToWizardStep, saveWizardDraft, discardWizardDraft, addWizardRow, removeWizardRow, submitFinishWizard, handleCNPJLookupWizard, handleCEPLookupWizard, autoSuggestPortalLink, toggleInputVisibility,
  switchCompanyTab, queryCNPJFicha, toggleWizardDemand, toggleCompanyDemand, updateCompanyStatusDirect,
  formatFullAddress, formatCPFCNPJ, formatCEP, isValidCNPJ, formatCNPJ
});

// Inicialização da aplicação
const inviteCheck = checkInviteParam();
if (inviteCheck) {
  renderInviteScreen(inviteCheck);
} else if (CURRENT_USER && CURRENT_USER.is_active) {
  startApp();
} else {
  renderLoginScreen();
}
