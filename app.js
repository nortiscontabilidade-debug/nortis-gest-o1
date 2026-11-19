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
   1. CONTROLE DE USUÁRIOS E PERMISSÕES (REQUISITO 1)
   ========================================================================== */
const PERMS_DEF = [
  { k: "companies_view", l: "Visualizar empresas", desc: "Listar e abrir dados cadastrais" },
  { k: "companies_edit", l: "Cadastrar e editar empresas", desc: "Criar ou alterar cadastros" },
  { k: "credentials_view", l: "Visualizar credenciais", desc: "Acessar o cofre de credenciais" },
  { k: "credentials_reveal", l: "Revelar e copiar senhas", desc: "Visualizar senhas e copiar tokens" },
  { k: "credentials_edit", l: "Cadastrar e editar credenciais", desc: "Adicionar, alterar e remover no cofre" },
  { k: "certificates_view", l: "Visualizar certificados", desc: "Acompanhar validades e emissoras" },
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
  },
  {
    id: "aud-02",
    timestamp: new Date(Date.now() - 86400 * 1000).toISOString(),
    user_name: "Rafael Moura",
    user_email: "rafael.moura@nortiscontabilidade.com.br",
    action: "reveal",
    action_label: "Revelou senha",
    entity: "credential",
    target: "Lume Cosméticos · SEFAZ-MG",
    details: "Visualizou senha confidencial no cofre",
    ip: "189.40.12.84"
  },
  {
    id: "aud-03",
    timestamp: new Date(Date.now() - 172800 * 1000).toISOString(),
    user_name: "Camila Ribeiro",
    user_email: "camila.ribeiro@nortiscontabilidade.com.br",
    action: "copy",
    action_label: "Copiou credencial",
    entity: "credential",
    target: "Casa Fênix · GOV.BR",
    details: "Copiou token para a área de transferência",
    ip: "189.40.12.84"
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
   2. DADOS DE EMPRESAS, ACESSOS E CERTIFICADOS
   ========================================================================== */
const SEG = ["E-commerce", "Dropshipping", "Marketplace", "Infoprodutos", "Afiliados", "Serviços digitais"];
const REG = ["Simples Nacional", "Lucro Presumido", "Lucro Real", "MEI"];
const RS = ["Camila Ribeiro", "Rafael Moura", "Beatriz Lima"];
const STS = ["Ativa", "Em implantação", "Pausada"];
const OR = ["GOV.BR", "SEFAZ", "Prefeitura", "e-CAC", "FGTS", "Banco", "Marketplace", "Emissor NF-e", "Certificado Digital", "Outro"];
const SIT = ["Ativo", "Revisar", "Pendente"];
const UFS = [["MG", "Belo Horizonte"], ["SP", "São Paulo"], ["RJ", "Rio de Janeiro"], ["PR", "Curitiba"], ["SC", "Florianópolis"]];
const CN = {
  "E-commerce": "4789-0/99 · Comércio varejista de outros produtos",
  "Dropshipping": "4619-2/00 · Representantes comerciais",
  "Marketplace": "6319-4/00 · Portais e provedores de conteúdo",
  "Infoprodutos": "8599-6/04 · Treinamento profissional",
  "Afiliados": "7319-0/02 · Promoção de vendas",
  "Serviços digitais": "6201-5/01 · Desenvolvimento de software"
};
const SO = ["Marina Alves", "Lucas Teixeira", "Paula Nogueira", "Henrique Costa", "Daniela Prado", "Gustavo Faria"];
const R = [
  ["Lume Cosméticos", "Lume Comércio Digital Ltda", "E-commerce", "Simples Nacional", 0, "Ativa", "2022-03", 240, ""],
  ["Orbit Dropship", "Orbit Importações Ltda", "Dropshipping", "Lucro Presumido", 1, "Ativa", "2021-08", 18, "ac"],
  ["Vértice Educação", "Vértice Infoprodutos Ltda", "Infoprodutos", "Simples Nacional", 2, "Ativa", "2023-01", -12, "im"],
  ["Casa Fênix", "Fênix Marketplace Ltda", "Marketplace", "Lucro Presumido", 0, "Ativa", "2020-11", 400, ""],
  ["Rota Afiliados", "Rota Marketing Digital ME", "Afiliados", "MEI", 1, "Ativa", "2024-02", 9, "end"],
  ["Alma Joias", "Alma Acessórios Ltda", "E-commerce", "Simples Nacional", 2, "Em implantação", "2026-10", null, "soc"],
  ["Pixel Cursos", "Pixel Educação Online Ltda", "Infoprodutos", "Lucro Presumido", 0, "Ativa", "2022-09", -40, ""],
  ["Nômade Store", "Nômade Importadora Ltda", "Dropshipping", "Simples Nacional", 1, "Ativa", "2023-06", 75, ""],
  ["Studio Aurora", "Aurora Serviços Digitais Ltda", "Serviços digitais", "Simples Nacional", 2, "Ativa", "2021-04", 300, ""],
  ["Mercado Serra", "Serra Comércio Eletrônico Ltda", "Marketplace", "Lucro Real", 0, "Ativa", "2019-07", 25, ""],
  ["Fluxo Digital", "Fluxo Tecnologia Ltda", "Serviços digitais", "Lucro Presumido", 1, "Pausada", "2022-12", 180, ""],
  ["Verde Afiliados", "Verde Performance ME", "Afiliados", "MEI", 2, "Ativa", "2024-05", 45, ""]
];

function mk(r, i) {
  const id = i + 1, u = UFS[id % 5], s = slug(r[0]), m = r[3] === "MEI", b = r[8];
  const ph = k => "(31) 9" + pad(7100 + id * 77 + k, 4) + "-" + pad(2200 + id * 61, 4);
  const ac = [
    ["GOV.BR", "Gov.br", "***." + (400 + id * 13) + ".***-**", "Conta prata com verificação em duas etapas"],
    ["SEFAZ", "SEFAZ-" + u[0], "ie." + s, "Portal do contribuinte"],
    ["Prefeitura", "NFS-e " + u[1], "nfse." + s, "Emissão de nota de serviço"],
    ["e-CAC", "e-CAC", "Certificado digital", "Acesso por procuração eletrônica"],
    ["FGTS", "Conectividade Social", "cs." + s, "Perfil empregador"],
    ["Banco", "Internet banking PJ", "gestao." + s, "Acesso somente leitura"]
  ];
  if (/commerce|Dropshipping|Marketplace/.test(r[2])) ac.push(["Marketplace", "Seller Center", "seller." + s, "Conta de vendedor principal"]);
  return {
    id, fan: r[0], raz: r[1], seg: r[2], reg: r[3], resp: RS[r[4]], st: r[5], ini: r[6],
    cnpj: pad(11 + i * 3, 2) + "." + pad(210 + i * 37, 3) + "." + pad(104 + i * 91, 3) + "/0001-" + pad(10 + i * 7, 2),
    nat: m ? "213-5 · Empresário individual" : "206-2 · Sociedade empresária limitada",
    ie: String(240123400 + id * 1771), im: b === "im" ? "" : String(4100000 + id * 53),
    end: b === "end" ? "" : "Rua das Acácias, " + (100 + id * 11) + ", sala " + id + " · " + u[1] + "/" + u[0],
    tel: ph(0), mail: "contato@" + s + ".com.br", cnae: CN[r[2]], cnaes: "4791-3/00; 7490-1/04",
    cert: {
      tipo: id % 3 === 0 ? "e-CNPJ A3 (token)" : "e-CNPJ A1 (arquivo)",
      val: iso(r[7]),
      tit: SO[id % 6],
      em: ["Certisign", "Serasa Experian", "Soluti"][id % 3],
      arq: id % 3 === 0 ? "Token no escritório" : "certificado_" + s + ".pfx",
      pw: "Cert#" + id + "24"
    },
    soc: b === "soc" ? [] : [{ n: SO[id % 6], cpf: "***." + (400 + id * 13) + ".***-**", p: m ? "100" : "60", fn: m ? "Titular" : "Sócio-administrador", ct: ph(0) }].concat(m ? [] : [{ n: SO[(id + 3) % 6], cpf: "***." + (300 + id * 9) + ".***-**", p: "40", fn: "Sócio", ct: ph(5) }]),
    ac: ac.map((x, k) => ({ cid: "crd-" + id + "-" + k, o: x[0], s: x[1], u: b === "ac" && x[0] === "e-CAC" ? "" : x[2], pw: "Nx" + id + k + "#24", sit: SIT[[0, 0, 0, 1, 2][(id * 3 + k) % 5]], obs: x[3] }))
  };
}

let C = getStored("companies", R.map(mk));
function saveCompanies() { setStored("companies", C); }

const H = [
  [2, 1, "Rafael Moura", "Atualizou a procuração e-CAC"],
  [5, 2, "Beatriz Lima", "Cadastrou a empresa"],
  [3, 3, "Camila Ribeiro", "Renovou acesso à SEFAZ"],
  [1, 5, "Camila Ribeiro", "Atualizou e-mail de contato"],
  [7, 6, "Rafael Moura", "Alterou o regime tributário"],
  [10, 8, "Camila Ribeiro", "Registrou nova senha do portal municipal"],
  [3, 9, "Beatriz Lima", "Adicionou sócio"],
  [9, 12, "Beatriz Lima", "Atualizou dados bancários"],
  [4, 15, "Rafael Moura", "Enviou novo certificado digital"],
  [8, 20, "Rafael Moura", "Corrigiu CNAE secundário"],
  [12, 25, "Beatriz Lima", "Cadastrou a empresa"],
  [6, 30, "Camila Ribeiro", "Registrou vencimento do certificado"]
];

const blank = () => ({
  id: 0, fan: "", raz: "", cnpj: "", seg: SEG[0], reg: REG[0], resp: RS[0], st: "Ativa",
  ini: T0.toISOString().slice(0, 7), nat: "206-2 · Sociedade empresária limitada",
  ie: "", im: "", end: "", tel: "", mail: "", cnae: "", cnaes: "",
  cert: { tipo: "e-CNPJ A1 (arquivo)", val: "", tit: "", em: "", arq: "", pw: "" },
  soc: [{ n: "", cpf: "", p: "", fn: "Sócio-administrador", ct: "" }],
  ac: ["GOV.BR", "SEFAZ", "Prefeitura", "e-CAC", "FGTS", "Banco"].map((o, k) => ({ cid: "crd-new-" + k, o, s: "", u: "", pw: "", sit: "Pendente", obs: "" }))
});

const nm = id => C.find(c => c.id == id);
const ago = n => (n == 0 ? "hoje" : n == 1 ? "ontem" : "há " + n + " dias");
const pill = (t, k) => `<span class="p ${k}">${t}</span>`;
const stP = c => pill(c.st, c.st === "Ativa" ? "ok" : c.st === "Pausada" ? "mu" : "wn");
const sitP = x => pill(x, x === "Ativo" ? "ok" : x === "Revisar" ? "wn" : "er");
const dd = c => (c.cert && c.cert.val ? Math.round((new Date(c.cert.val + "T12:00") - T0) / 864e5) : null);
const cs = c => { const n = dd(c); return n === null ? "mu" : n < 0 ? "er" : n <= 60 ? "wn" : "ok"; };
const cl = c => { const n = dd(c); return n === null ? "Não cadastrado" : n < 0 ? "Vencido há " + (-n) + " dias" : n <= 60 ? "Vence em " + n + " dias" : "Válido"; };
const cp = c => pill(cl(c), cs(c));
const cw = c => { const n = dd(c); return n === null ? 0 : Math.max(0, Math.min(100, n / 3.65)); };

const miss = c => {
  const m = [];
  [["cnpj", "CNPJ"], ["ie", "Inscrição estadual"], ["im", "Inscrição municipal"], ["end", "Endereço"], ["tel", "Telefone"], ["mail", "E-mail"]].forEach(([k, l]) => {
    if (!c[k]) m.push(l);
  });
  if (!c.soc || !c.soc.some(s => s.n)) m.push("Sócios");
  if (!c.cert || !c.cert.val) m.push("Certificado digital");
  const n = (c.ac || []).filter(a => !a.u).length;
  if (n) m.push(n + " acesso(s) sem usuário");
  return m;
};

const sel = (S, k, l, a, fn) => {
  const obj = S === "F" ? F : (S === "A" ? A : {});
  return `<select onchange="${S}.${k}=this.value;${fn}()"><option value="">${l}</option>${a.map(x => `<option ${obj[k] == x ? "selected" : ""}>${esc(x)}</option>`).join("")}</select>`;
};

/* ==========================================================================
   3. FLUXO DE LOGIN & CONVITES (REQUISITO 2)
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
          <p style="font-size:12px;color:var(--mu);margin-top:4px">Nortis Contabilidade Digital</p>
        </div>
        <div class="auth-title">Acesso Restrito</div>
        <div class="auth-sub">Entre com seu e-mail e senha individual</div>
        ${err ? `<div class="al er" style="font-size:13px;padding:9px 12px;margin-bottom:16px">${esc(err)}</div>` : ""}
        <form class="auth-form" onsubmit="event.preventDefault();handleLogin();">
          <div class="field">
            <label>E-mail corporativo</label>
            <input id="login-email" type="email" placeholder="seu.email@empresa.com.br" required autocomplete="username">
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

function quickFill(em, pw) {
  const eInput = $("#login-email"), pInput = $("#login-pwd");
  if (eInput && pInput) {
    eInput.value = em;
    pInput.value = pw;
    handleLogin();
  }
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
    recordAudit("login_blocked", "Acesso negado", "auth", email, "Usuário bloqueado pelo Administrador Master");
    renderLoginScreen("Seu acesso foi revogado pelo Administrador Master.");
    return;
  }

  const pwdHash = await hashPassword(pwd);

  // Validação segura com migração transparente de credenciais iniciais
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
  recordAudit("login", "Login realizado com sucesso", "auth", user.email, `Autenticação do usuário (${user.role.toUpperCase()})`);

  toast("Bem-vindo(a), " + user.name + "!");
  startApp();
}

function renderInviteScreen(token) {
  const inv = INVITES.find(i => i.token === token);
  $("#app").style.display = "none";
  $("#auth-root").style.display = "flex";

  if (!inv) {
    $("#auth-root").innerHTML = `
      <div class="auth-page">
        <div class="auth-card" style="text-align:center">
          <div class="al er">Convite Inválido ou Inexistente</div>
          <p class="sub">O link de convite fornecido não foi encontrado ou expirou.</p>
          <button class="btn pr" onclick="location.search='';location.hash='';renderLoginScreen()">Ir para o Login</button>
        </div>
      </div>
    `;
    return;
  }

  if (inv.status === "accepted") {
    $("#auth-root").innerHTML = `
      <div class="auth-page">
        <div class="auth-card" style="text-align:center">
          <div class="al wn">Convite Já Utilizado</div>
          <p class="sub">A conta de ${esc(inv.name)} (${esc(inv.email)}) já foi ativada previamente.</p>
          <button class="btn pr" onclick="location.search='';location.hash='';renderLoginScreen()">Fazer Login</button>
        </div>
      </div>
    `;
    return;
  }

  if (inv.status === "cancelled") {
    $("#auth-root").innerHTML = `
      <div class="auth-page">
        <div class="auth-card" style="text-align:center">
          <div class="al er">Convite Cancelado</div>
          <p class="sub">Este convite foi cancelado pelo Administrador Master.</p>
          <button class="btn pr" onclick="location.search='';location.hash='';renderLoginScreen()">Ir para o Login</button>
        </div>
      </div>
    `;
    return;
  }

  const isExpired = new Date(inv.expires_at) < new Date();
  if (isExpired) {
    $("#auth-root").innerHTML = `
      <div class="auth-page">
        <div class="auth-card" style="text-align:center">
          <div class="al er">Convite Expirado</div>
          <p class="sub">O prazo de 7 dias deste convite expirou. Solicite um novo envio ao Administrador Master.</p>
          <button class="btn pr" onclick="location.search='';location.hash='';renderLoginScreen()">Ir para o Login</button>
        </div>
      </div>
    `;
    return;
  }

  const grantedPerms = PERMS_DEF.filter(p => inv.permissions && inv.permissions[p.k]);

  $("#auth-root").innerHTML = `
    <div class="auth-page">
      <div class="auth-card" style="max-width:480px">
        <div class="auth-logo">
          <div class="brand-title" style="justify-content:center;font-size:24px">
            Nortis <span>Gestão</span>
          </div>
          <p style="font-size:12px;color:var(--mu);margin-top:4px">Ativação Individual de Conta</p>
        </div>
        <div class="auth-title">Ativar Minha Conta</div>
        <div class="auth-sub">Defina sua senha pessoal para acessar a plataforma Nortis</div>

        <div class="al ok" style="font-size:12px;margin-bottom:14px;flex-direction:column;align-items:flex-start">
          <div><b>Convidado:</b> ${esc(inv.name)}</div>
          <div><b>E-mail:</b> ${esc(inv.email)}</div>
          <div><b>Nível de acesso:</b> ${inv.role === "admin" ? "Administrador" : "Colaborador"}</div>
        </div>

        <div style="background:rgba(255,255,255,.03);padding:10px;border-radius:8px;border:1px solid var(--bd);margin-bottom:16px;font-size:11px">
          <b style="color:var(--mu);display:block;margin-bottom:4px">Permissões concedidas pelo Administrador Master:</b>
          ${grantedPerms.map(p => `• ${p.l}`).join("<br>")}
        </div>

        <form class="auth-form" onsubmit="event.preventDefault();submitAccountActivation('${inv.token}');">
          <div class="field">
            <label>Criar Senha (mínimo 6 caracteres) *</label>
            <input id="act-pwd" type="password" required minlength="6" placeholder="Sua senha secreta">
          </div>
          <div class="field">
            <label>Confirmar Senha *</label>
            <input id="act-pwd2" type="password" required minlength="6" placeholder="Confirme a senha">
          </div>
          <button type="submit" class="btn pr">Ativar Minha Conta e Entrar</button>
        </form>
      </div>
    </div>
  `;
}

async function submitAccountActivation(token) {
  const inv = INVITES.find(i => i.token === token);
  if (!inv) return;

  const p1 = $("#act-pwd").value, p2 = $("#act-pwd2").value;
  if (p1 !== p2) {
    alert("As senhas informadas não coincidem. Digite novamente.");
    return;
  }

  let user = USERS.find(u => u.email.toLowerCase() === inv.email.toLowerCase());
  if (!user) {
    const initialHash = await hashPassword(p1);
    user = {
      id: "usr-" + Date.now(),
      name: inv.name,
      email: inv.email,
      role: inv.role,
      is_active: true,
      created_at: new Date().toISOString(),
      password_hash: initialHash,
      permissions: Object.assign({}, inv.permissions)
    };
    USERS.push(user);
  } else {
    user.name = inv.name;
    user.role = inv.role;
    user.is_active = true;
    user.permissions = Object.assign({}, inv.permissions);
    user.password_hash = await hashPassword(p1);
  }

  inv.status = "accepted";
  inv.accepted_at = new Date().toISOString();

  setStored("users", USERS);
  setStored("invites", INVITES);

  CURRENT_USER = user;
  setStored("cur_user", CURRENT_USER);

  recordAudit("invite_accepted", "Conta ativada via convite", "users", user.email, `Colaborador (${user.name}) ativou sua conta`);

  history.replaceState(null, "", window.location.pathname);
  toast("Conta ativada com sucesso! Bem-vindo(a), " + user.name + "!");
  startApp();
}


/* ==========================================================================
   GERENCIAMENTO DE SENHAS (USUÁRIO E MASTER)
   ========================================================================== */
function openChangePasswordModal() {
  $("#pwd-current").value = "";
  $("#pwd-new").value = "";
  $("#pwd-new2").value = "";
  $("#md-change-pwd").classList.add("on");
}

async function submitChangePassword() {
  if (!CURRENT_USER) return;
  const current = ($("#pwd-current").value || "").trim();
  const pwdNew = ($("#pwd-new").value || "").trim();
  const pwdNew2 = ($("#pwd-new2").value || "").trim();

  if (!current || !pwdNew || !pwdNew2) {
    alert("Preencha todos os campos obrigatórios.");
    return;
  }
  if (pwdNew.length < 6) {
    alert("A nova senha deve possuir no mínimo 6 caracteres.");
    return;
  }
  if (pwdNew !== pwdNew2) {
    alert("A confirmação da nova senha não coincide.");
    return;
  }

  const currentHash = await hashPassword(current);
  let isCurrentValid = CURRENT_USER.password_hash === currentHash;
  if (!isCurrentValid) {
    const isLegacyMaster = isMasterEmail(CURRENT_USER.email) && (current === "Nortis@2026Master" || current === "Nortis@2026" || CURRENT_USER.password_hash === "master_auth_hash");
    const isLegacyAdmin = CURRENT_USER.email === "rafael.moura@nortiscontabilidade.com.br" && (current === "Admin@2026" || CURRENT_USER.password_hash === "admin_auth_hash");
    const isLegacyCollab = CURRENT_USER.email === "camila.ribeiro@nortiscontabilidade.com.br" && (current === "Collab@2026" || CURRENT_USER.password_hash === "collab_auth_hash");
    if (isLegacyMaster || isLegacyAdmin || isLegacyCollab) {
      isCurrentValid = true;
    }
  }

  if (!isCurrentValid) {
    alert("A senha atual digitada está incorreta.");
    return;
  }

  const newHash = await hashPassword(pwdNew);
  CURRENT_USER.password_hash = newHash;
  const uIdx = USERS.findIndex(u => u.id === CURRENT_USER.id);
  if (uIdx !== -1) {
    USERS[uIdx].password_hash = newHash;
    setStored("users", USERS);
  }
  setStored("cur_user", CURRENT_USER);
  recordAudit("password_change", "Alterou a própria senha", "auth", CURRENT_USER.email, "Senha individual redefinida pelo colaborador");
  closeModal("md-change-pwd");
  toast("Sua senha foi alterada com sucesso!");
}

function openResetUserPasswordModal(userId) {
  if (CURRENT_USER.role !== "master" && !isMasterEmail(CURRENT_USER.email)) {
    toast("Apenas o Administrador Master pode redefinir senhas.");
    return;
  }
  const u = USERS.find(x => x.id === userId);
  if (!u) return;
  $("#reset-user-id").value = u.id;
  $("#reset-pwd-sub").textContent = `Defina uma nova senha de acesso para ${u.name} (${u.email}).`;
  $("#reset-new-pwd").value = "";
  $("#reset-new-pwd2").value = "";
  $("#md-reset-pwd").classList.add("on");
}

async function submitResetUserPassword() {
  const userId = $("#reset-user-id").value;
  const p1 = ($("#reset-new-pwd").value || "").trim();
  const p2 = ($("#reset-new-pwd2").value || "").trim();

  if (p1.length < 6) {
    alert("A nova senha deve ter no mínimo 6 caracteres.");
    return;
  }
  if (p1 !== p2) {
    alert("As senhas digitadas não coincidem.");
    return;
  }

  const targetUser = USERS.find(u => u.id === userId);
  if (!targetUser) return;

  targetUser.password_hash = await hashPassword(p1);
  setStored("users", USERS);
  recordAudit("password_reset", "Redefiniu senha de usuário", "users", targetUser.email, `Senha de ${targetUser.name} redefinida pelo Administrador Master`);
  closeModal("md-reset-pwd");
  toast(`Senha de ${targetUser.name} atualizada com sucesso!`);
  if (location.hash === "#usuarios") usersView();
}

function logout() {
  if (CURRENT_USER) {
    recordAudit("logout", "Logout efetuado", "auth", CURRENT_USER.email, "Sessão finalizada pelo usuário");
  }
  CURRENT_USER = null;
  localStorage.removeItem("nortis_cur_user");
  renderAuthFlow();
}

/* ==========================================================================
   4. INICIALIZAÇÃO DO SISTEMA
   ========================================================================== */
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
   5. DASHBOARD — CARDS CLICÁVEIS (REQUISITO 5)
   ========================================================================== */
function dashFilter(tipo) {
  if (tipo === "empresas_ativas") {
    F.st = "Ativa";
    F.seg = ""; F.reg = ""; F.resp = ""; F.q = ""; F.pend = false;
    location.hash = "empresas";
  } else if (tipo === "cert_vencer") {
    CF = "wn";
    location.hash = "certificados";
  } else if (tipo === "cert_vencidos") {
    CF = "er";
    location.hash = "certificados";
  } else if (tipo === "pendencias") {
    F.pend = true;
    F.st = ""; F.seg = ""; F.reg = ""; F.resp = ""; F.q = "";
    location.hash = "empresas";
  }
}

function dash() {
  const n = C.length;
  const ativas = C.filter(c => c.st === "Ativa").length;
  const pe = C.filter(c => miss(c).length);
  const at = C.filter(c => ["wn", "er"].includes(cs(c))).sort((a, b) => dd(a) - dd(b));
  const vencers = at.filter(c => cs(c) === "wn").length;
  const vencidos = at.filter(c => cs(c) === "er").length;
  const hs = [...H].sort((a, b) => a[1] - b[1]).slice(0, 6);

  const bars = k => {
    const o = {};
    C.forEach(c => (o[c[k]] = (o[c[k]] || 0) + 1));
    return Object.entries(o).sort((x, y) => y[1] - x[1]).map(([l, v]) => `
      <div class="br">
        <span>${esc(l)}</span>
        <div class="tr"><i style="width:${(v / n) * 100}%"></i></div>
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
        <button class="btn" onclick="location.hash='acessos'">Abrir Cofre</button>
        ${hasPerm("companies_edit") ? `<button class="btn pr" onclick="location.hash='nova'">+ Nova Empresa</button>` : ""}
      </div>
    </div>

    <!-- CARDS PRINCIPAIS 100% CLICÁVEIS (REQUISITO 5) -->
    <div class="g g4">
      <div class="cd kp cl" onclick="dashFilter('empresas_ativas')" title="Clique para abrir empresas ativas">
        <span class="kp-hint">Ver ativas →</span>
        <span class="mu">Empresas cadastradas</span>
        <b>${n}</b>
        <span class="s ok">${ativas} ativas no sistema</span>
      </div>

      <div class="cd kp cl" onclick="dashFilter('cert_vencer')" title="Clique para filtrar certificados a vencer nos próximos 60 dias">
        <span class="kp-hint">Filtrar lista →</span>
        <span class="mu">Certificados a vencer</span>
        <b class="wn">${vencers}</b>
        <span class="s wn">nos próximos 60 dias</span>
      </div>

      <div class="cd kp cl" onclick="dashFilter('cert_vencidos')" title="Clique para filtrar certificados vencidos">
        <span class="kp-hint">Ver vencidos →</span>
        <span class="mu">Certificados vencidos</span>
        <b class="er">${vencidos}</b>
        <span class="s er">exigem renovação imediata</span>
      </div>

      <div class="cd kp cl" onclick="dashFilter('pendencias')" title="Clique para listar empresas com informações pendentes">
        <span class="kp-hint">Ver pendências →</span>
        <span class="mu">Com informações pendentes</span>
        <b class="wn">${pe.length}</b>
        <span class="s mu">identificar campos faltantes</span>
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
        <h2>Pendências de cadastro</h2>
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
          <h2>Certificados que exigem atenção</h2>
          <a class="lk" onclick="location.hash='certificados'">Ver todos →</a>
        </div>
        <table>
          <thead>
            <tr><th>Empresa</th><th>Responsável</th><th>Validade</th><th>Situação</th></tr>
          </thead>
          <tbody>
            ${at.length ? at.slice(0, 6).map(c => `
              <tr class="rw" onclick="location.hash='empresa-${c.id}'">
                <td><b>${esc(c.fan)}</b></td>
                <td>${esc(c.resp)}</td>
                <td>${fd(c.cert.val)}</td>
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
   6. EMPRESAS (LISTA E CADASTRO)
   ========================================================================== */
const F = { q: "", seg: "", reg: "", st: "", resp: "", pend: false };

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
      <input placeholder="Filtrar por nome ou CNPJ" value="${esc(F.q)}" oninput="F.q=this.value;fl()">
      ${sel("F", "seg", "Segmento", SEG, "fl")}
      ${sel("F", "reg", "Regime", REG, "fl")}
      ${sel("F", "st", "Status", STS, "fl")}
      ${sel("F", "resp", "Responsável", RS, "fl")}
      ${F.st || F.seg || F.reg || F.resp || F.q || F.pend ? `<button class="btn sm" onclick="F={q:'',seg:'',reg:'',st:'',resp:'',pend:false};lst()">Limpar Filtros</button>` : ""}
    </div>

    <div class="cd t">
      <table>
        <thead>
          <tr>
            <th>Empresa</th>
            <th>CNPJ</th>
            <th>Responsável</th>
            <th>Segmento</th>
            <th>Regime</th>
            <th>Status</th>
            <th>Início</th>
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
  let r = C.filter(c =>
    (!q || (c.fan + c.raz + c.cnpj).toLowerCase().includes(q)) &&
    (!F.seg || c.seg === F.seg) &&
    (!F.reg || c.reg === F.reg) &&
    (!F.st || c.st === F.st) &&
    (!F.resp || c.resp === F.resp) &&
    (!F.pend || miss(c).length > 0)
  );

  $("#tb").innerHTML = r.length ? r.map(c => {
    const m = miss(c);
    return `
      <tr class="rw" onclick="location.hash='empresa-${c.id}'">
        <td><b>${esc(c.fan)}</b><br><span class="s mu">${esc(c.raz)}</span></td>
        <td>${esc(c.cnpj || "—")}</td>
        <td>${esc(c.resp)}</td>
        <td>${esc(c.seg)}</td>
        <td>${esc(c.reg)}</td>
        <td>${stP(c)}</td>
        <td>${c.ini ? c.ini.slice(5) + "/" + c.ini.slice(0, 4) : "—"}</td>
        <td>${cp(c)}</td>
        ${F.pend ? `<td><span class="p wn s" title="${esc(m.join(', '))}">Falta: ${esc(m.slice(0, 2).join(', '))}${m.length > 2 ? ` +${m.length - 2}` : ""}</span></td>` : ""}
      </tr>
    `;
  }).join("") : `<tr><td colspan="${F.pend ? 9 : 8}" class="mu" style="padding:16px">Nenhuma empresa encontrada com os filtros selecionados.</td></tr>`;

  $("#ct").textContent = `${r.length} de ${C.length} empresas exibidas`;
}

let D = null, orig = null, dy = 0, cur = 0;
const get = p => p.split(".").reduce((o, z) => (o ? o[z] : ""), D);
const I = (p, l, o = {}) => `<label class="fi"${o.w ? ` style="grid-column:span ${o.w}"` : ""}><span>${l}</span><input data-p="${p}"${o.t ? ` type="${o.t}"` : ""}${o.m ? ` data-m="1"` : ""}${o.r ? ` data-r="1"` : ""} value="${esc(get(p) || "")}" ${!hasPerm("companies_edit") ? "disabled" : ""}></label>`;
const S = (p, l, a) => `<label class="fi"><span>${l}</span><select data-p="${p}" ${!hasPerm("companies_edit") ? "disabled" : ""}>${a.map(x => `<option ${x == get(p) ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></label>`;
const Ci = (p, t) => `<td><input data-p="${p}"${t ? ` type="${t}"` : ""} value="${esc(get(p) || "")}" ${!hasPerm("companies_edit") ? "disabled" : ""}></td>`;
const Cs = (p, a) => `<td><select data-p="${p}" ${!hasPerm("companies_edit") ? "disabled" : ""}>${a.map(x => `<option ${x == get(p) ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></td>`;

function fic() {
  const c = D, ex = !!orig;
  const i = ex ? C.indexOf(orig) : 0;
  const pv = C[(i + C.length - 1) % C.length];
  const nx = C[(i + 1) % C.length];
  const m = miss(c);
  const hs = ex ? H.filter(x => x[0] == c.id).sort((a, b) => a[1] - b[1]) : [];
  const go2 = id => `document.getElementById('${id}').scrollIntoView({behavior:'smooth'})`;

  $("#v").innerHTML = `
    <div class="bar">
      <div>
        <p class="s mu"><a class="lk" style="margin:0" href="#empresas">Empresas</a> / ${ex ? esc(orig.fan) : "Nova empresa"}</p>
        <h1>${ex ? esc(orig.raz) : "Nova empresa"}</h1>
      </div>
      <div class="sp"></div>
      <span id="dy" class="s wn" style="visibility:${dy ? "visible" : "hidden"}">Alterações não salvas</span>
      ${ex ? `
        <button class="btn" title="${esc(pv.fan)}" onclick="location.hash='empresa-${pv.id}'">‹ Anterior</button>
        <button class="btn" title="${esc(nx.fan)}" onclick="location.hash='empresa-${nx.id}'">Próxima ›</button>
        ${hasPerm("companies_edit") ? `<button class="btn" onclick="dc()">Descartar</button>` : ""}
      ` : `<button class="btn" onclick="location.hash='empresas'">Cancelar</button>`}
      ${hasPerm("companies_edit") ? `<button class="btn pr" onclick="sv()">Salvar Alterações</button>` : ""}
    </div>

    ${ex ? `<p style="margin-bottom:10px">${stP(c)} ${pill(c.reg, "mu")} ${cp(c)}</p>` : ""}

    <div class="chips">
      <a onclick="${go2("s1")}">Dados cadastrais</a>
      <a onclick="${go2("s2")}">Sócios (${c.soc.length})</a>
      <a onclick="${go2("s3")}">Certificado digital</a>
      <a onclick="${go2("s4")}">Acessos e Credenciais (${c.ac.length})</a>
      <a onclick="${go2("s5")}">Histórico</a>
    </div>

    ${m.length ? `<div class="al wn">⚠️ Informações pendentes nesta empresa: <b>${esc(m.join(", "))}</b>.</div>` : ""}

    <div class="cd" id="s1">
      <h2>Dados cadastrais</h2>
      <div class="fl">
        ${I("raz", "Razão social *", { w: 2 })}
        ${I("fan", "Nome fantasia")}
        ${I("cnpj", "CNPJ", { m: 1 })}
        ${S("seg", "Segmento", SEG)}
        ${S("reg", "Regime tributário", REG)}
        ${S("resp", "Responsável interno", RS)}
        ${S("st", "Status", STS)}
        ${I("ini", "Início do atendimento", { t: "month" })}
        ${I("nat", "Natureza jurídica")}
        ${I("end", "Endereço", { w: 2 })}
        ${I("tel", "Telefone")}
        ${I("mail", "E-mail", { w: 2 })}
        ${I("ie", "Inscrição estadual")}
        ${I("im", "Inscrição municipal")}
        ${I("cnae", "CNAE principal", { w: 2 })}
        ${I("cnaes", "CNAEs secundários")}
      </div>
    </div>

    <div class="cd" id="s2">
      <div class="hh">
        <h2>Sócios e responsáveis</h2>
        ${hasPerm("companies_edit") ? `<button class="btn sm" onclick="add('soc')">+ Adicionar sócio</button>` : ""}
      </div>
      <table class="ed">
        <thead>
          <tr><th>Nome</th><th>CPF</th><th style="width:90px">Particip. %</th><th>Função</th><th>Contato</th>${hasPerm("companies_edit") ? "<th></th>" : ""}</tr>
        </thead>
        <tbody>
          ${c.soc.map((s, k) => `
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

    <div class="cd" id="s3">
      <div class="hh">
        <h2>Certificado digital</h2>
        ${cp(c)}
      </div>
      <div class="fl">
        ${S("cert.tipo", "Tipo", ["e-CNPJ A1 (arquivo)", "e-CNPJ A3 (token)", "e-CPF A1", "e-CPF A3"])}
        ${I("cert.val", "Validade", { t: "date", r: 1 })}
        ${I("cert.tit", "Titular")}
        ${I("cert.em", "Emissora")}
        ${I("cert.arq", "Arquivo ou local de guarda")}
        <label class="fi">
          <span>Senha do certificado</span>
          <div style="display:flex;align-items:center;gap:6px">
            <input type="password" data-p="cert.pw" value="${esc(c.cert.pw)}" ${!hasPerm("companies_edit") ? "disabled" : ""}>
            ${hasPerm("credentials_reveal") ? `
              <a class="lk" onclick="revealField(this, 'cert', ${c.id})">Ver</a>
              <a class="lk" onclick="copySecret('${esc(c.cert.pw)}', '${esc(c.fan)} · Certificado')">Copiar</a>
            ` : `<span class="mu s" title="Apenas usuários autorizados">[Protegido]</span>`}
          </div>
        </label>
      </div>
    </div>

    <div class="cd" id="s4">
      <div class="hh">
        <h2>Acessos e Credenciais (Cofre)</h2>
        ${hasPerm("credentials_edit") ? `<button class="btn sm" onclick="openCredModal(null, ${c.id})">+ Adicionar credencial</button>` : ""}
      </div>
      <table class="ed">
        <thead>
          <tr>
            <th style="width:120px">Órgão</th>
            <th>Sistema</th>
            <th>Usuário</th>
            <th>Senha / Token</th>
            <th style="width:110px">Situação</th>
            <th>Observações</th>
            ${hasPerm("credentials_edit") ? "<th></th>" : ""}
          </tr>
        </thead>
        <tbody>
          ${c.ac.map((a, k) => `
            <tr>
              ${Cs(`ac.${k}.o`, OR)}
              ${Ci(`ac.${k}.s`)}
              ${Ci(`ac.${k}.u`)}
              <td>
                <div style="display:flex;align-items:center;gap:4px">
                  <input type="password" data-p="ac.${k}.pw" value="${esc(a.pw)}" ${!hasPerm("credentials_edit") ? "disabled" : ""}>
                  ${hasPerm("credentials_reveal") ? `
                    <a class="lk" onclick="revealField(this, 'acesso', ${c.id}, ${k})">Ver</a>
                    <a class="lk" onclick="copySecret('${esc(a.pw)}', '${esc(c.fan)} · ${esc(a.s)}')">Copiar</a>
                  ` : `<span class="mu s" title="Apenas usuários autorizados">[Oculto]</span>`}
                </div>
              </td>
              ${Cs(`ac.${k}.sit`, SIT)}
              ${Ci(`ac.${k}.obs`)}
              ${hasPerm("credentials_edit") ? `<td><span class="x" title="Remover" onclick="rm('ac',${k})">×</span></td>` : ""}
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="cd" id="s5">
      <h2>Histórico de alterações</h2>
      ${hs.length ? `
        <div class="tl">
          ${hs.map(x => `<div><b>${esc(x[3])}</b><br><span class="s mu">${esc(x[2])} · ${ago(x[1])}</span></div>`).join("")}
        </div>
      ` : `<p class="mu">As alterações salvas nesta ficha aparecem aqui, com data e responsável.</p>`}
    </div>
  `;
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
  el.textContent = isPass ? "Ocultar" : "Ver";

  if (isPass) {
    const sysName = type === "cert" ? "Certificado Digital" : (comp && comp.ac[index] ? comp.ac[index].s : "Acesso");
    recordAudit("reveal", "Revelou senha", "credential", `${comp ? comp.fan : ''} · ${sysName}`, `Usuário revelou senha do sistema`);
  }
}

function copySecret(val, targetLabel) {
  if (!hasPerm("credentials_reveal")) {
    toast("Acesso negado: Você não possui permissão para copiar senhas.");
    return;
  }
  navigator.clipboard.writeText(val).then(() => {
    recordAudit("copy", "Copiou senha", "credential", targetLabel, "Senha/token copiado para área de transferência");
    toast("Copiado com sucesso para a área de transferência!");
  }).catch(() => {
    toast("Falha ao copiar. Tente selecionar manualmente.");
  });
}

function add(k) {
  const y = scrollY;
  D[k].push(k === "soc" ? { n: "", cpf: "", p: "", fn: "Sócio", ct: "" } : { cid: "crd-" + Date.now(), o: "Outro", s: "", u: "", pw: "", sit: "Pendente", obs: "" });
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
  if (!D.raz.trim()) {
    toast("Informe a razão social para salvar.");
    $("[data-p=raz]").focus();
    return;
  }
  D.fan = D.fan.trim() || D.raz.trim();

  if (!orig) {
    D.id = Math.max(0, ...C.map(c => c.id)) + 1;
    C.push(D);
    saveCompanies();
    H.push([D.id, 0, CURRENT_USER.name, "Cadastrou a empresa"]);
    recordAudit("create", "Cadastrou empresa", "company", D.fan, `Nova empresa cadastrada por ${CURRENT_USER.name}`);
    dy = 0;
    toast("Empresa cadastrada com sucesso!");
    location.hash = "empresa-" + D.id;
    return;
  }

  const pk = o => { const { soc, ac, cert, ...r } = o; return JSON.stringify(r); };
  const j = JSON.stringify, ch = [];
  if (pk(D) != pk(orig)) ch.push("dados cadastrais");
  if (j(D.soc) != j(orig.soc)) ch.push("sócios");
  if (j(D.cert) != j(orig.cert)) ch.push("certificado");
  if (j(D.ac) != j(orig.ac)) ch.push("acessos");

  if (!ch.length) {
    toast("Nenhuma alteração para salvar.");
    return;
  }

  C[C.indexOf(orig)] = D;
  saveCompanies();
  H.push([D.id, 0, CURRENT_USER.name, "Editou " + ch.join(", ")]);
  recordAudit("update", "Alterou empresa", "company", D.fan, `Atualizou: ${ch.join(', ')}`);
  orig = D;
  D = structuredClone(D);
  dy = 0;
  fic();
  toast("Ficha da empresa salva com sucesso.");
}

/* Event listeners da ficha */
$("#v").addEventListener("input", e => {
  const t = e.target, p = t.dataset.p;
  if (!p || !D) return;
  const k = p.split(".");
  let o = D;
  while (k.length > 1) o = o[k.shift()];
  o[k[0]] = t.value;
  dy = 1;
  const elDy = $("#dy");
  if (elDy) elDy.style.visibility = "visible";
});

$("#v").addEventListener("change", e => {
  const t = e.target;
  if (t.dataset.m) {
    const v = t.value.replace(/\D/g, "").slice(0, 14);
    if (v.length === 14) t.value = v.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/, "$1.$2.$3/$4-$5");
    D.cnpj = t.value;
  }
  if (t.dataset.r) {
    const y = scrollY;
    fic();
    scrollTo(0, y);
  }
});

/* ==========================================================================
   7. COFRE DE CREDENCIAIS (REQUISITO 3)
   ========================================================================== */
const A = { q: "", emp: "", o: "", sit: "" };
let AL = [];

function acc() {
  if (!hasPerm("credentials_view")) {
    $("#v").innerHTML = `<div class="al er" style="margin-top:20px">🔒 Acesso Restrito: Você não possui a permissão de visualizar o Cofre de Credenciais.</div>`;
    return;
  }

  AL = C.flatMap(c => (c.ac || []).map((a, k) => ({ ...a, c, k })));

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
      <div>
        <h1>Cofre de Credenciais</h1>
        <p class="sub" id="ca" style="margin-bottom:0"></p>
      </div>
      <div style="display:flex;gap:8px">
        ${hasPerm("history_view") ? `<button class="btn" onclick="location.hash='auditoria'">Trilha de Auditoria</button>` : ""}
        ${hasPerm("credentials_edit") ? `<button class="btn pr" onclick="openCredModal()">+ Nova Credencial</button>` : ""}
      </div>
    </div>

    <div class="fb">
      <input placeholder="Buscar por sistema, usuário ou empresa" value="${esc(A.q)}" oninput="A.q=this.value;fa()">
      ${sel("A", "emp", "Empresa", C.map(c => c.fan), "fa")}
      ${sel("A", "o", "Órgão / Categoria", OR, "fa")}
      ${sel("A", "sit", "Situação", SIT, "fa")}
      ${A.emp || A.o || A.sit || A.q ? `<button class="btn sm" onclick="A={q:'',emp:'',o:'',sit:''};acc()">Limpar</button>` : ""}
    </div>

    <div class="cd t">
      <table>
        <thead>
          <tr>
            <th>Empresa</th>
            <th>Órgão / Categoria</th>
            <th>Sistema / Serviço</th>
            <th>Usuário / Chave</th>
            <th>Senha / Token</th>
            <th>Situação</th>
            <th>Observações</th>
            <th>Ações</th>
          </tr>
        </thead>
        <tbody id="ta"></tbody>
      </table>
    </div>
  `;
  fa();
}

function fa() {
  const q = A.q.toLowerCase();
  const r = AL.filter(a =>
    (!q || (a.s + a.u + a.c.fan + a.o).toLowerCase().includes(q)) &&
    (!A.emp || a.c.fan === A.emp) &&
    (!A.o || a.o === A.o) &&
    (!A.sit || a.sit === A.sit)
  );

  $("#ta").innerHTML = r.length ? r.map(a => `
    <tr>
      <td onclick="location.hash='empresa-${a.c.id}'" style="cursor:pointer"><b>${esc(a.c.fan)}</b></td>
      <td>${esc(a.o)}</td>
      <td><b>${esc(a.s)}</b></td>
      <td>${a.u ? `<span style="font-family:monospace">${esc(a.u)}</span>` : `<span class="er">vazio</span>`}</td>
      <td>
        <div class="pw-box">
          <span class="pw-display" id="pwd-${a.c.id}-${a.k}">••••••••</span>
          ${hasPerm("credentials_reveal") ? `
            <a class="lk" onclick="toggleVaultPwd(this, ${a.c.id}, ${a.k})">Ver</a>
            <a class="lk" onclick="copyVaultPwd(${a.c.id}, ${a.k})">Copiar</a>
          ` : `<span class="mu s" title="Apenas usuários com permissão de revelação">[Protegido]</span>`}
        </div>
      </td>
      <td>${sitP(a.sit)}</td>
      <td class="mu s">${esc(a.obs)}</td>
      <td>
        <div style="display:flex;gap:6px">
          <button class="btn sm" onclick="location.hash='empresa-${a.c.id}'">Ficha</button>
          ${hasPerm("credentials_edit") ? `<button class="btn sm" onclick="openCredModal(${a.c.id}, ${a.k})">Editar</button>` : ""}
          ${hasPerm("credentials_edit") ? `
            <button class="btn sm er" onclick="deleteCred(${a.c.id}, ${a.k})">Excluir</button>
          ` : ""}
        </div>
      </td>
    </tr>
  `).join("") : `<tr><td colspan="8" class="mu" style="padding:16px">Nenhuma credencial localizada no cofre.</td></tr>`;

  $("#ca").textContent = `${r.length} credenciais seguras vinculadas às empresas cadastradas`;
}

async function toggleVaultPwd(btn, compId, index) {
  if (!hasPerm("credentials_reveal")) {
    toast("Acesso negado: você não tem permissão para revelar senhas.");
    return;
  }
  const comp = nm(compId);
  if (!comp || !comp.ac[index]) return;
  const item = comp.ac[index];
  const span = $(`#pwd-${compId}-${index}`);
  const isHidden = span.textContent === "••••••••";

  if (isHidden) {
    const plain = await decryptVaultSecret(item.pw);
    span.textContent = plain || "(sem senha)";
    btn.textContent = "Ocultar";
    recordAudit("reveal", "Revelou senha do cofre", "credential", `${comp.fan} · ${item.s}`, "Visualizou credencial em texto aberto");
  } else {
    span.textContent = "••••••••";
    btn.textContent = "Ver";
  }
}

async function copyVaultPwd(compId, index) {
  if (!hasPerm("credentials_reveal")) {
    toast("Acesso negado: você não tem permissão para copiar senhas.");
    return;
  }
  const comp = nm(compId);
  if (!comp || !comp.ac[index]) return;
  const item = comp.ac[index];
  const plain = await decryptVaultSecret(item.pw);
  copySecret(plain, `${comp.fan} · ${item.s}`);
}

function deleteCred(compId, index) {
  if (!hasPerm("credentials_edit")) {
    toast("Acesso negado para excluir credencial.");
    return;
  }
  const comp = nm(compId);
  if (!comp) return;
  if (confirm(`Tem certeza que deseja excluir a credencial ${comp.ac[index].s} da empresa ${comp.fan}?`)) {
    const sysName = comp.ac[index].s;
    comp.ac.splice(index, 1);
    saveCompanies();
    recordAudit("delete", "Excluiu credencial", "credential", `${comp.fan} · ${sysName}`, `Credencial removida do cofre por ${CURRENT_USER.name}`);
    toast("Credencial removida do cofre.");
    acc();
  }
}

async function openCredModal(targetCompId = null, credIndex = null) {
  if (!hasPerm("credentials_edit")) {
    toast("Você não possui permissão para cadastrar ou editar credenciais.");
    return;
  }
  const selectEmp = $("#cred-emp");
  selectEmp.innerHTML = C.map(c => `<option value="${c.id}" ${targetCompId == c.id ? "selected" : ""}>${esc(c.fan)} (${esc(c.cnpj || "sem CNPJ")})</option>`).join("");

  const editIndexInput = $("#cred-edit-index");
  const modalTitle = $("#cred-modal-title");

  if (credIndex !== null && targetCompId !== null) {
    const comp = nm(targetCompId);
    const item = comp && comp.ac ? comp.ac[credIndex] : null;
    if (item) {
      if (editIndexInput) editIndexInput.value = credIndex;
      if (modalTitle) modalTitle.textContent = "Editar Credencial no Cofre";
      $("#cred-org").value = item.o || "Outro";
      $("#cred-sys").value = item.s || "";
      $("#cred-usr").value = item.u || "";
      $("#cred-pwd").value = await decryptVaultSecret(item.pw || "");
      $("#cred-sit").value = item.sit || "Ativo";
      $("#cred-obs").value = item.obs || "";
      $("#md-cred").classList.add("on");
      return;
    }
  }

  // Nova credencial
  if (editIndexInput) editIndexInput.value = "";
  if (modalTitle) modalTitle.textContent = "Nova Credencial no Cofre";
  $("#cred-sys").value = "";
  $("#cred-usr").value = "";
  $("#cred-pwd").value = "";
  $("#cred-obs").value = "";
  $("#md-cred").classList.add("on");
}

async function saveCred() {
  const compId = parseInt($("#cred-emp").value);
  const sys = $("#cred-sys").value.trim();
  const org = $("#cred-org").value;
  const usr = $("#cred-usr").value.trim();
  const rawPwd = $("#cred-pwd").value.trim();
  const sit = $("#cred-sit").value;
  const obs = $("#cred-obs").value.trim();
  const editIndexVal = $("#cred-edit-index") ? $("#cred-edit-index").value : "";

  if (!sys) {
    alert("Informe o nome do sistema ou serviço.");
    return;
  }

  const comp = nm(compId);
  if (!comp) {
    alert("Empresa selecionada inválida.");
    return;
  }

  comp.ac = comp.ac || [];
  const encPwd = await encryptVaultSecret(rawPwd);

  if (editIndexVal !== "" && editIndexVal !== null && !isNaN(parseInt(editIndexVal))) {
    const idx = parseInt(editIndexVal);
    const prevSys = comp.ac[idx] ? comp.ac[idx].s : sys;
    comp.ac[idx] = Object.assign(comp.ac[idx] || {}, {
      o: org,
      s: sys,
      u: usr,
      pw: encPwd,
      sit: sit,
      obs: obs
    });
    saveCompanies();
    recordAudit("update", "Alterou credencial no cofre", "credential", `${comp.fan} · ${sys}`, `Atualizado por ${CURRENT_USER.name} (anterior: ${prevSys})`);
    closeModal("md-cred");
    toast("Credencial atualizada no cofre!");
  } else {
    comp.ac.push({
      cid: "crd-" + Date.now(),
      o: org,
      s: sys,
      u: usr,
      pw: encPwd,
      sit: sit,
      obs: obs
    });
    saveCompanies();
    recordAudit("create", "Cadastrou credencial no cofre", "credential", `${comp.fan} · ${sys}`, `Criado por ${CURRENT_USER.name}`);
    closeModal("md-cred");
    toast("Credencial gravada no cofre com segurança!");
  }

  if (location.hash === "#acessos") acc();
  else if (location.hash.startsWith("#empresa-")) fic();
}

/* ==========================================================================
   8. GESTÃO DE CERTIFICADOS DIGITAIS
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
        <h1>Gestão de Certificados Digitais</h1>
        <p class="sub" style="margin-bottom:0">Clique em qualquer indicador para filtrar a listagem abaixo.</p>
      </div>
      ${CF ? `<button class="btn sm" onclick="CF='';certs()">Remover Filtro (${CF.toUpperCase()})</button>` : ""}
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
            <th>Responsável</th>
            <th>Validade</th>
            <th style="width:160px">Vigência</th>
            <th>Situação</th>
            <th>Arquivo / Guarda</th>
          </tr>
        </thead>
        <tbody>
          ${r.map(c => `
            <tr class="rw" onclick="location.hash='empresa-${c.id}'">
              <td><b>${esc(c.fan)}</b></td>
              <td>${esc(c.cert.tipo)}</td>
              <td>${esc(c.resp)}</td>
              <td>${fd(c.cert.val)}</td>
              <td><div class="tr"><i style="width:${cw(c)}%;background:var(--${cs(c)})"></i></div></td>
              <td>${cp(c)}</td>
              <td class="mu s">${esc(c.cert.arq)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

/* ==========================================================================
   9. USUÁRIOS E CONVITES (REQUISITO 1 E 2)
   ========================================================================== */
function usersView() {
  if (!hasPerm("users_manage") && CURRENT_USER.role !== "master") {
    $("#v").innerHTML = `<div class="al er" style="margin-top:20px">🔒 Acesso Restrito: Apenas o Administrador Master tem controle de gerenciamento de usuários.</div>`;
    return;
  }

  const isMaster = CURRENT_USER.role === "master" || isMasterEmail(CURRENT_USER.email);
  const pendingInvites = INVITES.filter(i => i.status === "pending");

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px">
      <div>
        <h1>Usuários e Controle de Acessos</h1>
        <p class="sub" style="margin-bottom:0">Acesso individual, controle de permissões e admissão estritamente por convite.</p>
      </div>
      ${isMaster ? `<button class="btn pr" onclick="openInviteModal()">+ Convidar Novo Usuário</button>` : ""}
    </div>

    <div class="g g4">
      <div class="cd kp">
        <span class="mu">Total de Usuários</span>
        <b>${USERS.length}</b>
        <span class="s ok">${USERS.filter(u => u.is_active).length} ativos</span>
      </div>
      <div class="cd kp">
        <span class="mu">Administradores</span>
        <b class="wn">${USERS.filter(u => u.role === "admin" || u.role === "master").length}</b>
        <span class="s mu">com acesso ampliado</span>
      </div>
      <div class="cd kp">
        <span class="mu">Colaboradores</span>
        <b>${USERS.filter(u => u.role === "collaborator").length}</b>
        <span class="s mu">acesso limitado individual</span>
      </div>
      <div class="cd kp">
        <span class="mu">Convites Pendentes</span>
        <b class="${pendingInvites.length ? 'wn' : ''}">${pendingInvites.length}</b>
        <span class="s mu">aguardando ativação</span>
      </div>
    </div>

    <!-- TABELA DE USUÁRIOS -->
    <div class="cd t" style="margin-bottom:24px">
      <div class="hh" style="padding:10px 14px 4px">
        <h2>Usuários Cadastrados</h2>
      </div>
      <table>
        <thead>
          <tr>
            <th>Nome</th>
            <th>E-mail</th>
            <th>Nível de Acesso</th>
            <th>Status</th>
            <th>Permissões Ativas</th>
            <th>Ações</th>
          </tr>
        </thead>
        <tbody>
          ${USERS.map(u => {
            const isUserMaster = u.role === "master" || isMasterEmail(u.email);
            const activePermCount = PERMS_DEF.filter(p => u.permissions && u.permissions[p.k]).length;
            return `
              <tr>
                <td><b>${esc(u.name)}</b> ${isUserMaster ? `<span class="p ok s" style="margin-left:4px">MASTER</span>` : ""}</td>
                <td>${esc(u.email)}</td>
                <td><span class="me-role ${isUserMaster ? 'ok' : u.role === 'admin' ? 'wn' : 'mu'}">${isUserMaster ? 'ADMIN MASTER' : u.role.toUpperCase()}</span></td>
                <td>${u.is_active ? `<span class="p ok">Ativo</span>` : `<span class="p er">Bloqueado</span>`}</td>
                <td>
                  <span class="mu s">${isUserMaster ? 'Acesso Total e Irrestrito (9/9)' : `${activePermCount} de 9 permissões`}</span>
                </td>
                <td>
                  <div style="display:flex;gap:6px">
                    ${!isUserMaster && isMaster ? `
                      <button class="btn sm" onclick="openEditPermsModal('${u.id}')">Permissões</button>
                      <button class="btn sm" onclick="openResetUserPasswordModal('${u.id}')" title="Redefinir senha de acesso">Redefinir Senha</button>
                      <button class="btn sm ${u.is_active ? 'er' : ''}" onclick="toggleUserStatus('${u.id}')">${u.is_active ? 'Revogar Acesso' : 'Desbloquear'}</button>
                      <button class="btn sm er" onclick="deleteUser('${u.id}')">Excluir</button>
                    ` : `<span class="mu s">${isUserMaster ? 'Protegido pelo sistema' : 'Apenas leitura'}</span>`}
                  </div>
                </td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    </div>

    <!-- TABELA DE CONVITES -->
    <div class="cd t">
      <div class="hh" style="padding:10px 14px 4px">
        <h2>Convites de Acesso Emitidos</h2>
        ${isMaster ? `<button class="btn sm pr" onclick="openInviteModal()">+ Novo Convite</button>` : ""}
      </div>
      <table>
        <thead>
          <tr>
            <th>Convidado</th>
            <th>E-mail</th>
            <th>Nível</th>
            <th>Enviado Por</th>
            <th>Data de Envio</th>
            <th>Expiração</th>
            <th>Status</th>
            <th>Ações</th>
          </tr>
        </thead>
        <tbody>
          ${INVITES.length ? INVITES.map(inv => {
            const isExp = new Date(inv.expires_at) < new Date();
            const statusLabel = inv.status === 'accepted' ? `<span class="p ok">Aceito</span>` :
                                inv.status === 'cancelled' ? `<span class="p er">Cancelado</span>` :
                                isExp ? `<span class="p mu">Expirado</span>` : `<span class="p wn">Pendente</span>`;
            return `
              <tr>
                <td><b>${esc(inv.name)}</b></td>
                <td>${esc(inv.email)}</td>
                <td><span class="tag-badge ${inv.role === 'admin' ? 'act-reveal' : 'act-copy'}">${inv.role.toUpperCase()}</span></td>
                <td class="mu s">${esc(inv.invited_by)}</td>
                <td class="mu s">${new Date(inv.invited_at).toLocaleDateString('pt-BR')}</td>
                <td class="mu s">${new Date(inv.expires_at).toLocaleDateString('pt-BR')}</td>
                <td>${statusLabel}</td>
                <td>
                  <div style="display:flex;gap:6px">
                    ${inv.status === 'pending' && !isExp ? `
                      <button class="btn sm" onclick="copyInviteLinkByToken('${inv.token}')">Copiar Link</button>
                      <button class="btn sm er" onclick="cancelInvite('${inv.id}')">Cancelar</button>
                    ` : ""}
                    ${(isExp || inv.status === 'cancelled') && isMaster ? `
                      <button class="btn sm pr" onclick="resendInvite('${inv.id}')">Reenviar</button>
                    ` : ""}
                  </div>
                </td>
              </tr>
            `;
          }).join("") : `<tr><td colspan="8" class="mu" style="padding:16px">Nenhum convite emitido até o momento.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function openInviteModal() {
  if (CURRENT_USER.role !== "master" && !isMasterEmail(CURRENT_USER.email)) {
    toast("Apenas o Administrador Master pode convidar novos usuários.");
    return;
  }
  $("#inv-name").value = "";
  $("#inv-email").value = "";
  $("#inv-role").value = "collaborator";
  onInviteRoleChange("collaborator");
  $("#md-invite").classList.add("on");
}

function onInviteRoleChange(role) {
  const container = $("#inv-perms-container");
  const defaultChecked = role === "admin"
    ? { companies_view: true, companies_edit: true, credentials_view: true, credentials_reveal: true, credentials_edit: true, certificates_view: true, obligations_manage: true, history_view: true, users_manage: false }
    : { companies_view: true, companies_edit: false, credentials_view: true, credentials_reveal: false, credentials_edit: false, certificates_view: true, obligations_manage: true, history_view: false, users_manage: false };

  container.innerHTML = PERMS_DEF.map(p => `
    <label class="perm-item">
      <input type="checkbox" id="inv-perm-${p.k}" ${defaultChecked[p.k] ? "checked" : ""}>
      <div>
        <b>${esc(p.l)}</b>
        <div class="mu" style="font-size:11px">${esc(p.desc)}</div>
      </div>
    </label>
  `).join("");
}

function submitInvite() {
  const name = $("#inv-name").value.trim();
  const email = $("#inv-email").value.trim().toLowerCase();
  const role = $("#inv-role").value;

  if (!name || !email) {
    alert("Informe o nome e o e-mail do colaborador.");
    return;
  }

  if (USERS.some(u => u.email.toLowerCase() === email)) {
    alert("Já existe um usuário cadastrado com este e-mail.");
    return;
  }

  const perms = {};
  PERMS_DEF.forEach(p => {
    const cb = $(`#inv-perm-${p.k}`);
    perms[p.k] = cb ? cb.checked : false;
  });

  const token = "tok_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
  const invite = {
    id: "inv-" + Date.now(),
    token: token,
    name: name,
    email: email,
    role: role,
    invited_by: CURRENT_USER.name + " (Master)",
    invited_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 7 * 864e5).toISOString(),
    status: "pending",
    accepted_at: null,
    permissions: perms
  };

  INVITES.unshift(invite);
  setStored("invites", INVITES);

  recordAudit("invite_sent", "Enviou convite de acesso", "users", email, `Convite emitido por ${CURRENT_USER.name} com validade de 7 dias`);

  closeModal("md-invite");

  const fullLink = window.location.origin + window.location.pathname + "?invite=" + token;
  $("#inv-generated-link").value = fullLink;
  $("#md-invite-success").classList.add("on");

  toast("Convite gerado e registrado no sistema!");
  if (location.hash === "#usuarios") usersView();
}

function copyInviteLink() {
  const txt = $("#inv-generated-link").value;
  navigator.clipboard.writeText(txt).then(() => {
    toast("Link copiado para a área de transferência!");
    closeModal("md-invite-success");
  });
}

function copyInviteLinkByToken(token) {
  const fullLink = window.location.origin + window.location.pathname + "?invite=" + token;
  navigator.clipboard.writeText(fullLink).then(() => {
    toast("Link de convite copiado com sucesso!");
  });
}

function cancelInvite(invId) {
  const inv = INVITES.find(i => i.id === invId);
  if (!inv) return;
  if (confirm(`Deseja cancelar o convite de ${inv.name} (${inv.email})?`)) {
    inv.status = "cancelled";
    setStored("invites", INVITES);
    recordAudit("invite_cancelled", "Cancelou convite", "users", inv.email, `Convite revogado pelo Master`);
    toast("Convite cancelado.");
    usersView();
  }
}

function resendInvite(invId) {
  const inv = INVITES.find(i => i.id === invId);
  if (!inv) return;
  inv.status = "pending";
  inv.invited_at = new Date().toISOString();
  inv.expires_at = new Date(Date.now() + 7 * 864e5).toISOString();
  setStored("invites", INVITES);
  recordAudit("invite_sent", "Reenviou convite", "users", inv.email, `Prazo renovado por mais 7 dias`);
  toast("Convite renovado com sucesso!");
  usersView();
}

let editingUserId = null;
function openEditPermsModal(userId) {
  const u = USERS.find(x => x.id === userId);
  if (!u) return;

  if (u.role === "master" || isMasterEmail(u.email)) {
    alert("O Administrador Master possui acesso total irrestrito e suas permissões não podem ser alteradas.");
    return;
  }

  editingUserId = userId;
  $("#edit-user-sub").innerHTML = `Configurando permissões para: <b>${esc(u.name)}</b> (${esc(u.email)})`;
  $("#edit-perms-container").innerHTML = PERMS_DEF.map(p => `
    <label class="perm-item">
      <input type="checkbox" id="edit-perm-${p.k}" ${u.permissions && u.permissions[p.k] ? "checked" : ""}>
      <div>
        <b>${esc(p.l)}</b>
        <div class="mu" style="font-size:11px">${esc(p.desc)}</div>
      </div>
    </label>
  `).join("");

  $("#md-edit-perms").classList.add("on");
}

function saveUserPerms() {
  const u = USERS.find(x => x.id === editingUserId);
  if (!u) return;

  u.permissions = u.permissions || {};
  PERMS_DEF.forEach(p => {
    const cb = $(`#edit-perm-${p.k}`);
    u.permissions[p.k] = cb ? cb.checked : false;
  });

  setStored("users", USERS);
  recordAudit("update", "Alterou permissões de usuário", "users", u.email, `Permissões redefinidas pelo Master`);
  closeModal("md-edit-perms");
  toast("Permissões de " + u.name + " atualizadas com sucesso!");
  usersView();
}

function toggleUserStatus(userId) {
  const u = USERS.find(x => x.id === userId);
  if (!u) return;

  if (u.role === "master" || isMasterEmail(u.email)) {
    alert("O Administrador Master não pode ser bloqueado.");
    return;
  }

  const newStatus = !u.is_active;
  const actionTxt = newStatus ? "desbloquear" : "bloquear e revogar o acesso imediatamente de";
  if (confirm(`Tem certeza que deseja ${actionTxt} ${u.name}?`)) {
    u.is_active = newStatus;
    setStored("users", USERS);
    recordAudit(newStatus ? "user_unblocked" : "user_blocked", newStatus ? "Desbloqueou usuário" : "Revogou acesso / Bloqueou", "users", u.email, `Status alterado por ${CURRENT_USER.name}`);
    toast(newStatus ? "Usuário desbloqueado." : "Acesso revogado imediatamente!");
    usersView();
  }
}

function deleteUser(userId) {
  const u = USERS.find(x => x.id === userId);
  if (!u) return;

  if (u.role === "master" || isMasterEmail(u.email)) {
    alert("O Administrador Master não pode ser excluído.");
    return;
  }

  if (confirm(`Deseja EXCLUIR definitivamente o usuário ${u.name} (${u.email})?`)) {
    USERS = USERS.filter(x => x.id !== userId);
    setStored("users", USERS);
    recordAudit("delete", "Excluiu usuário", "users", u.email, `Usuário removido do sistema pelo Master`);
    toast("Usuário excluído.");
    usersView();
  }
}

/* ==========================================================================
   10. AUDITORIA E HISTÓRICO (REQUISITO 1, 3 E 4)
   ========================================================================== */
const AUD_FILTER = { q: "", action: "", user: "" };

function auditView() {
  if (!hasPerm("history_view") && CURRENT_USER.role !== "master") {
    $("#v").innerHTML = `<div class="al er" style="margin-top:20px">🔒 Acesso Restrito: Você não tem permissão para visualizar o histórico de auditoria.</div>`;
    return;
  }

  const actions = [
    ["reveal", "Revelou senha"],
    ["copy", "Copiou credencial"],
    ["login", "Login realizado"],
    ["login_failed", "Tentativa com erro"],
    ["create", "Criação de registro"],
    ["update", "Edição de dados"],
    ["delete", "Exclusão"],
    ["user_blocked", "Bloqueio de usuário"],
    ["invite_sent", "Convite enviado"],
    ["invite_accepted", "Convite aceito"]
  ];

  const uniqueUsers = [...new Set(AUDIT_LOGS.map(l => l.user_email))].filter(Boolean);

  $("#v").innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
      <div>
        <h1>Auditoria e Histórico de Atividades</h1>
        <p class="sub" style="margin-bottom:0">Registro de todas as operações sensíveis, acessos a credenciais e autenticações.</p>
      </div>
      <button class="btn sm" onclick="exportAudit()">Exportar Registros</button>
    </div>

    <div class="fb">
      <input placeholder="Buscar por detalhes, empresa ou IP" value="${esc(AUD_FILTER.q)}" oninput="AUD_FILTER.q=this.value;renderAuditTable()">
      <select onchange="AUD_FILTER.action=this.value;renderAuditTable()">
        <option value="">Todas as ações</option>
        ${actions.map(([k, l]) => `<option value="${k}" ${AUD_FILTER.action === k ? "selected" : ""}>${esc(l)}</option>`).join("")}
      </select>
      <select onchange="AUD_FILTER.user=this.value;renderAuditTable()">
        <option value="">Todos os usuários</option>
        ${uniqueUsers.map(u => `<option value="${u}" ${AUD_FILTER.user === u ? "selected" : ""}>${esc(u)}</option>`).join("")}
      </select>
      ${AUD_FILTER.q || AUD_FILTER.action || AUD_FILTER.user ? `<button class="btn sm" onclick="AUD_FILTER={q:'',action:'',user:''};auditView()">Limpar</button>` : ""}
    </div>

    <div class="cd t">
      <table>
        <thead>
          <tr>
            <th style="width:140px">Data / Hora</th>
            <th>Usuário</th>
            <th>Operação</th>
            <th>Alvo / Empresa</th>
            <th>Detalhes da Atividade</th>
            <th>Endereço IP</th>
          </tr>
        </thead>
        <tbody id="audit-table-body"></tbody>
      </table>
    </div>
  `;

  renderAuditTable();
}

function renderAuditTable() {
  const q = AUD_FILTER.q.toLowerCase();
  const list = AUDIT_LOGS.filter(l =>
    (!q || (l.details + l.target + l.user_name + l.ip).toLowerCase().includes(q)) &&
    (!AUD_FILTER.action || l.action === AUD_FILTER.action) &&
    (!AUD_FILTER.user || l.user_email === AUD_FILTER.user)
  );

  const getActionBadge = l => {
    if (l.action === "reveal") return `<span class="tag-badge act-reveal">👁️ REVELOU SENHA</span>`;
    if (l.action === "copy") return `<span class="tag-badge act-copy">📋 COPIOU SENHA</span>`;
    if (l.action === "login") return `<span class="tag-badge act-login">✓ LOGIN OK</span>`;
    if (l.action === "login_failed" || l.action === "user_blocked") return `<span class="tag-badge act-block">⛔ BLOQUEIO</span>`;
    if (l.action === "create") return `<span class="tag-badge act-create">+ CADASTRO</span>`;
    if (l.action === "delete") return `<span class="tag-badge act-block">✕ EXCLUSÃO</span>`;
    return `<span class="tag-badge act-reveal">${esc(l.action_label || l.action)}</span>`;
  };

  $("#audit-table-body").innerHTML = list.length ? list.map(l => `
    <tr>
      <td class="mu s">${new Date(l.timestamp).toLocaleString('pt-BR')}</td>
      <td><b>${esc(l.user_name)}</b><br><span class="mu s">${esc(l.user_email)}</span></td>
      <td>${getActionBadge(l)}</td>
      <td><b>${esc(l.target || '—')}</b></td>
      <td>${esc(l.details)}</td>
      <td><span style="font-family:monospace;font-size:11px" class="mu">${esc(l.ip)}</span></td>
    </tr>
  `).join("") : `<tr><td colspan="6" class="mu" style="padding:16px">Nenhum evento localizado com os filtros aplicados.</td></tr>`;
}

function exportAudit() {
  const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(AUDIT_LOGS, null, 2));
  const dlAnchor = document.createElement("a");
  dlAnchor.setAttribute("href", jsonStr);
  dlAnchor.setAttribute("download", `auditoria_nortis_${new Date().toISOString().slice(0, 10)}.json`);
  dlAnchor.click();
}

function closeModal(id) {
  const el = $("#" + id);
  if (el) el.classList.remove("on");
}

/* ==========================================================================
   11. ROTEAMENTO GERAL
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
    const isTarget = x.dataset.r === (m === "empresa" || m === "nova" ? "empresas" : m);
    x.classList.toggle("on", isTarget);
  });

  dy = 0;

  if (m === "nova") {
    if (!hasPerm("companies_edit")) {
      toast("Acesso restrito: Você não tem permissão para cadastrar novas empresas.");
      location.hash = "empresas";
      return;
    }
    cur = 0; orig = null; D = blank(); scrollTo(0, 0); fic();
  }
  else if (m === "empresa" && nm(a)) {
    if (!hasPerm("companies_view")) {
      toast("Acesso restrito para visualizar empresas.");
      location.hash = "dashboard";
      return;
    }
    if (cur != a) { cur = a; scrollTo(0, 0); }
    orig = nm(a);
    D = structuredClone(orig);
    fic();
  }
  else if (m === "usuarios") {
    scrollTo(0, 0);
    usersView();
  }
  else if (m === "auditoria") {
    scrollTo(0, 0);
    auditView();
  }
  else {
    cur = 0; D = null; scrollTo(0, 0);
    ({ empresas: lst, acessos: acc, certificados: certs, dashboard: dash }[m] || dash)();
  }
}

addEventListener("hashchange", go);

const qInput = $("#q"), srBox = $("#sr");
if (qInput && srBox) {
  qInput.oninput = () => {
    const t = qInput.value.trim().toLowerCase();
    const r = t.length < 2 ? [] : C.filter(c => (c.raz + c.fan + c.cnpj).toLowerCase().includes(t)).slice(0, 6);
    srBox.style.display = r.length ? "block" : "none";
    srBox.innerHTML = r.map(c => `
      <div onmousedown="location.hash='empresa-${c.id}';qInput.value=''">
        <b>${esc(c.fan)}</b> <span class="mu s">${esc(c.cnpj)}</span>
      </div>
    `).join("");
  };
  qInput.onblur = () => setTimeout(() => (srBox.style.display = "none"), 180);
}

// Exporta para o escopo global para compatibilidade total com atributos inline onclick/onchange
Object.assign(window, {
  toggleMobileMenu, openChangePasswordModal, submitChangePassword, openResetUserPasswordModal, submitResetUserPassword,
  encryptVaultSecret, decryptVaultSecret, hashPassword,
  F, A, C, USERS, INVITES, AUDIT_LOGS, CURRENT_USER,
  th, logout, quickFill, handleLogin, submitAccountActivation,
  dashFilter, dash, lst, fl, fic, add, rm, dc, sv, revealField, copySecret,
  acc, fa, toggleVaultPwd, copyVaultPwd, deleteCred, openCredModal, saveCred,
  certs,
  usersView, openInviteModal, onInviteRoleChange, submitInvite, copyInviteLink, copyInviteLinkByToken, cancelInvite, resendInvite, openEditPermsModal, saveUserPerms, toggleUserStatus, deleteUser,
  auditView, renderAuditTable, exportAudit, closeModal, go
});

// Inicia aplicação
const inviteCheck = checkInviteParam();
if (inviteCheck) {
  renderInviteScreen(inviteCheck);
} else if (CURRENT_USER && CURRENT_USER.is_active) {
  startApp();
} else {
  renderLoginScreen();
}



// Migração e criptografia automática de credenciais em segundo plano
(async function initSecurityVault() {
  let changed = false;
  for (const c of C) {
    if (c.cert && c.cert.pw && !c.cert.pw.startsWith("enc:")) {
      c.cert.pw = await encryptVaultSecret(c.cert.pw);
      changed = true;
    }
    if (c.ac && Array.isArray(c.ac)) {
      for (const a of c.ac) {
        if (a.pw && !a.pw.startsWith("enc:")) {
          a.pw = await encryptVaultSecret(a.pw);
          changed = true;
        }
      }
    }
  }
  if (changed) saveCompanies();
})();
