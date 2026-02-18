import express from "express";
import helmet from "helmet";
<<<<<<< HEAD
import rateLimit from "express-rate-limit";
=======
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
<<<<<<< HEAD
import crypto from "crypto";
import mysql from "mysql2/promise";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
=======
import mysql from "mysql2/promise";
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
<<<<<<< HEAD

// -------------------- Request Id (auditoría)
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader("x-request-id", req.requestId);
  next();
});

app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    logJson("info", "http.request", {
      requestId: req.requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      ms: Date.now() - start,
      ip: req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || ""
    });
  });
  next();
});


function logJson(level, msg, meta = {}) {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      level,
      msg,
      ...meta,
    })
  );
}

// -------------------- Security / middleware
app.use(helmet());
app.use(cookieParser());

// JSON (AJAX) + urlencoded (fallback)
app.use(express.json({ limit: "1mb" }));
=======
app.use(helmet());
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Static assets (logo, etc.)
app.use("/assets", express.static(path.join(__dirname, "public", "assets")));

<<<<<<< HEAD
// Rate limit: 10 requests / 15 minutes per IP for /submit
const submitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limit dedicado para validación RNC (anti-abuso)
const validateRncLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limit para auth admin
const adminAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limit suave para endpoints admin (evita abuso / loops)
const adminApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

// -------------------- Helpers (sanitización)
const t = (v) => String(v ?? "").trim();
const toBool01 = (v) => {
  if (v === true) return 1;
  const s = String(v ?? "").toLowerCase().trim();
  return s === "1" || s === "true" || s === "on" || s === "yes" ? 1 : 0;
};

function pickMax2(arr) {
  const a = Array.isArray(arr) ? arr : arr ? [arr] : [];
  return a.slice(0, 2);
}

function toCSV(v) {
  if (!v) return "";
  return Array.isArray(v) ? v.join(", ") : String(v);
}

function sanitizePhone(phone) {
  return String(phone || "").replace(/\D/g, "");
}

function buildWhatsAppLink(phoneTo, message) {
  const p = sanitizePhone(phoneTo);
  const txt = encodeURIComponent(message);
  return `https://wa.me/${p}?text=${txt}`;
}

function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// -------------------- Admin Auth (JWT cookie httpOnly)
const JWT_SECRET = process.env.JWT_SECRET || "";
const ADMIN_COOKIE = "pa_admin";

function signAdminToken(payload) {
  return jwt.sign(payload, JWT_SECRET || "dev_secret", { expiresIn: "7d" });
}

function verifyAdminToken(token) {
  return jwt.verify(token, JWT_SECRET || "dev_secret");
}


function requireRole(...roles) {
  return (req, res, next) => {
    const role = req.admin?.role || "";
    if (!roles.includes(role)) return res.status(403).send("Forbidden");
    return next();
  };
}

function requireAdmin(req, res, next) {
  try {
    const token = req.cookies?.[ADMIN_COOKIE];
    if (!token) return res.redirect("/admin/login");
    const decoded = verifyAdminToken(token);
    req.admin = decoded;
    return next();
  } catch {
    res.clearCookie(ADMIN_COOKIE, { path: "/" });
    return res.redirect("/admin/login");
  }
}

// -------------------- Scoring (configurable) + Tier (A/B/C)
// Persistido en MySQL (scoring_config) y cacheado en memoria.
const DEFAULT_SCORING_CONFIG = {
  tiers: { A: 75, B: 50 },
  weights: {
    rnc_activo: 30,
    rnc_bad: -20,

    emp_20_plus: 20,
    emp_9_20: 15,
    emp_4_8: 10,
    emp_1_3: 5,

    freq_week: 15,
    freq_biweek: 10,
    freq_month: 6,

    credit_yes: 10,
    credit_depende: 5,

    has_email: 5,

    pr_credito: 8,
    pr_entrega: 4
  }
};

let scoringConfigCache = { value: DEFAULT_SCORING_CONFIG, loadedAt: 0 };
const SCORING_CACHE_TTL_MS = 60 * 1000; // 60s

async function loadScoringConfigFromDb() {
  try {
    const [rows] = await pool.query(`SELECT config_json FROM scoring_config WHERE id = 1 LIMIT 1`);
    const raw = rows?.[0]?.config_json;
    if (!raw) return DEFAULT_SCORING_CONFIG;

    const cfg = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!cfg || typeof cfg !== "object") return DEFAULT_SCORING_CONFIG;

    return {
      tiers: { ...DEFAULT_SCORING_CONFIG.tiers, ...(cfg.tiers || {}) },
      weights: { ...DEFAULT_SCORING_CONFIG.weights, ...(cfg.weights || {}) }
    };
  } catch {
    return DEFAULT_SCORING_CONFIG;
  }
}

async function getScoringConfig() {
  if (Date.now() - scoringConfigCache.loadedAt < SCORING_CACHE_TTL_MS) return scoringConfigCache.value;
  const cfg = await loadScoringConfigFromDb();
  scoringConfigCache = { value: cfg, loadedAt: Date.now() };
  return cfg;
}

function clampScore(n) {
  if (n < 0) return 0;
  if (n > 100) return 100;
  return n;
}

async function computeScore(lead) {
  const cfg = await getScoringConfig();
  const w = cfg.weights || DEFAULT_SCORING_CONFIG.weights;

  let score = 0;

  const est = String(lead.rnc_estado || "").toUpperCase().trim();
  if (est === "ACTIVO") score += Number(w.rnc_activo || 0);
  else if (est === "SUSPENDIDO" || est === "INACTIVO") score += Number(w.rnc_bad || 0);

  const emp = String(lead.negocio_empleados || "");
  if (emp.includes("20+")) score += Number(w.emp_20_plus || 0);
  else if (emp.includes("9–20") || emp.includes("9-20")) score += Number(w.emp_9_20 || 0);
  else if (emp.includes("4–8") || emp.includes("4-8")) score += Number(w.emp_4_8 || 0);
  else if (emp.includes("1–3") || emp.includes("1-3")) score += Number(w.emp_1_3 || 0);

  const f = String(lead.consumo_frecuencia || "").toLowerCase();
  if (f.includes("seman")) score += Number(w.freq_week || 0);
  else if (f.includes("quin")) score += Number(w.freq_biweek || 0);
  else if (f.includes("mens")) score += Number(w.freq_month || 0);

  const c30 = String(lead.facilidad_30_dias || "").toLowerCase();
  if (c30 === "sí" || c30 === "si") score += Number(w.credit_yes || 0);
  else if (c30.includes("depende")) score += Number(w.credit_depende || 0);

  if (String(lead.responsable_email || "").includes("@")) score += Number(w.has_email || 0);

  const pr = String(lead.prioridades || "").toLowerCase();
  if (pr.includes("crédito") || pr.includes("credito")) score += Number(w.pr_credito || 0);
  if (pr.includes("entrega")) score += Number(w.pr_entrega || 0);

  score = clampScore(score);

  const tierA = Number(cfg.tiers?.A ?? DEFAULT_SCORING_CONFIG.tiers.A);
  const tierB = Number(cfg.tiers?.B ?? DEFAULT_SCORING_CONFIG.tiers.B);

  let tier = "C";
  if (score >= tierA) tier = "A";
  else if (score >= tierB) tier = "B";

  return { score, tier };
}

async function scoreAndPersistLead(leadId) {
  const [rows] = await pool.execute(`SELECT * FROM leads WHERE id = ? LIMIT 1`, [leadId]);
  const lead = rows?.[0];
  if (!lead) return;

  const { score, tier } = await computeScore(lead);
  await pool.execute(`UPDATE leads SET score = ?, score_tier = ? WHERE id = ?`, [score, tier, leadId]);
}


// ---- RNC validate helpers (timeout + normalizer + DB cache)
const RNC_DB_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días
const RNC_STALE_OK_MS = 30 * 24 * 60 * 60 * 1000; // hasta 30 días usable como stale

function isValidRncNumber(s) {
  return /^[0-9]+$/.test(s) && (s.length === 9 || s.length === 11);
}

async function fetchJsonWithTimeout(url, { timeoutMs = 5000, headers = {} } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }

    return { ok: res.ok, status: res.status, json };
  } catch (err) {
    return { ok: false, status: 0, json: null, error: err?.message || String(err) };
  } finally {
    clearTimeout(t);
  }
}

function normalizeEstado(v) {
  const s = String(v || "").trim().toUpperCase();
  if (!s) return "";
  if (s.includes("ACTIV")) return "ACTIVO";
  if (s.includes("SUSP")) return "SUSPENDIDO";
  if (s.includes("INACT")) return "INACTIVO";
  return s;
}

function mapToStandard(payload) {
  const root = payload || {};
  const p =
    root.data && typeof root.data === "object"
      ? root.data
      : root.result && typeof root.result === "object"
        ? root.result
        : root;
  const razon =
    p.razon_social ||
    p.razonSocial ||
    p.razonSocialContribuyente ||
    p.nombre ||
    p.name ||
    p.legalName ||
    "";

  const comercial =
    p.nombre_comercial ||
    p.nombreComercial ||
    p.commercialName ||
    p.nombre_fantasia ||
    "";

  const estado =
    normalizeEstado(
      p.estado ||
      p.status ||
      p.estatus ||
      p.estadoContribuyente ||
      p.contributorStatus ||
      ""
    );

  return {
    razon_social: String(razon || "").trim(),
    nombre_comercial: String(comercial || "").trim(),
    estado,
  };
}

async function getRncCacheFromDb(rnc) {
  const [rows] = await pool.execute(
    `SELECT rnc, razon_social, nombre_comercial, estado, provider, raw_json,
            fetched_at, expires_at
       FROM rnc_cache
      WHERE rnc = ?
      LIMIT 1`,
    [rnc]
  );
  return rows?.[0] || null;
}

async function upsertRncCacheToDb(rnc, data, provider, rawJson, ok = true, errMsg = "") {
  const expiresAt = new Date(Date.now() + RNC_DB_TTL_MS);
  const razon = data?.razon_social || null;
  const comercial = data?.nombre_comercial || null;
  const estado = data?.estado || null;

  await pool.execute(
    `INSERT INTO rnc_cache (rnc, razon_social, nombre_comercial, estado, provider, raw_json, fetched_at, expires_at, last_error)
     VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?)
     ON DUPLICATE KEY UPDATE
       razon_social = VALUES(razon_social),
       nombre_comercial = VALUES(nombre_comercial),
       estado = VALUES(estado),
       provider = VALUES(provider),
       raw_json = VALUES(raw_json),
       fetched_at = NOW(),
       expires_at = VALUES(expires_at),
       last_error = VALUES(last_error)`,
    [
      rnc,
      razon,
      comercial,
      estado,
      provider || null,
      rawJson ? JSON.stringify(rawJson) : null,
      expiresAt,
      ok ? null : (errMsg || "provider_error").slice(0, 255),
    ]
  );
}

function isCacheFresh(row) {
  if (!row?.expires_at) return false;
  return new Date(row.expires_at).getTime() > Date.now();
}

function isCacheStaleButUsable(row) {
  if (!row?.fetched_at) return false;
  const age = Date.now() - new Date(row.fetched_at).getTime();
  return age <= RNC_STALE_OK_MS;
}

async function fetchRncFromProviders(rnc) {
  const primaryUrl = `https://api.digital.gob.do/v3/rnc/${encodeURIComponent(rnc)}`;
  const fallbackUrl = `https://rnc.megaplus.com.do/api/consulta?rnc=${encodeURIComponent(rnc)}`;

  // primary
  let r = await fetchJsonWithTimeout(primaryUrl, { timeoutMs: 5000 });
  if (r.ok && r.json) return { ok: true, json: r.json, provider: "digital.gob.do", status: r.status };

  // fallback
  r = await fetchJsonWithTimeout(fallbackUrl, { timeoutMs: 5000 });
  if (r.ok && r.json) return { ok: true, json: r.json, provider: "megaplus", status: r.status };

  return { ok: false, json: null, provider: "", status: r.status || 0 };
}


// -------------------- reCAPTCHA v3 (opcional)
async function verifyRecaptcha(token, ip) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;

  // Si no está configurado, saltar (modo local/dev)
  if (!secret) return { ok: true, skipped: true };
=======
// -------------------- reCAPTCHA (optional)
async async function verifyRecaptcha(token, ip) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;

  // If not configured, skip
  if (!secret) return { ok: true, skipped: true };

>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
  if (!token) return { ok: false, reason: "missing_token" };

  const params = new URLSearchParams();
  params.append("secret", secret);
  params.append("response", token);
  if (ip) params.append("remoteip", ip);

  const resp = await fetch("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  const data = await resp.json();

<<<<<<< HEAD
=======
  // v3 adds score/action; v2 doesn't.
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
  const minScore = Number(process.env.RECAPTCHA_MIN_SCORE || 0.5);
  const expectedAction = process.env.RECAPTCHA_ACTION || "submit";

  if (!data.success) return { ok: false, reason: "not_success", data };

<<<<<<< HEAD
  // v3: score/action
=======
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
  if (typeof data.score === "number") {
    if (data.score < minScore) return { ok: false, reason: "low_score", data };
    if (data.action && data.action !== expectedAction) return { ok: false, reason: "bad_action", data };
  }

  return { ok: true, data };
}

<<<<<<< HEAD
// -------------------- DB (MySQL) usando pool (producción)
let pool = null;

async function ensureColumn(table, column, ddlType) {
  const [rows] = await pool.execute(
    `SELECT 1 AS ok
       FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?
        AND COLUMN_NAME = ?
      LIMIT 1`,
    [table, column]
  );
  if (rows && rows.length) return;
  await pool.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${ddlType}`);
}

function parseDatabaseUrl(urlString) {
  const u = new URL(urlString);
  const user = decodeURIComponent(u.username || "");
  const password = decodeURIComponent(u.password || "");
  const host = u.hostname;
  const port = Number(u.port || 3306);
  const database = (u.pathname || "").replace(/^\//, "");
  return { host, port, user, password, database };
}

function getMysqlConfig() {
  // Opción A: URL única (Railway recomendado)
  if (process.env.DATABASE_URL && String(process.env.DATABASE_URL).startsWith("mysql")) {
    const parsed = parseDatabaseUrl(process.env.DATABASE_URL);
    if (parsed.host && parsed.user && parsed.database) return parsed;
  }

  // Opción B: variables separadas (local/otros)
  if (process.env.DB_HOST && process.env.DB_USER && process.env.DB_NAME) {
    return {
      host: t(process.env.DB_HOST),
      port: Number(process.env.DB_PORT || 3306),
      user: t(process.env.DB_USER),
      password: String(process.env.DB_PASS || ""),
      database: t(process.env.DB_NAME),
    };
  }

  // Opción C: Railway MySQL vars legacy
  if (process.env.MYSQLHOST && process.env.MYSQLUSER && process.env.MYSQLDATABASE) {
    return {
      host: t(process.env.MYSQLHOST),
      port: Number(process.env.MYSQLPORT || 3306),
      user: t(process.env.MYSQLUSER),
      password: String(process.env.MYSQLPASSWORD || ""),
      database: t(process.env.MYSQLDATABASE),
    };
=======
// -------------------- DB (MySQL)
function getMysqlConfig() {

  // 1️⃣ Prefer Railway MySQL vars (RECOMENDADO)
  const host = process.env.MYSQLHOST;
  const port = Number(process.env.MYSQLPORT || 3306);
  const user = process.env.MYSQLUSER;
  const password = process.env.MYSQLPASSWORD;
  const database = process.env.MYSQLDATABASE;

  if (host && user && database) {
    console.log("✅ Using Railway MySQL variables");
    return { host, port, user, password, database };
  }

  // 2️⃣ Fallback DATABASE_URL (only if valid)
  if (process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith("mysql")) {
    console.log("⚠️ Using DATABASE_URL");
    return { uri: process.env.DATABASE_URL };
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
  }

  return null;
}

<<<<<<< HEAD
async function initDb() {
  const cfg = getMysqlConfig();
  if (!cfg) {
    throw new Error(
      "Faltan variables de MySQL. Define DATABASE_URL o DB_HOST/DB_USER/DB_NAME (o MYSQLHOST/MYSQLUSER/MYSQLDATABASE)."
    );
  }

  pool = mysql.createPool({
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    password: cfg.password,
    database: cfg.database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  // Tabla (idempotente)
=======

let pool = null;

async function initDb() {
  const cfg = getMysqlConfig();
  if (!cfg) {
    throw new Error("Faltan variables de MySQL. Define DATABASE_URL o MYSQLHOST/MYSQLUSER/MYSQLDATABASE.");
  }

  pool = cfg.uri
    ? mysql.createPool(cfg.uri)
    : mysql.createPool({
        host: cfg.host,
        port: cfg.port,
        user: cfg.user,
        password: cfg.password,
        database: cfg.database,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
      });

  // Create table
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
  await pool.query(`
    CREATE TABLE IF NOT EXISTS leads (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

      negocio_nombre_comercial VARCHAR(255) NOT NULL,
      negocio_razon_social VARCHAR(255) NULL,
      negocio_rnc VARCHAR(64) NULL,
      negocio_actividad VARCHAR(128) NOT NULL,
      negocio_actividad_otro VARCHAR(255) NULL,
      negocio_local_plaza VARCHAR(128) NULL,
      negocio_empleados VARCHAR(32) NULL,

      responsable_nombre VARCHAR(255) NOT NULL,
      responsable_cargo VARCHAR(255) NULL,
      responsable_whatsapp VARCHAR(64) NOT NULL,
      responsable_email VARCHAR(255) NULL,
      autoriza_compras VARCHAR(64) NULL,
      autoriza_compras_otro VARCHAR(255) NULL,

      consumo_frecuencia VARCHAR(64) NULL,
      consumo_nota TEXT NULL,
      consumo_productos TEXT NULL,
      consumo_productos_otro VARCHAR(255) NULL,
      prioridades VARCHAR(255) NULL,

      facilidad_30_dias VARCHAR(32) NULL,
      estados_cuenta_por VARCHAR(32) NULL,

      acepta_terminos TINYINT(1) NOT NULL,

      acepta_privacidad TINYINT(1) NOT NULL DEFAULT 1,
      privacidad_version VARCHAR(32) NULL,
      terminos_version VARCHAR(32) NULL,
      consentimiento_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,

      autorizacion_nombre VARCHAR(255) NULL,
      autorizacion_fecha VARCHAR(32) NULL,

      user_agent TEXT NULL,
      ip VARCHAR(64) NULL
    );
  `);

<<<<<<< HEAD
  // --- Evolución de esquema (estado RNC + scoring)
  await ensureColumn("leads", "rnc_estado", "VARCHAR(32) NULL");
  await ensureColumn("leads", "rnc_validated_at", "TIMESTAMP NULL");
  await ensureColumn("leads", "score", "INT NULL");
  await ensureColumn("leads", "score_tier", "VARCHAR(16) NULL");

  // --- Next level: pipeline + auditoría
  await ensureColumn("leads", "status", "VARCHAR(24) NOT NULL DEFAULT 'NUEVO'");
  await ensureColumn(
    "leads",
    "updated_at",
    "TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
  );

  // Asignación (owner) del lead
  await ensureColumn("leads", "owner_admin_id", "INT NULL");

  // Cache persistente de validación RNC/Cédula (para performance/estabilidad)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS rnc_cache (
      rnc VARCHAR(11) NOT NULL PRIMARY KEY,
      razon_social VARCHAR(255) NULL,
      nombre_comercial VARCHAR(255) NULL,
      estado VARCHAR(32) NULL,

      provider VARCHAR(64) NULL,
      raw_json JSON NULL,

      fetched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP NULL,
      last_error VARCHAR(255) NULL,

      INDEX idx_expires_at (expires_at)
    );
  `);

  // --- Admin users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(32) NOT NULL DEFAULT 'admin',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_login_at TIMESTAMP NULL
    );
  `);


  // --- Scoring config (editable desde UI)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scoring_config (
      id INT NOT NULL PRIMARY KEY,
      config_json JSON NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
  `);

  // Seed scoring_config si no existe
  const [scRows] = await pool.query(`SELECT id FROM scoring_config WHERE id = 1 LIMIT 1`);
  if (!scRows.length) {
    await pool.execute(`INSERT INTO scoring_config (id, config_json) VALUES (1, ?)`, [JSON.stringify(DEFAULT_SCORING_CONFIG)]);
  }

  // --- WhatsApp templates (plantillas)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS whatsapp_templates (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      body TEXT NOT NULL,
      is_default TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed template default si no existe ninguno
  const [tplRows] = await pool.query(`SELECT id FROM whatsapp_templates LIMIT 1`);
  if (!tplRows.length) {
    const body =
      "Hola {responsable}, soy del equipo de Portafolio. Recibimos tu solicitud (ID #{id}) para {negocio}.\n\n" +
      "¿Podemos validar algunos datos y activar tu cuenta hoy?";
    await pool.execute(
      `INSERT INTO whatsapp_templates (name, body, is_default) VALUES (?, ?, 1)`,
      ["Primer contacto", body]
    );
  }

  // --- Tareas / recordatorios por lead
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lead_tasks (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      lead_id INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      due_at DATETIME NULL,
      done TINYINT(1) NOT NULL DEFAULT 0,
      done_at DATETIME NULL,
      created_by INT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_lead_id (lead_id),
      INDEX idx_due_at (due_at),
      INDEX idx_done (done)
    );
  `);

  // --- Notas internas por lead
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lead_notes (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      lead_id INT NOT NULL,
      admin_id INT NOT NULL,
      note TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_lead_id (lead_id),
      CONSTRAINT fk_notes_lead FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE,
      CONSTRAINT fk_notes_admin FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE
    );
  `);

  // --- Historial de cambios de status (auditoría)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lead_status_events (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      lead_id INT NOT NULL,
      admin_id INT NOT NULL,
      from_status VARCHAR(24) NULL,
      to_status VARCHAR(24) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_lead_id (lead_id),
      CONSTRAINT fk_status_lead FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE,
      CONSTRAINT fk_status_admin FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE
    );
  `);

  // Seed admin (solo si no existe ninguno)
  const [admins] = await pool.query(`SELECT id FROM admin_users LIMIT 1`);
  if (!admins.length) {
    const email = t(process.env.ADMIN_EMAIL).toLowerCase();
    const pass = String(process.env.ADMIN_PASSWORD || "");
    if (email && pass) {
      const hash = await bcrypt.hash(pass, 12);
      await pool.execute(`INSERT INTO admin_users (email, password_hash, role) VALUES (?, ?, 'admin')`, [email, hash]);
      logJson("info", "admin.seed.created", { email });
    } else {
      logJson("warn", "admin.seed.missing_env", { note: "Define ADMIN_EMAIL y ADMIN_PASSWORD en .env" });
    }
  }

  console.log("✅ MySQL pool conectado y tablas verificadas");
}

// -------------------- Email transporter (SMTP) (opcional)
=======
  // Schema evolution helpers (safe on older DBs)
  async function hasColumn(columnName) {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) AS c
       FROM information_schema.columns
       WHERE table_schema = DATABASE()
         AND table_name = 'leads'
         AND column_name = ?`,
      [columnName]
    );
    return Number(rows?.[0]?.c || 0) > 0;
  }

  async function ensureColumn(columnName, ddl) {
    const exists = await hasColumn(columnName);
    if (!exists) {
      await pool.query(`ALTER TABLE leads ADD COLUMN ${ddl}`);
    }
  }

  await ensureColumn("consumo_nota", "consumo_nota TEXT NULL");
  await ensureColumn("acepta_privacidad", "acepta_privacidad TINYINT(1) NOT NULL DEFAULT 1");
  await ensureColumn("privacidad_version", "privacidad_version VARCHAR(32) NULL");
  await ensureColumn("terminos_version", "terminos_version VARCHAR(32) NULL");
  await ensureColumn("consentimiento_at", "consentimiento_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP");

  console.log("✅ MySQL conectado y tabla leads verificada");
}

// -------------------- Email transporter (SMTP) (optional)
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
function makeTransporter() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE || "false") === "true";

  if (!host) return null;

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

<<<<<<< HEAD
=======
// -------------------- Helpers
function pickMax2(arr) {
  const a = Array.isArray(arr) ? arr : arr ? [arr] : [];
  return a.slice(0, 2);
}

function toCSV(v) {
  if (!v) return "";
  return Array.isArray(v) ? v.join(", ") : String(v);
}

function sanitizePhone(phone) {
  return String(phone || "").replace(/\D/g, "");
}

function buildWhatsAppLink(phoneTo, message) {
  const p = sanitizePhone(phoneTo);
  const txt = encodeURIComponent(message);
  return `https://wa.me/${p}?text=${txt}`;
}

function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
// -------------------- Routes
app.get("/", async (req, res) => {
  try {
    const siteKey = process.env.RECAPTCHA_SITE_KEY || "";
    const fp = path.join(__dirname, "views", "form.html");
    let html = await fs.promises.readFile(fp, "utf-8");
    html = html.replaceAll("{{RECAPTCHA_SITE_KEY}}", siteKey);
<<<<<<< HEAD
    html = html.replaceAll("{{FB_PIXEL_ID}}", process.env.FB_PIXEL_ID || "");
    html = html.replaceAll("{{GA_MEASUREMENT_ID}}", process.env.GA_MEASUREMENT_ID || "");
=======
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html);
  } catch (err) {
    console.error("Error cargando formulario:", err?.message || err);
    res.status(500).send("Error cargando formulario");
  }
});

<<<<<<< HEAD

// -------------------- Healthchecks (Railway / Load Balancer)
app.get("/health", async (req, res) => {
  try {
    if (!pool) return res.status(503).json({ ok: false, db: "down" });
    await pool.query("SELECT 1");
    return res.json({ ok: true, db: "up", ts: new Date().toISOString() });
  } catch {
    return res.status(503).json({ ok: false, db: "down" });
  }
});

app.get("/ready", async (req, res) => {
  try {
    if (!pool) return res.status(503).send("not ready");
    await pool.query("SELECT 1");
    return res.send("ready");
  } catch {
    return res.status(503).send("not ready");
  }
});

=======
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
app.get("/thanks", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "thanks.html"));
});

app.get("/privacidad", async (req, res) => {
  const html = await fs.promises.readFile(path.join(__dirname, "views", "privacidad.html"), "utf-8");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
});

app.get("/terminos", async (req, res) => {
  const html = await fs.promises.readFile(path.join(__dirname, "views", "terminos.html"), "utf-8");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
});

<<<<<<< HEAD
// -------------------- Admin UI
app.get("/admin/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin-login.html"));
});

app.post("/admin/login", adminAuthLimiter, async (req, res) => {
  try {
    const email = t(req.body.email).toLowerCase();
    const password = String(req.body.password || "");

    const [rows] = await pool.execute(`SELECT * FROM admin_users WHERE email = ? LIMIT 1`, [email]);
    const user = rows?.[0];
    if (!user) return res.status(401).send("Credenciales inválidas");

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send("Credenciales inválidas");

    await pool.execute(`UPDATE admin_users SET last_login_at = NOW() WHERE id = ?`, [user.id]);

    const token = signAdminToken({ id: user.id, email: user.email, role: user.role });
    res.cookie(ADMIN_COOKIE, token, {
      httpOnly: true,
      sameSite: "lax",
      secure: String(process.env.COOKIE_SECURE || "false") === "true",
      path: "/",
      domain: process.env.COOKIE_DOMAIN || undefined,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.redirect("/admin");
  } catch (err) {
    logJson("error", "admin.login.error", { requestId: req.requestId, err: err?.message || String(err) });
    return res.status(500).send("Error interno");
  }
});

app.post("/admin/logout", requireAdmin, (req, res) => {
  res.clearCookie(ADMIN_COOKIE, { path: "/" });
  res.redirect("/admin/login");
});

app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin.html"));
});


app.get("/admin/kanban", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin-kanban.html"));
});

app.get("/admin/templates", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin-templates.html"));
});

app.get("/admin/scoring", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin-scoring.html"));
});

app.get("/admin/leads/:id", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin-lead.html"));
});

// -------------------- Admin API
app.get("/api/admin/stats", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const [a] = await pool.query(`SELECT COUNT(*) AS total FROM leads`);
    const [b] = await pool.query(`SELECT score_tier, COUNT(*) AS n FROM leads GROUP BY score_tier`);
    const [s] = await pool.query(`SELECT status, COUNT(*) AS n FROM leads GROUP BY status`);
    const [c] = await pool.query(
      `SELECT DATE(created_at) AS d, COUNT(*) AS n
         FROM leads
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
        GROUP BY DATE(created_at)
        ORDER BY d DESC`
    );
    res.json({ ok: true, total: a?.[0]?.total || 0, byTier: b || [], byStatus: s || [], last14d: c || [] });
  } catch {
    res.json({ ok: false });
  }
});

app.get("/api/admin/leads", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const q = t(req.query.q);
    const tier = t(req.query.tier).toUpperCase();
    const status = t(req.query.status).toUpperCase();
    const limit = Math.min(Number(req.query.limit || 50), 200);
    const offset = Math.max(Number(req.query.offset || 0), 0);

    const where = [];
    const params = [];

    if (tier && ["A", "B", "C"].includes(tier)) {
      where.push(`score_tier = ?`);
      params.push(tier);
    }

    if (status && ["NUEVO", "CONTACTADO", "APROBADO", "RECHAZADO"].includes(status)) {
      where.push(`status = ?`);
      params.push(status);
    }

    if (q) {
      where.push(`(
        negocio_nombre_comercial LIKE ? OR
        negocio_razon_social LIKE ? OR
        negocio_rnc LIKE ? OR
        responsable_nombre LIKE ? OR
        responsable_whatsapp LIKE ?
      )`);
      const like = `%${q}%`;
      params.push(like, like, like, like, like);
    }

    const sqlWhere = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [rows] = await pool.execute(
      `SELECT l.id, l.created_at, l.updated_at, l.status,
              l.negocio_nombre_comercial, l.negocio_razon_social, l.negocio_rnc, l.rnc_estado,
              l.negocio_actividad, l.negocio_empleados, l.consumo_frecuencia, l.prioridades,
              l.responsable_nombre, l.responsable_whatsapp, l.responsable_email,
              l.facilidad_30_dias, l.score, l.score_tier,
              l.owner_admin_id, au.email AS owner_email
         FROM leads l
         LEFT JOIN admin_users au ON au.id = l.owner_admin_id
         ${sqlWhere}
         ORDER BY l.created_at DESC
         LIMIT ${limit} OFFSET ${offset}`,
      params
    );

    res.json({ ok: true, rows });
  } catch {
    res.json({ ok: false, rows: [] });
  }
});

app.get("/api/admin/lead/:id", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok: false });

    const [rows] = await pool.execute(`SELECT * FROM leads WHERE id = ? LIMIT 1`, [id]);
    const lead = rows?.[0];
    if (!lead) return res.status(404).json({ ok: false });

    const [notes] = await pool.execute(
      `SELECT n.id, n.note, n.created_at, a.email AS admin_email
         FROM lead_notes n
         JOIN admin_users a ON a.id = n.admin_id
        WHERE n.lead_id = ?
        ORDER BY n.created_at DESC
        LIMIT 200`,
      [id]
    );

    const [events] = await pool.execute(
      `SELECT e.id, e.from_status, e.to_status, e.created_at, a.email AS admin_email
         FROM lead_status_events e
         JOIN admin_users a ON a.id = e.admin_id
        WHERE e.lead_id = ?
        ORDER BY e.created_at DESC
        LIMIT 200`,
      [id]
    );

    return res.json({ ok: true, lead, notes, events });
  } catch {
    return res.json({ ok: false });
  }
});

app.post("/api/admin/lead/:id/status", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const toStatus = t(req.body.status).toUpperCase();
    if (!id) return res.status(400).json({ ok: false });
    if (!["NUEVO", "CONTACTADO", "APROBADO", "RECHAZADO"].includes(toStatus)) {
      return res.status(400).json({ ok: false, message: "Status inválido" });
    }

    const [rows] = await pool.execute(`SELECT status FROM leads WHERE id = ? LIMIT 1`, [id]);
    const cur = rows?.[0];
    if (!cur) return res.status(404).json({ ok: false });

    const fromStatus = String(cur.status || "");
    if (fromStatus !== toStatus) {
      await pool.execute(`UPDATE leads SET status = ? WHERE id = ?`, [toStatus, id]);
      await pool.execute(
        `INSERT INTO lead_status_events (lead_id, admin_id, from_status, to_status) VALUES (?, ?, ?, ?)` ,
        [id, req.admin.id, fromStatus || null, toStatus]
      );
    }

    return res.json({ ok: true });
  } catch {
    return res.json({ ok: false });
  }
});

app.post("/api/admin/lead/:id/notes", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const note = t(req.body.note);
    if (!id) return res.status(400).json({ ok: false });
    if (!note) return res.status(400).json({ ok: false, message: "Nota vacía" });

    const noteCut = note.slice(0, 4000);
    await pool.execute(
      `INSERT INTO lead_notes (lead_id, admin_id, note) VALUES (?, ?, ?)` ,
      [id, req.admin.id, noteCut]
    );

    return res.json({ ok: true });
  } catch {
    return res.json({ ok: false });
  }
});

function toCsvValue(v) {
  const s = String(v ?? "").replaceAll("\r", " ").replaceAll("\n", " ");
  if (/[",]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

app.get("/api/admin/leads.csv", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const q = t(req.query.q);
    const tier = t(req.query.tier).toUpperCase();
    const status = t(req.query.status).toUpperCase();

    const where = [];
    const params = [];

    if (tier && ["A", "B", "C"].includes(tier)) { where.push(`score_tier = ?`); params.push(tier); }
    if (status && ["NUEVO", "CONTACTADO", "APROBADO", "RECHAZADO"].includes(status)) { where.push(`status = ?`); params.push(status); }
    if (q) {
      where.push(`(
        negocio_nombre_comercial LIKE ? OR
        negocio_razon_social LIKE ? OR
        negocio_rnc LIKE ? OR
        responsable_nombre LIKE ? OR
        responsable_whatsapp LIKE ?
      )`);
      const like = `%${q}%`;
      params.push(like, like, like, like, like);
    }

    const sqlWhere = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [rows] = await pool.execute(
      `SELECT id, created_at, status, score, score_tier,
              negocio_nombre_comercial, negocio_razon_social, negocio_rnc, rnc_estado,
              negocio_actividad, negocio_empleados,
              responsable_nombre, responsable_whatsapp, responsable_email,
              consumo_frecuencia, prioridades, facilidad_30_dias
         FROM leads
         ${sqlWhere}
         ORDER BY created_at DESC
         LIMIT 5000`,
      params
    );

    const headers = [
      "id","created_at","status","score","score_tier",
      "negocio_nombre_comercial","negocio_razon_social","negocio_rnc","rnc_estado",
      "negocio_actividad","negocio_empleados",
      "responsable_nombre","responsable_whatsapp","responsable_email",
      "consumo_frecuencia","prioridades","facilidad_30_dias"
    ];

    let csv = headers.join(",") + "\n";
    for (const r of rows) {
      csv += headers.map((h) => toCsvValue(r[h])).join(",") + "\n";
    }

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="leads-${new Date().toISOString().slice(0,10)}.csv"`);
    return res.send(csv);
  } catch {
    return res.status(500).send("csv_error");
  }
});

app.post("/api/admin/rescore/:id", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.json({ ok: false });
    await scoreAndPersistLead(id);
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// API JSON: Guardar BD es CRÍTICO. Email es SECUNDARIO (fallo gracioso).


// ---- Admin API: usuarios (para asignación)
app.get("/api/admin/users", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT id, email, role FROM admin_users ORDER BY email ASC`);
    res.json({ ok: true, rows });
  } catch {
    res.json({ ok: false, rows: [] });
  }
});

// ---- Admin API: asignar owner
app.post("/api/admin/lead/:id/assign", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.json({ ok: false });

    const owner = req.body?.owner_admin_id;
    const ownerId = owner === null || owner === "" || owner === undefined ? null : Number(owner);
    if (ownerId !== null && !ownerId) return res.json({ ok: false });

    await pool.execute(`UPDATE leads SET owner_admin_id = ? WHERE id = ?`, [ownerId, id]);
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// ---- Admin API: tareas / recordatorios
app.get("/api/admin/lead/:id/tasks", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.json({ ok: false, rows: [] });

    const [rows] = await pool.execute(
      `SELECT id, title, due_at, done, done_at, created_at
       FROM lead_tasks
       WHERE lead_id = ?
       ORDER BY done ASC, due_at IS NULL, due_at ASC, created_at DESC`,
      [id]
    );
    res.json({ ok: true, rows });
  } catch {
    res.json({ ok: false, rows: [] });
  }
});

app.post("/api/admin/lead/:id/tasks", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const leadId = Number(req.params.id);
    const title = t(req.body?.title);
    const due = t(req.body?.due_at);

    if (!leadId || !title) return res.json({ ok: false });

    const dueAt = due ? new Date(due) : null;
    await pool.execute(
      `INSERT INTO lead_tasks (lead_id, title, due_at, created_by) VALUES (?, ?, ?, ?)`,
      [leadId, title, dueAt, req.admin?.id || null]
    );
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

app.post("/api/admin/task/:id/toggle", requireAdmin, adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.json({ ok: false });

    const done = Number(req.body?.done) ? 1 : 0;
    await pool.execute(
      `UPDATE lead_tasks SET done = ?, done_at = CASE WHEN ? = 1 THEN NOW() ELSE NULL END WHERE id = ?`,
      [done, done, id]
    );
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// ---- Admin API: WhatsApp templates
app.get("/api/admin/templates", requireAdmin, requireRole("admin"), adminApiLimiter, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, body, is_default, created_at FROM whatsapp_templates ORDER BY is_default DESC, id DESC`
    );
    res.json({ ok: true, rows });
  } catch {
    res.json({ ok: false, rows: [] });
  }
});

app.post("/api/admin/templates", requireAdmin, requireRole("admin"), adminApiLimiter, async (req, res) => {
  try {
    const id = req.body?.id ? Number(req.body.id) : null;
    const name = t(req.body?.name);
    const body = t(req.body?.body);
    const isDefault = Number(req.body?.is_default) ? 1 : 0;

    if (!name || !body) return res.json({ ok: false });

    if (isDefault) {
      await pool.query(`UPDATE whatsapp_templates SET is_default = 0`);
    }

    if (id) {
      await pool.execute(
        `UPDATE whatsapp_templates SET name = ?, body = ?, is_default = ? WHERE id = ?`,
        [name, body, isDefault, id]
      );
    } else {
      await pool.execute(
        `INSERT INTO whatsapp_templates (name, body, is_default) VALUES (?, ?, ?)`,
        [name, body, isDefault]
      );
    }

    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

app.post("/api/admin/templates/:id/delete", requireAdmin, requireRole("admin"), adminApiLimiter, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.json({ ok: false });

    await pool.execute(`DELETE FROM whatsapp_templates WHERE id = ?`, [id]);

    const [rows] = await pool.query(`SELECT id FROM whatsapp_templates WHERE is_default = 1 LIMIT 1`);
    if (!rows.length) {
      const [any] = await pool.query(`SELECT id FROM whatsapp_templates ORDER BY id DESC LIMIT 1`);
      if (any.length) await pool.execute(`UPDATE whatsapp_templates SET is_default = 1 WHERE id = ?`, [any[0].id]);
    }

    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// ---- Admin API: scoring config editable
app.get("/api/admin/scoring", requireAdmin, requireRole("admin"), adminApiLimiter, async (req, res) => {
  try {
    const cfg = await loadScoringConfigFromDb();
    res.json({ ok: true, config: cfg });
  } catch {
    res.json({ ok: false });
  }
});

app.post("/api/admin/scoring", requireAdmin, requireRole("admin"), adminApiLimiter, async (req, res) => {
  try {
    const cfg = req.body?.config;
    if (!cfg || typeof cfg !== "object") return res.json({ ok: false });

    const nextCfg = {
      tiers: { ...DEFAULT_SCORING_CONFIG.tiers, ...(cfg.tiers || {}) },
      weights: { ...DEFAULT_SCORING_CONFIG.weights, ...(cfg.weights || {}) }
    };

    await pool.execute(`UPDATE scoring_config SET config_json = ? WHERE id = 1`, [JSON.stringify(nextCfg)]);
    scoringConfigCache = { value: nextCfg, loadedAt: Date.now() };
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// ---- RNC/Cédula validation proxy (anti-CORS) - PRO
// - Cache persistente en MySQL (rnc_cache)
// - Stale-while-revalidate
// - Timeout 5s
// - Rate-limit dedicado
app.get("/api/validate-rnc/:rnc", validateRncLimiter, async (req, res) => {
  const start = Date.now();

  try {
    const num = String(req.params.rnc || "").trim();
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "";

    if (!isValidRncNumber(num)) {
      return res.status(400).json({
        ok: false,
        found: false,
        message: "RNC/Cédula inválido (9 u 11 dígitos numéricos).",
      });
    }

    // 1) DB cache first
    const cached = await getRncCacheFromDb(num);
    if (cached) {
      const payload = {
        ok: true,
        found: true,
        data: {
          razon_social: cached.razon_social || "",
          nombre_comercial: cached.nombre_comercial || "",
          estado: cached.estado || "",
        },
        cache: isCacheFresh(cached) ? "fresh" : "stale",
      };

      if (isCacheFresh(cached)) {
        logJson("info", "rnc.validate.cache_hit", {
          requestId: req.requestId,
          ip,
          rnc: num,
          cache: "fresh",
          ms: Date.now() - start,
        });
        return res.json(payload);
      }

      if (isCacheStaleButUsable(cached)) {
        logJson("info", "rnc.validate.cache_hit", {
          requestId: req.requestId,
          ip,
          rnc: num,
          cache: "stale",
          ms: Date.now() - start,
        });

        // Revalidación async (no bloqueante)
        setTimeout(async () => {
          try {
            const rr = await fetchRncFromProviders(num);
            if (!rr.ok || !rr.json) return;
            const data = mapToStandard(rr.json);
            if (!data.razon_social && !data.nombre_comercial) return;
            await upsertRncCacheToDb(num, data, rr.provider, rr.json, true, "");
            logJson("info", "rnc.validate.revalidated", {
              requestId: req.requestId,
              rnc: num,
              provider: rr.provider,
            });
          } catch {
            logJson("warn", "rnc.validate.revalidate_failed", {
              requestId: req.requestId,
              rnc: num,
            });
          }
        }, 0);

        return res.json(payload);
      }
      // cache muy viejo -> cae a miss
    }

    // 2) Cache miss -> provider
    const rr = await fetchRncFromProviders(num);
    if (!rr.ok || !rr.json) {
      // guardamos error (best effort)
      upsertRncCacheToDb(num, null, rr.provider, null, false, "provider_fail").catch(() => {});
      logJson("warn", "rnc.validate.provider_fail", {
        requestId: req.requestId,
        ip,
        rnc: num,
        status: rr.status || 0,
        ms: Date.now() - start,
      });
      return res.json({ ok: false, found: false });
    }

    if (rr.status === 404) {
      logJson("info", "rnc.validate.not_found", {
        requestId: req.requestId,
        ip,
        rnc: num,
        ms: Date.now() - start,
      });
      return res.json({ ok: true, found: false });
    }

    const data = mapToStandard(rr.json);
    if (!data.razon_social && !data.nombre_comercial) {
      return res.json({ ok: true, found: false });
    }

    await upsertRncCacheToDb(num, data, rr.provider, rr.json, true, "");

    logJson("info", "rnc.validate.ok", {
      requestId: req.requestId,
      ip,
      rnc: num,
      provider: rr.provider,
      estado: data.estado,
      ms: Date.now() - start,
    });

    return res.json({ ok: true, found: true, data, cache: "miss" });
  } catch (err) {
    logJson("error", "rnc.validate.error", {
      requestId: req.requestId,
      err: err?.message || String(err),
    });
    return res.json({ ok: false, found: false });
  }
});

app.post("/submit", submitLimiter, async (req, res) => {
=======
app.post("/submit", async (req, res) => {
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
  try {
    const b = req.body || {};
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "";
    const user_agent = req.headers["user-agent"] || "";

<<<<<<< HEAD
    // reCAPTCHA (opcional)
    const recaptchaToken = t(b.recaptcha_token || b["g-recaptcha-response"]);
    const captcha = await verifyRecaptcha(recaptchaToken, ip);
    if (!captcha.ok) {
      return res.status(400).json({ ok: false, message: "Validación reCAPTCHA fallida. Intenta de nuevo." });
    }

    // required + sanitize
    const negocio_nombre_comercial = t(b.negocio_nombre_comercial);
    const negocio_actividad = t(b.negocio_actividad);
    const responsable_nombre = t(b.responsable_nombre);
    const responsable_whatsapp = t(b.responsable_whatsapp);

    if (!negocio_nombre_comercial) return res.status(400).json({ ok: false, message: "Falta: Nombre comercial" });
    if (!negocio_actividad) return res.status(400).json({ ok: false, message: "Falta: Actividad principal" });
    if (!responsable_nombre) return res.status(400).json({ ok: false, message: "Falta: Nombre responsable" });
    if (!responsable_whatsapp) return res.status(400).json({ ok: false, message: "Falta: WhatsApp responsable" });

    const acepta_terminos = toBool01(b.acepta_terminos);
    if (!acepta_terminos) return res.status(400).json({ ok: false, message: "Debe aceptar términos" });

    const consumo_productos = toCSV(b.consumo_productos);
    const prioridades = toCSV(pickMax2(b.prioridades));
    const consumo_nota = t(b.consumo_nota);

    // Estado RNC desde cache (best-effort, no bloquea)
    const negocio_rnc = t(b.negocio_rnc);
    let rnc_estado = null;
    if (isValidRncNumber(negocio_rnc)) {
      const cached = await getRncCacheFromDb(negocio_rnc);
      if (cached?.estado) rnc_estado = cached.estado;
    }

    const data = {
      negocio_nombre_comercial,
      negocio_razon_social: t(b.negocio_razon_social),
      negocio_rnc,
      negocio_actividad,
      negocio_actividad_otro: t(b.negocio_actividad_otro),
      negocio_local_plaza: t(b.negocio_local_plaza),
      negocio_empleados: t(b.negocio_empleados),

      responsable_nombre,
      responsable_cargo: t(b.responsable_cargo),
      responsable_whatsapp,
      responsable_email: t(b.responsable_email),

      autoriza_compras: t(b.autoriza_compras),
      autoriza_compras_otro: t(b.autoriza_compras_otro),

      consumo_frecuencia: t(b.consumo_frecuencia),
      consumo_nota,
      consumo_productos,
      consumo_productos_otro: t(b.consumo_productos_otro),
      prioridades,

      facilidad_30_dias: t(b.facilidad_30_dias),
      estados_cuenta_por: t(b.estados_cuenta_por),

      acepta_terminos,
=======
    // reCAPTCHA (optional)
    const recaptchaToken = String(b.recaptcha_token || b["g-recaptcha-response"] || "");
    const captcha = await verifyRecaptcha(recaptchaToken, ip);
    if (!captcha.ok) {
      return res.status(400).send("Validación reCAPTCHA fallida. Intenta de nuevo.");
    }

    const required = (name) => b[name] && String(b[name]).trim().length > 0;
    if (!required("negocio_nombre_comercial")) return res.status(400).send("Falta: Nombre comercial");
    if (!required("negocio_actividad")) return res.status(400).send("Falta: Actividad principal");
    if (!required("responsable_nombre")) return res.status(400).send("Falta: Nombre responsable");
    if (!required("responsable_whatsapp")) return res.status(400).send("Falta: WhatsApp responsable");

    const acepta = b.acepta_terminos === "on" ? 1 : 0;
    if (!acepta) return res.status(400).send("Debe aceptar términos");

    const consumo_productos = toCSV(b.consumo_productos);
    const prioridades = toCSV(pickMax2(b.prioridades));
    const consumo_nota = (b.consumo_nota || "").toString().trim();

    const data = {
      negocio_nombre_comercial: b.negocio_nombre_comercial?.trim(),
      negocio_razon_social: b.negocio_razon_social?.trim() || "",
      negocio_rnc: b.negocio_rnc?.trim() || "",
      negocio_actividad: b.negocio_actividad,
      negocio_actividad_otro: b.negocio_actividad_otro?.trim() || "",
      negocio_local_plaza: b.negocio_local_plaza?.trim() || "",
      negocio_empleados: b.negocio_empleados || "",

      responsable_nombre: b.responsable_nombre?.trim(),
      responsable_cargo: b.responsable_cargo?.trim() || "",
      responsable_whatsapp: b.responsable_whatsapp?.trim(),
      responsable_email: b.responsable_email?.trim() || "",

      autoriza_compras: b.autoriza_compras || "",
      autoriza_compras_otro: b.autoriza_compras_otro?.trim() || "",

      consumo_frecuencia: b.consumo_frecuencia || "",
      consumo_nota,
      consumo_productos,
      consumo_productos_otro: b.consumo_productos_otro?.trim() || "",
      prioridades,

      facilidad_30_dias: b.facilidad_30_dias || "",
      estados_cuenta_por: b.estados_cuenta_por || "",

      acepta_terminos: acepta,
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16

      acepta_privacidad: 1,
      privacidad_version: "2026-01-01",
      terminos_version: "2026-01-01",
      consentimiento_at: new Date(),

<<<<<<< HEAD
      autorizacion_nombre: t(b.autorizacion_nombre),
      autorizacion_fecha: t(b.autorizacion_fecha),

      user_agent,
      ip,
      rnc_estado,
=======
      autorizacion_nombre: b.autorizacion_nombre?.trim() || "",
      autorizacion_fecha: b.autorizacion_fecha?.trim() || "",

      user_agent,
      ip,
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
    };

    if (!pool) throw new Error("DB no inicializada");

<<<<<<< HEAD
    // 1) CRÍTICO: guardar en BD
=======
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
    const [result] = await pool.execute(
      `INSERT INTO leads (
        negocio_nombre_comercial, negocio_razon_social, negocio_rnc,
        negocio_actividad, negocio_actividad_otro, negocio_local_plaza, negocio_empleados,
        responsable_nombre, responsable_cargo, responsable_whatsapp, responsable_email,
        autoriza_compras, autoriza_compras_otro,
        consumo_frecuencia, consumo_nota, consumo_productos, consumo_productos_otro, prioridades,
        facilidad_30_dias, estados_cuenta_por,
        acepta_terminos,
        acepta_privacidad, privacidad_version, terminos_version, consentimiento_at,
        autorizacion_nombre, autorizacion_fecha,
        user_agent, ip
<<<<<<< HEAD
        , rnc_estado, rnc_validated_at
=======
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
      ) VALUES (
        ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?,
        ?,
        ?, ?, ?, ?,
        ?, ?,
        ?, ?
<<<<<<< HEAD
        , ?, NOW()
      )`,
      [
        data.negocio_nombre_comercial,
        data.negocio_razon_social,
        data.negocio_rnc,
        data.negocio_actividad,
        data.negocio_actividad_otro,
        data.negocio_local_plaza,
        data.negocio_empleados,
        data.responsable_nombre,
        data.responsable_cargo,
        data.responsable_whatsapp,
        data.responsable_email,
        data.autoriza_compras,
        data.autoriza_compras_otro,
        data.consumo_frecuencia,
        data.consumo_nota,
        data.consumo_productos,
        data.consumo_productos_otro,
        data.prioridades,
        data.facilidad_30_dias,
        data.estados_cuenta_por,
        data.acepta_terminos,
        data.acepta_privacidad,
        data.privacidad_version,
        data.terminos_version,
        data.consentimiento_at,
        data.autorizacion_nombre,
        data.autorizacion_fecha,
        data.user_agent,
        data.ip,
        data.rnc_estado,
=======
      )`,
      [
        data.negocio_nombre_comercial, data.negocio_razon_social, data.negocio_rnc,
        data.negocio_actividad, data.negocio_actividad_otro, data.negocio_local_plaza, data.negocio_empleados,
        data.responsable_nombre, data.responsable_cargo, data.responsable_whatsapp, data.responsable_email,
        data.autoriza_compras, data.autoriza_compras_otro,
        data.consumo_frecuencia, data.consumo_nota, data.consumo_productos, data.consumo_productos_otro, data.prioridades,
        data.facilidad_30_dias, data.estados_cuenta_por,
        data.acepta_terminos,
        data.acepta_privacidad, data.privacidad_version, data.terminos_version, data.consentimiento_at,
        data.autorizacion_nombre, data.autorizacion_fecha,
        data.user_agent, data.ip,
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
      ]
    );

    const leadId = result.insertId;

<<<<<<< HEAD
    // scoring persistente (A/B/C)
    await scoreAndPersistLead(leadId);

    // 2) SECUNDARIO: email (fallo gracioso)
    try {
      const transporter = makeTransporter();
      const toEmail = t(process.env.LEADS_TO_EMAIL);

      if (transporter && toEmail) {
=======
    // Email (optional)
    const transporter = makeTransporter();
    if (transporter) {
      const toEmail = process.env.LEADS_TO_EMAIL || "";
      if (toEmail) {
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
        const subject = `Nuevo registro - Código Empresarial Portafolio (#${leadId})`;

        const html = `
          <h2>Nuevo registro: Código Empresarial Portafolio</h2>
          <p><b>ID:</b> ${leadId} | <b>Fecha:</b> ${new Date().toISOString()}</p>
          <hr/>
          <h3>1) Datos del Negocio</h3>
          <ul>
            <li><b>Nombre comercial:</b> ${escapeHtml(data.negocio_nombre_comercial)}</li>
            <li><b>Razón social:</b> ${escapeHtml(data.negocio_razon_social)}</li>
            <li><b>RNC:</b> ${escapeHtml(data.negocio_rnc)}</li>
            <li><b>Actividad:</b> ${escapeHtml(data.negocio_actividad)} ${data.negocio_actividad === "Otro" ? " - " + escapeHtml(data.negocio_actividad_otro) : ""}</li>
            <li><b>Local / plaza:</b> ${escapeHtml(data.negocio_local_plaza)}</li>
            <li><b>Empleados:</b> ${escapeHtml(data.negocio_empleados)}</li>
          </ul>

          <h3>2) Responsable</h3>
          <ul>
            <li><b>Nombre:</b> ${escapeHtml(data.responsable_nombre)}</li>
            <li><b>Cargo:</b> ${escapeHtml(data.responsable_cargo)}</li>
            <li><b>WhatsApp:</b> ${escapeHtml(data.responsable_whatsapp)}</li>
            <li><b>Email:</b> ${escapeHtml(data.responsable_email)}</li>
            <li><b>Autoriza compras:</b> ${escapeHtml(data.autoriza_compras)} ${data.autoriza_compras === "Otro" ? " - " + escapeHtml(data.autoriza_compras_otro) : ""}</li>
          </ul>

          <h3>3) Consumo Operativo</h3>
          <ul>
            <li><b>Frecuencia:</b> ${escapeHtml(data.consumo_frecuencia)}</li>
            <li><b>Nota:</b> ${escapeHtml(data.consumo_nota)}</li>
            <li><b>Productos:</b> ${escapeHtml(data.consumo_productos)} ${data.consumo_productos_otro ? " | Otro: " + escapeHtml(data.consumo_productos_otro) : ""}</li>
            <li><b>Prioridades (máx 2):</b> ${escapeHtml(data.prioridades)}</li>
          </ul>

          <h3>4) Activación</h3>
          <ul>
            <li><b>Facilidad 30 días:</b> ${escapeHtml(data.facilidad_30_dias)}</li>
            <li><b>Estados de cuenta por:</b> ${escapeHtml(data.estados_cuenta_por)}</li>
          </ul>

          <h3>5) Autorización</h3>
          <ul>
            <li><b>Aceptó términos:</b> ${data.acepta_terminos ? "Sí" : "No"}</li>
            <li><b>Nombre:</b> ${escapeHtml(data.autorizacion_nombre)}</li>
            <li><b>Fecha:</b> ${escapeHtml(data.autorizacion_fecha)}</li>
          </ul>

          <hr/>
          <p><b>IP:</b> ${escapeHtml(data.ip)} | <b>User-Agent:</b> ${escapeHtml(data.user_agent)}</p>
        `;

        await transporter.sendMail({
          from: process.env.SMTP_USER,
          to: toEmail,
          subject,
          html,
        });
      }
<<<<<<< HEAD
    } catch (mailErr) {
      console.error("⚠️ Email falló (no bloqueante):", mailErr?.message || mailErr);
      // NO interrumpe: el lead ya está guardado
    }

    // Redirect URL (frontend hará window.location)
    const waTo = t(process.env.WHATSAPP_TO);
=======
    }

    // Redirect to thanks + WhatsApp
    const waTo = process.env.WHATSAPP_TO || "";
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
    const waMessage =
      `Hola, acabo de enviar una solicitud de Código Empresarial / crédito.\n\n` +
      `ID: #${leadId}\n` +
      `Negocio: ${data.negocio_nombre_comercial}\n` +
      (data.negocio_local_plaza ? `Local: ${data.negocio_local_plaza}\n` : ``) +
      `Responsable: ${data.responsable_nombre}\n` +
      `Teléfono: ${data.responsable_whatsapp}\n` +
      (data.responsable_email ? `Correo: ${data.responsable_email}\n` : ``) +
      `\n¿Me confirman recepción? Gracias.`;

    const waLink = buildWhatsAppLink(waTo, waMessage);
<<<<<<< HEAD
    const redirectUrl = `/thanks?wa=${encodeURIComponent(waLink)}`;

    return res.json({ ok: true, redirectUrl });
  } catch (err) {
    console.error("❌ Error submit:", err?.message || err);
    return res.status(500).json({ ok: false, message: "Error interno al procesar el formulario." });
  }
});


// -------------------- Global error handler (no stack to client)
app.use((err, req, res, next) => {
  logJson("error", "app.error", { requestId: req.requestId, err: err?.message || String(err) });
  if (res.headersSent) return next(err);
  res.status(500).json({ ok: false, message: "Error interno." });
});

=======
    res.redirect(`/thanks?wa=${encodeURIComponent(waLink)}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error interno al procesar el formulario.");
  }
});

>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
// -------------------- Boot
const port = Number(process.env.PORT || 3000);

(async () => {
  try {
    await initDb();
    app.listen(port, () => console.log(`✅ Portafolio Empresas corriendo en puerto ${port}`));
  } catch (err) {
    console.error("❌ Error iniciando servidor:", err?.message || err);
    process.exit(1);
  }
<<<<<<< HEAD
})();
=======
})();
>>>>>>> cfbf8a0ab586bf5302c0b289fbeabde600f66e16
