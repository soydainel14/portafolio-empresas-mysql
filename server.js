import express from "express";
import helmet from "helmet";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import mysql from "mysql2/promise";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(helmet());
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Static assets (logo, etc.)
app.use("/assets", express.static(path.join(__dirname, "public", "assets")));

// -------------------- reCAPTCHA (optional)
async async function verifyRecaptcha(token, ip) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;

  // If not configured, skip
  if (!secret) return { ok: true, skipped: true };

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

  // v3 adds score/action; v2 doesn't.
  const minScore = Number(process.env.RECAPTCHA_MIN_SCORE || 0.5);
  const expectedAction = process.env.RECAPTCHA_ACTION || "submit";

  if (!data.success) return { ok: false, reason: "not_success", data };

  if (typeof data.score === "number") {
    if (data.score < minScore) return { ok: false, reason: "low_score", data };
    if (data.action && data.action !== expectedAction) return { ok: false, reason: "bad_action", data };
  }

  return { ok: true, data };
}

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
  }

  return null;
}


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

// -------------------- Routes
app.get("/", async (req, res) => {
  try {
    const siteKey = process.env.RECAPTCHA_SITE_KEY || "";
    const fp = path.join(__dirname, "views", "form.html");
    let html = await fs.promises.readFile(fp, "utf-8");
    html = html.replaceAll("{{RECAPTCHA_SITE_KEY}}", siteKey);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html);
  } catch (err) {
    console.error("Error cargando formulario:", err?.message || err);
    res.status(500).send("Error cargando formulario");
  }
});

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

app.post("/submit", async (req, res) => {
  try {
    const b = req.body || {};
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "";
    const user_agent = req.headers["user-agent"] || "";

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

      acepta_privacidad: 1,
      privacidad_version: "2026-01-01",
      terminos_version: "2026-01-01",
      consentimiento_at: new Date(),

      autorizacion_nombre: b.autorizacion_nombre?.trim() || "",
      autorizacion_fecha: b.autorizacion_fecha?.trim() || "",

      user_agent,
      ip,
    };

    if (!pool) throw new Error("DB no inicializada");

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
      ]
    );

    const leadId = result.insertId;

    // Email (optional)
    const transporter = makeTransporter();
    if (transporter) {
      const toEmail = process.env.LEADS_TO_EMAIL || "";
      if (toEmail) {
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
    }

    // Redirect to thanks + WhatsApp
    const waTo = process.env.WHATSAPP_TO || "";
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
    res.redirect(`/thanks?wa=${encodeURIComponent(waLink)}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error interno al procesar el formulario.");
  }
});

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
})();
