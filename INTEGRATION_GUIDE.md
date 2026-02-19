# Guía de Integración (Railway + GitHub + MySQL) — Portafolio Empresas

Objetivo: **poner a producir en minutos** el formulario de leads (UI banco moderno + stepper) con:
- Node.js/Express
- MySQL (Railway)
- Captura de leads en BD (CRÍTICO)
- Email (SECUNDARIO, fallo gracioso)
- Proxy RNC + cache + Admin Dashboard

---

## 0) Requisitos mínimos
- Cuenta de **Railway**
- Cuenta de **GitHub**
- Node.js **18+** en tu PC (solo si vas a correr local)
- Un correo SMTP (opcional, recomendado) o dejarlo sin configurar

---

## 1) Subir el código a GitHub (rápido)
### Opción A (recomendada): subir el ZIP y crear repo desde GitHub
1. En GitHub → **New repository**
2. Nombre: `portafolio-empresas-mysql`
3. Crea el repo vacío (sin README si quieres)
4. En tu PC, descomprime este ZIP y abre la carpeta.
5. En terminal dentro de la carpeta:

```bash
git init
git add .
git commit -m "Deploy: Portafolio Empresas"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/portafolio-empresas-mysql.git
git push -u origin main
```

> Si no quieres usar terminal: puedes usar GitHub Desktop y arrastrar la carpeta.

---

## 2) Crear MySQL en Railway (lo más simple)
1. Railway → **New Project**
2. **Add service** → **Database** → **MySQL**
3. Espera que esté listo.

Railway te va a dar variables tipo:
- `DATABASE_URL` (recomendado)
y/o
- `MYSQLHOST`, `MYSQLUSER`, `MYSQLPASSWORD`, `MYSQLDATABASE`, `MYSQLPORT`

✅ Este proyecto soporta ambos.

---

## 3) Crear el servicio Node.js y enlazar el repo
1. Railway → dentro del mismo proyecto → **Add service** → **GitHub Repo**
2. Selecciona tu repo `portafolio-empresas-mysql`
3. Railway detecta Node automáticamente.
4. En **Settings** del servicio:
   - Start command: `npm start`
   - (Railway usualmente lo detecta solo)

---

## 4) Variables de Entorno (CRÍTICO)
En Railway → servicio Node → **Variables** agrega:

### Base (obligatorias)
- `BASE_URL` = `https://TU-DOMINIO-O-URL-RAILWAY`  
  Ej: `https://portafolio-empresas.up.railway.app`
- **BD (elige una opción):**
  - Opción A: `DATABASE_URL` (cópiala desde el servicio MySQL)
  - Opción B: `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`, `DB_PORT`

### WhatsApp + Email destino (recomendadas)
- `WHATSAPP_TO` = `1809XXXXXXX` (sin +)
- `LEADS_TO_EMAIL` = `hola@portafolio.do`

### Admin (OBLIGATORIAS para entrar al panel)
- `JWT_SECRET` = (string largo random)
- `ADMIN_EMAIL` = `admin@portafolio.do`
- `ADMIN_PASSWORD` = (password fuerte)
- `COOKIE_SECURE` = `true` (en Railway)

### reCAPTCHA v3 (opcional pero recomendado)
- `RECAPTCHA_SITE_KEY` = tu site key
- `RECAPTCHA_SECRET_KEY` = tu secret key
- `RECAPTCHA_MIN_SCORE` = `0.5`
- `RECAPTCHA_ACTION` = `submit`

### SMTP (opcional)
Si NO configuras SMTP, **no pasa nada** (el lead igual se guarda).
Si lo configuras:
- `SMTP_HOST`
- `SMTP_PORT` (ej: 587)
- `SMTP_SECURE` (`false` para 587 / `true` para 465)
- `SMTP_USER`
- `SMTP_PASS`

---

## 5) Conectar variables entre servicios (Railway “Reference variables”)
Recomendación rápida:
1. En el servicio MySQL → copia `DATABASE_URL`
2. Pégala tal cual en el servicio Node como `DATABASE_URL`

✅ Con eso basta.

---

## 6) Deploy y verificación (2 minutos)
1. Railway → servicio Node → **Deployments** → espera `Success`.
2. Abre la URL pública de Railway:
   - Formulario: `https://TU-URL/`
   - Admin login: `https://TU-URL/admin/login`

### Checks rápidos
- Completa el formulario → debe redirigir a `/thanks`
- En MySQL deben aparecer registros en la tabla `leads`
- Prueba RNC: escribe 9 u 11 dígitos → debe autocompletar si encuentra
- Admin:
  - Login con `ADMIN_EMAIL` / `ADMIN_PASSWORD`
  - Debes ver leads + score/tier

> Importante: el servidor auto-crea tablas y columnas al iniciar. No tienes que “migrar” manualmente.

---

## 7) Dominio propio (si quieres Portafolio.do)
1. Railway → servicio Node → **Settings → Domains**
2. Add domain: `formularios.portafolio.do` (ejemplo)
3. En tu DNS (Cloudflare/Proveedor):
   - CNAME `formularios` → el dominio que Railway te indica
4. Actualiza `BASE_URL` al dominio final.

---

## 8) Flujo recomendado para operar “ya”
- Lanza hoy con:
  - BD conectada
  - WhatsApp destino
  - Admin panel
- SMTP lo puedes agregar después sin romper nada.

---

## 9) Modo local (si necesitas probar en tu PC)
1. Crea archivo `.env` (usa `.env.example`)
2. Instala y corre:

```bash
npm install
npm start
```

Abrir: `http://localhost:3000`

---

## 10) Solución rápida a errores típicos
### Error: “Faltan variables de MySQL”
- Asegúrate que `DATABASE_URL` esté en el **servicio Node** (no solo en MySQL).
- O llena `DB_HOST/DB_USER/DB_NAME`.

### Error Admin no entra
- `JWT_SECRET` vacío → agrega.
- `ADMIN_EMAIL/ADMIN_PASSWORD` mal → corrige y redeploy.
- Si ya se creó un admin anterior en BD, cambia password desde BD o borra tabla `admin_users` y reinicia.

### reCAPTCHA falla en producción
- Asegúrate que el dominio esté agregado en tu configuración de reCAPTCHA.
- Si quieres desactivarlo temporalmente: elimina `RECAPTCHA_SECRET_KEY`.

---

## 11) Checklist final (producción real)
- [ ] `DATABASE_URL` configurada
- [ ] `BASE_URL` correcto (https)
- [ ] `WHATSAPP_TO` y `LEADS_TO_EMAIL` configurados
- [ ] `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `COOKIE_SECURE=true`
- [ ] Deploy success
- [ ] Lead se guarda en BD
- [ ] Admin abre y lista leads


## Healthcheck
- `GET /health` devuelve estado del servidor y DB.
- `GET /ready` para readiness.


## Tracking (opcional)
- `FB_PIXEL_ID` Meta Pixel (PageView + Lead en /thanks)
- `GA_MEASUREMENT_ID` Google Analytics (gtag)
