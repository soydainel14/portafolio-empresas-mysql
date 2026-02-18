# Portafolio Empresas — Código Empresarial (Formulario + Leads) [MySQL]

## Requisitos
- Node.js 18+ (recomendado)
- NPM
- MySQL (Railway MySQL recomendado)

## Instalación
```bash
npm install
```

## Configuración (.env)
Crea un archivo `.env` en la raíz (puedes copiar `.env.example`) y completa:

### Base de datos (obligatorio)
- **Opción A (recomendada):** `DATABASE_URL=mysql://USER:PASS@HOST:PORT/DBNAME`
- **Opción B:** `MYSQLHOST`, `MYSQLPORT`, `MYSQLUSER`, `MYSQLPASSWORD`, `MYSQLDATABASE`

### WhatsApp (obligatorio)
- `WHATSAPP_TO` (número de Portafolio en formato internacional, sin `+`)

### Correo (opcional)
- Si completas SMTP, el sistema enviará un email a `LEADS_TO_EMAIL`
- Si no completas SMTP, igual guarda el lead en MySQL

## Ejecutar
```bash
npm start
```

Abrir: http://localhost:3000

## Producción en Railway
1. Deploy desde GitHub
2. Agrega un servicio **MySQL**
3. Copia las credenciales a variables en tu servicio web (DATABASE_URL o variables separadas)
4. Deploy y prueba

La tabla `leads` se crea automáticamente al iniciar.
