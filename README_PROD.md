# Producción "Bulletproof" — Checklist

## Endpoints
- `/health` (JSON) -> ok + db
- `/ready` -> texto `ready`

## Seguridad
- Helmet activo
- Rate limit `/submit` y `/api/validate-rnc`
- Admin: JWT httpOnly cookie (setea `COOKIE_SECURE=true` en Railway)

## Observabilidad
- Logs JSON por request (sin body)
- Header `x-request-id`

## Tracking (opcional)
- `FB_PIXEL_ID`: PageView y Lead en /thanks
- `GA_MEASUREMENT_ID`: gtag

## Roles (RBAC)
- `admin_users.role` soporta `admin` y `agent`
- Acciones sensibles (scoring/templates) restringidas a `admin`

## Backups (Railway)
- Usa snapshots/backup desde el panel del servicio MySQL en Railway.
