# Plugin License Hub

Generic licensing API + web console for multiple plugins.

## What it does
- Issues per-user license keys from BuiltByBit webhook downloads.
- Validates license keys for plugin runtime checks.
- Provides admin console (`/console`) to list/search/revoke/activate licenses.
- Supports multiple plugins/products via `BBB_RESOURCE_PRODUCT_MAP`.
- Enforces activation binding: `1 license key -> 1 server fingerprint + 1 public IP`.
- Includes a **Test Injector** to simulate a BBB-injected download 1:1 before publishing.

## Endpoints
- `POST /bbb/license-key`
- `POST /license/validate`
- `POST /admin/revoke` (header `X-Admin-Secret`)
- `POST /admin/activate` (header `X-Admin-Secret`)
- `POST /admin/reset-binding` (header `X-Admin-Secret`)
- `GET /console` (password login)
- `GET /health`

### Test Injector endpoints (console auth required)
- `GET /console/api/test/base`
- `POST /console/api/test/base` (multipart, field `jar`)
- `POST /console/api/test/generate`
- `GET /console/api/test/download/:token`
- `POST /console/api/reset-binding`

## Local run
```bash
npm install
cp .env.example .env
npm start
```

## Docker Swarm
Use `plugins.stack.yml`:
```bash
docker stack deploy -c plugins.stack.yml plugins
```

## BuiltByBit setup
Create external license key placeholder:
- Placeholder: `%%__COLISEUM_LICENSE__%%`
- Type: `External license key`
- Url: `https://api.yourdomain.com/bbb/license-key`
- Secret: same as `BBB_SECRET`

Recommended nonce aliases:
- `%%__COLISEUM_NONCE_A__%%`
- `%%__COLISEUM_NONCE_B__%%`

## Test flow (BBB-like, before approval)
1. Open `/console`.
2. In **Test Injector**, set product (example: `coliseum`).
3. Upload your base jar for that product.
4. Fill user/resource/version test fields.
5. Click **Generate Injected JAR**.
6. Download the generated jar and use it in server `mods/`.

The generator injects:
- `%%__BUILTBYBIT__%%` -> `true`
- `%%__USER__%%`, `%%__USERNAME__%%`
- `%%__RESOURCE__%%`, `%%__RESOURCE_TITLE__%%`
- `%%__VERSION__%%`, `%%__VERSION_NUMBER__%%`
- `%%__TIMESTAMP__%%`
- `%%__NONCE__%%`
- `%%__COLISEUM_LICENSE__%%`
- `%%__COLISEUM_NONCE_A__%%`, `%%__COLISEUM_NONCE_B__%%`

## Plugin validate request
Your plugin should call:
- `POST https://api.yourdomain.com/license/validate`
- Header: `X-Plugin-Secret: <VALIDATE_SECRET>`
- JSON body at minimum:
```json
{
  "product": "coliseum",
  "external_key": "...",
  "server_fingerprint": "..."
}
```

Response example:
```json
{ "valid": true, "reason": "ok", "product": "coliseum" }
```

## Environment
See `.env.example`.
Important:
- `BBB_SECRET`
- `VALIDATE_SECRET`
- `ADMIN_SECRET`
- `PANEL_PASSWORD`
- `BBB_RESOURCE_PRODUCT_MAP`
