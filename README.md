# Plugin License Hub

Generic licensing API + web console for multiple plugins.

## What it does
- Issues per-user license keys from BuiltByBit webhook downloads.
- Validates license keys for plugin runtime checks.
- Provides admin console (`/console`) to list/search/revoke/activate licenses.
- Supports multiple plugins/products via `BBB_RESOURCE_PRODUCT_MAP`.

## Endpoints
- `POST /bbb/license-key`
- `POST /license/validate`
- `POST /admin/revoke` (header `X-Admin-Secret`)
- `POST /admin/activate` (header `X-Admin-Secret`)
- `GET /console` (password login)
- `GET /health`

## Product model
- Each license has a `product` field.
- Product resolution for BBB webhook:
1. `body.product` if provided
2. `BBB_RESOURCE_PRODUCT_MAP[resource_id]` if configured
3. `DEFAULT_PRODUCT_ID`

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

## GitHub Actions image publish
- Workflow file: `.github/workflows/docker-publish.yml`
- Publishes to: `ghcr.io/lucasvicentec/licensehub`
- On push to `main`: publishes `:latest` and `:sha-<short>`
- On tag `v*`: publishes tag image too

## BuiltByBit setup
Create external license key placeholder:
- Placeholder: `%%__COLISEUM_LICENSE__%%` (or your plugin alias)
- Type: `External license key`
- Url: `https://api.yourdomain.com/bbb/license-key`
- Secret: same as `BBB_SECRET`

Recommended nonce aliases:
- `%%__PLUGIN_NONCE_A__%%`
- `%%__PLUGIN_NONCE_B__%%`

## Plugin validate request
Your plugin should call:
- `POST https://api.yourdomain.com/license/validate`
- Header: `X-Plugin-Secret: <VALIDATE_SECRET>`
- JSON body at minimum:
```json
{
  "product": "coliseum",
  "external_key": "..."
}
```

Response:
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
