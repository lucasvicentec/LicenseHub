const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const AdmZip = require("adm-zip");
const Database = require("better-sqlite3");

const PORT = parseInt(process.env.PORT || "8080", 10);
const HOST = process.env.HOST || "0.0.0.0";
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "licenses.db");
const DEFAULT_PRODUCT_ID = (process.env.DEFAULT_PRODUCT_ID || "default-plugin").trim().toLowerCase();
const BBB_SECRET = process.env.BBB_SECRET || "";
const VALIDATE_SECRET = process.env.VALIDATE_SECRET || "";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || "";
const ALLOW_ISSUE_WITHOUT_SECRET = (process.env.ALLOW_ISSUE_WITHOUT_SECRET || "false").toLowerCase() === "true";

const TEST_BASE_DIR = path.join(DATA_DIR, "test", "base");
const TEST_OUTPUT_DIR = path.join(DATA_DIR, "test", "generated");

function parseResourceProductMap(raw) {
  const value = (raw || "").trim();
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out = {};
    for (const [key, v] of Object.entries(parsed)) {
      const k = String(key).trim();
      const p = String(v || "").trim().toLowerCase();
      if (k && p) out[k] = p;
    }
    return out;
  } catch {
    return {};
  }
}

const BBB_RESOURCE_PRODUCT_MAP = parseResourceProductMap(process.env.BBB_RESOURCE_PRODUCT_MAP);

if (!PANEL_PASSWORD) {
  console.warn("[panel] PANEL_PASSWORD is empty. Set it in environment for production.");
}

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
fs.mkdirSync(TEST_BASE_DIR, { recursive: true });
fs.mkdirSync(TEST_OUTPUT_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_key TEXT NOT NULL UNIQUE,
  product TEXT NOT NULL,
  user_id TEXT NOT NULL,
  username TEXT,
  resource_id TEXT,
  resource_title TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  bound_fingerprint TEXT,
  bound_ip TEXT,
  first_validated_at INTEGER,
  last_validated_at INTEGER,
  validation_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_issued_at INTEGER,
  issue_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_licenses_product_status ON licenses (product, status);
CREATE INDEX IF NOT EXISTS idx_licenses_user_product ON licenses (user_id, product);
CREATE TABLE IF NOT EXISTS test_builds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  product TEXT NOT NULL,
  user_id TEXT NOT NULL,
  username TEXT,
  license_key TEXT NOT NULL,
  source_name TEXT NOT NULL,
  generated_name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  download_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_test_builds_created ON test_builds (created_at DESC);
`);

function ensureColumn(tableName, columnName, ddl) {
  const columns = db.prepare(`PRAGMA table_info(${tableName})`).all().map(c => c.name);
  if (!columns.includes(columnName)) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${ddl}`);
  }
}

ensureColumn("licenses", "bound_fingerprint", "bound_fingerprint TEXT");
ensureColumn("licenses", "bound_ip", "bound_ip TEXT");
ensureColumn("licenses", "first_validated_at", "first_validated_at INTEGER");
ensureColumn("licenses", "last_validated_at", "last_validated_at INTEGER");
ensureColumn("licenses", "validation_count", "validation_count INTEGER NOT NULL DEFAULT 0");

const qFindByKey = db.prepare("SELECT * FROM licenses WHERE license_key = ? LIMIT 1");
const qFindByUserProduct = db.prepare("SELECT * FROM licenses WHERE user_id = ? AND product = ? LIMIT 1");
const qInsert = db.prepare(`
INSERT INTO licenses (
  license_key, product, user_id, username, resource_id, resource_title,
  status, created_at, updated_at, last_issued_at, issue_count
) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, 1)
`);
const qTouchIssue = db.prepare(`
UPDATE licenses
SET username = ?, resource_id = ?, resource_title = ?, updated_at = ?, last_issued_at = ?, issue_count = issue_count + 1
WHERE id = ?
`);
const qSetStatus = db.prepare("UPDATE licenses SET status = ?, updated_at = ? WHERE license_key = ?");
const qResetBinding = db.prepare(`
UPDATE licenses
SET bound_fingerprint = NULL,
    bound_ip = NULL,
    first_validated_at = NULL,
    last_validated_at = NULL,
    validation_count = 0,
    updated_at = ?
WHERE license_key = ?
`);
const qListAll = db.prepare(`
SELECT id, license_key, product, user_id, username, resource_id, resource_title, status, bound_ip, validation_count, created_at, updated_at, last_issued_at, issue_count
FROM licenses
ORDER BY updated_at DESC
LIMIT ?
`);
const qListByProduct = db.prepare(`
SELECT id, license_key, product, user_id, username, resource_id, resource_title, status, bound_ip, validation_count, created_at, updated_at, last_issued_at, issue_count
FROM licenses
WHERE product = ?
ORDER BY updated_at DESC
LIMIT ?
`);
const qCountByStatusAll = db.prepare(`
SELECT status, COUNT(*) AS total
FROM licenses
GROUP BY status
`);
const qCountByStatusProduct = db.prepare(`
SELECT status, COUNT(*) AS total
FROM licenses
WHERE product = ?
GROUP BY status
`);
const qSearchAll = db.prepare(`
SELECT id, license_key, product, user_id, username, resource_id, resource_title, status, bound_ip, validation_count, created_at, updated_at, last_issued_at, issue_count
FROM licenses
WHERE (
  license_key LIKE ?
  OR user_id LIKE ?
  OR username LIKE ?
  OR resource_id LIKE ?
  OR resource_title LIKE ?
  OR product LIKE ?
)
ORDER BY updated_at DESC
LIMIT 250
`);
const qSearchByProduct = db.prepare(`
SELECT id, license_key, product, user_id, username, resource_id, resource_title, status, bound_ip, validation_count, created_at, updated_at, last_issued_at, issue_count
FROM licenses
WHERE product = ?
  AND (
    license_key LIKE ?
    OR user_id LIKE ?
    OR username LIKE ?
    OR resource_id LIKE ?
    OR resource_title LIKE ?
  )
ORDER BY updated_at DESC
LIMIT 250
`);
const qBindActivation = db.prepare(`
UPDATE licenses
SET bound_fingerprint = ?, bound_ip = ?, first_validated_at = ?, last_validated_at = ?, validation_count = validation_count + 1, updated_at = ?
WHERE id = ?
`);
const qTouchValidation = db.prepare(`
UPDATE licenses
SET last_validated_at = ?, validation_count = validation_count + 1, updated_at = ?
WHERE id = ?
`);
const qInsertTestBuild = db.prepare(`
INSERT INTO test_builds (
  token, product, user_id, username, license_key, source_name, generated_name, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
const qListTestBuilds = db.prepare(`
SELECT token, product, user_id, username, license_key, source_name, generated_name, created_at, download_count
FROM test_builds
ORDER BY created_at DESC
LIMIT 100
`);
const qFindTestBuild = db.prepare(`
SELECT token, product, user_id, username, license_key, source_name, generated_name, created_at, download_count
FROM test_builds
WHERE token = ?
LIMIT 1
`);
const qTouchTestDownload = db.prepare("UPDATE test_builds SET download_count = download_count + 1 WHERE token = ?");

function nowTs() {
  return Math.floor(Date.now() / 1000);
}

function norm(value) {
  return value == null ? "" : String(value).trim();
}

function sendTextKey(res, key) {
  res.type("text/plain; charset=utf-8").send(key);
}

function issueKey(product, userId, resourceId) {
  const random = crypto.randomBytes(10).toString("hex").toUpperCase();
  const digest = crypto
    .createHash("sha256")
    .update(`${product}|${userId}|${resourceId}|${Date.now()}|${random}`)
    .digest("hex")
    .slice(0, 12)
    .toUpperCase();
  const prefix = product.replace(/[^a-z0-9]/gi, "").slice(0, 6).toUpperCase() || "PLUG";
  return `${prefix}-${random}-${digest}`;
}

function parseBbbPayload(body) {
  return {
    secret: norm(body.secret),
    userId: norm(body.user || body.user_id),
    username: norm(body.username),
    resourceId: norm(body.resource || body.resource_id),
    resourceTitle: norm(body.resource_title),
    product: norm(body.product).toLowerCase(),
    versionNumber: norm(body.version_number || body.version),
    timestamp: norm(body.timestamp)
  };
}

function getRequestIp(req) {
  const xff = norm(req.header("x-forwarded-for"));
  if (xff) {
    return xff.split(",")[0].trim();
  }
  return norm(req.ip || req.connection?.remoteAddress || "");
}

function resolveProductFromPayload(payload) {
  if (payload.product) return payload.product;
  if (payload.resourceId && BBB_RESOURCE_PRODUCT_MAP[payload.resourceId]) {
    return BBB_RESOURCE_PRODUCT_MAP[payload.resourceId];
  }
  return DEFAULT_PRODUCT_ID;
}

function authAdminApi(req, res, next) {
  if (!ADMIN_SECRET) {
    return res.status(500).json({ ok: false, error: "admin_secret_not_configured" });
  }
  if (norm(req.header("X-Admin-Secret")) !== ADMIN_SECRET) {
    return res.status(403).json({ ok: false, error: "forbidden" });
  }
  return next();
}

function authPanel(req, res, next) {
  const panelToken = norm(req.cookies.panel_token);
  const validToken = crypto.createHash("sha256").update(PANEL_PASSWORD || "").digest("hex");
  if (!PANEL_PASSWORD || panelToken !== validToken) {
    return res.redirect("/login");
  }
  return next();
}

function toProduct(value) {
  const raw = norm(value).toLowerCase();
  const safe = raw.replace(/[^a-z0-9\-_]/g, "");
  return safe || DEFAULT_PRODUCT_ID;
}

function getOrCreateLicense(product, userId, username, resourceId, resourceTitle) {
  const ts = nowTs();
  const current = qFindByUserProduct.get(userId, product);
  if (current) {
    qTouchIssue.run(
      username || current.username || "",
      resourceId || current.resource_id || "",
      resourceTitle || current.resource_title || "",
      ts,
      ts,
      current.id
    );
    return current.license_key;
  }
  const key = issueKey(product, userId, resourceId || "unknown");
  qInsert.run(key, product, userId, username || "", resourceId || "", resourceTitle || "", ts, ts, ts);
  return key;
}

function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}

function getBaseJarPath(product) {
  return path.join(TEST_BASE_DIR, `${product}.jar`);
}

function injectPlaceholdersToJar(sourcePath, targetPath, replacements) {
  const zip = new AdmZip(sourcePath);
  const entries = zip.getEntries();
  let replacedTokens = 0;
  let touchedEntries = 0;

  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const original = entry.getData().toString("utf8");
    if (!original.includes("%%__")) continue;

    let updated = original;
    let changed = false;
    for (const [token, value] of Object.entries(replacements)) {
      if (!token) continue;
      if (updated.includes(token)) {
        const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const rx = new RegExp(escaped, "g");
        const count = (updated.match(rx) || []).length;
        if (count > 0) {
          replacedTokens += count;
          updated = updated.replace(rx, value);
          changed = true;
        }
      }
    }
    if (changed) {
      touchedEntries += 1;
      zip.updateFile(entry.entryName, Buffer.from(updated, "utf8"));
    }
  }

  zip.writeZip(targetPath);
  return { touchedEntries, replacedTokens };
}

const app = express();
const upload = multer({
  limits: { fileSize: 200 * 1024 * 1024 }
});

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use("/assets", express.static(path.join(__dirname, "..", "public")));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "plugin-license-hub",
    default_product: DEFAULT_PRODUCT_ID,
    mapped_resources: Object.keys(BBB_RESOURCE_PRODUCT_MAP).length
  });
});

app.post("/bbb/license-key", (req, res) => {
  const p = parseBbbPayload(req.body || {});
  if (!ALLOW_ISSUE_WITHOUT_SECRET) {
    if (!BBB_SECRET || p.secret !== BBB_SECRET) {
      return res.status(403).send("forbidden");
    }
  }
  if (!p.userId) {
    return res.status(400).send("missing user");
  }

  const product = resolveProductFromPayload(p);
  const key = getOrCreateLicense(product, p.userId, p.username, p.resourceId, p.resourceTitle);
  return sendTextKey(res, key);
});

app.post("/license/validate", (req, res) => {
  if (VALIDATE_SECRET) {
    if (norm(req.header("X-Plugin-Secret")) !== VALIDATE_SECRET && norm(req.header("X-Coliseum-Secret")) !== VALIDATE_SECRET) {
      return res.status(403).json({ valid: false, reason: "forbidden" });
    }
  }
  const body = req.body || {};
  const requestedProduct = norm(body.product).toLowerCase();
  const key = norm(body.external_key);
  const serverFingerprint = norm(body.server_fingerprint);
  const requestIp = getRequestIp(req);
  if (!key) {
    return res.json({ valid: false, reason: "missing_license_key" });
  }
  if (!serverFingerprint) {
    return res.json({ valid: false, reason: "missing_server_fingerprint" });
  }
  const row = qFindByKey.get(key);
  if (!row) return res.json({ valid: false, reason: "unknown_license" });
  if (requestedProduct && row.product !== requestedProduct) return res.json({ valid: false, reason: "invalid_product" });
  if (row.status !== "active") return res.json({ valid: false, reason: `status_${row.status}` });

  const ts = nowTs();
  const boundFingerprint = norm(row.bound_fingerprint);
  const boundIp = norm(row.bound_ip);

  if (!boundFingerprint || !boundIp) {
    qBindActivation.run(serverFingerprint, requestIp, ts, ts, ts, row.id);
    return res.json({
      valid: true,
      reason: "ok",
      product: row.product,
      user_id: row.user_id,
      username: row.username || "",
      activation: "bound_new"
    });
  }

  if (boundFingerprint !== serverFingerprint) {
    return res.json({ valid: false, reason: "fingerprint_mismatch" });
  }
  if (boundIp !== requestIp) {
    return res.json({ valid: false, reason: "ip_mismatch" });
  }

  qTouchValidation.run(ts, ts, row.id);
  return res.json({
    valid: true,
    reason: "ok",
    product: row.product,
    user_id: row.user_id,
    username: row.username || "",
    activation: "already_bound"
  });
});

app.post("/admin/revoke", authAdminApi, (req, res) => {
  const key = norm((req.body || {}).license_key);
  if (!key) return res.status(400).json({ ok: false, error: "missing_license_key" });
  qSetStatus.run("revoked", nowTs(), key);
  res.json({ ok: true });
});

app.post("/admin/activate", authAdminApi, (req, res) => {
  const key = norm((req.body || {}).license_key);
  if (!key) return res.status(400).json({ ok: false, error: "missing_license_key" });
  qSetStatus.run("active", nowTs(), key);
  res.json({ ok: true });
});

app.post("/admin/reset-binding", authAdminApi, (req, res) => {
  const key = norm((req.body || {}).license_key);
  if (!key) return res.status(400).json({ ok: false, error: "missing_license_key" });
  qResetBinding.run(nowTs(), key);
  res.json({ ok: true });
});

app.get("/login", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Plugin License Console Login</title><link rel="stylesheet" href="/assets/app.css"></head>
<body><main class="card"><h1>Plugin License Console</h1>
<form method="post" action="/login"><label>Password</label><input name="password" type="password" required />
<button type="submit">Login</button></form></main></body></html>`);
});

app.post("/login", (req, res) => {
  const password = norm(req.body.password);
  if (!PANEL_PASSWORD || password !== PANEL_PASSWORD) {
    return res.status(403).send("invalid credentials");
  }
  const token = crypto.createHash("sha256").update(PANEL_PASSWORD).digest("hex");
  res.cookie("panel_token", token, { httpOnly: true, sameSite: "lax", secure: false, maxAge: 24 * 60 * 60 * 1000 });
  return res.redirect("/console");
});

app.post("/logout", (_req, res) => {
  res.clearCookie("panel_token");
  res.redirect("/login");
});

app.get("/console", authPanel, (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "console.html"));
});

app.get("/console/api/overview", authPanel, (req, res) => {
  const product = norm(req.query.product).toLowerCase();
  const stats = product ? qCountByStatusProduct.all(product) : qCountByStatusAll.all();
  const data = { active: 0, revoked: 0, suspended: 0, other: 0 };
  for (const row of stats) {
    if (row.status === "active") data.active = row.total;
    else if (row.status === "revoked") data.revoked = row.total;
    else if (row.status === "suspended") data.suspended = row.total;
    else data.other += row.total;
  }
  res.json(data);
});

app.get("/console/api/licenses", authPanel, (req, res) => {
  const q = norm(req.query.q);
  const product = norm(req.query.product).toLowerCase();
  if (q) {
    const like = `%${q}%`;
    if (product) {
      return res.json(qSearchByProduct.all(product, like, like, like, like, like));
    }
    return res.json(qSearchAll.all(like, like, like, like, like, like));
  }
  if (product) {
    return res.json(qListByProduct.all(product, 250));
  }
  return res.json(qListAll.all(250));
});

app.post("/console/api/revoke", authPanel, (req, res) => {
  const key = norm((req.body || {}).license_key);
  if (!key) return res.status(400).json({ ok: false, error: "missing_license_key" });
  qSetStatus.run("revoked", nowTs(), key);
  res.json({ ok: true });
});

app.post("/console/api/activate", authPanel, (req, res) => {
  const key = norm((req.body || {}).license_key);
  if (!key) return res.status(400).json({ ok: false, error: "missing_license_key" });
  qSetStatus.run("active", nowTs(), key);
  res.json({ ok: true });
});

app.post("/console/api/reset-binding", authPanel, (req, res) => {
  const key = norm((req.body || {}).license_key);
  if (!key) return res.status(400).json({ ok: false, error: "missing_license_key" });
  qResetBinding.run(nowTs(), key);
  res.json({ ok: true });
});

app.get("/console/api/test/base", authPanel, (_req, res) => {
  const files = fs.readdirSync(TEST_BASE_DIR, { withFileTypes: true })
    .filter(d => d.isFile() && d.name.toLowerCase().endsWith(".jar"))
    .map(d => d.name)
    .sort();
  res.json({ files });
});

app.post("/console/api/test/base", authPanel, upload.single("jar"), (req, res) => {
  const product = toProduct((req.body || {}).product);
  if (!req.file || !req.file.buffer) {
    return res.status(400).json({ ok: false, error: "missing_jar_file" });
  }
  const targetPath = getBaseJarPath(product);
  fs.writeFileSync(targetPath, req.file.buffer);
  res.json({ ok: true, product, file: path.basename(targetPath) });
});

app.get("/console/api/test/builds", authPanel, (_req, res) => {
  res.json(qListTestBuilds.all());
});

app.post("/console/api/test/generate", authPanel, (req, res) => {
  const body = req.body || {};
  const product = toProduct(body.product);
  const userId = norm(body.user_id || body.user || `test-user-${Date.now()}`);
  const username = norm(body.username || "test-user");
  const resourceId = norm(body.resource_id || "test-resource");
  const resourceTitle = norm(body.resource_title || "Test Download");
  const versionNumber = norm(body.version_number || "v-test");

  const baseJarPath = getBaseJarPath(product);
  if (!fs.existsSync(baseJarPath)) {
    return res.status(400).json({ ok: false, error: "base_jar_not_found", expected: path.basename(baseJarPath) });
  }

  const licenseKey = getOrCreateLicense(product, userId, username, resourceId, resourceTitle);
  const ts = nowTs();
  const token = crypto.randomBytes(8).toString("hex");
  const generatedName = `${product}-${ts}-${token}.jar`;
  const outputPath = path.join(TEST_OUTPUT_DIR, generatedName);

  const replacements = {
    "%%__BUILTBYBIT__%%": "true",
    "%%__USER__%%": userId,
    "%%__USERNAME__%%": username,
    "%%__RESOURCE__%%": resourceId,
    "%%__RESOURCE_TITLE__%%": resourceTitle,
    "%%__VERSION__%%": "0",
    "%%__VERSION_NUMBER__%%": versionNumber,
    "%%__TIMESTAMP__%%": String(ts),
    "%%__NONCE__%%": generateNonce(),
    "%%__COLISEUM_LICENSE__%%": licenseKey,
    "%%__COLISEUM_NONCE_A__%%": generateNonce(),
    "%%__COLISEUM_NONCE_B__%%": generateNonce()
  };

  const injection = injectPlaceholdersToJar(baseJarPath, outputPath, replacements);
  qInsertTestBuild.run(token, product, userId, username, licenseKey, path.basename(baseJarPath), generatedName, ts);

  res.json({
    ok: true,
    token,
    product,
    license_key: licenseKey,
    generated_file: generatedName,
    download_url: `/console/api/test/download/${token}`,
    replaced_tokens: injection.replacedTokens,
    touched_entries: injection.touchedEntries
  });
});

app.get("/console/api/test/download/:token", authPanel, (req, res) => {
  const token = norm(req.params.token);
  if (!token) return res.status(400).send("missing token");
  const row = qFindTestBuild.get(token);
  if (!row) return res.status(404).send("not found");
  const filePath = path.join(TEST_OUTPUT_DIR, row.generated_name);
  if (!fs.existsSync(filePath)) return res.status(404).send("file missing");

  qTouchTestDownload.run(token);
  res.download(filePath, row.generated_name);
});

app.get("/", (_req, res) => res.redirect("/console"));

app.listen(PORT, HOST, () => {
  console.log(`[license-server] listening on http://${HOST}:${PORT}`);
  console.log(`[license-server] db=${DB_PATH}`);
  console.log(`[license-server] default_product=${DEFAULT_PRODUCT_ID}`);
  console.log(`[license-server] mapped_resources=${Object.keys(BBB_RESOURCE_PRODUCT_MAP).length}`);
});
