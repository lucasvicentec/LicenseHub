function fmtTs(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

async function fetchOverview() {
  const product = document.getElementById("product").value.trim();
  const url = product ? `/console/api/overview?product=${encodeURIComponent(product)}` : "/console/api/overview";
  const r = await fetch(url);
  const d = await r.json();
  document.getElementById("activeCount").textContent = d.active ?? 0;
  document.getElementById("revokedCount").textContent = d.revoked ?? 0;
  document.getElementById("suspendedCount").textContent = d.suspended ?? 0;
}

function rowTemplate(row) {
  const action = row.status === "active"
    ? `<button data-k="${row.license_key}" data-a="revoke">Revoke</button>`
    : `<button data-k="${row.license_key}" data-a="activate">Activate</button>`;
  return `<tr>
    <td>${row.status}</td>
    <td class="mono">${row.product || ""}</td>
    <td class="mono">${row.license_key}</td>
    <td class="mono">${row.user_id || ""}</td>
    <td>${row.username || ""}</td>
    <td class="mono">${row.resource_id || ""}</td>
    <td>${row.issue_count || 0}</td>
    <td class="mono">${row.bound_ip || "-"}</td>
    <td>${row.validation_count || 0}</td>
    <td>${fmtTs(row.updated_at)}</td>
    <td>${action}</td>
  </tr>`;
}

async function fetchRows() {
  const q = document.getElementById("search").value.trim();
  const product = document.getElementById("product").value.trim();
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (product) params.set("product", product);
  const url = params.toString() ? `/console/api/licenses?${params.toString()}` : "/console/api/licenses";
  const r = await fetch(url);
  const rows = await r.json();
  const tbody = document.getElementById("rows");
  tbody.innerHTML = rows.map(rowTemplate).join("");
}

async function postAction(action, key) {
  const url = action === "revoke" ? "/console/api/revoke" : "/console/api/activate";
  await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ license_key: key })
  });
}

async function loadBaseJars() {
  const r = await fetch("/console/api/test/base");
  const data = await r.json();
  const list = (data.files || []).length ? data.files.join(", ") : "none";
  document.getElementById("baseList").textContent = `Base JARs: ${list}`;
}

async function uploadBaseJar() {
  const product = document.getElementById("testProduct").value.trim();
  const fileInput = document.getElementById("testJar");
  const file = fileInput.files[0];
  if (!product || !file) {
    document.getElementById("testResult").textContent = "Set product and choose a .jar file.";
    return;
  }

  const fd = new FormData();
  fd.append("product", product);
  fd.append("jar", file);

  const r = await fetch("/console/api/test/base", {
    method: "POST",
    body: fd
  });
  const data = await r.json();
  if (!r.ok || !data.ok) {
    document.getElementById("testResult").textContent = `Upload failed: ${data.error || r.status}`;
    return;
  }
  document.getElementById("testResult").textContent = `Base JAR uploaded for product '${data.product}': ${data.file}`;
  await loadBaseJars();
}

async function generateInjectedJar() {
  const payload = {
    product: document.getElementById("testProduct").value.trim() || "coliseum",
    user_id: document.getElementById("testUserId").value.trim() || `test-user-${Date.now()}`,
    username: document.getElementById("testUsername").value.trim() || "testbuyer",
    resource_id: document.getElementById("testResourceId").value.trim() || "123456",
    version_number: document.getElementById("testVersion").value.trim() || "v-test"
  };

  const r = await fetch("/console/api/test/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await r.json();
  if (!r.ok || !data.ok) {
    document.getElementById("testResult").textContent = `Generate failed: ${data.error || r.status}`;
    return;
  }

  document.getElementById("testResult").innerHTML = `Generated: <a href="${data.download_url}">${data.generated_file}</a> | Key: <span class="mono">${data.license_key}</span> | Replaced tokens: ${data.replaced_tokens}`;
  await fetchOverview();
  await fetchRows();
}

document.getElementById("refreshBtn").addEventListener("click", async () => {
  await fetchOverview();
  await fetchRows();
});

document.getElementById("search").addEventListener("input", async () => {
  await fetchRows();
});

document.getElementById("product").addEventListener("input", async () => {
  await fetchOverview();
  await fetchRows();
});

document.getElementById("rows").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-a]");
  if (!btn) return;
  await postAction(btn.dataset.a, btn.dataset.k);
  await fetchOverview();
  await fetchRows();
});

document.getElementById("uploadBaseBtn").addEventListener("click", uploadBaseJar);
document.getElementById("reloadBaseBtn").addEventListener("click", loadBaseJars);
document.getElementById("generateTestBtn").addEventListener("click", generateInjectedJar);

(async () => {
  await fetchOverview();
  await fetchRows();
  await loadBaseJars();
})();
