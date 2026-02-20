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

(async () => {
  await fetchOverview();
  await fetchRows();
})();
