(() => {
  const endpoint = window.SITE_CONFIG.workerUrl.replace(/\/$/, "");
  const login = document.querySelector("#login"), logs = document.querySelector("#logs");
  const form = document.querySelector("#login-form"), tokenInput = document.querySelector("#token");
  const message = document.querySelector("#message"), rows = document.querySelector("#rows");
  const more = document.querySelector("#more"), empty = document.querySelector("#empty");
  let token = "", cursor = null, busy = false, generation = 0;
  async function load(append = false) {
    if (busy) return;
    if (!endpoint) { message.textContent = "Set the Worker URL in config.js first."; return; }
    busy = true; const current = generation; message.textContent = "Loading visits…";
    try {
      const query = append && cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
      const res = await fetch(`${endpoint}/api/visits${query}`, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
      if (!res.ok) throw new Error(res.status === 401 ? "Invalid admin token." : `Could not load visits (${res.status}).`);
      const data = await res.json();
      if (current !== generation) return;
      if (!append) rows.replaceChildren();
      for (const entry of data.visits) {
        const tr = document.createElement("tr");
        for (const value of [entry.time, entry.ip, entry.path]) { const cell = document.createElement("td"); cell.textContent = value; tr.appendChild(cell); }
        rows.appendChild(tr);
      }
      cursor = data.cursor; more.hidden = !cursor; empty.hidden = rows.children.length > 0;
      login.hidden = true; logs.hidden = false; tokenInput.value = ""; message.textContent = "";
    } catch (error) { if (current === generation) message.textContent = error.message || "Could not connect to the Worker."; }
    finally { busy = false; }
  }
  form.addEventListener("submit", event => { event.preventDefault(); token = tokenInput.value.trim(); load(); });
  document.querySelector("#refresh").addEventListener("click", () => load());
  more.addEventListener("click", () => load(true));
  document.querySelector("#logout").addEventListener("click", () => { generation++; token = ""; cursor = null; rows.replaceChildren(); logs.hidden = true; login.hidden = false; message.textContent = "Signed out."; });
})();
