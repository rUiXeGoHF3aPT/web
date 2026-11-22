(() => {
  const endpoint = window.SITE_CONFIG.workerUrl.replace(/\/$/, "");
  if (!endpoint) return;
  // Queries and fragments are deliberately excluded from the log.
  fetch(`${endpoint}/api/visit`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path: location.pathname }), keepalive: true,
  }).catch(() => {});
})();
