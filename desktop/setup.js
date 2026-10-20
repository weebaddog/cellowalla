const params = new URLSearchParams(location.search);
const input = document.getElementById("address");
document.getElementById("error").textContent = params.get("error") || "";
input.value = (params.get("box") || "").replace(/^https:\/\//, "");
document.getElementById("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await window.cellowallaDesktop.connect(input.value.trim());
  if (r.error) document.getElementById("error").textContent = r.error;
});
for (const b of document.querySelectorAll(".chip")) b.addEventListener("click", () => { input.value = b.dataset.a; input.focus(); });
