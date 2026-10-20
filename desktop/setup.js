const params = new URLSearchParams(location.search);
const input = document.getElementById("address");
document.getElementById("error").textContent = params.get("error") || "";
input.value = (params.get("box") || "").replace(/^https:\/\//, "");
document.getElementById("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await window.cellowallaDesktop.connect(input.value.trim());
  if (r.error) document.getElementById("error").textContent = r.error;
});
const themeChips = document.querySelectorAll(".chip[data-theme]");
const markTheme = (mode) => themeChips.forEach((c) => { c.classList.toggle("on", c.dataset.theme === mode); c.setAttribute("aria-checked", String(c.dataset.theme === mode)); });
window.cellowallaDesktop.theme().then(markTheme);
themeChips.forEach((c) => c.addEventListener("click", () => { window.cellowallaDesktop.themeChanged(c.dataset.theme); markTheme(c.dataset.theme); }));
for (const b of document.querySelectorAll(".chip[data-a]")) b.addEventListener("click", () => { input.value = b.dataset.a; input.focus(); });
