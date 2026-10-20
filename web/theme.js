// Light / Dark / Auto, applied before the page draws (so it never flashes the wrong colors).
// Saved on this device. The Android and desktop apps are told when it changes, and can set it.
(function () {
  var saved = null;
  try { saved = localStorage.getItem("cw.theme"); } catch (e) { /* private window */ }

  function apply(mode) {
    if (mode === "light" || mode === "dark") document.documentElement.setAttribute("data-theme", mode);
    else document.documentElement.removeAttribute("data-theme");
  }

  window.cwTheme = function () { try { return localStorage.getItem("cw.theme") || "auto"; } catch (e) { return "auto"; } };

  /** Sets the theme. `fromApp`: the app itself asked, so don't tell it back. */
  window.cwSetTheme = function (mode, fromApp) {
    if (mode !== "light" && mode !== "dark") mode = "auto";
    try { localStorage.setItem("cw.theme", mode); } catch (e) { /* not saved */ }
    apply(mode);
    document.dispatchEvent(new CustomEvent("cw-theme", { detail: mode }));
    if (!fromApp) {
      try { if (window.CellowallaApp && window.CellowallaApp.themeChanged) window.CellowallaApp.themeChanged(mode); } catch (e) { /* old app */ }
      try { if (window.cellowallaDesktop && window.cellowallaDesktop.themeChanged) window.cellowallaDesktop.themeChanged(mode); } catch (e) { /* old app */ }
    }
  };

  apply(saved || "auto");
})();
