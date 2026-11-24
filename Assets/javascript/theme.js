/* Theme switcher: system (default) / light / dark. Loaded in <head> to avoid a flash. */
(function () {
  var KEY = "theme", root = document.documentElement;
  function read() { try { return localStorage.getItem(KEY) || "system"; } catch (e) { return "system"; } }
  function apply(v) { if (v === "light" || v === "dark") root.setAttribute("data-theme", v); else root.removeAttribute("data-theme"); }
  apply(read());
  document.addEventListener("DOMContentLoaded", function () {
    var sel = document.getElementById("theme-select");
    if (!sel) return;
    sel.value = read();
    sel.addEventListener("change", function () {
      apply(sel.value);
      try { localStorage.setItem(KEY, sel.value); } catch (e) { /* storage unavailable: theme still applies this visit */ }
    });
  });
})();
