(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var codec = window.SiiCodec, dz = $("dropzone"), input = $("file-input"), download = null, counter = 0;
  var LABELS = { encrypted: "ScsC (encrypted)", plain: "SiiNunit (plain text)", binary: "BSII (binary)", nk3: "3nK (encoded)", unknown: "Unknown" };

  function step(name, state) {
    var li = document.querySelector('[data-step="' + name + '"]'); if (!li) return;
    li.className = state || "";
  }
  function status(kind, msg) { var s = $("status"); s.hidden = false; s.className = "status " + kind; s.textContent = msg; }
  function bytesLabel(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(2) + " MB"; }

  function reset(file) {
    counter++; $("ticket-id").textContent = "#SII-" + String(counter).padStart(3, "0");
    $("file-name").textContent = file.name; $("file-size").textContent = bytesLabel(file.size); $("file-format").textContent = "…";
    $("file-info").hidden = false; $("status").hidden = true; $("result").hidden = true; download = null;
    ["read", "decrypt", "inflate", "done"].forEach(function (n) { step(n, ""); });
  }

  function show(bytes, name, isText, note) {
    var text = isText ? new TextDecoder("utf-8").decode(bytes) : "(binary content, " + bytes.length.toLocaleString() + " bytes, not shown as text)";
    $("preview").textContent = text.length > 200000 ? text.slice(0, 200000) + "\n\n… (preview truncated; the download has the full content)" : text;
    var base = name.replace(/\.(sii|bsii|bin|txt)$/i, "");
    download = { blob: new Blob([bytes], { type: isText ? "text/plain" : "application/octet-stream" }), name: base + (isText ? ".sii" : ".decoded.bin") };
    $("result").hidden = false; step("done", "done");
    status(note ? "warn" : "ok", note || "Decoded " + bytes.length.toLocaleString() + " bytes of plain text.");
  }

  async function handle(file) {
    reset(file);
    if (file.size > codec.MAX_BYTES) { step("read", "error-step"); return status("err", "That file is over 200 MB, which is far larger than any save file. Check that you picked the right one."); }
    if (!window.crypto || !crypto.subtle) { step("read", "error-step"); return status("err", "Your browser doesn't provide Web Crypto, which is needed to decrypt files. Use HTTPS or a current browser."); }
    var bytes;
    step("read", "active");
    try { bytes = new Uint8Array(await file.arrayBuffer()); } catch (e) { step("read", "error-step"); return status("err", "Couldn't read the file: " + e.message); }
    var kind = codec.detect(bytes); $("file-format").textContent = LABELS[kind]; step("read", "done");
    try {
      if (kind === "encrypted") {
        step("decrypt", "active"); var out;
        try { out = await codec.decryptScsC(bytes); } catch (e) { step("decrypt", "error-step"); throw e; }
        step("decrypt", "done"); step("inflate", "done");
        var inner = codec.detect(out);
        if (inner === "plain") show(out, file.name, true);
        else show(out, file.name, false, inner === "binary"
          ? "Decrypted successfully, but the content is SCS's binary BSII format. Converting it to text isn't supported here, so the raw decrypted bytes are offered instead."
          : "Decrypted, but the content isn't recognised as SiiNunit or BSII. Here are the raw decoded bytes.");
      } else {
        step("decrypt", "skip"); step("inflate", "skip");
        if (kind === "plain") { show(bytes, file.name, true); status("ok", "This file is already plain SiiNunit text, so nothing needed decrypting."); }
        else if (kind === "binary") show(bytes, file.name, false, "This is an unencrypted binary BSII file. There's nothing to decrypt, and converting it to text isn't supported here. Raw bytes are offered instead.");
        else if (kind === "nk3") { step("done", "error-step"); status("warn", "This is a 3nK-encoded file (used for localization). It's a different encoding from encrypted saves, and this tool doesn't decode it."); }
        else { step("read", "error-step"); status("err", "Unrecognised file. This doesn't look like an SCS .sii file."); }
      }
    } catch (e) { status("err", e.message); }
  }

  dz.addEventListener("click", function () { input.click(); });
  dz.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  ["dragenter", "dragover"].forEach(function (t) { dz.addEventListener(t, function (e) { e.preventDefault(); dz.classList.add("drag"); }); });
  ["dragleave", "dragend", "drop"].forEach(function (t) { dz.addEventListener(t, function (e) { e.preventDefault(); dz.classList.remove("drag"); }); });
  dz.addEventListener("drop", function (e) { var f = e.dataTransfer.files[0]; if (f) handle(f); });
  input.addEventListener("change", function () { if (input.files[0]) handle(input.files[0]); input.value = ""; });
  $("download-btn").addEventListener("click", function () {
    if (!download) return;
    var url = URL.createObjectURL(download.blob), a = document.createElement("a");
    a.href = url; a.download = download.name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  });
})();
