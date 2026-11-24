/*
 * SII codec: decodes SCS Software "ScsC" containers (ETS2 / ATS profile and save files).
 * Format documented by the SII_Decrypt community project. Layout:
 *   0-3 "ScsC" | 4-35 HMAC (unused) | 36-51 AES IV | 52-55 decoded size (uint32 LE) | 56- AES-256-CBC(zlib(SiiNunit|BSII))
 * Runs fully client-side via Web Crypto + DecompressionStream.
 */
(function (root) {
  "use strict";
  var KEY = new Uint8Array([0x2a,0x5f,0xcb,0x17,0x91,0xd2,0x2f,0xb6,0x02,0x45,0xb3,0xd8,0x36,0x9e,0xd0,0xb2,
    0xc2,0x73,0x71,0x56,0x3f,0xbf,0x1f,0x3c,0x9e,0xdf,0x6b,0x11,0x82,0x5a,0x5d,0x0a]);
  var SIG = { PLAIN: 0x4e696953, ENCRYPTED: 0x43736353, BINARY: 0x49495342, NK3: 0x014b6e33 };
  var MAX_BYTES = 200 * 1024 * 1024;

  function u32(b, o) { return ((b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0); }
  function detect(bytes) {
    if (bytes.length < 4) return "unknown";
    var s = u32(bytes, 0);
    return s === SIG.ENCRYPTED ? "encrypted" : s === SIG.PLAIN ? "plain" : s === SIG.BINARY ? "binary" : s === SIG.NK3 ? "nk3" : "unknown";
  }

  /* Web Crypto always enforces PKCS#7, but SCS data isn't padded that way. Appending one block that
     decrypts to valid padding lets the browser return the full plaintext untouched. */
  async function aesDecryptRaw(iv, cipher) {
    var key = await crypto.subtle.importKey("raw", KEY, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
    var pad = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv: cipher.slice(-16) }, key, new Uint8Array(0)));
    var joined = new Uint8Array(cipher.length + 16); joined.set(cipher); joined.set(pad.slice(0, 16), cipher.length);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: iv }, key, joined));
  }

/* Inflate one zlib stream exactly as given; throws on any error. */
async function inflateExact(bytes) {
  if (typeof DecompressionStream === "undefined") throw new Error("This browser can't decompress the payload (DecompressionStream missing). Try a current Chrome, Edge, Firefox or Safari.");
  var reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate")).getReader();
  var chunks = [], total = 0;
  for (;;) { var r = await reader.read(); if (r.done) break; chunks.push(r.value); total += r.value.length; }
  var out = new Uint8Array(total), o = 0;
  chunks.forEach(function (c) { out.set(c, o); o += c.length; });
  return out;
}

/* The AES payload is padded to a 16-byte boundary, so up to 15 junk bytes follow the zlib stream.
   Trim them before inflating: try the trailing-zero count first, then every other trim length. */
async function inflate(bytes, expected) {
  var z = 0;
  while (z < 15 && bytes[bytes.length - 1 - z] === 0) z++;
  var order = [], t;
  for (t = z; t >= 0; t--) order.push(t);
  for (t = z + 1; t <= 15; t++) order.push(t);
  var lastErr = null;
  for (var i = 0; i < order.length; i++) {
    try {
      var out = await inflateExact(bytes.subarray(0, bytes.length - order[i]));
      if (!expected || out.length === expected) return out;
      lastErr = new Error("decoded size didn't match the header");
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error("could not inflate");
}

  async function decryptScsC(bytes) {
    if (bytes.length < 72 || (bytes.length - 56) % 16 !== 0) throw new Error("The file is truncated or isn't a valid encrypted .sii container.");
    var plain;
    try { plain = await aesDecryptRaw(bytes.slice(36, 52), bytes.slice(56)); }
    catch (e) { throw new Error("AES decryption failed. The file may be corrupted."); }
    var inner;
    try { inner = await inflate(plain, u32(bytes, 52)); }
    catch (e) { throw new Error("Decompression failed after decryption (" + e.message + ")."); }
    return inner;
  }

  var api = { detect: detect, decryptScsC: decryptScsC, MAX_BYTES: MAX_BYTES };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.SiiCodec = api;
})(typeof self !== "undefined" ? self : this);
