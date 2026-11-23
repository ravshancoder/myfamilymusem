/*
 * MuzeyCore: shifrlash, ZIP va mavzular uchun umumiy kod.
 * Bu fayl ham muzey sahifasida (docs/index.html), ham rasm tayyorlash
 * sahifasida (tayyorlash/index.html) ishlatiladi, shuning uchun
 * shifrlash va ochish har doim bir-biriga mos keladi.
 *
 * Shifr: AES-256-GCM. Kalit paroldan PBKDF2-SHA256 (300 000 aylanish) bilan olinadi.
 */
(function (root) {
  "use strict";

  var enc = new TextEncoder();
  var dec = new TextDecoder();
  var ITER = 300000;

  function subtle() {
    var c = root.crypto;
    if (!c || !c.subtle) {
      throw new Error("Brauzer shifrlashni qo'llamaydi (https yoki yangiroq brauzer kerak)");
    }
    return c.subtle;
  }

  function randomBytes(n) {
    var a = new Uint8Array(n);
    root.crypto.getRandomValues(a);
    return a;
  }

  function toB64u(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromB64u(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    var s = atob(str);
    var a = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
    return a;
  }

  function randomId(nBytes) {
    var b = randomBytes(nBytes || 9);
    var h = "";
    for (var i = 0; i < b.length; i++) h += ("0" + b[i].toString(16)).slice(-2);
    return h;
  }

  /** 128 bit tasodifiy parol (22 belgi). */
  function generatePassword() {
    return toB64u(randomBytes(16));
  }

  async function deriveKey(password, salt, iterations) {
    var base = await subtle().importKey("raw", enc.encode(String(password).trim()), "PBKDF2", false, ["deriveKey"]);
    return subtle().deriveKey(
      { name: "PBKDF2", salt: salt, iterations: iterations || ITER, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /** Natija: 12 bayt IV + shifrlangan ma'lumot (+16 bayt GCM tegi). */
  async function encryptBytes(key, data) {
    var iv = randomBytes(12);
    var ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: iv }, key, data));
    var out = new Uint8Array(12 + ct.length);
    out.set(iv, 0);
    out.set(ct, 12);
    return out;
  }

  /** Noto'g'ri parol yoki buzilgan fayl bo'lsa xato tashlaydi. */
  async function decryptBytes(key, data) {
    var u8 = data instanceof Uint8Array ? data : new Uint8Array(data);
    var plain = await subtle().decrypt({ name: "AES-GCM", iv: u8.subarray(0, 12) }, key, u8.subarray(12));
    return new Uint8Array(plain);
  }

  async function encryptJSON(key, obj) {
    return encryptBytes(key, enc.encode(JSON.stringify(obj)));
  }

  async function decryptJSON(key, data) {
    return JSON.parse(dec.decode(await decryptBytes(key, data)));
  }

  /* ---------- ZIP (siqmasdan, "store" usuli) ---------- */

  var crcTable = null;
  function crc32(u8) {
    if (!crcTable) {
      crcTable = new Uint32Array(256);
      for (var n = 0; n < 256; n++) {
        var c = n;
        for (var k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        crcTable[n] = c >>> 0;
      }
    }
    var crc = 0xffffffff;
    for (var i = 0; i < u8.length; i++) crc = crcTable[(crc ^ u8[i]) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }

  /** files: [{name: "data/a.bin", data: Uint8Array}] -> Uint8Array (zip fayl) */
  function makeZip(files) {
    var d = new Date();
    var dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    var dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    var chunks = [];
    var central = [];
    var offset = 0;

    files.forEach(function (f) {
      var name = enc.encode(f.name);
      var crc = crc32(f.data);
      var size = f.data.length;

      var lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true);
      lh.setUint16(4, 20, true);
      lh.setUint16(6, 0x0800, true);
      lh.setUint16(8, 0, true);
      lh.setUint16(10, dosTime, true);
      lh.setUint16(12, dosDate, true);
      lh.setUint32(14, crc, true);
      lh.setUint32(18, size, true);
      lh.setUint32(22, size, true);
      lh.setUint16(26, name.length, true);
      lh.setUint16(28, 0, true);
      chunks.push(new Uint8Array(lh.buffer), name, f.data);

      var ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true);
      ch.setUint16(4, 20, true);
      ch.setUint16(6, 20, true);
      ch.setUint16(8, 0x0800, true);
      ch.setUint16(10, 0, true);
      ch.setUint16(12, dosTime, true);
      ch.setUint16(14, dosDate, true);
      ch.setUint32(16, crc, true);
      ch.setUint32(20, size, true);
      ch.setUint32(24, size, true);
      ch.setUint16(28, name.length, true);
      ch.setUint16(30, 0, true);
      ch.setUint16(32, 0, true);
      ch.setUint16(34, 0, true);
      ch.setUint16(36, 0, true);
      ch.setUint32(38, 0, true);
      ch.setUint32(42, offset, true);
      central.push(new Uint8Array(ch.buffer), name);

      offset += 30 + name.length + size;
    });

    var centralSize = 0;
    central.forEach(function (c) { centralSize += c.length; });

    var end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, files.length, true);
    end.setUint16(10, files.length, true);
    end.setUint32(12, centralSize, true);
    end.setUint32(16, offset, true);

    var all = chunks.concat(central, [new Uint8Array(end.buffer)]);
    var total = 0;
    all.forEach(function (c) { total += c.length; });
    var out = new Uint8Array(total);
    var p = 0;
    all.forEach(function (c) { out.set(c, p); p += c.length; });
    return out;
  }

  /* ---------- Xona mavzulari (ranglar) ---------- */

  var THEMES = [
    { name: "Pushti",   wall: "#f4d5dc", floor: "#c9985f", accent: "#d9607f" },
    { name: "Yashil",   wall: "#d3e5d5", floor: "#d3ad78", accent: "#4f9a6b" },
    { name: "Moviy",    wall: "#d2e1f2", floor: "#c4a073", accent: "#4a82c4" },
    { name: "Sariq",    wall: "#f6e8bf", floor: "#b98a58", accent: "#d9a431" },
    { name: "Binafsha", wall: "#e0d6f0", floor: "#c7a67a", accent: "#8a62c4" },
    { name: "Shaftoli", wall: "#f8dccb", floor: "#bb8b5e", accent: "#e0804f" },
    { name: "Feruza",   wall: "#cfeaea", floor: "#cdb084", accent: "#2f9aa0" },
    { name: "Krem",     wall: "#f1ead9", floor: "#a87a4f", accent: "#b5835a" }
  ];

  root.MuzeyCore = {
    ITER: ITER,
    THEMES: THEMES,
    randomBytes: randomBytes,
    randomId: randomId,
    toB64u: toB64u,
    fromB64u: fromB64u,
    generatePassword: generatePassword,
    deriveKey: deriveKey,
    encryptBytes: encryptBytes,
    decryptBytes: decryptBytes,
    encryptJSON: encryptJSON,
    decryptJSON: decryptJSON,
    crc32: crc32,
    makeZip: makeZip
  };
})(typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : this);
