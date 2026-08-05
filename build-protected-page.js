#!/usr/bin/env node
"use strict";

/*
 * Build a password-gated static page.
 *
 * The source HTML is encrypted with AES-256-GCM using a key derived from the
 * password via PBKDF2 (SHA-256). The plaintext never ships to the browser;
 * the generated page only decrypts the content client-side after the correct
 * password is entered. This matches the Web Crypto API so decryption happens
 * natively in the browser with no external libraries.
 *
 * Usage: node build-protected-page.js <sourceHtml> <outHtml> <password>
 *
 * Note: the password is passed as a CLI argument only at build time and is not
 * embedded in the output. It is never logged.
 */

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const ITERATIONS = 200000;
const KEY_LEN = 32; // AES-256
const SALT_LEN = 16;
const IV_LEN = 12; // GCM standard

function main() {
  const [, , sourcePath, outPath, password] = process.argv;

  // Validate inputs (rule: sanitize/validate external input before file use).
  if (!sourcePath || !outPath || !password) {
    console.error(
      "Usage: node build-protected-page.js <sourceHtml> <outHtml> <password>"
    );
    process.exit(1);
  }

  const resolvedSource = path.resolve(sourcePath);
  const resolvedOut = path.resolve(outPath);

  const plaintext = fs.readFileSync(resolvedSource, "utf8");

  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, "sha256");

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Web Crypto expects ciphertext || authTag concatenated.
  const payload = Buffer.concat([encrypted, authTag]);

  const bundle = {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    iterations: ITERATIONS,
    data: payload.toString("base64"),
  };

  const outHtml = renderGate(bundle);
  fs.writeFileSync(resolvedOut, outHtml, "utf8");
  console.log(`Wrote ${resolvedOut} (${payload.length} encrypted bytes).`);
}

function renderGate(bundle) {
  const json = JSON.stringify(bundle);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Protected</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500&family=Inter:wght@400;450;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --paper:#F4F5F1;--surface:#FCFCFA;--ink:#1B211C;--green-deep:#23543E;
    --green:#37795A;--rust:#AD4A2F;--muted:#77807A;--hair:#E1E2DB;--hair-strong:#CFD1C8;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);
    font-family:'Inter',system-ui,sans-serif;line-height:1.5;
    min-height:100vh;display:flex;flex-direction:column}
  .nav{border-bottom:1px solid var(--hair);background:var(--paper);
    position:sticky;top:0;z-index:20;flex:none}
  .nav-inner{max-width:1040px;margin:0 auto;padding:0 clamp(16px,4vw,40px);
    display:flex;align-items:center;gap:20px;height:56px}
  .nav-brand{font-family:'Fraunces',serif;font-weight:500;font-size:16px;
    letter-spacing:-.01em;color:var(--ink);white-space:nowrap}
  .nav-tabs{display:flex;gap:2px;align-items:stretch;height:100%}
  .nav-tabs a{display:inline-flex;align-items:center;padding:0 14px;font-size:13.5px;
    font-weight:500;color:var(--muted);text-decoration:none;
    border-bottom:2px solid transparent;transition:color .15s}
  .nav-tabs a:hover{color:var(--ink)}
  .nav-tabs a.active{color:var(--green-deep);border-bottom-color:var(--green-deep);font-weight:600}
  @media(max-width:560px){.nav-brand{display:none}.nav-inner{gap:0;justify-content:center}
    .nav-tabs a{padding:0 11px;font-size:12.5px}}
  .stage{flex:1;min-height:0;display:flex;align-items:center;justify-content:center;padding:24px}
  .stage.unlocked{padding:0;align-items:stretch}
  iframe{width:100%;height:100%;border:0;background:var(--paper);display:block}
  .gate{background:var(--surface);border:1px solid var(--hair);border-radius:16px;
    padding:36px 32px;max-width:400px;width:100%;
    box-shadow:0 1px 2px rgba(27,33,28,.04),0 12px 32px rgba(27,33,28,.06)}
  .eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;
    color:var(--muted);font-weight:600;margin:0 0 12px}
  h1{font-family:'Fraunces',serif;font-weight:500;font-size:28px;
    letter-spacing:-.02em;margin:0 0 8px}
  p.sub{color:#3c433d;font-size:14px;margin:0 0 22px}
  label{display:block;font-size:13px;font-weight:600;margin:0 0 8px;color:var(--ink)}
  .row{display:flex;gap:8px}
  input[type=password]{flex:1;padding:12px 14px;font-size:15px;
    border:1px solid var(--hair-strong);border-radius:10px;background:#fff;
    color:var(--ink);font-family:inherit;outline:none}
  input[type=password]:focus{border-color:var(--green);box-shadow:0 0 0 3px rgba(55,121,90,.15)}
  button{padding:12px 18px;font-size:15px;font-weight:600;font-family:inherit;
    border:none;border-radius:10px;background:var(--green-deep);color:#fff;cursor:pointer}
  button:hover{background:var(--green)}
  button:disabled{opacity:.6;cursor:default}
  .err{color:var(--rust);font-size:13px;font-weight:500;margin:14px 0 0;min-height:18px}
</style>
</head>
<body>
  <nav class="nav">
    <div class="nav-inner">
      <span class="nav-brand">Condo planner</span>
      <div class="nav-tabs">
        <a href="./index.html">What we each put in</a>
        <a href="./gap-planner.html" class="active">How much more do I need?</a>
      </div>
    </div>
  </nav>
  <div class="stage" id="stage">
    <main class="gate" id="gate">
      <p class="eyebrow">Protected</p>
      <h1>Enter password</h1>
      <p class="sub">This page is password protected. Please enter the password to continue.</p>
      <form id="form" autocomplete="off">
        <label for="pw">Password</label>
        <div class="row">
          <input type="password" id="pw" name="pw" autocomplete="current-password" autofocus>
          <button type="submit" id="go">Unlock</button>
        </div>
        <p class="err" id="err" role="alert"></p>
      </form>
    </main>
  </div>

<script>
(function(){
  "use strict";
  var BUNDLE = ${json};

  function b64ToBytes(b64){
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function decrypt(password){
    var enc = new TextEncoder();
    var salt = b64ToBytes(BUNDLE.salt);
    var iv = b64ToBytes(BUNDLE.iv);
    var data = b64ToBytes(BUNDLE.data);

    var baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    var key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: BUNDLE.iterations, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    var plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv }, key, data
    );
    return new TextDecoder().decode(plainBuf);
  }

  var form = document.getElementById("form");
  var pw = document.getElementById("pw");
  var err = document.getElementById("err");
  var go = document.getElementById("go");

  form.addEventListener("submit", async function(e){
    e.preventDefault();
    err.textContent = "";
    go.disabled = true;
    try {
      var html = await decrypt(pw.value);
      // Correct password: render the decrypted page in the stage, keep the nav.
      var stage = document.getElementById("stage");
      stage.classList.add("unlocked");
      stage.innerHTML = "";
      var frame = document.createElement("iframe");
      frame.setAttribute("title", "content");
      stage.appendChild(frame);
      frame.srcdoc = html;
    } catch (ex) {
      // Wrong password fails GCM auth; no plaintext is ever exposed.
      err.textContent = "Incorrect password. Please try again.";
      go.disabled = false;
      pw.select();
    }
  });
})();
</script>
</body>
</html>
`;
}

main();
