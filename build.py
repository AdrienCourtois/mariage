"""
Construit la version publique (chiffrée) du site.

    python build.py

- Lit les pages en clair dans src/
- Les chiffre avec le mot de passe de motdepasse.txt (AES-256-GCM, clé dérivée par PBKDF2)
- Écrit le résultat dans docs/ (c'est ce dossier que GitHub Pages publie)
- Génère le QR code dans qr/ (lien avec le mot de passe intégré : à NE PAS publier)

src/, motdepasse.txt et qr/ ne partent jamais sur GitHub (voir .gitignore).
"""

import base64
import json
import os
import re
import secrets
import shutil
import sys
import unicodedata
from hashlib import pbkdf2_hmac
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import segno

# ── Réglages ────────────────────────────────────────────────
# Adresse du site une fois en ligne (sert au QR code).
SITE_URL = "https://adriencourtois.github.io/mariage/"
PAGES = ["index.html", "rsvp.html"]
THEME = "jour"  # src/themes/<THEME>.css, ajouté à src/themes/base.css
ITERATIONS = 250_000
# ────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
OUT = ROOT / "docs"
QR_DIR = ROOT / "qr"


def normalize(pwd: str) -> str:
    # Majuscules, espaces autour et accents composés différemment : tout est accepté.
    return unicodedata.normalize("NFC", pwd.strip().lower())


def stylesheet() -> str:
    themes = SRC / "themes"
    return (themes / "base.css").read_text(encoding="utf-8") + "\n" + (themes / f"{THEME}.css").read_text(encoding="utf-8")


def inline_assets(html: str) -> str:
    def css(_m):
        return "<style>\n" + stylesheet() + "\n</style>"

    def js(m):
        return "<script>\n" + (SRC / m.group(1)).read_text(encoding="utf-8") + "\n</script>"

    html = re.sub(r'<link rel="stylesheet" href="style\.css">', css, html)
    html = re.sub(r'<script src="([\w.-]+\.js)"></script>', js, html)
    return html


GATE = r"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Louise &amp; Adrien</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;500&family=EB+Garamond:ital,wght@0,400;0,500;1,400&display=swap">
<style>
:root{--text:#1e2450;--muted:#4a5079;--gold:#c4a052;--gold-text:#86621d;--line:rgba(196,160,82,.55);
--display:"Cinzel","Trajan Pro","Times New Roman",serif;--body:"EB Garamond",Garamond,Georgia,serif;color-scheme:light}
*{box-sizing:border-box}
html,body{min-height:100%}
body{margin:0;background:#e3e7f2;color:var(--text);font-family:var(--body);font-size:1.1875rem;line-height:1.6;
display:grid;place-items:center;min-height:100vh;padding:24px max(16px,env(safe-area-inset-left,0px)) 24px max(16px,env(safe-area-inset-right,0px))}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:#e3e7f2 url("assets/ciel-jour.jpg") center/cover no-repeat}
.card{width:100%;max-width:28rem;text-align:center;display:grid;gap:1rem;justify-items:center;padding:3rem 1.8rem;
border:1.5px solid var(--gold);border-radius:26px;
background:url("assets/coin-hg.png") left 10px top 10px/64px no-repeat,url("assets/coin-hd.png") right 10px top 10px/64px no-repeat,
url("assets/coin-bg.png") left 10px bottom 10px/64px no-repeat,url("assets/coin-bd.png") right 10px bottom 10px/64px no-repeat,rgba(255,255,255,.4)}
.embleme{width:5.5rem;height:auto;display:block}
h1{font-family:var(--display);font-weight:400;font-size:clamp(2.4rem,10vw,3.4rem);line-height:1.05;margin:0;display:grid}
h1 span{font-size:.62em;color:var(--gold-text)}
.alliances{width:4.6rem;height:2.4rem;color:var(--gold)}
p{margin:0;color:var(--muted)}
#gate{display:grid;gap:1rem;width:100%}
form{width:100%;display:grid;gap:.7rem}
label{font-family:var(--display);font-size:.85rem;letter-spacing:.08em;color:var(--gold-text)}
input{font:inherit;width:100%;padding:.8rem 1rem;border:1.5px solid var(--line);border-radius:999px;background:rgba(255,255,255,.75);color:var(--text);text-align:center;letter-spacing:.05em}
input:focus{outline:2px solid var(--gold);outline-offset:2px;border-color:var(--gold)}
button{font-family:var(--display);font-size:.85rem;letter-spacing:.1em;padding:.85rem 1.6rem;border:1px solid var(--text);border-radius:999px;background:var(--text);color:#f5f1e6;cursor:pointer}
button:hover{filter:brightness(1.15)}
button:focus-visible{outline:2px solid var(--gold);outline-offset:3px}
button:disabled{opacity:.6;cursor:wait}
.err{color:#8e2f3a;min-height:1.6em;font-size:1rem}
[hidden]{display:none!important}
</style>
</head>
<body>
<main class="card">
  <img class="embleme" src="assets/embleme.png" alt="" width="530" height="515">
  <h1>Louise <span>&amp;</span> Adrien</h1>
  <svg class="alliances" viewBox="0 0 88 46" aria-hidden="true">
    <ellipse cx="33" cy="26" rx="20" ry="12.5" transform="rotate(-12 33 26)" fill="none" stroke="currentColor" stroke-width="2.4"/>
    <ellipse cx="55" cy="20" rx="20" ry="12.5" transform="rotate(-12 55 20)" fill="none" stroke="currentColor" stroke-width="2.4"/>
  </svg>
  <p id="loading">Ouverture…</p>
  <div id="gate" hidden>
    <p>Le mot de passe est sur votre faire-part. Ou flashez le QR code, c'est encore plus simple.</p>
    <form id="f" autocomplete="off">
      <label for="pwd">Mot de passe</label>
      <input id="pwd" name="pwd" type="text" autocapitalize="none" autocorrect="off" spellcheck="false" required>
      <button id="go" type="submit">Entrer</button>
      <p class="err" id="err" role="alert"></p>
    </form>
  </div>
  <noscript><p>Ce site a besoin de JavaScript pour s'ouvrir.</p></noscript>
</main>
<script>
(function () {
  var SALT = "__SALT__", ITER = __ITER__, DATA = "__DATA__", STORE = "la-mariage-cle";

  function b64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
  function norm(s) { return s.trim().toLowerCase().normalize("NFC"); }
  function hex(u) { return Array.from(u, function (b) { return b.toString(16).padStart(2, "0"); }).join(""); }
  function unhex(h) { return new Uint8Array(h.match(/../g).map(function (x) { return parseInt(x, 16); })); }

  function derive(pwd) {
    return crypto.subtle.importKey("raw", new TextEncoder().encode(norm(pwd)), "PBKDF2", false, ["deriveBits"])
      .then(function (base) {
        return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64(SALT), iterations: ITER }, base, 256);
      })
      .then(function (bits) { return new Uint8Array(bits); });
  }
  function decrypt(raw) {
    var d = b64(DATA);
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"])
      .then(function (k) { return crypto.subtle.decrypt({ name: "AES-GCM", iv: d.slice(0, 12) }, k, d.slice(12)); })
      .then(function (pt) { return new TextDecoder().decode(pt); });
  }
  function remember(raw) {
    try { localStorage.setItem(STORE, JSON.stringify({ salt: SALT, key: hex(raw) })); } catch (e) {}
  }
  // Remplace toute la page par le site déchiffré, puis relance ses scripts (dans l'ordre)
  function show(html) {
    var doc = new DOMParser().parseFromString(html, "text/html");
    document.replaceChild(document.adoptNode(doc.documentElement), document.documentElement);
    Array.prototype.forEach.call(document.querySelectorAll("script"), function (old) {
      var s = document.createElement("script");
      s.textContent = old.textContent;
      old.parentNode.replaceChild(s, old);
    });
    window.scrollTo(0, 0);
  }
  function tryPassword(pwd) {
    return derive(pwd).then(function (raw) {
      return decrypt(raw).then(function (html) { remember(raw); return html; });
    });
  }
  function ask() {
    document.getElementById("loading").hidden = true;
    document.getElementById("gate").hidden = false;
    document.getElementById("pwd").focus();
  }

  // 1. Lien du QR code : …/#cle=motdepasse
  var fromUrl = new URLSearchParams(location.hash.slice(1)).get("cle");
  // 2. Clé mémorisée lors d'une visite précédente
  var saved = null;
  try { saved = JSON.parse(localStorage.getItem(STORE) || "null"); } catch (e) {}

  var attempt;
  if (fromUrl) {
    history.replaceState(null, "", location.pathname + location.search);
    attempt = tryPassword(fromUrl);
  } else if (saved && saved.salt === SALT) {
    attempt = decrypt(unhex(saved.key));
  } else {
    attempt = Promise.reject();
  }
  attempt.then(show, ask);

  document.getElementById("f").addEventListener("submit", function (e) {
    e.preventDefault();
    var btn = document.getElementById("go"), err = document.getElementById("err");
    btn.disabled = true;
    err.textContent = "";
    tryPassword(document.getElementById("pwd").value).then(show, function () {
      btn.disabled = false;
      err.textContent = "Raté ! Vérifiez votre faire-part (on ne dira rien aux mariés).";
    });
  });
})();
</script>
</body>
</html>
"""


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    pwd_file = ROOT / "motdepasse.txt"
    if not pwd_file.exists():
        sys.exit("Créez motdepasse.txt avec le mot de passe sur la première ligne.")
    password = pwd_file.read_text(encoding="utf-8").splitlines()[0]
    if not normalize(password):
        sys.exit("motdepasse.txt est vide.")

    salt = secrets.token_bytes(16)
    key = pbkdf2_hmac("sha256", normalize(password).encode("utf-8"), salt, ITERATIONS, 32)
    aes = AESGCM(key)

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()

    for page in PAGES:
        html = inline_assets((SRC / page).read_text(encoding="utf-8"))
        iv = secrets.token_bytes(12)
        data = base64.b64encode(iv + aes.encrypt(iv, html.encode("utf-8"), None)).decode()
        gate = (GATE.replace("__SALT__", base64.b64encode(salt).decode())
                    .replace("__ITER__", str(ITERATIONS))
                    .replace("__DATA__", data))
        (OUT / page).write_text(gate, encoding="utf-8")
        print(f"  docs/{page}")

    # Dessins et ciels tirés des versos des faire-part (aucun texte) : publics, non chiffrés
    shutil.copytree(SRC / "assets", OUT / "assets")
    (OUT / "robots.txt").write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")

    # QR code + lien magique
    QR_DIR.mkdir(exist_ok=True)
    link = SITE_URL + "#cle=" + quote(password.strip(), safe="")
    qr = segno.make(link, error="q")
    try:
        qr.save(str(QR_DIR / "qr-code.svg"), scale=10, border=2, dark="#1d2a23")
        qr.save(str(QR_DIR / "qr-code.png"), scale=20, border=2, dark="#1d2a23")
        (QR_DIR / "lien-invites.txt").write_text(link + "\n", encoding="utf-8")
    except OSError:
        print("\n⚠ Impossible d'écrire le QR code : fermez l'image qr-code si elle est ouverte, puis relancez.")
        print("  (Le site dans docs/ est bien à jour.)")

    print("\nQR code : qr/qr-code.png (et .svg pour l'imprimeur)")
    print("Lien avec mot de passe : " + link)
    if "VOTRE-PSEUDO" in SITE_URL:
        print("\n⚠ SITE_URL n'est pas encore réglé dans build.py : le QR code pointe vers une adresse bidon.")
    local = (OUT / "index.html").as_uri() + "#cle=" + quote(password.strip(), safe="")
    print("Tester en local : " + local)


if __name__ == "__main__":
    main()
