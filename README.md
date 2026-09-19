# Password Vault — Web App (PWA)

Versione web sicura per iPhone e qualsiasi browser moderno.  
Decifra il vault localmente — **nessun dato inviato a server**.

## 🚀 Deploy su GitHub Pages (gratuito)

### Passo 1 — Crea repository GitHub
1. Vai su [github.com](https://github.com) → **New repository**
2. Nome: `passwordvault-web` (o qualsiasi nome)
3. Spunta **Public** (necessario per GitHub Pages gratuito)
4. Clicca **Create repository**

### Passo 2 — Carica i file
Nella pagina del repository clicca **Add file → Upload files** e carica:
- `index.html`
- `app.js`
- `styles.css`
- `manifest.json`
- `sw.js`
- `icon-192.svg`
- `icon-512.svg`

### Passo 3 — Abilita GitHub Pages
1. **Settings** → **Pages** (menu laterale)
2. Source: **Deploy from a branch**
3. Branch: **main** · Folder: **/ (root)**
4. Clicca **Save**
5. Dopo 2 minuti l'URL sarà: `https://TUOUSERNAME.github.io/passwordvault-web`

---

## 📱 Installare su iPhone come app

1. Apri **Safari** su iPhone (obbligatorio, non Chrome)
2. Vai su `https://TUOUSERNAME.github.io/passwordvault-web`
3. Tocca il pulsante **Condividi** (quadrato con freccia ↑)
4. Scorri e tocca **"Aggiungi a schermata Home"**
5. Tocca **Aggiungi**

L'icona 🔐 appare sulla schermata Home come una vera app.

---

## 🔓 Come usare

1. Installa **OneDrive** su iPhone (gratuito, App Store)
2. OneDrive sincronizza automaticamente il file `.vault` dal PC
3. Apri **Password Vault** dall'icona sulla Home
4. Tocca **Seleziona file .vault**
5. Nella finestra Files, vai su **OneDrive** e seleziona il tuo file `.vault`
6. Inserisci la **Master Password**
7. Tocca **Sblocca Vault** (attendi 3-5 secondi per la decifrazione)

---

## 🛡️ Sicurezza

| Aspetto | Dettaglio |
|---|---|
| Crittografia | AES-256-GCM identica all'app desktop |
| PBKDF2 | 600.000 iterazioni HMAC-SHA256 |
| Decifrazione | 100% locale nel browser, nessuna rete |
| Service Worker | Blocca tutte le richieste esterne |
| CSP Header | `connect-src 'none'` — zero connessioni |
| Master password | Mai inviata, mai salvata |

## ⚠️ Limitazioni

- **Solo lettura** — non è possibile modificare o salvare credenziali
- **No auto-lock** — chiudi il tab quando finisci
- **PBKDF2 600k iter** su iPhone richiede 3-8 secondi (normale)
- Usa sempre **Safari** su iPhone per la funzione PWA

---

## 🔧 Sviluppo locale

```bash
# Avvia un server locale (Python)
python -m http.server 8080
# Oppure (Node.js)
npx serve .
```
Poi apri `http://localhost:8080`

> **Nota:** La Web Crypto API richiede HTTPS o localhost.  
> Su GitHub Pages HTTPS è automatico.
