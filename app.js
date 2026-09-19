/**
 * Password Vault PWA — app.js
 *
 * Decifra il formato PVLT (AES-256-GCM + PBKDF2-SHA256 600k iter)
 * interamente nel browser, senza mai inviare dati al server.
 *
 * Formato binario vault:
 *   [0..3]   Magic "PVLT"  (4 byte ASCII)
 *   [4]      Version 0x01  (1 byte)
 *   [5..20]  Salt PBKDF2   (16 byte)
 *   [21..32] GCM Nonce     (12 byte)
 *   [33..48] GCM Tag       (16 byte)
 *   [49..]   Ciphertext    (N byte)
 */

'use strict';

/* ═══════════════════════════════════════════════════════════════
   STATO GLOBALE
═══════════════════════════════════════════════════════════════ */
let selectedFile   = null;   // File object selezionato dall'utente
let vaultData      = null;   // VaultData decifrato (oggetto JS)
let filteredEntries = [];    // Credenziali filtrate correntemente
let currentEntry   = null;   // Voce visualizzata nel dettaglio
let toastTimer     = null;   // Timer per nascondere il toast
let pwVisible      = false;  // Visibilità master password
let detailPwVisible = false; // Visibilità password nel dettaglio

/* ═══════════════════════════════════════════════════════════════
   CRITTOGRAFIA — Parser PVLT + AES-256-GCM via Web Crypto API
═══════════════════════════════════════════════════════════════ */

/**
 * Decifra un file .vault.
 * @param {ArrayBuffer} buffer  - Contenuto grezzo del file
 * @param {string}      password - Master password in chiaro
 * @returns {Promise<Object>}   - VaultData come oggetto JS
 */
async function decryptVault(buffer, password) {
  const bytes = new Uint8Array(buffer);

  // ── 1. Valida magic header ──────────────────────────────────
  if (bytes.length < 49) throw new Error('File troppo corto o non valido.');
  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
  if (magic !== 'PVLT') throw new Error('Il file selezionato non è un vault valido.');
  const version = bytes[4];
  if (version !== 1) throw new Error(`Versione vault non supportata: ${version}`);

  // ── 2. Estrai componenti ────────────────────────────────────
  const salt       = bytes.slice(5,  21);  // 16 byte
  const nonce      = bytes.slice(21, 33);  // 12 byte
  const tag        = bytes.slice(33, 49);  // 16 byte
  const ciphertext = bytes.slice(49);      // N byte

  // ── 3. Importa password come chiave PBKDF2 ─────────────────
  const pwBytes = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey(
    'raw', pwBytes, 'PBKDF2', false, ['deriveKey']
  );

  // ── 4. Deriva AES-256 key (600.000 iterazioni, identico al desktop) ──
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // ── 5. Ricomponi ciphertext + tag (Web Crypto vuole tag alla fine) ──
  const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
  ciphertextWithTag.set(ciphertext, 0);
  ciphertextWithTag.set(tag, ciphertext.length);

  // ── 6. Decifra AES-256-GCM ─────────────────────────────────
  let plainBuffer;
  try {
    plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 },
      aesKey,
      ciphertextWithTag
    );
  } catch {
    throw new Error('Master password errata o file corrotto.');
  }

  // ── 7. Deserializza JSON → VaultData ───────────────────────
  const json = new TextDecoder().decode(plainBuffer);
  let vault;
  try {
    vault = JSON.parse(json);
  } catch {
    throw new Error('Il vault è corrotto (JSON non valido).');
  }

  if (!vault || !Array.isArray(vault.Entries)) {
    throw new Error('Formato vault non riconosciuto.');
  }

  return vault;
}

/* ═══════════════════════════════════════════════════════════════
   UTILITY
═══════════════════════════════════════════════════════════════ */

function getCategoryIcon(entry) {
  const icons = {
    'Personale':          '👤',
    'Lavoro':             '💼',
    'Finanza & Banche':   '🏦',
    'Social & Svago':     '🎮',
    'Shopping & Ecommerce': '🛒',
    'Importati da CSV':   '📥',
    'Altro':              '🏷️',
  };
  if (entry.Category && icons[entry.Category]) return icons[entry.Category];
  if (entry.Category && vaultData && vaultData.CategoryIcons) {
    return vaultData.CategoryIcons[entry.Category] || '🔑';
  }
  return '🔑';
}

function isExpired(entry) {
  if (!entry.ExpiryDate) return false;
  return new Date(entry.ExpiryDate) < new Date();
}

function isExpiringSoon(entry) {
  if (!entry.ExpiryDate || isExpired(entry)) return false;
  const days = (new Date(entry.ExpiryDate) - new Date()) / 86400000;
  const threshold = entry.ReminderDaysBefore ?? 14;
  return days <= threshold;
}

function daysUntil(dateStr) {
  return Math.ceil((new Date(dateStr) - new Date()) / 86400000);
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString('it-IT', {
    day: '2-digit', month: '2-digit', year: 'numeric'
  });
}

function showToast(msg, duration = 2000) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.remove('hidden', 'fade-out');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.add('fade-out');
    setTimeout(() => el.classList.add('hidden'), 300);
  }, duration);
}

async function copyToClipboard(text, label = 'Copiato') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`✅ ${label} copiato!`);
  } catch {
    // Fallback per Safari
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast(`✅ ${label} copiato!`);
  }
}

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.add('hidden');
    s.classList.remove('active');
  });
  const target = document.getElementById(id);
  target.classList.remove('hidden');
  target.classList.add('active');
  target.scrollTop = 0;
}

function lockVault() {
  vaultData = null;
  filteredEntries = [];
  currentEntry = null;
  selectedFile = null;
  document.getElementById('file-name-display').textContent = 'Nessun file selezionato';
  document.getElementById('master-password').value = '';
  document.getElementById('btn-unlock').disabled = true;
  document.getElementById('unlock-error').classList.add('hidden');
  showScreen('screen-unlock');
}

/* ═══════════════════════════════════════════════════════════════
   VAULT LIST
═══════════════════════════════════════════════════════════════ */

function getEffectiveEntries() {
  if (!vaultData) return [];
  return vaultData.Entries.filter(e => !e.IsDeleted);
}

function populateCategoryFilter() {
  const select = document.getElementById('category-filter');
  select.innerHTML = '<option value="">Tutte</option>';

  const cats = new Set();
  getEffectiveEntries().forEach(e => { if (e.Category) cats.add(e.Category); });
  [...cats].sort().forEach(cat => {
    const opt = document.createElement('option');
    opt.value = cat;
    opt.textContent = cat;
    select.appendChild(opt);
  });
}

function applyFilter() {
  const query = (document.getElementById('search-input').value || '').toLowerCase().trim();
  const cat   = document.getElementById('category-filter').value;
  let entries = getEffectiveEntries();

  if (query) {
    entries = entries.filter(e =>
      (e.Title    || '').toLowerCase().includes(query) ||
      (e.Username || '').toLowerCase().includes(query) ||
      (e.Url      || '').toLowerCase().includes(query) ||
      (e.Notes    || '').toLowerCase().includes(query)
    );
  }
  if (cat) {
    entries = entries.filter(e => e.Category === cat);
  }

  // Ordina: scadute prima, poi in scadenza, poi alfabetico
  entries.sort((a, b) => {
    const ae = isExpired(a), be = isExpired(b);
    const as_ = isExpiringSoon(a), bs = isExpiringSoon(b);
    if (ae && !be) return -1; if (be && !ae) return 1;
    if (as_ && !bs) return -1; if (bs && !as_) return 1;
    return (a.Title || '').localeCompare(b.Title || '', 'it');
  });

  filteredEntries = entries;
  renderEntryList();
}

function renderEntryList() {
  const list  = document.getElementById('entries-list');
  const empty = document.getElementById('empty-state');
  const stats = document.getElementById('stats-bar');
  const total = getEffectiveEntries().length;

  stats.textContent = filteredEntries.length === total
    ? `${total} credenziali`
    : `${filteredEntries.length} di ${total} credenziali`;

  if (filteredEntries.length === 0) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  list.innerHTML = filteredEntries.map((entry, idx) => {
    const icon     = getCategoryIcon(entry);
    const expired  = isExpired(entry);
    const soon     = isExpiringSoon(entry);
    const title    = entry.Title    || '(senza titolo)';
    const username = entry.Username || '';

    let badgesHtml = '';
    if (entry.Category) {
      badgesHtml += `<span class="badge badge-cat">${entry.Category}</span>`;
    }
    if (expired) {
      badgesHtml += `<span class="badge badge-expiry">🔴 Scaduta</span>`;
    } else if (soon) {
      const d = daysUntil(entry.ExpiryDate);
      badgesHtml += `<span class="badge badge-soon">⚠️ ${d}gg</span>`;
    }

    return `
      <div class="entry-card" data-idx="${idx}" onclick="openEntry(${idx})">
        <div class="entry-icon">${icon}</div>
        <div class="entry-info">
          <div class="entry-title">${escHtml(title)}</div>
          ${username ? `<div class="entry-username">${escHtml(username)}</div>` : ''}
          ${badgesHtml ? `<div class="entry-badges">${badgesHtml}</div>` : ''}
        </div>
        <div class="entry-arrow">›</div>
      </div>`;
  }).join('');
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ═══════════════════════════════════════════════════════════════
   ENTRY DETAIL
═══════════════════════════════════════════════════════════════ */

function openEntry(idx) {
  currentEntry = filteredEntries[idx];
  detailPwVisible = false;
  renderDetail();
  showScreen('screen-detail');
}

function renderDetail() {
  const e = currentEntry;
  if (!e) return;

  document.getElementById('detail-title-header').textContent = e.Title || '(senza titolo)';

  const icon = getCategoryIcon(e);
  const expired = isExpired(e);
  const soon    = isExpiringSoon(e);

  let html = `<div class="detail-icon-row">${icon}</div>`;

  // ── Username ──────────────────────────────────────────────
  if (e.Username) {
    html += `
      <div class="field-card">
        <div class="field-label">Username / Email</div>
        <div class="field-row">
          <div class="field-value">${escHtml(e.Username)}</div>
          <div class="field-actions">
            <button class="btn-field" onclick="copyToClipboard('${escHtml(e.Username).replace(/'/g,"\\'")}','Username')">📋</button>
          </div>
        </div>
      </div>`;
  }

  // ── Password ──────────────────────────────────────────────
  if (e.Password) {
    const pwDisplay = detailPwVisible
      ? `<span class="field-value mono">${escHtml(e.Password)}</span>`
      : `<span class="field-value password-hidden">••••••••••••</span>`;
    const eyeIcon = detailPwVisible ? '🙈' : '👁';
    html += `
      <div class="field-card">
        <div class="field-label">Password</div>
        <div class="field-row">
          ${pwDisplay}
          <div class="field-actions">
            <button class="btn-field" onclick="toggleDetailPw()">${eyeIcon}</button>
            <button class="btn-field" onclick="copyToClipboard(currentEntry.Password,'Password')">📋</button>
          </div>
        </div>
      </div>`;
  }

  // ── URL ───────────────────────────────────────────────────
  if (e.Url) {
    const href = e.Url.startsWith('http') ? e.Url : `https://${e.Url}`;
    html += `
      <div class="field-card">
        <div class="field-label">URL</div>
        <div class="field-row">
          <div class="field-value"><a href="${escHtml(href)}" target="_blank" rel="noopener">${escHtml(e.Url)}</a></div>
          <div class="field-actions">
            <button class="btn-field" onclick="window.open('${escHtml(href)}','_blank','noopener')">🌐</button>
          </div>
        </div>
      </div>`;
  }

  // ── Categoria ─────────────────────────────────────────────
  if (e.Category) {
    html += `
      <div class="field-card">
        <div class="field-label">Categoria</div>
        <div class="field-row">
          <div class="field-value">${icon} ${escHtml(e.Category)}</div>
        </div>
      </div>`;
  }

  // ── Scadenza ──────────────────────────────────────────────
  if (e.ExpiryDate) {
    const d = daysUntil(e.ExpiryDate);
    let statusClass = 'text-success';
    let statusText  = `Scade tra ${d} giorni`;
    let statusIcon  = '✅';
    if (expired) {
      statusClass = 'text-danger';
      statusText  = `Scaduta da ${Math.abs(d)} giorni`;
      statusIcon  = '🔴';
    } else if (soon) {
      statusClass = 'text-warning';
      statusText  = d === 0 ? 'Scade oggi!' : `Scade tra ${d} giorni`;
      statusIcon  = '⚠️';
    }
    html += `
      <div class="expiry-card">
        <div class="expiry-icon">${statusIcon}</div>
        <div class="expiry-info">
          <p class="expiry-date">${formatDate(e.ExpiryDate)}</p>
          <p class="${statusClass}">${statusText}</p>
        </div>
      </div>`;
  }

  // ── Note ──────────────────────────────────────────────────
  if (e.Notes && e.Notes.trim()) {
    html += `
      <div class="notes-card">
        <div class="field-label">Note</div>
        <div class="notes-text">${escHtml(e.Notes)}</div>
      </div>`;
  }

  // ── Metadati ──────────────────────────────────────────────
  if (e.UpdatedAt || e.CreatedAt) {
    const updated = e.UpdatedAt ? formatDate(e.UpdatedAt) : '—';
    const created = e.CreatedAt ? formatDate(e.CreatedAt) : '—';
    html += `
      <div class="field-card">
        <div class="field-label">Info</div>
        <div class="field-row" style="flex-direction:column;align-items:flex-start;gap:4px">
          <div style="font-size:13px;color:var(--text-muted)">Creata: ${created}</div>
          <div style="font-size:13px;color:var(--text-muted)">Modificata: ${updated}</div>
        </div>
      </div>`;
  }

  document.getElementById('detail-content').innerHTML = html;
}

function toggleDetailPw() {
  detailPwVisible = !detailPwVisible;
  renderDetail();
}

/* ═══════════════════════════════════════════════════════════════
   EVENT LISTENERS — Inizializzazione
═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

  // ── File picker ─────────────────────────────────────────────
  const fileInput = document.getElementById('file-input');
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (!file.name.endsWith('.vault')) {
      showToast('⚠️ Seleziona un file .vault');
      return;
    }
    selectedFile = file;
    document.getElementById('file-name-display').textContent = `📄 ${file.name}`;
    checkUnlockReady();
  });

  // ── Password input ───────────────────────────────────────────
  const pwInput = document.getElementById('master-password');
  pwInput.addEventListener('input', checkUnlockReady);
  pwInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') attemptUnlock();
  });

  // ── Toggle password visibility ───────────────────────────────
  document.getElementById('btn-toggle-password').addEventListener('click', () => {
    pwVisible = !pwVisible;
    pwInput.type = pwVisible ? 'text' : 'password';
    document.getElementById('btn-toggle-password').textContent = pwVisible ? '🙈' : '👁';
  });

  // ── Unlock button ────────────────────────────────────────────
  document.getElementById('btn-unlock').addEventListener('click', attemptUnlock);

  // ── Lock button ──────────────────────────────────────────────
  document.getElementById('btn-lock').addEventListener('click', () => {
    if (confirm('Bloccare il vault? Dovrai reinserire la master password.')) {
      lockVault();
    }
  });

  // ── Back button ──────────────────────────────────────────────
  document.getElementById('btn-back').addEventListener('click', () => {
    showScreen('screen-vault');
  });

  // ── Search ───────────────────────────────────────────────────
  document.getElementById('search-input').addEventListener('input', applyFilter);

  // ── Category filter ──────────────────────────────────────────
  document.getElementById('category-filter').addEventListener('change', applyFilter);

  // ── Service Worker ───────────────────────────────────────────
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
});

function checkUnlockReady() {
  const hasPw   = document.getElementById('master-password').value.length > 0;
  const hasFile = selectedFile !== null;
  document.getElementById('btn-unlock').disabled = !(hasPw && hasFile);
}

async function attemptUnlock() {
  if (!selectedFile) { showToast('⚠️ Seleziona prima il file .vault'); return; }
  const pw = document.getElementById('master-password').value;
  if (!pw) { showToast('⚠️ Inserisci la master password'); return; }

  // Mostra loading
  const overlay = document.getElementById('loading-overlay');
  const errEl   = document.getElementById('unlock-error');
  overlay.classList.remove('hidden');
  errEl.classList.add('hidden');

  try {
    const buffer = await selectedFile.arrayBuffer();
    vaultData = await decryptVault(buffer, pw);

    // Successo
    overlay.classList.add('hidden');
    document.getElementById('master-password').value = '';

    // Prepara UI vault
    populateCategoryFilter();
    applyFilter();
    showScreen('screen-vault');

  } catch (err) {
    overlay.classList.add('hidden');
    errEl.textContent = '❌ ' + err.message;
    errEl.classList.remove('hidden');
    document.getElementById('master-password').value = '';
    document.getElementById('master-password').focus();
  }
}
