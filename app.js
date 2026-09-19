/* ═══════════════════════════════════════════════════════════════
   Password Vault PWA — Main App Logic
═══════════════════════════════════════════════════════════════ */

let vaultData = null;
let filteredEntries = [];
let currentEntry = null;
let selectedFile = null;
let pwVisible = false;
let detailPwVisible = false;

/* ── CRYPTO ENGINE ── */
async function decryptVault(buffer, password) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 49) throw new Error('File troppo corto o non valido.');

  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
  if (magic !== 'PVLT') throw new Error('Il file selezionato non è un vault valido.');

  const version = bytes[4];
  if (version !== 1) throw new Error('Versione vault non supportata: ' + version);

  const salt       = bytes.slice(5, 21);
  const nonce      = bytes.slice(21, 33);
  const tag        = bytes.slice(33, 49);
  const ciphertext = bytes.slice(49);

  const pwBytes = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveKey']);

  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
  ciphertextWithTag.set(ciphertext, 0);
  ciphertextWithTag.set(tag, ciphertext.length);

  let plainBuffer;
  try {
    plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 },
      aesKey,
      ciphertextWithTag
    );
  } catch (e) {
    throw new Error('Master password errata o file corrotto.');
  }

  const json = new TextDecoder('utf-8').decode(plainBuffer);
  return JSON.parse(json);
}

/* ── UI NAVIGATION ── */
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}

function lockVault() {
  vaultData = null;
  filteredEntries = [];
  currentEntry = null;
  document.getElementById('search-input').value = '';
  document.getElementById('master-password').value = '';
  document.getElementById('entries-list').innerHTML = '';
  showScreen('screen-unlock');
}

/* ── UTILS ── */
let toastTimeout;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden', 'fade-out');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    t.classList.add('fade-out');
    setTimeout(() => t.classList.add('hidden'), 300);
  }, 2500);
}

function copyToClipboard(text, name) {
  if (!navigator.clipboard) {
    const input = document.createElement('textarea');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
    showToast(`✅ ${name} copiato`);
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    showToast(`✅ ${name} copiato`);
  }).catch(() => showToast('❌ Errore copia'));
}

/* ── VAULT LIST E FILTRI ── */
function populateCategoryFilter() {
  const select = document.getElementById('category-filter');
  select.innerHTML = '<option value="">Tutte</option>';
  if (!vaultData) return;

  if (vaultData.RecentlyUsedEntryIds && vaultData.RecentlyUsedEntryIds.length > 0) {
    const recentOpt = document.createElement('option');
    recentOpt.value = "Utilizzati di recente";
    recentOpt.textContent = "⏱️ Utilizzati di recente";
    select.appendChild(recentOpt);
  }

  const cats = new Set();
  const hidden = (vaultData.HiddenDefaultCategories || []).map(h => h.toLowerCase());
  const deleted = (vaultData.DeletedCustomCategories || []).map(d => d.toLowerCase());

  const defaults = ["Personale", "Lavoro", "Finanza & Banche", "Social & Svago", "Shopping & Ecommerce", "Altro"];
  defaults.forEach(d => {
    if (!hidden.includes(d.toLowerCase()) && !deleted.includes(d.toLowerCase())) cats.add(d);
  });

  if (vaultData.CustomCategories) {
    vaultData.CustomCategories.forEach(c => {
      if (!deleted.includes(c.toLowerCase())) cats.add(c);
    });
  }

  if (vaultData.Entries) {
    vaultData.Entries.forEach(e => {
      // Ignora le categorie delle password nel cestino
      if (e.Category && !e.IsDeleted && !deleted.includes(e.Category.toLowerCase())) {
        cats.add(e.Category);
      }
    });
  }

  const sorted = Array.from(cats).sort((a,b) => a.localeCompare(b));
  sorted.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c; opt.textContent = c;
    select.appendChild(opt);
  });
}

function applyFilter() {
  if (!vaultData) return;
  const q = document.getElementById('search-input').value.toLowerCase();
  const cat = document.getElementById('category-filter').value;

  filteredEntries = vaultData.Entries.filter(e => {
    // 0. IGNORA LE PASSWORD NEL CESTINO
    if (e.IsDeleted === true) return false;

    // 1. Filtro Categoria
    if (cat === "Utilizzati di recente") {
      if (!vaultData.RecentlyUsedEntryIds || !vaultData.RecentlyUsedEntryIds.includes(e.Id)) return false;
    } else if (cat) {
      const c1 = (e.Category || '').trim().toLowerCase();
      const c2 = cat.trim().toLowerCase();
      if (c1 !== c2) return false;
    }

    // 2. Filtro Ricerca
    if (!q) return true;
    return (e.Title && e.Title.toLowerCase().includes(q)) || 
           (e.Username && e.Username.toLowerCase().includes(q)) ||
           (e.Url && e.Url.toLowerCase().includes(q)) ||
           (e.Notes && e.Notes.toLowerCase().includes(q));
  });

  if (cat === "Utilizzati di recente" && vaultData.RecentlyUsedEntryIds) {
    filteredEntries.sort((a, b) => {
      return vaultData.RecentlyUsedEntryIds.indexOf(a.Id) - vaultData.RecentlyUsedEntryIds.indexOf(b.Id);
    });
  }

  document.getElementById('entries-list').innerHTML = generateEntriesHtml(filteredEntries);
  
  const empty = document.getElementById('empty-state');
  if (filteredEntries.length === 0) empty.classList.remove('hidden');
  else empty.classList.add('hidden');

  document.getElementById('stats-bar').textContent = `${filteredEntries.length} credenziali trovate`;
}

function daysUntil(isoDate) {
  if (!isoDate) return null;
  const d = new Date(isoDate);
  const now = new Date();
  const diffTime = d.getTime() - now.getTime();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}
function isExpired(entry) {
  if (!entry.ExpiryDate) return false;
  return new Date(entry.ExpiryDate) < new Date();
}
function isExpiringSoon(entry) {
  const d = daysUntil(entry.ExpiryDate);
  return d !== null && d >= 0 && d <= 30;
}
function formatDate(isoDate) {
  if (!isoDate) return '';
  return new Date(isoDate).toLocaleDateString('it-IT');
}

function getCategoryIcon(entry) {
  const c = entry.Category ? entry.Category.trim() : '';
  if (!c) return '🏷️';
  
  if (vaultData && vaultData.CategoryIcons) {
    const customKey = Object.keys(vaultData.CategoryIcons).find(k => k.toLowerCase() === c.toLowerCase());
    if (customKey && vaultData.CategoryIcons[customKey]) {
      return vaultData.CategoryIcons[customKey];
    }
  }

  const defaults = {
    'personale': '👤',
    'lavoro': '💼',
    'finanza & banche': '🏦',
    'social & svago': '🎮',
    'shopping & ecommerce': '🛒',
    'importati da csv': '📥',
    'altro': '🏷️'
  };
  
  const lowerC = c.toLowerCase();
  if (defaults[lowerC]) return defaults[lowerC];

  if (lowerC.includes('banca') || lowerC.includes('finanz')) return '🏦';
  if (lowerC.includes('email') || lowerC.includes('posta')) return '📧';
  if (lowerC.includes('social')) return '💬';
  if (lowerC.includes('shop') || lowerC.includes('acquisti')) return '🛒';
  
  return '🏷️';
}

function generateEntriesHtml(entries) {
  return entries.map((entry, idx) => {
    const title = entry.Title || '(Senza titolo)';
    const username = entry.Username || '';
    const icon = getCategoryIcon(entry);
    
    let badgesHtml = '';
    if (entry.Category) badgesHtml += `<span class="badge badge-cat">${escHtml(entry.Category)}</span>`;
    
    const expired = isExpired(entry);
    const soon = isExpiringSoon(entry);
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

/* ── ENTRY DETAIL ── */
window.openEntry = function(idx) {
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

  if (e.Category) {
    html += `
      <div class="field-card">
        <div class="field-label">Categoria</div>
        <div class="field-row">
          <div class="field-value">${icon} ${escHtml(e.Category)}</div>
        </div>
      </div>`;
  }

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

  if (e.Notes && e.Notes.trim()) {
    html += `
      <div class="notes-card">
        <div class="field-label">Note</div>
        <div class="notes-text">${escHtml(e.Notes)}</div>
      </div>`;
  }

  document.getElementById('detail-content').innerHTML = html;
}

window.toggleDetailPw = function() {
  detailPwVisible = !detailPwVisible;
  renderDetail();
}

/* ── EVENT LISTENERS ── */
document.addEventListener('DOMContentLoaded', () => {

  document.getElementById('btn-pick-file').addEventListener('click', () => {
    document.getElementById('file-input').click();
  });

  const fileInput = document.getElementById('file-input');
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    selectedFile = file;
    document.getElementById('file-name-display').textContent = `📄 ${file.name}`;
    checkUnlockReady();
  });

  const pwInput = document.getElementById('master-password');
  pwInput.addEventListener('input', checkUnlockReady);
  pwInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') attemptUnlock();
  });

  document.getElementById('btn-toggle-password').addEventListener('click', () => {
    pwVisible = !pwVisible;
    pwInput.type = pwVisible ? 'text' : 'password';
    document.getElementById('btn-toggle-password').textContent = pwVisible ? '🙈' : '👁';
  });

  document.getElementById('btn-unlock').addEventListener('click', attemptUnlock);

  document.getElementById('btn-lock').addEventListener('click', () => {
    if (confirm('Bloccare il vault? Dovrai reinserire la master password.')) {
      lockVault();
    }
  });

  document.getElementById('btn-back').addEventListener('click', () => {
    showScreen('screen-vault');
  });

  document.getElementById('search-input').addEventListener('input', applyFilter);
  document.getElementById('category-filter').addEventListener('change', applyFilter);

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
});

function checkUnlockReady() {
  const hasPw   = document.getElementById('master-password').value.length > 0;
  const hasFile = selectedFile !== null;
  document.getElementById('btn-unlock').disabled = !(hasPw && hasFile);
}

window.attemptUnlock = async function() {
  if (!selectedFile) { showToast('⚠️ Seleziona prima il file'); return; }
  const pw = document.getElementById('master-password').value;
  if (!pw) { showToast('⚠️ Inserisci la master password'); return; }

  const overlay = document.getElementById('loading-overlay');
  const errEl   = document.getElementById('unlock-error');
  overlay.classList.remove('hidden');
  errEl.classList.add('hidden');

  try {
    const buffer = await selectedFile.arrayBuffer();
    vaultData = await decryptVault(buffer, pw);

    overlay.classList.add('hidden');
    document.getElementById('master-password').value = '';

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
