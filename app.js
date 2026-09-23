/* ═══════════════════════════════════════════════════════════════
   Password Vault PWA — Main App Logic
═══════════════════════════════════════════════════════════════ */

let vaultData = null;
let filteredEntries = [];
let currentEntry = null;
let selectedFile = null;
let pwVisible = false;
let detailPwVisible = false;
let revealTimer;
let listScrollTop = 0;
let unlocking = false;
function hideDetailPassword() {
  clearTimeout(revealTimer);
  if (detailPwVisible) { detailPwVisible = false; if (currentEntry) renderDetail(); }
}

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
  const target = document.getElementById(id);
  target.classList.remove('screen-enter', 'screen-return');
  void target.offsetWidth;
  target.classList.add(id === 'screen-detail' ? 'screen-enter' : 'screen-return');
  document.getElementById('vault-actions').classList.toggle('hidden', id === 'screen-unlock');
}

function lockVault() {
  document.getElementById('link-confirm').close();
  hideDetailPassword();
  vaultData = null;
  filteredEntries = [];
  currentEntry = null;
  document.getElementById('search-input').value = '';
  document.getElementById('master-password').value = '';
  document.getElementById('entries-list').innerHTML = '';
  document.getElementById('detail-content').textContent = '';
  document.getElementById('detail-title-header').textContent = '';
  document.getElementById('category-filter').innerHTML = '<option value="">Tutte</option>';
  document.getElementById('master-password').type = 'password';
  pwVisible = false;
  checkUnlockReady();
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
  if (!vaultData) return;
  if (!navigator.clipboard) {
    const input = document.createElement('textarea');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    const copied = document.execCommand('copy');
    document.body.removeChild(input);
    showToast(copied ? `✅ ${name} copiato` : '❌ Copia non disponibile');
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    showToast(`✅ ${name} copiato`);
  }).catch(() => showToast('❌ Errore copia'));
}

function entryUrl(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (/^[a-z][a-z0-9+.-]*:/i.test(text) && !/^https?:\/\//i.test(text) && !/^[\w.-]+:\d+(?:\/|$)/.test(text)) return '';
  try {
    const url = new URL(/^https?:\/\//i.test(text) ? text : 'https://' + text);
    return ['http:', 'https:'].includes(url.protocol) && url.hostname && !url.username && !url.password ? url.href : '';
  } catch (_) { return ''; }
}

function siteFaviconUrl(value) {
  const url = entryUrl(value);
  if (!url) return '';
  try {
    return new URL('/favicon.ico', url).href;
  } catch (_) { return ''; }
}

function siteIconHtml(entry, idx) {
  const url = entryUrl(entry.Url);
  const favicon = siteFaviconUrl(entry.Url);
  const title = entry.Title || 'sito';
  const label = url ? `Apri il sito ${title}` : `Nessun sito disponibile per ${title}`;
  const image = favicon
    ? `<img src="${escHtml(favicon)}" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer" onerror="this.remove()">`
    : '';

  return `<button class="site-icon-button" type="button" aria-label="${escHtml(label)}" title="${escHtml(label)}" onclick="openEntryUrl(${idx})" ${url ? '' : 'disabled'}>
    <span class="site-icon-fallback" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.4 3 14.6 0 18M12 3c-3 3.4-3 14.6 0 18"/></svg></span>
    ${image}
  </button>`;
}

window.openEntryUrl = function(idx) {
  requestEntryLink(filteredEntries[idx]?.Url);
};

window.requestEntryLink = function(value) {
  if (!vaultData) return;
  const url = entryUrl(value);
  if (!url) return;
  document.getElementById('link-confirm-url').textContent = url;
  document.getElementById('link-confirm-yes').href = url;
  document.getElementById('link-confirm').showModal();
};

window.openEntryCategory = function(idx) {
  if (!vaultData) return;
  const category = (filteredEntries[idx]?.Category || '').trim();
  if (!category) return;
  const select = document.getElementById('category-filter');
  let option = Array.from(select.options).find(o => o.value.trim().toLowerCase() === category.toLowerCase());
  if (!option) {
    option = document.createElement('option');
    option.value = category;
    const count = vaultData.Entries.filter(e => !e.IsDeleted && (e.Category || '').trim().toLowerCase() === category.toLowerCase()).length;
    option.textContent = `${getCategoryIcon({Category: category})} ${category} (${count})`;
    select.appendChild(option);
  }
  select.value = option.value;
  document.getElementById('search-input').value = '';
  applyFilter();
  document.getElementById('screen-vault').scrollTop = 0;
};

window.quickCopy = function(idx, field) {
  const entry = filteredEntries[idx];
  if (!vaultData || !entry || !['Username', 'Password'].includes(field)) return;
  copyToClipboard(entry[field] || '', field === 'Password' ? 'Password' : 'Username');
};

/* ── VAULT LIST E FILTRI ── */
function populateCategoryFilter() {
  const select = document.getElementById('category-filter');
  select.innerHTML = '<option value="">Tutte</option>';
  if (!vaultData) return;

  const active = (vaultData.Entries || []).filter(e => !e.IsDeleted);
  select.options[0].textContent = `🗂️ Tutte (${active.length})`;
  if (vaultData.RecentlyUsedEntryIds && vaultData.RecentlyUsedEntryIds.length > 0) {
    const recentOpt = document.createElement('option');
    recentOpt.value = "Utilizzati di recente";
    recentOpt.textContent = `⏱️ Utilizzati di recente (${active.filter(e => vaultData.RecentlyUsedEntryIds.includes(e.Id)).length})`;
    select.appendChild(recentOpt);
  }

  const hasExpiry = vaultData.Entries && vaultData.Entries.some(e => e.ExpiryDate && !e.IsDeleted);
  if (hasExpiry) {
    const expOpt = document.createElement('option');
    expOpt.value = "Scadenza";
    expOpt.textContent = `⏰ Scadenze (${active.filter(e => e.ExpiryDate).length})`;
    select.appendChild(expOpt);
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
      if (e.Category && !e.IsDeleted && !deleted.includes(e.Category.toLowerCase())) {
        cats.add(e.Category);
      }
    });
  }

  const sorted = Array.from(cats).sort((a,b) => a.localeCompare(b));
  sorted.forEach(c => {
    const opt = document.createElement('option');
    const count = active.filter(e => (e.Category || '').trim().toLowerCase() === c.trim().toLowerCase()).length;
    opt.value = c; opt.textContent = `${getCategoryIcon({ Category: c })} ${c} (${count})`;
    select.appendChild(opt);
  });
}

function applyFilter() {
  document.getElementById('clear-search').classList.toggle('hidden', !document.getElementById('search-input').value);
  document.getElementById('clear-category').classList.toggle('hidden', !document.getElementById('category-filter').value);
  if (!vaultData) return;
  const q = document.getElementById('search-input').value.trim().toLowerCase();
  const cat = document.getElementById('category-filter').value;

  filteredEntries = vaultData.Entries.filter(e => {
    if (e.IsDeleted === true) return false;

    if (cat === "Utilizzati di recente") {
      if (!vaultData.RecentlyUsedEntryIds || !vaultData.RecentlyUsedEntryIds.includes(e.Id)) return false;
    } else if (cat === "Scadenza") {
      if (!e.ExpiryDate) return false;
    } else if (cat) {
      const c1 = (e.Category || '').trim().toLowerCase();
      const c2 = cat.trim().toLowerCase();
      if (c1 !== c2) return false;
    }

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
  } else {
    filteredEntries.sort((a, b) => {
      if (a.ExpiryDate && b.ExpiryDate) {
        return new Date(a.ExpiryDate).getTime() - new Date(b.ExpiryDate).getTime();
      }
      if (a.ExpiryDate && !b.ExpiryDate) return -1;
      if (!a.ExpiryDate && b.ExpiryDate) return 1;
      
      const tA = (a.Title || '').toLowerCase();
      const tB = (b.Title || '').toLowerCase();
      return tA.localeCompare(tB);
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
    
    if (entry.ExpiryDate) {
      const dateStr = formatDate(entry.ExpiryDate);
      const expired = isExpired(entry);
      const soon = isExpiringSoon(entry);
      
      if (expired) {
        badgesHtml += `<span class="badge badge-expiry">🔴 Scade il ${dateStr}</span>`;
      } else if (soon) {
        const d = daysUntil(entry.ExpiryDate);
        badgesHtml += `<span class="badge badge-soon">⚠️ Scade il ${dateStr} (-${d}gg)</span>`;
      } else {
        badgesHtml += `<span class="badge" style="background:#2c2c2e; color:#a1a1a6;">⏳ Scade il ${dateStr}</span>`;
      }
    }

    return `
      <div class="entry-card" data-idx="${idx}">
        <div class="entry-heading">
        ${siteIconHtml(entry, idx)}
        <button class="entry-open" aria-label="Apri ${escHtml(title)}" onclick="openEntry(${idx})">
        <div class="entry-info">
          <div class="entry-title">${highlightSearch(title)}</div>
          ${username ? `<div class="entry-username">${highlightSearch(username)}</div>` : ''}
          ${document.getElementById('search-input').value.trim() && entry.Url ? `<div class="entry-username">${highlightSearch(entry.Url)}</div>` : ''}
          ${document.getElementById('search-input').value.trim() && entry.Notes ? `<div class="search-note">${highlightSearch(entry.Notes)}</div>` : ''}
          ${badgesHtml ? `<div class="entry-badges">${badgesHtml}</div>` : ''}
        </div>
        <span class="entry-chevron" aria-hidden="true">›</span>
        </button>
        </div>
        <div class="entry-bottom">
        <button class="category-shortcut" onclick="openEntryCategory(${idx})" aria-label="Filtra categoria ${escHtml(entry.Category || '')}" ${(entry.Category || '').trim() ? '' : 'disabled'}><span aria-hidden="true">${escHtml(icon)}</span><span>${escHtml((entry.Category || '').trim() || 'Nessuna categoria')}</span></button>
        <div class="quick-actions">
          <button class="btn-field" aria-label="Apri link" title="Apri link" onclick="openEntryUrl(${idx})" ${entryUrl(entry.Url) ? '' : 'disabled'}><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3h7v7M21 3l-11 11M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/></svg></button>
          <button class="btn-field" aria-label="Copia utente" title="Copia utente" onclick="quickCopy(${idx}, 'Username')" ${username ? '' : 'disabled'}><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="7" r="4"/><path d="M2 21v-3a7 7 0 0 1 12-5M17 12h5v9h-7v-7h2z"/></svg></button>
          <button class="btn-field" aria-label="Copia password" title="Copia password" onclick="quickCopy(${idx}, 'Password')" ${entry.Password ? '' : 'disabled'}><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="7" cy="8" r="4"/><path d="m10 11 5 5v3h3v3h4v-4L11 7"/></svg></button>
        </div>
        </div>
      </div>`;
  }).join('');
}

function highlightSearch(value) {
  const text = String(value || '');
  const query = document.getElementById('search-input').value.trim();
  if (!query) return escHtml(text);
  const lower = text.toLowerCase();
  const needle = query.toLowerCase();
  let start = 0, result = '', index;
  while ((index = lower.indexOf(needle, start)) !== -1) {
    result += escHtml(text.slice(start, index)) + '<mark>' + escHtml(text.slice(index, index + query.length)) + '</mark>';
    start = index + query.length;
  }
  return result + escHtml(text.slice(start));
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── ENTRY DETAIL ── */
window.openEntry = function(idx) {
  listScrollTop = document.getElementById('screen-vault').scrollTop;
  hideDetailPassword();
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

  let html = '';

  if (e.Username) {
    html += `
      <div class="field-card">
        <div class="field-label">Username / Email</div>
        <div class="field-row">
          <div class="field-value">${escHtml(e.Username)}</div>
          <div class="field-actions">
            <button class="btn-field" aria-label="Copia username" onclick="copyToClipboard(currentEntry.Username,'Username')">📋</button>
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
    const href = entryUrl(e.Url);
    html += `
      <div class="field-card">
        <div class="field-label">URL</div>
        <div class="field-row">
          <div class="field-value">${escHtml(e.Url)}</div>
          <div class="field-actions">
            ${href ? `<button class="btn-field" aria-label="Apri link" onclick="requestEntryLink(currentEntry.Url)">↗</button>` : ''}
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
  clearTimeout(revealTimer);
  detailPwVisible = !detailPwVisible;
  renderDetail();
  if (detailPwVisible) revealTimer = setTimeout(hideDetailPassword, 10000);
}

/* ── EVENT LISTENERS ── */
document.addEventListener('DOMContentLoaded', () => {
  const linkDialog = document.getElementById('link-confirm');
  document.getElementById('link-confirm-no').addEventListener('click', () => linkDialog.close());
  document.getElementById('link-confirm-yes').addEventListener('click', () => linkDialog.close());
  document.getElementById('action-file').addEventListener('click', () => {
    lockVault();
    document.getElementById('file-input').value = '';
    document.getElementById('file-input').click();
  });
  document.getElementById('clear-search').addEventListener('click', () => {
    document.getElementById('search-input').value = ''; applyFilter();
    document.getElementById('search-input').focus();
  });
  document.getElementById('clear-category').addEventListener('click', () => {
    document.getElementById('category-filter').value = ''; applyFilter();
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) hideDetailPassword(); });

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
    hideDetailPassword();
    showScreen('screen-vault');
    document.getElementById('screen-vault').scrollTop = listScrollTop;
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
  if (unlocking) return;
  if (!selectedFile) { showToast('⚠️ Seleziona prima il file'); return; }
  const pw = document.getElementById('master-password').value;
  if (!pw) { showToast('⚠️ Inserisci la master password'); return; }
  unlocking = true;

  const overlay = document.getElementById('loading-overlay');
  const errEl   = document.getElementById('unlock-error');
  overlay.classList.remove('hidden');
  errEl.classList.add('hidden');

  try {
    const buffer = await selectedFile.arrayBuffer();
    const opened = await decryptVault(buffer, pw);
    if (!opened || !Array.isArray(opened.Entries)) throw new Error('Archivio non valido.');
    vaultData = opened;
    document.getElementById('local-file-status').textContent = selectedFile.name;

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
  } finally {
    unlocking = false;
  }
}
