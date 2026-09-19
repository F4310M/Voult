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

  // NUOVA CATEGORIA: Scadenze (come su PC)
  const hasExpiry = vaultData.Entries && vaultData.Entries.some(e => e.ExpiryDate && !e.IsDeleted);
  if (hasExpiry) {
    const expOpt = document.createElement('option');
    expOpt.value = "Scadenza";
    expOpt.textContent = "⏰ Scadenze";
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
    } else if (cat === "Scadenza") {
      // Filtra solo quelle che HANNO una scadenza
      if (!e.ExpiryDate) return false;
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

  // 3. ORDINAMENTO
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
