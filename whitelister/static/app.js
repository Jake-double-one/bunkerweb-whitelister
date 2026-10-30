/* Progressive enhancement only: everything works without this file. */
(() => {
  'use strict';
  const root = document.documentElement;
  root.classList.remove('no-js');
  root.classList.add('js');

  /* Skin choice, remembered in this browser only */
  const SKINS = ['dark', 'amoled', 'sunset', 'light', 'mint', 'mango'];
  const KEY = 'whitelister.skin';
  let stored = null;
  try { stored = localStorage.getItem(KEY); } catch (e) { stored = null; }
  const configured = root.dataset.defaultSkin || 'auto';
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  const apply = (skin) => {
    if (skin && SKINS.includes(skin)) root.dataset.theme = skin; else delete root.dataset.theme;
    if (themeMeta) themeMeta.content = getComputedStyle(root).getPropertyValue('--bg').trim() || themeMeta.content;
    document.querySelectorAll('[data-skin-set]').forEach((b) => {
      b.setAttribute('aria-checked', String(b.dataset.skinSet === (root.dataset.theme || '')));
    });
  };
  apply(stored || (configured !== 'auto' ? configured : null));
  document.querySelectorAll('[data-skin-set]').forEach((b) => {
    b.addEventListener('click', () => {
      apply(b.dataset.skinSet);
      try { localStorage.setItem(KEY, b.dataset.skinSet); } catch (e) { /* private mode */ }
    });
  });

  /* Date fields only show when "until date" is picked */
  document.querySelectorAll('[data-duration-group]').forEach((group) => {
    const dateField = group.querySelector('.date-field');
    const dateInput = dateField && dateField.querySelector('input[type="date"]');
    const update = () => {
      const picked = group.querySelector('input[type="radio"]:checked');
      const wantsDate = picked && picked.value === 'date';
      if (dateField) dateField.hidden = !wantsDate;
      if (dateInput) dateInput.required = Boolean(wantsDate);
      group.querySelectorAll('[data-hint]').forEach((h) => {
        h.hidden = !(picked && h.dataset.hint === (picked.value === 'date' || picked.value === 'forever' ? picked.value : 'days-' + picked.value));
      });
    };
    group.querySelectorAll('input[type="radio"]').forEach((r) => r.addEventListener('change', update));
    update();
  });

  /* Shortcuts next to the address field */
  const ip = document.getElementById('network');
  const myIp = document.getElementById('my-ip');
  if (ip && myIp && myIp.dataset.ip) {
    myIp.addEventListener('click', () => { ip.value = myIp.dataset.ip; ip.focus(); });
  }
  const net24 = document.getElementById('net24');
  if (ip && net24) {
    net24.addEventListener('click', () => {
      const m = ip.value.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}(\/\d+)?$/);
      if (m) ip.value = `${m[1]}.${m[2]}.${m[3]}.0/24`;
      ip.focus();
    });
  }

  /* Installable app: the worker only caches /static/ and the offline page, never a logged-in page */
  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('/sw.js').catch(() => { /* optional */ });
  }

  /* Label suggestion: the last label used in this browser, else "Browser · System" (a computer name is not
     something a web page can read) */
  const labelField = document.querySelector('[data-suggest-label]');
  const LABEL_KEY = 'whitelister.label';
  if (labelField) {
    const deviceName = () => {
      const ua = navigator.userAgent || '';
      const data = navigator.userAgentData;
      let browser = '';
      if (data && Array.isArray(data.brands)) {
        const b = data.brands.find((x) => !/Not.?A.?Brand|Chromium/i.test(x.brand)) || data.brands.find((x) => !/Not.?A.?Brand/i.test(x.brand));
        if (b) browser = b.brand.replace(/^Google |^Microsoft /, '');
      }
      if (!browser) {
        browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox'
          : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
      }
      const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android'
        : /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'Mac' : /CrOS/.test(ua) ? 'ChromeOS'
        : /Linux/.test(ua) ? 'Linux' : '';
      return os ? `${browser} · ${os}` : browser;
    };
    let last = null;
    try { last = localStorage.getItem(LABEL_KEY); } catch (e) { last = null; }
    if (!labelField.value) labelField.value = last || deviceName();
    const form = labelField.closest('form');
    if (form) form.addEventListener('submit', () => {
      try { if (labelField.value.trim()) localStorage.setItem(LABEL_KEY, labelField.value.trim()); } catch (e) { /* private mode */ }
    });
  }

  /* List tools: search, filter, sort. Pure view logic on the rendered rows. */
  const tools = document.querySelector('[data-list-tools]');
  if (tools) {
    tools.hidden = false;
    const list = tools.closest('.list');
    const rows = Array.from(list.querySelectorAll('.entry'));
    const search = tools.querySelector('[data-list-search]');
    const sortSel = tools.querySelector('[data-list-sort]');
    const count = tools.querySelector('[data-list-count]');
    const emptyNote = list.querySelector('[data-list-empty]');
    const countText = (count && count.dataset.template) || '{shown} / {total}';
    let filter = 'all';
    const keyOf = (row, mode) => {
      const exp = row.dataset.expires === '' ? Number.MAX_SAFE_INTEGER : Number(row.dataset.expires);
      if (mode === 'label') return (row.dataset.label || '\uffff').toLowerCase();
      if (mode === 'network') return row.dataset.network;
      if (mode === 'newest') return -Number(row.dataset.created);
      return exp;
    };
    const render = () => {
      const q = (search.value || '').trim().toLowerCase();
      const mode = sortSel.value;
      const sorted = rows.slice().sort((a, b) => {
        const ka = keyOf(a, mode), kb = keyOf(b, mode);
        return ka < kb ? -1 : ka > kb ? 1 : 0;
      });
      let shown = 0;
      sorted.forEach((row) => {
        const matches = (!q || row.dataset.network.toLowerCase().includes(q) || (row.dataset.label || '').toLowerCase().includes(q))
          && (filter === 'all' || row.dataset.state === filter);
        row.hidden = !matches;
        if (matches) shown += 1;
        list.appendChild(row);
      });
      if (emptyNote) { emptyNote.hidden = shown !== 0; list.appendChild(emptyNote); }
      if (count) count.textContent = countText.replace('{shown}', shown).replace('{total}', rows.length);
    };
    search.addEventListener('input', render);
    sortSel.addEventListener('change', render);
    tools.querySelectorAll('[data-list-filter]').forEach((b) => b.addEventListener('click', () => {
      filter = b.dataset.listFilter;
      tools.querySelectorAll('[data-list-filter]').forEach((x) => x.classList.toggle('on', x === b));
      render();
    }));
    render();
  }

  /* Ask before removing */
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (ev) => {
      if (!window.confirm(form.dataset.confirm)) ev.preventDefault();
    });
  });
})();
