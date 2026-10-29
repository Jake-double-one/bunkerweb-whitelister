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
  const apply = (skin) => {
    if (skin && SKINS.includes(skin)) root.dataset.theme = skin; else delete root.dataset.theme;
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

  /* Ask before removing */
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (ev) => {
      if (!window.confirm(form.dataset.confirm)) ev.preventDefault();
    });
  });
})();
