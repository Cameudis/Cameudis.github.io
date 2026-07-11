(function() {
  const STORAGE_KEY = 'user-color-scheme';
  const THEMES = ['dark', 'light', 'blue-white'];
  const themePicker = document.querySelector('#theme-picker');
  const themeTrigger = document.querySelector('#theme-picker-trigger');
  const themeMenu = document.querySelector('#theme-picker-menu');
  const themeCurrent = document.querySelector('.theme-picker-current');
  const themeOptions = Array.from(document.querySelectorAll('[data-theme-value]'));

  function setMenuOpen(open) {
    if (!themeTrigger || !themeMenu) return;
    themeTrigger.setAttribute('aria-expanded', String(open));
    themeMenu.hidden = !open;
    themePicker.classList.toggle('is-open', open);
  }
  
  function applyTheme(theme) {
    const selectedTheme = THEMES.includes(theme) ? theme : 'dark';
    document.documentElement.setAttribute('data-theme', selectedTheme);
    themeOptions.forEach((option) => {
      const selected = option.dataset.themeValue === selectedTheme;
      option.setAttribute('aria-checked', String(selected));
      option.querySelector('.theme-option-state').textContent = selected ? 'ON' : 'OFF';
      if (selected && themeCurrent) themeCurrent.textContent = option.dataset.themeLabel;
    });
    localStorage.setItem(STORAGE_KEY, selectedTheme);
  }

  // Get initial theme
  let savedTheme = localStorage.getItem(STORAGE_KEY);
  if (!savedTheme) {
    savedTheme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  // Initial apply (already handled in head to prevent FOUC, but ensuring compatibility)
  applyTheme(savedTheme);

  if (themeTrigger && themeMenu) {
    themeTrigger.addEventListener('click', () => {
      const open = themeTrigger.getAttribute('aria-expanded') !== 'true';
      setMenuOpen(open);
      if (open) {
        const selectedOption = themeOptions.find((option) => option.getAttribute('aria-checked') === 'true');
        (selectedOption || themeOptions[0]).focus();
      }
    });

    themeOptions.forEach((option, index) => {
      option.addEventListener('click', () => {
        applyTheme(option.dataset.themeValue);
        setMenuOpen(false);
        themeTrigger.focus();
      });

      option.addEventListener('keydown', (event) => {
        if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
        event.preventDefault();
        const offset = event.key === 'ArrowDown' ? 1 : -1;
        themeOptions[(index + offset + themeOptions.length) % themeOptions.length].focus();
      });
    });

    document.addEventListener('click', (event) => {
      if (!themePicker.contains(event.target)) setMenuOpen(false);
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && themeTrigger.getAttribute('aria-expanded') === 'true') {
        setMenuOpen(false);
        themeTrigger.focus();
      }
    });
  }
})();
