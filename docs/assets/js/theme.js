(function() {
  const STORAGE_KEY = 'user-color-scheme';
  const themeToggle = document.querySelector('#theme-toggle');
  
  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem(STORAGE_KEY, theme);
  }

  // Get initial theme
  let savedTheme = localStorage.getItem(STORAGE_KEY);
  if (!savedTheme) {
    savedTheme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  // Initial apply (already handled in head to prevent FOUC, but ensuring compatibility)
  applyTheme(savedTheme);

  // Toggle listener
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      applyTheme(newTheme);
    });
  }
})();
