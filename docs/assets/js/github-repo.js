(function () {
  'use strict';

  var API_ROOT = 'https://api.github.com/repos/';
  var CACHE_PREFIX = 'github-repo-card:';
  var CACHE_TTL = 6 * 60 * 60 * 1000;
  var languageColors = {
    C: '#555555',
    'C++': '#f34b7d',
    CSS: '#563d7c',
    Go: '#00add8',
    HTML: '#e34c26',
    Java: '#b07219',
    JavaScript: '#f1e05a',
    Kotlin: '#a97bff',
    PHP: '#4f5d95',
    Python: '#3572a5',
    Ruby: '#701516',
    Rust: '#dea584',
    Shell: '#89e051',
    Swift: '#f05138',
    TypeScript: '#3178c6'
  };

  function query(card, selector) {
    return card.querySelector(selector);
  }

  function readCache(repo) {
    try {
      var cached = JSON.parse(localStorage.getItem(CACHE_PREFIX + repo));
      if (cached && Date.now() - cached.savedAt < CACHE_TTL) return cached.data;
    } catch (_) {
      // Storage can be unavailable in privacy modes; fetching still works.
    }
    return null;
  }

  function writeCache(repo, data) {
    try {
      localStorage.setItem(CACHE_PREFIX + repo, JSON.stringify({ savedAt: Date.now(), data: data }));
    } catch (_) {
      // A full or disabled localStorage should not break the card.
    }
  }

  function compactNumber(value) {
    try {
      return new Intl.NumberFormat('zh-CN', {
        notation: 'compact',
        maximumFractionDigits: 1
      }).format(value);
    } catch (_) {
      return String(value);
    }
  }

  function render(card, data) {
    var owner = query(card, '.github-repo-card__owner');
    var name = query(card, '.github-repo-card__name');
    var visibility = query(card, '.github-repo-card__visibility');
    var description = query(card, '.github-repo-card__description');
    var meta = query(card, '.github-repo-card__meta');
    var language = query(card, '.github-repo-card__language');
    var license = query(card, '.github-repo-card__license');
    var updated = query(card, '.github-repo-card__updated');

    owner.textContent = data.owner.login;
    name.textContent = data.name;
    visibility.textContent = data.visibility || (data.private ? 'Private' : 'Public');
    visibility.hidden = false;
    description.textContent = data.description || '这个仓库暂时没有简介。';

    query(card, '.github-repo-card__stars-count').textContent = compactNumber(data.stargazers_count);
    query(card, '.github-repo-card__forks-count').textContent = compactNumber(data.forks_count);

    if (data.language) {
      query(card, '.github-repo-card__language-name').textContent = data.language;
      query(card, '.github-repo-card__language-color').style.backgroundColor = languageColors[data.language] || '#8b949e';
      language.hidden = false;
    }

    if (data.license && data.license.spdx_id && data.license.spdx_id !== 'NOASSERTION') {
      license.textContent = data.license.spdx_id;
      license.hidden = false;
    }

    if (data.pushed_at) {
      var date = new Date(data.pushed_at);
      updated.dateTime = data.pushed_at;
      updated.textContent = '更新于 ' + date.toLocaleDateString('zh-CN');
      updated.hidden = false;
    }

    meta.hidden = false;
    card.classList.add('is-loaded');
    card.setAttribute('aria-busy', 'false');
  }

  function renderError(card) {
    query(card, '.github-repo-card__description').textContent = '仓库信息暂时无法加载，点击可直接前往 GitHub。';
    card.classList.add('has-error');
    card.setAttribute('aria-busy', 'false');
  }

  function load(card) {
    var repo = (card.getAttribute('data-github-repo') || '').trim();
    var parts = repo.split('/').filter(Boolean);
    if (parts.length !== 2) {
      renderError(card);
      return;
    }

    var cached = readCache(repo);
    if (cached) {
      render(card, cached);
      return;
    }

    var apiPath = parts.map(encodeURIComponent).join('/');
    fetch(API_ROOT + apiPath, { headers: { Accept: 'application/vnd.github+json' } })
      .then(function (response) {
        if (!response.ok) throw new Error('GitHub API returned ' + response.status);
        return response.json();
      })
      .then(function (data) {
        writeCache(repo, data);
        render(card, data);
      })
      .catch(function () {
        renderError(card);
      });
  }

  function init() {
    var cards = document.querySelectorAll('[data-github-repo]');
    if (!('IntersectionObserver' in window)) {
      cards.forEach(load);
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        observer.unobserve(entry.target);
        load(entry.target);
      });
    }, { rootMargin: '320px 0px' });

    cards.forEach(function (card) { observer.observe(card); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
