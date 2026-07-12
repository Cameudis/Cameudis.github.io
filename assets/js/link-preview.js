(function () {
  'use strict';

  var API_URL = 'https://api.microlink.io/?url=';
  var CACHE_PREFIX = 'link-preview:';
  var CACHE_TTL = 24 * 60 * 60 * 1000;

  function query(card, selector) {
    return card.querySelector(selector);
  }

  function safeMediaUrl(value) {
    if (!value) return '';
    try {
      var url = new URL(value, window.location.href);
      return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : '';
    } catch (_) {
      return '';
    }
  }

  function readCache(url) {
    try {
      var cached = JSON.parse(localStorage.getItem(CACHE_PREFIX + url));
      if (cached && Date.now() - cached.savedAt < CACHE_TTL) return cached.data;
    } catch (_) {
      // Link previews still work when storage is disabled.
    }
    return null;
  }

  function writeCache(url, data) {
    try {
      localStorage.setItem(CACHE_PREFIX + url, JSON.stringify({ savedAt: Date.now(), data: data }));
    } catch (_) {
      // Ignore unavailable or full storage.
    }
  }

  function render(card, data) {
    var manualTitle = card.getAttribute('data-manual-title');
    var manualDescription = card.getAttribute('data-manual-description');
    var manualImage = card.getAttribute('data-manual-image');
    var imageUrl = safeMediaUrl(manualImage || (data.image && data.image.url));
    var logoUrl = safeMediaUrl(data.logo && data.logo.url);

    query(card, '.link-preview__title').textContent = manualTitle || data.title || card.getAttribute('data-link-preview');
    query(card, '.link-preview__description').textContent = manualDescription || data.description || '点击查看链接内容。';
    var resolvedUrl = data.url || card.getAttribute('data-link-preview');
    query(card, '.link-preview__site-name').textContent = data.publisher || data.siteName || data.author || new URL(resolvedUrl).hostname;

    if (imageUrl) {
      var image = query(card, '.link-preview__image');
      image.addEventListener('error', function () { image.hidden = true; }, { once: true });
      image.src = imageUrl;
      image.hidden = false;
    }

    if (logoUrl) {
      var favicon = query(card, '.link-preview__favicon');
      favicon.addEventListener('error', function () { favicon.hidden = true; }, { once: true });
      favicon.src = logoUrl;
      favicon.hidden = false;
    }

    card.classList.add('is-loaded');
    card.setAttribute('aria-busy', 'false');
  }

  function renderError(card) {
    var description = query(card, '.link-preview__description');
    if (!card.getAttribute('data-manual-description')) {
      description.textContent = '预览暂时无法加载，点击可直接访问链接。';
    }
    card.classList.add('has-error');
    card.setAttribute('aria-busy', 'false');
  }

  function load(card) {
    var url = (card.getAttribute('data-link-preview') || '').trim();
    try {
      var parsed = new URL(url);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new Error('Unsupported URL');
    } catch (_) {
      renderError(card);
      return;
    }

    var cached = readCache(url);
    if (cached) {
      render(card, cached);
      return;
    }

    fetch(API_URL + encodeURIComponent(url))
      .then(function (response) {
        if (!response.ok) throw new Error('Preview API returned ' + response.status);
        return response.json();
      })
      .then(function (result) {
        if (result.status !== 'success' || !result.data) throw new Error('Preview unavailable');
        writeCache(url, result.data);
        render(card, result.data);
      })
      .catch(function () {
        renderError(card);
      });
  }

  function init() {
    document.querySelectorAll('[data-link-preview]').forEach(load);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
