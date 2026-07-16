(function () {
  'use strict';

  var API_URL = 'https://api.microlink.io/?url=';
  var CACHE_PREFIX = 'link-preview:v2:';
  var CACHE_TTL = 24 * 60 * 60 * 1000;
  var FETCH_TIMEOUT = 8000;

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

  function fetchWithTimeout(url, options) {
    if (!window.AbortController) return fetch(url, options);

    var controller = new AbortController();
    var timeout = window.setTimeout(function () { controller.abort(); }, FETCH_TIMEOUT);
    var requestOptions = Object.assign({}, options, { signal: controller.signal });

    return fetch(url, requestOptions).finally(function () {
      window.clearTimeout(timeout);
    });
  }

  function metaContent(documentNode, selectors) {
    for (var index = 0; index < selectors.length; index += 1) {
      var node = documentNode.querySelector(selectors[index]);
      if (node && node.content) return node.content.trim();
    }
    return '';
  }

  function absoluteMediaUrl(value, baseUrl) {
    if (!value) return '';
    try {
      return new URL(value, baseUrl).href;
    } catch (_) {
      return '';
    }
  }

  function documentMetadata(html, sourceUrl) {
    var documentNode = new DOMParser().parseFromString(html, 'text/html');
    var title = metaContent(documentNode, [
      'meta[property="og:title"]',
      'meta[name="twitter:title"]'
    ]) || (documentNode.querySelector('title') || {}).textContent || '';
    var description = metaContent(documentNode, [
      'meta[property="og:description"]',
      'meta[name="twitter:description"]',
      'meta[name="description"]'
    ]);
    var siteName = metaContent(documentNode, ['meta[property="og:site_name"]']);
    var image = metaContent(documentNode, [
      'meta[property="og:image"]',
      'meta[name="twitter:image"]'
    ]);
    var icon = documentNode.querySelector('link[rel~="icon"]');

    return {
      title: title.trim(),
      description: description,
      siteName: siteName,
      url: sourceUrl,
      image: image ? { url: absoluteMediaUrl(image, sourceUrl) } : null,
      logo: icon && icon.href ? { url: absoluteMediaUrl(icon.getAttribute('href'), sourceUrl) } : null
    };
  }

  function localPreviewUrl(card, targetUrl) {
    var siteUrl = card.getAttribute('data-site-url');
    if (!siteUrl) return '';

    try {
      var canonical = new URL(siteUrl);
      if (targetUrl.hostname !== canonical.hostname) return '';
      return new URL(targetUrl.pathname + targetUrl.search, window.location.origin).href;
    } catch (_) {
      return '';
    }
  }

  function fetchInternalMetadata(url) {
    return fetchWithTimeout(url, { headers: { Accept: 'text/html' } })
      .then(function (response) {
        if (!response.ok) throw new Error('Internal preview returned ' + response.status);
        return response.text();
      })
      .then(function (html) { return documentMetadata(html, url); });
  }

  function fetchExternalMetadata(url) {
    return fetchWithTimeout(API_URL + encodeURIComponent(url))
      .then(function (response) {
        if (!response.ok) throw new Error('Preview API returned ' + response.status);
        return response.json();
      })
      .then(function (result) {
        if (result.status !== 'success' || !result.data) throw new Error('Preview unavailable');
        return result.data;
      });
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
    var parsed;
    try {
      parsed = new URL(url);
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

    var internalUrl = localPreviewUrl(card, parsed);
    var request = internalUrl ? fetchInternalMetadata(internalUrl) : fetchExternalMetadata(url);

    request
      .then(function (data) {
        writeCache(url, data);
        render(card, data);
      })
      .catch(function () {
        renderError(card);
      });
  }

  function init() {
    var cards = document.querySelectorAll('[data-link-preview]');
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
