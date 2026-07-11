/**
 * search.js - Algolia-powered search modal
 *
 * Expects the page to define `window.BLOG_SEARCH_CONFIG` with:
 *   { appId, apiKey, indexName }
 * and to contain the search overlay DOM (#search-toggle, #search-overlay,
 * #search-close, #search-input, #search-results).
 */
(function () {
  const cfg = window.BLOG_SEARCH_CONFIG;
  if (!cfg) return;

  // Defer until DOM is ready.
  function init() {
    const searchClient = algoliasearch(cfg.appId, cfg.apiKey);
    const index = searchClient.initIndex(cfg.indexName);

    const searchToggle = document.getElementById('search-toggle');
    const searchOverlay = document.getElementById('search-overlay');
    const searchClose = document.getElementById('search-close');
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');

    if (!searchToggle || !searchOverlay || !searchClose || !searchInput || !searchResults) return;

    let searchTimeout;

    searchToggle.addEventListener('click', function () {
      searchOverlay.classList.add('active');
      searchInput.focus();
    });

    function closeSearch() {
      searchOverlay.classList.remove('active');
      searchInput.value = '';
      searchResults.replaceChildren();
    }

    searchClose.addEventListener('click', closeSearch);

    // 点击遮罩关闭
    searchOverlay.addEventListener('click', function (e) {
      if (e.target === searchOverlay) {
        closeSearch();
      }
    });

    // ESC 键关闭
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && searchOverlay.classList.contains('active')) {
        closeSearch();
      }
    });

    // 搜索功能
    searchInput.addEventListener('input', function () {
      const query = this.value.trim();

      clearTimeout(searchTimeout);

      if (query.length === 0) {
        searchResults.replaceChildren();
        return;
      }

      // 防抖处理
      searchTimeout = setTimeout(() => {
        performSearch(query);
      }, 300);
    });

    function performSearch(query) {
      index.search(query, {
        hitsPerPage: 10,
        attributesToHighlight: ['title', 'content'],
        highlightPreTag: '<span class="search-highlight">',
        highlightPostTag: '</span>'
      }).then(({ hits }) => {
        displayResults(hits);
      }).catch(error => {
        console.error('搜索错误:', error);
        displayMessage('搜索出错，请稍后重试');
      });
    }

    function displayMessage(message) {
      const element = document.createElement('div');
      element.className = 'search-no-results';
      element.textContent = message;
      searchResults.replaceChildren(element);
    }

    function normalizeResultUrl(value) {
      if (typeof value !== 'string') return '#';

      try {
        const url = new URL(value, window.location.origin);
        if (url.origin !== window.location.origin) return '#';
        return `${url.pathname}${url.search}${url.hash}`;
      } catch (error) {
        return '#';
      }
    }

    function plainText(value) {
      const parser = new DOMParser();
      const document = parser.parseFromString(String(value || ''), 'text/html');
      return document.body.textContent || '';
    }

    function displayResults(hits) {
      if (hits.length === 0) {
        displayMessage('没有找到相关内容');
        return;
      }

      const fragment = document.createDocumentFragment();

      hits.forEach(hit => {
        const title = plainText(hit._highlightResult?.title?.value || hit.title || '无标题');
        const excerpt = hit._highlightResult?.content?.value || hit.excerpt || hit.content || '';
        const url = normalizeResultUrl(hit.url);
        const date = plainText(hit.date);
        const cleanExcerpt = plainText(excerpt).substring(0, 150);

        const result = document.createElement('article');
        result.className = 'search-result';

        const heading = document.createElement('h3');
        const link = document.createElement('a');
        link.href = url;
        link.textContent = title;
        heading.appendChild(link);
        result.appendChild(heading);

        const summary = document.createElement('p');
        summary.textContent = `${cleanExcerpt}${cleanExcerpt.length === 150 ? '...' : ''}`;
        result.appendChild(summary);

        if (date) {
          const timestamp = document.createElement('small');
          timestamp.textContent = date;
          result.appendChild(timestamp);
        }

        fragment.appendChild(result);
      });

      searchResults.replaceChildren(fragment);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
