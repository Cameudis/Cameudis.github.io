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

    if (!searchToggle || !searchOverlay) return;

    let searchTimeout;

    searchToggle.addEventListener('click', function () {
      searchOverlay.classList.add('active');
      searchInput.focus();
    });

    function closeSearch() {
      searchOverlay.classList.remove('active');
      searchInput.value = '';
      searchResults.innerHTML = '';
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
        searchResults.innerHTML = '';
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
        displayResults(hits, query);
      }).catch(error => {
        console.error('搜索错误:', error);
        searchResults.innerHTML = '<div class="search-no-results">搜索出错，请稍后重试</div>';
      });
    }

    function displayResults(hits, query) {
      if (hits.length === 0) {
        searchResults.innerHTML = '<div class="search-no-results">没有找到相关内容</div>';
        return;
      }

      const resultsHtml = hits.map(hit => {
        const title = hit._highlightResult?.title?.value || hit.title || '无标题';
        const excerpt = hit._highlightResult?.content?.value || hit.excerpt || hit.content || '';
        const url = hit.url || '#';
        const date = hit.date || '';

        // 截取摘要
        const cleanExcerpt = excerpt.replace(/<[^>]*>/g, '').substring(0, 150);

        return `
        <div class="search-result" onclick="window.location.href='${url}'">
          <h3><a href="${url}">${title}</a></h3>
          <p>${cleanExcerpt}${cleanExcerpt.length === 150 ? '...' : ''}</p>
          ${date ? `<small>${date}</small>` : ''}
        </div>
      `;
      }).join('');

      searchResults.innerHTML = resultsHtml;
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();