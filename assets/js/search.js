/**
 * Pagefind-powered search modal.
 *
 * The Pagefind runtime and index are loaded only when search is opened. The
 * generated bundle URL is provided by #search-overlay[data-pagefind-url].
 */
(function () {
  'use strict';

  function init() {
    const searchToggle = document.getElementById('search-toggle');
    const searchOverlay = document.getElementById('search-overlay');
    const searchModal = searchOverlay?.querySelector('.search-modal');
    const searchClose = document.getElementById('search-close');
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');

    if (!searchToggle || !searchOverlay || !searchModal || !searchClose || !searchInput || !searchResults) {
      return;
    }

    const pagefindUrl = searchOverlay.dataset.pagefindUrl;
    let pagefindPromise;
    let latestRequest = 0;
    let previousFocus = null;

    function loadPagefind() {
      if (!pagefindPromise) {
        pagefindPromise = import(pagefindUrl)
          .then(async (pagefind) => {
            await pagefind.options({ excerptLength: 32 });
            await pagefind.init();
            return pagefind;
          })
          .catch((error) => {
            pagefindPromise = null;
            throw error;
          });
      }
      return pagefindPromise;
    }

    function displayMessage(message, className = 'search-no-results') {
      const element = document.createElement('div');
      element.className = className;
      element.textContent = message;
      searchResults.replaceChildren(element);
    }

    function normalizeResultUrl(value) {
      if (typeof value !== 'string') return '#';

      try {
        const url = new URL(value, window.location.origin);
        if (url.origin !== window.location.origin) return '#';
        return `${url.pathname}${url.search}${url.hash}`;
      } catch (_) {
        return '#';
      }
    }

    function appendExcerpt(target, excerpt, fallback) {
      if (!excerpt) {
        target.textContent = fallback || '';
        return;
      }

      const template = document.createElement('template');
      template.innerHTML = excerpt;

      function appendNode(node, parent) {
        if (node.nodeType === Node.TEXT_NODE) {
          parent.appendChild(document.createTextNode(node.textContent || ''));
          return;
        }

        if (node.nodeType !== Node.ELEMENT_NODE) return;
        const nextParent = node.nodeName === 'MARK' ? document.createElement('mark') : parent;
        if (nextParent !== parent) parent.appendChild(nextParent);
        node.childNodes.forEach((child) => appendNode(child, nextParent));
      }

      template.content.childNodes.forEach((node) => appendNode(node, target));
    }

    function displayResults(results) {
      if (results.length === 0) {
        displayMessage('没有找到相关内容');
        return;
      }

      const fragment = document.createDocumentFragment();

      results.forEach((result) => {
        const article = document.createElement('article');
        article.className = 'search-result';

        const heading = document.createElement('h3');
        const link = document.createElement('a');
        link.href = normalizeResultUrl(result.url);
        link.textContent = result.meta?.title || '无标题';
        heading.appendChild(link);
        article.appendChild(heading);

        const summary = document.createElement('p');
        appendExcerpt(summary, result.excerpt, result.plain_excerpt);
        article.appendChild(summary);

        const metadata = [result.meta?.date, result.meta?.tags].filter(Boolean);
        if (metadata.length > 0) {
          const detail = document.createElement('small');
          detail.textContent = metadata.join(' · ');
          article.appendChild(detail);
        }

        fragment.appendChild(article);
      });

      searchResults.replaceChildren(fragment);
    }

    async function performSearch(query, requestId) {
      try {
        const pagefind = await loadPagefind();
        const response = await pagefind.debouncedSearch(query, {}, 250);
        if (!response || requestId !== latestRequest) return;

        const results = await Promise.all(
          response.results.slice(0, 10).map((result) => result.data())
        );
        if (requestId !== latestRequest) return;
        displayResults(results);
      } catch (error) {
        if (requestId !== latestRequest) return;
        console.error('搜索错误:', error);
        displayMessage('搜索暂时不可用，请稍后重试');
      }
    }

    function openSearch() {
      previousFocus = document.activeElement;
      searchOverlay.classList.add('active');
      searchOverlay.setAttribute('aria-hidden', 'false');
      document.body.classList.add('search-open');
      searchInput.focus();

      loadPagefind().catch((error) => {
        console.error('搜索索引加载错误:', error);
        displayMessage('搜索索引加载失败，请稍后重试');
      });
    }

    function closeSearch() {
      latestRequest += 1;
      searchOverlay.classList.remove('active');
      searchOverlay.setAttribute('aria-hidden', 'true');
      document.body.classList.remove('search-open');
      searchInput.value = '';
      searchResults.replaceChildren();

      if (previousFocus instanceof HTMLElement) previousFocus.focus();
      previousFocus = null;
    }

    function isTypingTarget(target) {
      return target instanceof HTMLElement && (
        target.isContentEditable || target.matches('input, textarea, select')
      );
    }

    searchToggle.addEventListener('click', openSearch);
    searchClose.addEventListener('click', closeSearch);

    searchOverlay.addEventListener('click', (event) => {
      if (event.target === searchOverlay) closeSearch();
    });

    searchInput.addEventListener('input', () => {
      const query = searchInput.value.trim();
      const requestId = ++latestRequest;

      if (!query) {
        searchResults.replaceChildren();
        return;
      }

      displayMessage('正在搜索…', 'search-loading');
      performSearch(query, requestId);
    });

    document.addEventListener('keydown', (event) => {
      const isOpen = searchOverlay.classList.contains('active');
      const shortcut = event.key === '/' || (
        (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k'
      );

      if (!isOpen && shortcut && !isTypingTarget(event.target)) {
        event.preventDefault();
        openSearch();
        return;
      }

      if (!isOpen) return;

      if (event.key === 'Escape') {
        event.preventDefault();
        closeSearch();
        return;
      }

      const resultLinks = Array.from(searchResults.querySelectorAll('a'));
      if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && resultLinks.length > 0) {
        const currentIndex = resultLinks.indexOf(document.activeElement);
        const offset = event.key === 'ArrowDown' ? 1 : -1;
        const nextIndex = currentIndex < 0
          ? (offset > 0 ? 0 : resultLinks.length - 1)
          : (currentIndex + offset + resultLinks.length) % resultLinks.length;
        event.preventDefault();
        resultLinks[nextIndex].focus();
        return;
      }

      if (event.key === 'Tab') {
        const focusable = [searchInput, searchClose, ...resultLinks];
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
