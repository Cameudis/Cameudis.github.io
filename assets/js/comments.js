/** Load Valine only when the reader approaches or explicitly opens comments. */
(function () {
  'use strict';

  function init() {
    const comments = document.getElementById('comments');
    const loadButton = comments?.querySelector('.comments-load');
    if (!comments || !loadButton) return;

    let loading = false;
    let observer;

    function setButton(message, disabled) {
      loadButton.textContent = message;
      loadButton.disabled = disabled;
    }

    function mountComments() {
      new window.Valine({
        el: '#comments',
        app_id: comments.dataset.appId,
        app_key: comments.dataset.appKey,
        placeholder: comments.dataset.placeholder
      });
    }

    function loadComments() {
      if (loading) return;

      if (window.Valine) {
        try {
          mountComments();
        } catch (error) {
          console.error('评论初始化失败:', error);
          setButton('评论加载失败，点击重试', false);
        }
        return;
      }

      loading = true;
      setButton('LOADING_COMMENTS…', true);
      observer?.disconnect();

      const script = document.createElement('script');
      script.src = comments.dataset.valineUrl;
      script.async = true;

      script.addEventListener('load', () => {
        try {
          mountComments();
        } catch (error) {
          console.error('评论初始化失败:', error);
          loading = false;
          setButton('评论加载失败，点击重试', false);
        }
      }, { once: true });

      script.addEventListener('error', () => {
        script.remove();
        loading = false;
        setButton('评论加载失败，点击重试', false);
      }, { once: true });

      document.head.appendChild(script);
    }

    loadButton.addEventListener('click', loadComments);

    if ('IntersectionObserver' in window) {
      observer = new IntersectionObserver((entries) => {
        if (entries.some((entry) => entry.isIntersecting)) loadComments();
      }, { rootMargin: '600px 0px' });
      observer.observe(comments);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
}());
