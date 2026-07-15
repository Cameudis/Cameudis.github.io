/** Footer uptime and opt-in visitor map loader. */
(function () {
  'use strict';

  function updateUptime() {
    const output = document.getElementById('site-uptime');
    if (!output) return;

    const diff = Date.now() - new Date('2022-07-16T00:00:00').getTime();
    if (diff < 0) return;

    const years = Math.floor(diff / 31536000000);
    const days = Math.floor((diff % 31536000000) / 86400000);
    const hours = Math.floor((diff % 86400000) / 3600000);
    const mins = Math.floor((diff % 3600000) / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    output.textContent = `${years}y ${days}d ${hours}h ${mins}m ${secs}s`;
  }

  function escapeAttribute(value) {
    return value.replace(/[&<>"']/g, (character) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[character]);
  }

  function initVisitorMap() {
    const button = document.querySelector('.footer-map-load');
    if (!button) return;

    button.addEventListener('click', () => {
      let mapUrl;
      try {
        const parsed = new URL(button.dataset.mapSrc);
        if (parsed.protocol !== 'https:') throw new Error('Only HTTPS is allowed');
        mapUrl = parsed.href;
      } catch (error) {
        button.textContent = 'VISITOR_MAP_UNAVAILABLE';
        button.disabled = true;
        return;
      }

      const frame = document.createElement('iframe');
      frame.className = 'footer-map-frame';
      frame.title = 'Visitor map';
      frame.loading = 'lazy';
      frame.setAttribute('sandbox', 'allow-scripts allow-popups allow-popups-to-escape-sandbox');
      frame.width = '240';
      frame.height = '150';
      frame.srcdoc = `<!doctype html><meta charset="utf-8"><style>html,body{margin:0;background:transparent;color-scheme:dark}</style><script src="${escapeAttribute(mapUrl)}"><\/script>`;
      button.replaceWith(frame);
    }, { once: true });
  }

  updateUptime();
  window.setInterval(updateUptime, 1000);
  initVisitorMap();
}());
