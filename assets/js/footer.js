/** Footer uptime and visitor map loader. */
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

  function initVisitorMap() {
    const container = document.querySelector('.footer-map-mini[data-map-src]');
    if (!container) return;

    let mapUrl;
    try {
      const parsed = new URL(container.dataset.mapSrc);
      if (parsed.protocol !== 'https:' || parsed.hostname !== 'mapmyvisitors.com') {
        throw new Error('Unexpected visitor map URL');
      }
      mapUrl = parsed.href;
    } catch (error) {
      container.textContent = 'VISITOR_MAP_UNAVAILABLE';
      return;
    }

    // The legacy JSONP endpoint is blocked in third-party iframe contexts, even
    // without sandboxing. Load it in the page like the vendor's original embed.
    // The vendor script keeps its bundled jQuery private via noConflict(true).
    const script = document.createElement('script');
    script.id = 'mapmyvisitors';
    script.src = mapUrl;
    script.async = true;
    script.referrerPolicy = 'strict-origin-when-cross-origin';
    script.addEventListener('error', () => {
      container.textContent = 'VISITOR_MAP_UNAVAILABLE';
    }, { once: true });
    container.appendChild(script);
  }

  updateUptime();
  window.setInterval(updateUptime, 1000);
  initVisitorMap();
}());
