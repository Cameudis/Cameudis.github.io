/**
 * post.js - Interactivity for Retro-Modern Blog Posts
 * 
 * Features:
 * - Table of Contents (TOC) Scroll-Spy (Refined)
 * - Diary-specific "Most Recent" functionality
 */

const postScript = document.currentScript;
const externalIconManifestUrl = postScript?.dataset.externalIconManifest;

document.addEventListener('DOMContentLoaded', () => {
  // 1. Code block chrome and copy controls
  const codeBlocks = Array.from(
    document.querySelectorAll('.post-content .highlight > pre > code')
  ).filter(code => !code.classList.contains('language-mermaid') && !code.closest('.language-mermaid'));
  const copyText = async text => {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return;
      } catch (error) {
        // Fall through for browsers that expose the API but deny permission.
      }
    }

    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.setAttribute('readonly', '');
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.select();
    const copied = document.execCommand('copy');
    textArea.remove();
    if (!copied) throw new Error('Copy command was rejected');
  };

  codeBlocks.forEach(code => {
    const highlight = code.closest('div.highlight');
    if (!highlight || highlight.dataset.codeFrameReady === 'true') return;

    const languageContainer = highlight.parentElement;
    const languageClass = languageContainer
      ? Array.from(languageContainer.classList).find(className => className.startsWith('language-'))
      : null;
    const language = languageClass ? languageClass.replace('language-', '') : 'code';
    const frame = languageContainer && languageContainer.classList.contains('highlighter-rouge')
      ? languageContainer
      : highlight;

    frame.classList.add('code-frame');
    highlight.dataset.codeFrameReady = 'true';

    const toolbar = document.createElement('div');
    toolbar.className = 'code-toolbar';

    const label = document.createElement('span');
    label.className = 'code-language';
    label.textContent = language === 'plaintext' ? 'TEXT' : language.toUpperCase();

    const copyButton = document.createElement('button');
    copyButton.className = 'code-copy-button';
    copyButton.type = 'button';
    copyButton.textContent = 'COPY';
    copyButton.setAttribute('aria-label', `Copy ${label.textContent} code`);

    copyButton.addEventListener('click', async () => {
      try {
        await copyText(code.textContent);
        copyButton.textContent = 'COPIED';
        copyButton.classList.add('is-copied');
      } catch (error) {
        copyButton.textContent = 'ERROR';
        copyButton.classList.add('is-error');
      }

      window.setTimeout(() => {
        copyButton.textContent = 'COPY';
        copyButton.classList.remove('is-copied', 'is-error');
      }, 1800);
    });

    toolbar.append(label, copyButton);
    frame.insertBefore(toolbar, highlight);
  });

  // 2. Locally cached favicons for ordinary external links
  const decorateExternalLinks = async () => {
    if (!externalIconManifestUrl) return;

    const links = Array.from(document.querySelectorAll('.post-content a[href]')).filter(link => {
      if (link.closest('.link-preview, .github-repo-card, .static-tweet')) return false;
      if (link.querySelector('img, svg')) return false;

      try {
        const url = new URL(link.href, window.location.href);
        return (url.protocol === 'http:' || url.protocol === 'https:') && url.origin !== window.location.origin;
      } catch (_) {
        return false;
      }
    });
    if (links.length === 0) return;

    try {
      const response = await fetch(externalIconManifestUrl, { credentials: 'same-origin' });
      if (!response.ok) return;

      const manifest = await response.json();
      const iconBaseUrl = new URL('./', new URL(externalIconManifestUrl, window.location.href));

      links.forEach(link => {
        const host = new URL(link.href, window.location.href).hostname.toLowerCase();
        const filename = manifest.icons?.[host];
        if (!filename) return;

        const icon = document.createElement('img');
        icon.className = 'external-link-icon';
        icon.alt = '';
        icon.width = 14;
        icon.height = 14;
        icon.decoding = 'async';
        icon.fetchPriority = 'low';
        icon.setAttribute('aria-hidden', 'true');
        const markLoaded = () => link.classList.add('has-external-link-icon');
        icon.addEventListener('load', markLoaded, { once: true });
        icon.addEventListener('error', () => icon.remove(), { once: true });
        icon.src = new URL(filename, iconBaseUrl).href;
        link.prepend(icon);

        // A memory-cached image can finish before event delivery on some browsers.
        if (icon.complete && icon.naturalWidth > 0) markLoaded();
      });
    } catch (_) {
      // The existing external-link arrow remains the fallback.
    }
  };

  decorateExternalLinks();

  // 3. Table of Contents (TOC) Scroll-Spy
  const tocContainer = document.querySelector('.post-toc');
  const tocToggle = tocContainer?.querySelector('.toc-toggle');
  const tocLinks = document.querySelectorAll('.post-toc a[href^="#"]');
  const contentHeadings = [];

  if (tocContainer && tocToggle) {
    const setTocOpen = (open) => {
      tocContainer.classList.toggle('is-open', open);
      tocToggle.setAttribute('aria-expanded', String(open));
    };

    tocToggle.addEventListener('click', () => {
      setTocOpen(!tocContainer.classList.contains('is-open'));
    });

    tocLinks.forEach((link) => {
      link.addEventListener('click', () => {
        if (window.matchMedia('(max-width: 600px) and (hover: none) and (pointer: coarse)').matches) {
          setTocOpen(false);
        }
      });
    });
  }

  if (tocLinks.length > 0 && tocContainer) {
    let currentActiveLink = null;

    // Collect headings and their corresponding TOC links
    tocLinks.forEach(link => {
      const id = decodeURIComponent(link.getAttribute('href').substring(1));
      const heading = document.getElementById(id);
      if (heading) {
        contentHeadings.push({ heading, link });
      }
    });

    const highlightToc = () => {
      // Use a 100px offset from the top for activation
      const scrollPos = window.scrollY + 120;
      let activeItem = null;

      // Find the most recent heading that has passed the scroll threshold
      for (let i = 0; i < contentHeadings.length; i++) {
        if (contentHeadings[i].heading.offsetTop <= scrollPos) {
          activeItem = contentHeadings[i];
        } else {
          // Headings are sorted by position, so we can stop here
          break;
        }
      }

      // Update the active link and expand only its top-level section. On
      // narrower layouts CSS keeps all subsections visible.
      tocLinks.forEach(link => link.classList.remove('active'));
      const activeSection = activeItem
        ? activeItem.link.closest('.post-toc > ul > li')
        : null;
      tocContainer.querySelectorAll(':scope > ul > li').forEach(item => {
        item.classList.toggle('is-expanded', item === activeSection);
        item.classList.toggle('is-current', item === activeSection);
      });

      if (activeItem) {
        activeItem.link.classList.add('active');

        // Keep the current item visible inside a long floating TOC without
        // moving the page itself.
        if (activeItem.link !== currentActiveLink && window.innerWidth > 1399) {
          const tocRect = tocContainer.getBoundingClientRect();
          const linkRect = activeItem.link.getBoundingClientRect();
          if (linkRect.top < tocRect.top || linkRect.bottom > tocRect.bottom) {
            tocContainer.scrollTo({
              top: tocContainer.scrollTop + linkRect.top - tocRect.top - tocRect.height / 2,
              behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'
            });
          }
        }

        currentActiveLink = activeItem.link;
      }
    };

    // Scroll listener with simple throttling
    let isScrolling = false;
    window.addEventListener('scroll', () => {
      if (!isScrolling) {
        window.requestAnimationFrame(() => {
          highlightToc();
          isScrolling = false;
        });
        isScrolling = true;
      }
    }, { passive: true });

    // Initial highlight
    highlightToc();
  }

  // 4. Diary-specific Features
  const isDiaryPage = window.location.pathname.includes('/diary/');

  if (isDiaryPage && tocContainer) {
    const tocList = tocContainer.querySelector('ul');
    if (tocList) {
      const allHeadings = document.querySelectorAll('.post-content h1, .post-content h2, .post-content h3');

      if (allHeadings.length > 0) {
        const latestHeading = allHeadings[allHeadings.length - 1];

        const recentLi = document.createElement('li');
        const recentLink = document.createElement('a');
        recentLink.href = `#${latestHeading.id}`;
        recentLink.textContent = '[ MOST_RECENT ]';
        recentLink.className = 'diary-recent-link';
        recentLink.style.fontWeight = 'bold';
        recentLink.style.color = 'var(--brand-color, #5e81ac)';
        recentLink.style.display = 'block';
        recentLink.style.marginBottom = '10px';

        recentLi.appendChild(recentLink);
        tocList.insertBefore(recentLi, tocList.firstChild);

        // Add active state to "Most Recent" if the last heading is active
        window.addEventListener('scroll', () => {
          if (latestHeading.offsetTop <= window.scrollY + 120) {
            recentLink.classList.add('active');
          } else {
            recentLink.classList.remove('active');
          }
        }, { passive: true });
      }
    }
  }
});
