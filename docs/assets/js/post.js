/**
 * post.js - Interactivity for Retro-Modern Blog Posts
 * 
 * Features:
 * - Table of Contents (TOC) Scroll-Spy (Refined)
 * - Diary-specific "Most Recent" functionality
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Code block chrome and copy controls
  const codeBlocks = document.querySelectorAll('.post-content .highlight > pre > code');
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

  // 2. Table of Contents (TOC) Scroll-Spy
  const tocLinks = document.querySelectorAll('.post-toc a[href^="#"]');
  const contentHeadings = [];

  if (tocLinks.length > 0) {
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

      // Update classes
      tocLinks.forEach(link => link.classList.remove('active'));
      if (activeItem) {
        activeItem.link.classList.add('active');
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

  // 3. Diary-specific Features
  const isDiaryPage = window.location.pathname.includes('/diary/');
  const tocContainer = document.querySelector('.post-toc');

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
