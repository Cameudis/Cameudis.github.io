/**
 * post.js - Interactivity for Retro-Modern Blog Posts
 * 
 * Features:
 * - Table of Contents (TOC) Scroll-Spy (Refined)
 * - Diary-specific "Most Recent" functionality
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Table of Contents (TOC) Scroll-Spy
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

  // 2. Diary-specific Features
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
