// ============================================
// TABLE OF CONTENTS (TOC) - CONFIGURATION
// ============================================

const TOC_CONFIG = {
  // Scroll behavior
  scrollOffset: 100,           // Offset from top when calculating active section
  debounceDelay: 10,           // Debounce delay for scroll events (ms)
  initDelay: 500,              // Delay before initialization (ms)

  // CSS selectors
  tocSelector: '.toc',
  tocContainerSelector: '.toc-container',
  tocLinkSelector: '.toc a[href^="#"]',
  contentSelector: '.post-content',

  // Class names
  activeClass: 'active',
  collapsedClass: 'collapsed',
  visibleClass: 'visible',
  hiddenClass: 'toc-hidden',

  // Auto-hide settings
  autoHideBreakpoint: 1200,    // Viewport width below which TOC can auto-hide
  storageKey: 'toc-visible',   // localStorage key for user preference

  // Diary-specific
  diaryPath: '/diary'          // URL path pattern for diary pages
};

// ============================================
// CORE TOC FUNCTIONALITY
// ============================================

const TocHighlighter = {
  headings: [],
  tocLinks: null,

  /**
   * Initialize the TOC highlighter
   */
  init() {
    this.collectHeadings();

    if (this.headings.length === 0) {
      console.warn('没有找到有效的标题元素，可能需要检查目录生成或标题ID');
      return false;
    }

    this.setupScrollListener();
    this.highlightCurrent();
    return true;
  },

  /**
   * Collect all valid heading elements referenced in TOC
   */
  collectHeadings() {
    this.headings = [];
    this.tocLinks = document.querySelectorAll(TOC_CONFIG.tocLinkSelector);

    this.tocLinks.forEach(link => {
      const href = link.getAttribute('href');
      if (href && href.startsWith('#')) {
        const id = href.substring(1);
        const heading = document.getElementById(id);

        if (heading) {
          this.headings.push({
            element: heading,
            link: link,
            id: id
          });
        } else {
          console.warn('找不到标题元素:', id);
        }
      }
    });
  },

  /**
   * Highlight the current section based on scroll position
   */
  highlightCurrent() {
    const scrollPos = window.scrollY + TOC_CONFIG.scrollOffset;
    let current = null;

    // Find the heading that should be highlighted
    for (let i = 0; i < this.headings.length; i++) {
      if (this.headings[i].element.offsetTop <= scrollPos) {
        current = this.headings[i];
      } else {
        break;
      }
    }

    // Remove all highlights
    this.headings.forEach(heading => {
      heading.link.classList.remove(TOC_CONFIG.activeClass);
    });

    // Add highlight to current section
    if (current) {
      current.link.classList.add(TOC_CONFIG.activeClass);
    }

    return current;
  },

  /**
   * Setup scroll event listener with debouncing
   */
  setupScrollListener() {
    let scrollTimeout;

    const throttledHighlight = () => {
      if (scrollTimeout) {
        clearTimeout(scrollTimeout);
      }
      scrollTimeout = setTimeout(() => {
        this.highlightCurrent();
      }, TOC_CONFIG.debounceDelay);
    };

    window.addEventListener('scroll', throttledHighlight);
  }
};

// ============================================
// DIARY-SPECIFIC TOC EXTENSION
// ============================================

const DiaryTocExtension = {
  mostRecentLink: null,
  lastHeading: null,

  /**
   * Check if current page is a diary page
   */
  isDiaryPage() {
    return window.location.pathname.startsWith(TOC_CONFIG.diaryPath);
  },

  /**
   * Initialize diary-specific features
   */
  init() {
    if (!this.isDiaryPage()) {
      return false;
    }

    this.addMostRecentLink();
    this.setupMostRecentHighlight();
    return true;
  },

  /**
   * Add "Most Recent" link to TOC for diary pages
   */
  addMostRecentLink() {
    const allHeads = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
    this.lastHeading = allHeads[allHeads.length - 3];

    if (!this.lastHeading) {
      console.warn('找不到最后的标题元素');
      return;
    }

    const tocContainer = document.querySelector(TOC_CONFIG.tocSelector);
    if (!tocContainer) {
      return;
    }

    let tocList = tocContainer.querySelector('ul');
    if (!tocList) {
      tocList = document.createElement('ul');
      tocContainer.appendChild(tocList);
    }

    // Remove existing "Most Recent" link if present
    const existingItem = tocList.querySelector('li.toc-most-recent');
    if (existingItem) {
      existingItem.remove();
    }

    // Create and add new "Most Recent" link
    const listItem = document.createElement('li');
    listItem.classList.add('toc-most-recent');

    this.mostRecentLink = document.createElement('a');
    this.mostRecentLink.textContent = 'Most Recent';
    this.mostRecentLink.href = `#${this.lastHeading.id}`;

    listItem.appendChild(this.mostRecentLink);
    tocList.insertBefore(listItem, tocList.firstChild);
  },

  /**
   * Setup highlighting for "Most Recent" link
   */
  setupMostRecentHighlight() {
    if (!this.mostRecentLink || !this.lastHeading) {
      return;
    }

    // Extend the highlightCurrent function to handle "Most Recent" link
    const originalHighlight = TocHighlighter.highlightCurrent.bind(TocHighlighter);

    TocHighlighter.highlightCurrent = () => {
      const current = originalHighlight();

      // Remove highlight from "Most Recent" link
      this.mostRecentLink.classList.remove(TOC_CONFIG.activeClass);

      // Add highlight if current section is the last heading
      if (current && current.element === this.lastHeading) {
        this.mostRecentLink.classList.add(TOC_CONFIG.activeClass);
      }
    };
  }
};

// ============================================
// AUTO-HIDE TOC FUNCTIONALITY
// ============================================

const TocAutoHide = {
  tocContainer: null,
  toggleButton: null,
  isVisible: true,

  /**
   * Initialize auto-hide functionality
   */
  init() {
    this.tocContainer = document.querySelector(TOC_CONFIG.tocContainerSelector);

    if (!this.tocContainer) {
      return false;
    }

    // Load saved state from localStorage
    this.loadState();

    // Create toggle button
    this.createToggleButton();

    // Setup viewport checking
    this.checkViewport();
    this.setupResizeListener();

    return true;
  },

  /**
   * Create toggle button for manual show/hide
   */
  createToggleButton() {
    this.toggleButton = document.createElement('button');
    this.toggleButton.className = 'toc-toggle';
    this.toggleButton.innerHTML = '☰'; // Menu icon
    this.toggleButton.setAttribute('aria-label', 'Toggle table of contents');
    this.toggleButton.title = 'Toggle table of contents';

    this.toggleButton.addEventListener('click', () => {
      this.toggle();
    });

    document.body.appendChild(this.toggleButton);
  },

  /**
   * Check viewport width and show/hide toggle button
   */
  checkViewport() {
    const width = window.innerWidth;

    // On mobile (below 768px), don't use auto-hide
    if (width <= 768) {
      this.hideToggleButton();
      this.show(false); // Show TOC, don't save state
      return;
    }

    // Show toggle button if viewport is below breakpoint
    if (width < TOC_CONFIG.autoHideBreakpoint) {
      this.showToggleButton();

      // If no saved state, auto-hide on narrow screens
      const savedState = localStorage.getItem(TOC_CONFIG.storageKey);
      if (savedState === null) {
        this.hide(false); // Hide TOC, don't save state
      }
    } else {
      this.hideToggleButton();
      this.show(false); // Show TOC on wide screens, don't save state
    }
  },

  /**
   * Setup resize event listener
   */
  setupResizeListener() {
    let resizeTimeout;

    window.addEventListener('resize', () => {
      if (resizeTimeout) {
        clearTimeout(resizeTimeout);
      }

      resizeTimeout = setTimeout(() => {
        this.checkViewport();
      }, 100);
    });
  },

  /**
   * Toggle TOC visibility
   */
  toggle() {
    if (this.isVisible) {
      this.hide();
    } else {
      this.show();
    }
  },

  /**
   * Show TOC
   * @param {boolean} saveState - Whether to save state to localStorage
   */
  show(saveState = true) {
    this.isVisible = true;
    this.tocContainer.classList.remove(TOC_CONFIG.collapsedClass);

    if (this.toggleButton) {
      this.toggleButton.classList.remove(TOC_CONFIG.hiddenClass);
      this.toggleButton.innerHTML = '☰';
      this.toggleButton.title = 'Hide table of contents';
    }

    if (saveState) {
      this.saveState();
    }
  },

  /**
   * Hide TOC
   * @param {boolean} saveState - Whether to save state to localStorage
   */
  hide(saveState = true) {
    this.isVisible = false;
    this.tocContainer.classList.add(TOC_CONFIG.collapsedClass);

    if (this.toggleButton) {
      this.toggleButton.classList.add(TOC_CONFIG.hiddenClass);
      this.toggleButton.innerHTML = '☰';
      this.toggleButton.title = 'Show table of contents';
    }

    if (saveState) {
      this.saveState();
    }
  },

  /**
   * Show toggle button
   */
  showToggleButton() {
    if (this.toggleButton) {
      this.toggleButton.classList.add(TOC_CONFIG.visibleClass);
    }
  },

  /**
   * Hide toggle button
   */
  hideToggleButton() {
    if (this.toggleButton) {
      this.toggleButton.classList.remove(TOC_CONFIG.visibleClass);
    }
  },

  /**
   * Save visibility state to localStorage
   */
  saveState() {
    localStorage.setItem(TOC_CONFIG.storageKey, this.isVisible ? 'true' : 'false');
  },

  /**
   * Load visibility state from localStorage
   */
  loadState() {
    const saved = localStorage.getItem(TOC_CONFIG.storageKey);

    if (saved !== null) {
      this.isVisible = saved === 'true';

      if (this.isVisible) {
        this.tocContainer.classList.remove(TOC_CONFIG.collapsedClass);
      } else {
        this.tocContainer.classList.add(TOC_CONFIG.collapsedClass);
      }
    }
  }
};

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', function() {
  // Wait for page to fully load before initializing TOC
  setTimeout(function() {
    // Initialize core TOC functionality
    const tocInitialized = TocHighlighter.init();

    if (!tocInitialized) {
      return;
    }

    // Initialize diary-specific features if on diary page
    DiaryTocExtension.init();

    // Initialize auto-hide functionality
    TocAutoHide.init();

  }, TOC_CONFIG.initDelay);
});
