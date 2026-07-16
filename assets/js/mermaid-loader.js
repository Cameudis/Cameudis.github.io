const sourceBlocks = Array.from(new Set([
  ...document.querySelectorAll('code.language-mermaid'),
  ...document.querySelectorAll('.language-mermaid pre > code')
]));

if (sourceBlocks.length > 0) {
  const loaderUrl = new URL(import.meta.url);
  const mermaidUrl = new URL('../vendor/mermaid/mermaid.esm.min.mjs', loaderUrl);
  const assetVersion = loaderUrl.searchParams.get('v');
  if (assetVersion) mermaidUrl.searchParams.set('v', assetVersion);

  let started = false;

  const sourceFrame = code => {
    const highlighted = code.closest('.language-mermaid.highlighter-rouge');
    return highlighted || code.closest('pre') || code;
  };

  const showLoadError = error => {
    console.error('Unable to load Mermaid.', error);
    sourceBlocks.forEach(code => {
      const frame = sourceFrame(code);
      if (frame.nextElementSibling?.classList.contains('mermaid-load-error')) return;

      const message = document.createElement('p');
      message.className = 'mermaid-load-error';
      message.setAttribute('role', 'status');
      message.textContent = 'Mermaid 图表加载失败，以下为图表源码。';
      frame.insertAdjacentElement('afterend', message);
    });
  };

  const start = async () => {
    if (started) return;
    started = true;

    let mermaid;
    try {
      ({ default: mermaid } = await import(mermaidUrl.href));
    } catch (error) {
      showLoadError(error);
      return;
    }

    if (document.fonts?.ready) await document.fonts.ready;

    const diagrams = sourceBlocks.map((code, index) => {
      const frame = sourceFrame(code);
      const source = code.textContent.trim();
      const figure = document.createElement('figure');
      const canvas = document.createElement('div');
      const errorMessage = document.createElement('p');

      figure.className = 'mermaid-diagram is-rendering';
      figure.dataset.mermaidIndex = String(index);
      figure.setAttribute('aria-busy', 'true');
      canvas.className = 'mermaid-diagram__canvas';
      errorMessage.className = 'mermaid-diagram__error';
      errorMessage.setAttribute('role', 'status');
      errorMessage.textContent = 'Mermaid 图表渲染失败，以下为图表源码。';
      errorMessage.hidden = true;
      frame.classList.add('mermaid-diagram__source');

      frame.replaceWith(figure);
      figure.append(canvas, errorMessage, frame);

      return { canvas, errorMessage, figure, frame, index, source };
    });

    const cssValue = (styles, name) => styles.getPropertyValue(name).trim();
    const configuration = theme => {
      const rootStyles = getComputedStyle(document.documentElement);
      const bodyStyles = getComputedStyle(document.body);

      return {
        startOnLoad: false,
        securityLevel: 'strict',
        suppressErrorRendering: true,
        theme: 'base',
        fontFamily: bodyStyles.fontFamily,
        themeVariables: {
          darkMode: theme === 'dark',
          background: cssValue(rootStyles, '--mermaid-background'),
          primaryColor: cssValue(rootStyles, '--mermaid-primary'),
          primaryTextColor: cssValue(rootStyles, '--mermaid-primary-text'),
          primaryBorderColor: cssValue(rootStyles, '--mermaid-primary-border'),
          secondaryColor: cssValue(rootStyles, '--mermaid-secondary'),
          tertiaryColor: cssValue(rootStyles, '--mermaid-tertiary'),
          lineColor: cssValue(rootStyles, '--mermaid-line'),
          textColor: cssValue(rootStyles, '--mermaid-primary-text'),
          mainBkg: cssValue(rootStyles, '--mermaid-primary'),
          secondBkg: cssValue(rootStyles, '--mermaid-secondary'),
          mainContrastColor: cssValue(rootStyles, '--mermaid-primary-text'),
          darkTextColor: cssValue(rootStyles, '--mermaid-primary-text'),
          defaultLinkColor: cssValue(rootStyles, '--mermaid-line'),
          edgeLabelBackground: cssValue(rootStyles, '--mermaid-background'),
          actorBkg: cssValue(rootStyles, '--mermaid-primary'),
          actorBorder: cssValue(rootStyles, '--mermaid-primary-border'),
          actorTextColor: cssValue(rootStyles, '--mermaid-primary-text'),
          actorLineColor: cssValue(rootStyles, '--mermaid-line'),
          activationBkgColor: cssValue(rootStyles, '--mermaid-secondary'),
          activationBorderColor: cssValue(rootStyles, '--mermaid-primary-border'),
          signalColor: cssValue(rootStyles, '--mermaid-line'),
          signalTextColor: cssValue(rootStyles, '--mermaid-primary-text'),
          labelBoxBkgColor: cssValue(rootStyles, '--mermaid-tertiary'),
          labelBoxBorderColor: cssValue(rootStyles, '--mermaid-primary-border'),
          labelTextColor: cssValue(rootStyles, '--mermaid-primary-text'),
          loopTextColor: cssValue(rootStyles, '--mermaid-primary-text'),
          noteBkgColor: cssValue(rootStyles, '--mermaid-note'),
          noteTextColor: cssValue(rootStyles, '--mermaid-note-text'),
          noteBorderColor: cssValue(rootStyles, '--mermaid-note-border')
        }
      };
    };

    let renderPass = 0;
    let renderedTheme = null;
    let renderPending = false;
    let rendering = false;

    const requestRender = async () => {
      renderPending = true;
      if (rendering) return;

      rendering = true;
      while (renderPending) {
        renderPending = false;
        const theme = document.documentElement.dataset.theme || 'dark';
        if (theme === renderedTheme) continue;

        const pass = ++renderPass;
        mermaid.initialize(configuration(theme));

        for (const diagram of diagrams) {
          diagram.figure.classList.add('is-rendering');
          diagram.figure.setAttribute('aria-busy', 'true');

          try {
            const result = await mermaid.render(
              `mermaid-${pass}-${diagram.index}`,
              diagram.source
            );

            diagram.canvas.innerHTML = result.svg;
            const svg = diagram.canvas.querySelector('svg');
            const viewBoxWidth = svg?.viewBox?.baseVal?.width || 0;
            const wideWidth = Math.min(Math.ceil(viewBoxWidth), 720);
            diagram.canvas.classList.toggle(
              'is-wide',
              wideWidth > diagram.canvas.clientWidth * 1.5
            );
            diagram.canvas.style.setProperty('--mermaid-wide-width', `${wideWidth}px`);
            result.bindFunctions?.(diagram.canvas);
            diagram.frame.hidden = true;
            diagram.errorMessage.hidden = true;
            diagram.figure.classList.remove('has-error');
          } catch (error) {
            console.error(`Unable to render Mermaid diagram ${diagram.index + 1}.`, error);
            if (!diagram.canvas.firstElementChild) diagram.frame.hidden = false;
            diagram.errorMessage.hidden = false;
            diagram.figure.classList.add('has-error');
          } finally {
            diagram.figure.classList.remove('is-rendering');
            diagram.figure.setAttribute('aria-busy', 'false');
          }
        }

        if ((document.documentElement.dataset.theme || 'dark') !== theme) {
          renderPending = true;
        } else {
          renderedTheme = theme;
        }
      }
      rendering = false;
    };

    document.addEventListener('themechange', requestRender);
    new MutationObserver(mutations => {
      if (mutations.some(mutation => mutation.attributeName === 'data-theme')) requestRender();
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    requestRender();
  };

  const firstFrame = sourceFrame(sourceBlocks[0]);
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(entries => {
      if (!entries.some(entry => entry.isIntersecting)) return;
      observer.disconnect();
      start();
    }, { rootMargin: '500px 0px' });
    observer.observe(firstFrame);
  } else {
    start();
  }

  window.addEventListener('beforeprint', start, { once: true });
}
