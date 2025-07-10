document.addEventListener('DOMContentLoaded', function() {
  // 等待页面完全加载
  setTimeout(function() {
    const tocLinks = document.querySelectorAll('.toc a[href^="#"]');
    
    // 收集所有有效的标题元素
    const headings = [];
    tocLinks.forEach(link => {
      const href = link.getAttribute('href');
      if (href && href.startsWith('#')) {
        const id = href.substring(1);
        const heading = document.getElementById(id);
        if (heading) {
          headings.push({
            element: heading,
            link: link,
            id: id
          });
        } else {
          console.warn('找不到标题元素:', id);
        }
      }
    });
    
    if (headings.length === 0) {
      console.warn('没有找到有效的标题元素，可能需要检查目录生成或标题ID');
      return;
    }
    
    // 按页面位置排序
    headings.sort((a, b) => a.element.offsetTop - b.element.offsetTop);
    
    function highlightCurrentSection() {
      const scrollPos = window.scrollY + 100; // 偏移量
      let current = null;
      
      // 找到当前应该高亮的标题
      for (let i = 0; i < headings.length; i++) {
        if (headings[i].element.offsetTop <= scrollPos) {
          current = headings[i];
        } else {
          break;
        }
      }
      
      // 移除所有高亮
      headings.forEach(heading => {
        heading.link.classList.remove('active');
      });
      
      // 添加当前高亮
      if (current) {
        current.link.classList.add('active');
      }
    }
    
    // 防抖函数，提高性能
    let scrollTimeout;
    function throttledHighlight() {
      if (scrollTimeout) {
        clearTimeout(scrollTimeout);
      }
      scrollTimeout = setTimeout(highlightCurrentSection, 10);
    }
    
    window.addEventListener('scroll', throttledHighlight);
    highlightCurrentSection(); // 初始化
    
  }, 500); // 延迟500ms确保页面完全加载
});