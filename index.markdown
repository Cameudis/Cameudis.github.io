---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

layout: home
---

<script src="https://unpkg.com/typed.js@2.1.0/dist/typed.umd.js"></script>

<style>
  .ascii-container {
    position: relative;
    display: inline-block;
    font-family: 'Courier New', monospace;
    white-space: pre;
    line-height: 1;
    font-size: 4px;
    background: #000;
    padding: 0px 20px;
    border-radius: 8px;
    overflow: hidden;
  }
  
  .ascii-art {
    position: relative;
    z-index: 2;
    color: #fff;
    transition: none;
    /* text-shadow: 0 0 10px rgba(255, 255, 255, 0.6),
                 0 0 20px rgba(255, 255, 255, 0.4),
                 0 0 30px rgba(211, 211, 211, 0.3); */
  }
  
  .ascii-glow {
    position: absolute;
    top: -20%;
    left: -20%;
    right: -20%;
    bottom: -20%;
    z-index: 1;
    background: linear-gradient(75deg, 
                                transparent 0%,
                                rgba(255, 255, 255, 0) calc(var(--mouse-x, 50%) - 120px), 
                                rgba(255, 255, 255, 0.1) calc(var(--mouse-x, 50%) - 80px), 
                                rgba(255, 255, 255, 0.6) calc(var(--mouse-x, 50%) - 40px), 
                                rgba(255, 255, 255, 0.9) var(--mouse-x, 50%), 
                                rgba(255, 255, 255, 0.6) calc(var(--mouse-x, 50%) + 40px), 
                                rgba(255, 255, 255, 0.1) calc(var(--mouse-x, 50%) + 80px), 
                                rgba(255, 255, 255, 0) calc(var(--mouse-x, 50%) + 120px),
                                transparent 100%);
    filter: blur(5px);
    opacity: 1;
    pointer-events: none;
    transform: skewX(-30deg);
  }
</style>

<!-- 径向渐变发光效果 - 绝对坐标鼠标跟踪 -->
<div class="ascii-container" id="asciiContainer1">
  <div class="ascii-art">
▄████████    ▄████████   ▄▄▄▄███▄▄▄▄      ▄████████ ███    █▄  ████████▄   ▄█     ▄████████ 
███    ███   ███    ███ ▄██▀▀▀███▀▀▀██▄   ███    ███ ███    ███ ███   ▀███ ███    ███    ███ 
███    █▀    ███    ███ ███   ███   ███   ███    █▀  ███    ███ ███    ███ ███▌   ███    █▀  
███          ███    ███ ███   ███   ███  ▄███▄▄▄     ███    ███ ███    ███ ███▌   ███        
███        ▀███████████ ███   ███   ███ ▀▀███▀▀▀     ███    ███ ███    ███ ███▌ ▀███████████ 
███    █▄    ███    ███ ███   ███   ███   ███    █▄  ███    ███ ███    ███ ███           ███ 
███    ███   ███    ███ ███   ███   ███   ███    ███ ███    ███ ███   ▄███ ███     ▄█    ███ 
████████▀    ███    █▀   ▀█   ███   █▀    ██████████ ████████▀  ████████▀  █▀    ▄████████▀  
  </div>
  <div class="ascii-glow" id="asciiGlow"></div>
</div>

<br>欢迎来到 **Y²** (a.k.a **cameudis**) 的博客！我是一个<span id="im"></span>

你可以在这里找到一些随机主题的技术相关或不相关文章。欢迎留言 （<ゝω・）☆>      

<!-- P.S. 本站基于 Jekyll 和 Github Pages 搭建，使用 Valine 作为评论系统。 -->

<script>
  // Typed.js 初始化
  var typed = new Typed('#im', {
    strings: [
        '计算机爱好者。',
        '复旦大学/上海交通大学学生。',
        '鼓手。',
        '一个一个。',
    ],
    typeSpeed: 50,
    backSpeed: 50,
    backDelay: 2500,
    loop: true,
  });

  // 绝对坐标发光效果（限制在ASCII容器内）
  const container1 = document.getElementById('asciiContainer1');
  
  // 监听整个页面的鼠标移动
  document.addEventListener('mousemove', (e) => {
    // 获取ASCII容器的位置信息
    const rect = container1.getBoundingClientRect();
    
    // 计算鼠标相对于ASCII容器的位置（像素值）
    const relativeX = e.clientX - 0.75 * rect.left;
    
    // 设置发光条的相对位置
    container1.style.setProperty('--mouse-x', relativeX + 'px');
  });
</script>