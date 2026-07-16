# AGENTS.md

本博客基于 Jekyll + 重度魔改的 minima 主题，部署在 GitHub Pages（`gh-pages` 分支）。下面只列**非默认行为**和**踩坑点**，标准 Jekyll 知识不再赘述。

> 维护原则：项目更改后，如果有以后每次会话都需要的内容，就加到本文件中；其它内容不记录。

## 构建

- `_config.yml` 里 `destination: ./docs` —— **`docs/` 是 build 产物且提交进 git，Pages 直接从这个目录部署**。首次安装依赖运行 `npm ci`；改完源码后统一运行 `bin/build`（先规范化 Markdown 链接间距，再执行 Jekyll 和生成 Pagefind 索引），再连同 `docs/` 一起提交。工作区常有一堆 `M docs/*.html` 是正常的，不要手动编辑 `docs/*.html`，会被覆盖。
- `bin/build` 在 Jekyll 之后运行 `bin/cache-external-link-icons`：扫描生成页面中的外链，按域名抓取 favicon，压成 32×32 PNG 缓存到 `assets/external-link-icons/`，并同步到 `docs/`。抓取会读取实际链接页的 icon 声明、尝试站点常见 favicon 路径，并仅在构建阶段用 Google favicon 服务兜底；读者始终只请求本站资源。已有缓存不会重复请求；失败只保留原有外链箭头且不阻塞构建。只重试缺失项用 `--retry-missing`，全部强制重抓用 `--refresh`。
- 本地用原生 `jekyll ~> 4.4`，**不用** `github-pages` gem（Ruby 4.0 不兼容，见 `Gemfile` 注释）。第三方 Jekyll gem 插件只有 `jekyll-feed`；`_plugins/optimize_images.rb` 是本地 HTML filter，给正文图片补原生懒加载与异步解码；搜索使用构建后的 Pagefind 静态索引。
- `_config.yml` 有 `exclude: [AGENTS.md, README.md]`——这两份根目录文件不会进 `docs/` 部署产物，别误删这条。
- `sitemap.xml` 是无插件依赖的 Liquid 模板；构建时自动生成 `docs/sitemap.xml`，收录正式页面和已发布文章。不要用旧站遗留的静态 sitemap 覆盖它。

## 文章

- 新文章用 `bin/new-post "标题"`（支持 `-c/-d/-t/-s/-e`），**不要手写** front matter 或文件名。脚本保证 slug 规则（含 CJK）和目录归类统一。
- `bin/normalize-link-spacing` 会由 `bin/build` 自动运行：普通 Markdown 链接和自动链接的两侧若紧邻文字或数字，就各补一个半角空格；若与 Unicode 标点/符号（包括中文全角标点）之间已有空格或 Markdown 软换行，则删掉间隔。脚本会保留硬换行以及列表、引用、标题的结构空格，并跳过 front matter、代码块、行内代码、图片和链接定义；可用 `--check` 只检查而不改文件。
- `_posts/` 按类型分子目录：`ctf/`、`binary/`、`pwnable.tw/`、`unclassified/`。`category` 由目录路径决定，不是 front matter 字段。
- front matter 极简：`layout: post` + `title` + `tags`（空格分隔的英文短词，如 `pwn kernel`）。

## 样式

- 样式源在 `_sass/minima.scss`（入口）和 `_sass/minima/_*.scss`，**不要改 `assets/main.css`**（产物）。
- SCSS 用 `@use` 模块化：`$`变量在 `_variables.scss`、mixin 在 `_mixins.scss`、`%placeholder` 在 `_placeholders.scss`。新 partial 顶部 `@use "minima/variables" as *;`（用到 mixin/placeholder 再加对应行）。**不要用 `@import`**。
- 入口是本地 `assets/main.scss`（`@use "minima"`），覆盖 theme gem 那个含 `@import` 的版本——不要删这个文件。
- 搜索使用 Pagefind 1.5.2：`bin/build` 在 Jekyll 构建后扫描 `docs/`，生成并提交 `docs/pagefind/`；逻辑在 `assets/js/search.js`，样式在 `_sass/minima/_search.scss`。只有带 `data-pagefind-body` 的文章正文会进入索引，Pagefind 运行时在首次打开搜索时动态加载；使用 post layout 但不应进入搜索的页面加 `search: false`（Diary 即如此）。
- 文章 TOC 在桌面侧边浮动、窄屏电脑内联完整显示，仅小屏触控设备默认折叠；结构在 `_layouts/post.html`，交互在 `assets/js/post.js`，断点样式在 `_sass/minima/_layout.scss`。
- 主 CSS 用 `_config.yml` 的 `asset_versions.main_css` 做全站缓存破坏，修改全局样式后同步递增；`link.md` 的 front matter `asset_version` 会覆盖全站值，修改友链页样式时仍单独递增它。
- 站点主题由 `assets/js/theme.js` 的选择器管理，主题 token 在 `_sass/minima/_theme.scss`。蓝白主题的平铺背景源自用户提供的 PDF，部署资产是 `images/theme-blue-white-tile.png`；不要直接编辑该 PNG。
- 像素字体采用分层加载：所有设备加载 `assets/fonts/fusion-pixel-10px-ui.woff2`（约 14 KB，只含拉丁、常用标点和界面符号），桌面端再加载完整简体中文字体；正文仍使用 `_variables.scss` 的系统中文字体栈。UI 子集由 FontTools 从 10px 简中字体生成，调整字符范围时需重新生成，不要用完整的 `*-latin.otf.woff2` 代替（该文件同样约 424 KB）。
- 正文可用 `{% include github_repo.html repo="owner/repository" %}` 插入 GitHub 仓库卡片。结构在 `_includes/github_repo.html`，数据与 6 小时浏览器缓存逻辑在 `assets/js/github-repo.js`，样式在 `_sass/minima/_github-repo.scss`；公开 API 失败时会降级为仓库链接。
- 正文组件还包括 `{% include callout.html ... %}`、`{% include link_preview.html ... %}` 和 `{% include static_tweet.html ... %}`；写法见 `README.md`。结构在 `_includes/`，共用样式在 `_sass/minima/_embeds.scss`，链接元数据与 24 小时缓存逻辑在 `assets/js/link-preview.js`。

## 三方集成（随时可能挂，挂了表现为页面某块空白）

- **评论**：Valine（LeanCloud），`_includes/valine_comments.html`，凭据走 `_config.yml` 的 `valine:` 段（`site.valine.*`）。该 include 只在 post layout 出现，`assets/js/comments.js` 仅在读者接近评论区或点击按钮时加载 Valine，**首页/about/404 和未滚到文末的长文章不请求 Valine/LeanCloud**。
- **搜索**：Pagefind，完全使用随站部署的静态索引，不依赖第三方搜索服务；缺少或陈旧的 `docs/pagefind/` 通常表示绕过了 `bin/build`、只执行了 Jekyll。
- **链接预览**：Microlink 公共元数据 API，由 `assets/js/link-preview.js` 调用；会把文章中指定的 URL 发送给 Microlink。失败或图片禁止外链时自动降级，不应出现空白卡片。
- **访客地图**：`_includes/footer.html` 由 `assets/js/footer.js` 默认加载 `mapmyvisitors.com/map.js`；外观保持原来的灰度地图，不显示加载按钮。这个旧组件的 JSONP 数据请求在 iframe 中会永久停在 `Loading data...`（即使 iframe 不加 sandbox），所以必须按厂商原始方式在主页面加载；脚本用 `noConflict(true)` 保持其旧版 jQuery 私有，但它仍是拥有页面权限的第三方脚本。脚本元素必须保留 `id="mapmyvisitors"`，第三方脚本会用这个 ID 定位自身配置。修改 `assets/js/footer.js` 后同步递增 `_config.yml` 的 `asset_versions.footer`，避免线上继续命中旧脚本缓存。
- **MathJax**：`_includes/head.html` 里 **按 `page.use_math` 开关加载**，不是全局。写含数学公式的文章时，front matter 加 `use_math: true` 才会引入 MathJax CDN。

页面某区域空白时，优先怀疑第三方服务，而非本地 CSS。

## 不要碰

- `_algolia_api_key`、`Gemfile.lock.bak`、`.obsidian/`。`Gemfile.lock` 只在明确变更 Ruby 依赖时由 Bundler 更新，不要手工编辑或顺带升级无关 gem。
- `master` 分支存在但站点不用，别往那推。

## 完工收尾

任务完成后，**主动询问用户是否需要 git 提交**。如果用户同意，自行 `git add` 相关改动 → `git commit`（写清晰的 message）→ `git push`。当前在 `gh-pages` 默认分支，push 前确认改动范围，不要带上无关的脏文件。

视觉相关更改完成并运行 `bin/build` 后，除询问是否需要 git 提交外，还要主动启动本地预览服务器（统一使用 `bundle exec jekyll serve -P 4002`），打开包含本次改动的代表性页面供用户预览，并告知 4002 端口的访问地址；如果用户已经启动预览服务器，则直接复用，不要重复启动。服务器保持运行，直到用户看完或要求停止。
