# AGENTS.md

本博客基于 Jekyll + 重度魔改的 minima 主题，部署在 GitHub Pages（`gh-pages` 分支）。下面只列**非默认行为**和**踩坑点**，标准 Jekyll 知识不再赘述。

## 构建

- `_config.yml` 里 `destination: ./docs` —— **`docs/` 是 build 产物且提交进 git，Pages 直接从这个目录部署**。
- 改完 `_posts/`、`_includes/`、`_sass/` 后必须 `bundle exec jekyll build`，再连同 `docs/` 一起提交。工作区常有一堆 `M docs/*.html` 是正常的（上次 build 的产物），不要手动编辑 `docs/*.html`，会被覆盖。
- 本地用原生 `jekyll ~> 4.4`，**不用** `github-pages` gem（Ruby 4.0 不兼容，见 `Gemfile` 注释）。插件只有 `jekyll-feed`、`jekyll-algolia`。

## 文章

- 新文章用 `bin/new-post "标题"`（支持 `-c/-d/-t/-s/-e`），**不要手写** front matter 或文件名。脚本保证 slug 规则（含 CJK）和目录归类统一。
- `_posts/` 按类型分子目录：`ctf/`、`binary/`、`pwnable.tw/`、`unclassified/`。`category` 由目录路径决定，不是 front matter 字段。
- front matter 极简：`layout: post` + `title` + `tags`（空格分隔的英文短词，如 `pwn kernel`）。

## 样式

- 样式源在 `_sass/minima.scss` 和 `_sass/minima/_*.scss`，**不要改 `assets/main.css`**（产物）。
- `post.html` layout 带左侧 TOC 侧栏（`_includes/toc.html`）和「RELATED POSTS」（`_includes/related_posts.html`，按 tag 匹配最多 3 篇）。
- 默认暗色主题；`head.html` 里 `data-theme` 切换逻辑 + `assets/js/theme.js` 负责运行时切换。

## 三方集成（随时可能挂，挂了表现为页面某块空白）

- **评论**：Valine（LeanCloud），`_includes/valine_comments.html`，app_id/app_key 硬编码。
- **搜索**：Algolia，配置在 `_config.yml` 末尾，search_only_api_key 明文。push 索引用 `ALGOLIA_API_KEY=... bundle exec jekyll algolia`（key 在 gitignore 的 `_algolia_api_key`）。
- **访客地图**：`_includes/footer.html` 嵌 `mapmyvisitors.com/map.js`。`.footer-map-mini` 上的 `filter: invert()` 是为旧 widget 调的，换源后可能要重调。
- **MathJax**：`_includes/head.html` CDN 引入。

页面某区域空白时，优先怀疑第三方服务，而非本地 CSS。

## 不要碰

- `_algolia_api_key`、`Gemfile.lock`、`Gemfile.lock.bak`、`.obsidian/`。
- `master` 分支存在但站点不用，别往那推。

## 完工收尾

任务完成后，**主动询问用户是否需要 git 提交**。如果用户同意，自行 `git add` 相关改动 → `git commit`（写清晰的 message）→ `git push`。当前在 `gh-pages` 默认分支，push 前确认改动范围，不要带上无关的脏文件。