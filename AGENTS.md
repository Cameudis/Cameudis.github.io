# AGENTS.md

本博客基于 Jekyll + 重度魔改的 minima 主题，部署在 GitHub Pages（`gh-pages` 分支）。下面只列**非默认行为**和**踩坑点**，标准 Jekyll 知识不再赘述。

> 维护原则：项目更改后，如果有以后每次会话都需要的内容，就加到本文件中；其它内容不记录。

## 构建

- `_config.yml` 里 `destination: ./docs` —— **`docs/` 是 build 产物且提交进 git，Pages 直接从这个目录部署**。改完源码后 `bundle exec jekyll build`，再连同 `docs/` 一起提交。工作区常有一堆 `M docs/*.html` 是正常的，不要手动编辑 `docs/*.html`，会被覆盖。
- 本地用原生 `jekyll ~> 4.4`，**不用** `github-pages` gem（Ruby 4.0 不兼容，见 `Gemfile` 注释）。插件只有 `jekyll-feed`、`jekyll-algolia`。
- `_config.yml` 有 `exclude: [AGENTS.md, README.md]`——这两份根目录文件不会进 `docs/` 部署产物，别误删这条。

## 文章

- 新文章用 `bin/new-post "标题"`（支持 `-c/-d/-t/-s/-e`），**不要手写** front matter 或文件名。脚本保证 slug 规则（含 CJK）和目录归类统一。
- `_posts/` 按类型分子目录：`ctf/`、`binary/`、`pwnable.tw/`、`unclassified/`。`category` 由目录路径决定，不是 front matter 字段。
- front matter 极简：`layout: post` + `title` + `tags`（空格分隔的英文短词，如 `pwn kernel`）。

## 样式

- 样式源在 `_sass/minima.scss`（入口）和 `_sass/minima/_*.scss`，**不要改 `assets/main.css`**（产物）。
- SCSS 用 `@use` 模块化：`$`变量在 `_variables.scss`、mixin 在 `_mixins.scss`、`%placeholder` 在 `_placeholders.scss`。新 partial 顶部 `@use "minima/variables" as *;`（用到 mixin/placeholder 再加对应行）。**不要用 `@import`**。
- 入口是本地 `assets/main.scss`（`@use "minima"`），覆盖 theme gem 那个含 `@import` 的版本——不要删这个文件。
- 搜索弹窗的 JS/CSS 已外提：逻辑在 `assets/js/search.js`（通过 `window.BLOG_SEARCH_CONFIG` 接收 Algolia 配置），样式在 `_sass/minima/_search.scss`。
- `link.md` 用 front matter 的 `asset_version` 给友链页主 CSS 做缓存破坏；修改友链页样式后同步递增该值，避免线上 CDN 继续返回旧 CSS。

## 三方集成（随时可能挂，挂了表现为页面某块空白）

- **评论**：Valine（LeanCloud），`_includes/valine_comments.html`，凭据走 `_config.yml` 的 `valine:` 段（`site.valine.*`）。该 include 只在 post layout 出现，Valine 的 `<script src=...>` 也搬到这里，**首页/about/404 不加载 Valine**。
- **搜索**：Algolia，配置在 `_config.yml` 末尾，凭据通过 `window.BLOG_SEARCH_CONFIG` 注入 `assets/js/search.js`。push 索引用 `ALGOLIA_API_KEY=... bundle exec jekyll algolia`（key 在 gitignore 的 `_algolia_api_key`）。
- **访客地图**：`_includes/footer.html` 嵌 `mapmyvisitors.com/map.js`。
- **MathJax**：`_includes/head.html` 里 **按 `page.use_math` 开关加载**，不是全局。写含数学公式的文章时，front matter 加 `use_math: true` 才会引入 MathJax CDN。

页面某区域空白时，优先怀疑第三方服务，而非本地 CSS。

## 不要碰

- `_algolia_api_key`、`Gemfile.lock`、`Gemfile.lock.bak`、`.obsidian/`。
- `master` 分支存在但站点不用，别往那推。

## 完工收尾

任务完成后，**主动询问用户是否需要 git 提交**。如果用户同意，自行 `git add` 相关改动 → `git commit`（写清晰的 message）→ `git push`。当前在 `gh-pages` 默认分支，push 前确认改动范围，不要带上无关的脏文件。
