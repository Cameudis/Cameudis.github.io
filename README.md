# Y2 Blog

## 快速创建推文

用 `bin/new-post` 可以在 `_posts` 下生成新的 Jekyll 文章草稿：

```sh
bin/new-post "文章标题"
```

常用选项：

```sh
bin/new-post -c ctf -t "pwn parser" "CTF 题目记录"
bin/new-post -c binary -d 2026-06-17 --slug vmware-notes "VMware 笔记"
bin/new-post -e "随手记"
```

默认会创建到 `_posts/unclassified/`，日期使用今天，文件名由标题自动生成。同名文件不会被覆盖，会自动追加数字后缀。

## 在文章中插入 GitHub 仓库卡片

在 Markdown 正文中使用：

```liquid
{% include github_repo.html repo="owner/repository" %}
```

卡片会在浏览器中读取 GitHub 公共 API，并展示仓库简介、语言、Stars、Forks、License 和最近更新时间。请求结果会在浏览器本地缓存 6 小时；API 不可用时，卡片仍可作为普通 GitHub 链接使用。

## 正文组件

Callout 支持 `note`、`tip`、`warning`、`danger` 和 `important`：

```liquid
{% capture notice %}
这里可以写 **Markdown**，也可以写多段内容。
{% endcapture %}
{% include callout.html type="warning" title="注意" content=notice %}
```

通用链接预览只需要 URL；也可以用 `title`、`description`、`image` 覆盖自动获取的内容：

```liquid
{% include link_preview.html url="https://example.com/article" %}
```

自动预览会把该 URL 发送给 Microlink 获取公开元数据，并在浏览器本地缓存 24 小时；接口或预览图不可用时会自动降级为纯文字链接。

静态推文不加载 X 的第三方脚本，头像和配图均为可选项：

```liquid
{% include static_tweet.html
  username="Example User"
  handle="example"
  avatar="https://example.com/avatar.jpg"
  text="这是一条静态保存的推文。"
  date="2026-07-12"
  datetime="2026-07-12T10:00:00+08:00"
  url="https://x.com/example/status/123"
  image="https://example.com/image.jpg"
  image_alt="推文配图说明"
%}
```
