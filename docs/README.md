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
