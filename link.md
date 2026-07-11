---
layout: page
title: Links
permalink: /links/
asset_version: "friends-v2"
---

<section class="friends-section">
  <div class="friends-grid">
    {% for friend in site.data.link.friends %}
      <div class="friend-card">
        <a href="{{ friend.url }}" target="_blank" rel="noopener noreferrer">
          <div class="friend-avatar">
            {% if friend.avatar and friend.avatar != "" %}
              <img src="{{ friend.avatar }}" alt="{{ friend.name }}" loading="lazy"
                   onerror="this.hidden = true; this.nextElementSibling.hidden = false;">
              <div class="default-avatar" hidden>{{ friend.name | slice: 0 }}</div>
            {% elsif friend.gravatar and friend.gravatar != "" %}
              <img src="https://www.gravatar.com/avatar/{{ friend.gravatar | strip | downcase }}?s=100&d=404"
                   alt="{{ friend.name }}" loading="lazy"
                   onerror="this.hidden = true; this.nextElementSibling.hidden = false;">
              <div class="default-avatar" hidden>{{ friend.name | slice: 0 }}</div>
            {% else %}
              <div class="default-avatar">{{ friend.name | slice: 0 }}</div>
            {% endif %}
          </div>
          <div class="friend-info">
            <h3>{{ friend.name }}</h3>
            {% if friend.slogan and friend.slogan != "" %}
              <p class="friend-slogan">{{ friend.slogan }}</p>
            {% endif %}
          </div>
        </a>
      </div>
    {% endfor %}
  </div>

  <section class="friend-apply" aria-labelledby="friend-apply-title">
    <div class="friend-apply-content">
      <p class="friend-apply-kicker">&gt; CONNECT_REQUEST</p>
      <h2 id="friend-apply-title">申请友链</h2>
      <p>如果你也有自己的个人博客/网站，欢迎交换友链。</p>
      <ul>
        <li>网站已支持 HTTPS</li>
        <li>内容以原创为主，并已添加本站友链</li>
        <li>头像建议使用 <a href="https://docs.gravatar.com/avatars/" target="_blank" rel="noopener noreferrer">Gravatar</a>，也可以填写图片 URL</li>
      </ul>
    </div>

    <div class="friend-apply-action">
      <dl class="friend-site-info">
        <div><dt>名称</dt><dd>Y²的博客</dd></div>
        <div><dt>地址</dt><dd>https://www.cameudis.com</dd></div>
        <div><dt>简介</dt><dd>计算机、安全和其他</dd></div>
      </dl>
      <a class="friend-apply-button"
         href="https://github.com/Cameudis/Cameudis.github.io/issues/new?template=friend-link.yml"
         target="_blank" rel="noopener noreferrer">
        在 GitHub 上申请
      </a>
    </div>
  </section>
</section>
