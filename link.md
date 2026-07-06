---
layout: page
title: Links
permalink: /links/
---

<section class="friends-section">
  <div class="friends-grid">
    {% for friend in site.data.link.friends %}
      <div class="friend-card">
        <a href="{{ friend.url }}" target="_blank" rel="noopener noreferrer">
          <div class="friend-avatar">
            {% if friend.avatar and friend.avatar != "" %}
              <img src="{{ friend.avatar }}" alt="{{ friend.name }}" loading="lazy">
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
</section>
