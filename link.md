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


<style>
.friends-section {
  margin-bottom: 20px;
}

.friends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
}

.friend-card {
  background:rgb(255, 255, 255);
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 20px 10px;
  transition: all 0.3s ease;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  height: 40px;
  display: flex;
  align-items: center;
}

.friend-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

.friend-card a {
  text-decoration: none;
  color: inherit;
  display: flex;
  align-items: center;
  gap: 15px;
  width: 100%;
  height: 100%;
}

.friend-avatar {
  flex-shrink: 0;
  width: 60px;
  height: 60px;
  border-radius: 4px;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #e9ecef;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.friend-avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.default-avatar {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: black;
  font-weight: bold;
  font-size: 1.2em;
  text-transform: uppercase;
}

.friend-info {
  flex: 1;
  min-width: 0;
}

.friend-info h3 {
  margin: 0 0 5px 0;
  color: #333;
  font-size: 1.1em;
  font-weight: 600;
}

.friend-slogan {
  margin: 0 0 8px 0;
  color: #666;
  font-size: 0.9em;
  font-style: italic;
  line-height: 1.3;
}

.friend-url {
  margin: 0;
  color: #999;
  font-size: 0.8em;
  word-break: break-all;
  line-height: 1.2;
}

.friend-card a:hover h3 {
  color: #007bff;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .friends-grid {
    grid-template-columns: 1fr;
  }
  
  .friends-page {
    padding: 10px;
  }
}
</style>
