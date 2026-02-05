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
  margin-top: 20px;
  margin-bottom: 40px;
}

.friends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 20px;
}

.friend-card {
  background: var(--card-bg); 
  border: 1px dashed var(--grey-color);
  padding: 15px;
  transition: all 0.2s ease;
  position: relative;
  overflow: hidden;
}

.friend-card:hover {
  border-color: var(--brand-color);
  background: var(--card-bg);
  opacity: 0.9;
  transform: translateY(-2px);
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
}

.friend-card a {
  text-decoration: none;
  color: inherit;
  display: flex;
  align-items: center;
  gap: 15px;
  width: 100%;
}

.friend-avatar {
  flex-shrink: 0;
  width: 50px;
  height: 50px;
  border: 1px solid var(--grey-color-light);
  background: var(--grey-color-dark);
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
}

.friend-avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  filter: grayscale(20%);
}

.default-avatar {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--brand-color);
  font-family: "FusionPixel12Mono", monospace;
  font-weight: bold;
  font-size: 1.5em;
}

.friend-info {
  flex: 1;
  min-width: 0;
}

.friend-info h3 {
  margin: 0 0 5px 0;
  color: var(--heading-color);
  font-family: "FusionPixel10Prop", sans-serif;
  font-size: 1.2em;
  letter-spacing: 1px;
}

.friend-slogan {
  margin: 0;
  color: var(--text-color);
  font-size: 0.85em;
  font-style: italic;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  line-height: 1.4;
  opacity: 0.8;
}

/* Decoration for cards */
.friend-card::before {
  content: ">";
  position: absolute;
  top: 5px;
  right: 10px;
  font-family: "FusionPixel10Prop", sans-serif;
  font-size: 0.8em;
  color: var(--brand-color);
  opacity: 0.3;
}

/* 响应式设计 */
@media (max-width: 600px) {
  .friends-grid {
    grid-template-columns: 1fr;
  }
  
  .friend-card {
    padding: 12px;
  }
  
  .friend-info h3 {
    font-size: 1.1em;
  }
}
</style>
