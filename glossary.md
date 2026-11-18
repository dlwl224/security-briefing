---
layout: page
title: 📚 보안 용어 사전
permalink: /glossary/
---

매일 브리핑에 등장한 보안 용어를 모아둔 사전입니다. (총 {{ site.data.glossary | size }}개)

{% assign terms = site.data.glossary | sort: "term" %}
{% for t in terms %}
<h3 id="{{ t.term | slugify: 'raw' }}">{{ t.term }} <small>({{ t.english }})</small></h3>
<p>{{ t.definition }}</p>
<p><small>처음 등장: <a href="{{ t.post | relative_url }}">{{ t.first_seen }} 브리핑</a></small></p>
{% endfor %}
