---
layout: page
title: 📚 보안 용어 사전
permalink: /glossary/
---

매일 브리핑에 등장한 보안 용어를 모아둔 사전입니다. (총 {{ site.data.glossary | size }}개)

{% comment %}용어 데이터는 AI가 만든 값이므로 모든 출력에 escape 필터를 적용해 XSS를 막는다.{% endcomment %}
{% assign terms = site.data.glossary | sort: "term" %}
{% for t in terms %}
<h3 id="{{ t.term | slugify: 'raw' | escape }}">{{ t.term | escape }} <small>({{ t.english | escape }})</small></h3>
<p>{{ t.definition | escape }}</p>
<p><small>처음 등장: <a href="{{ t.post | relative_url | escape }}">{{ t.first_seen | escape }} 브리핑</a></small></p>
{% endfor %}
