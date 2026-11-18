---
layout: page
title: 보안 용어 사전
ghost: Glossary
kicker: GLOSSARY
permalink: /glossary/
---
{%- comment -%}용어 데이터는 AI가 만든 값이므로 모든 출력에 escape 필터를 적용해 XSS를 막는다.{%- endcomment -%}
{%- assign terms = site.data.glossary | sort: "term" -%}
<p class="hero__sub glossary-lead">매일 브리핑에 등장한 보안 용어 <b>{{ terms.size }}</b>개를 모았습니다.</p>

<div class="search">
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
  <input type="search" id="term-search" placeholder="용어, 영어 원어, 설명으로 검색" aria-label="용어 검색" autocomplete="off">
</div>
<div class="alpha" id="term-filter" role="group" aria-label="첫 글자로 거르기"></div>

<div class="terms" id="term-list">
  {%- for t in terms -%}
  <article class="tcard" id="{{ t.term | slugify: 'raw' | escape }}" data-term="{{ t.term | escape }}" data-en="{{ t.english | escape }}">
    <p class="tcard__t">{{ t.term | escape }}</p>
    <p class="tcard__e">{{ t.english | escape }}</p>
    <p class="tcard__d">{{ t.definition | escape }}</p>
    <p class="tcard__e"><a href="{{ t.post | relative_url | escape }}">{{ t.first_seen | escape }} 브리핑에서 처음 등장 →</a></p>
  </article>
  {%- endfor -%}
</div>
<p class="empty" id="term-empty" hidden>찾는 용어가 없어요.</p>
