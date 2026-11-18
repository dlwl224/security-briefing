---
layout: page
title: 사람 손 없이, 매일 09:00
ghost: Pipeline
kicker: HOW IT WORKS
lead: 수집부터 알림까지 모든 단계가 GitHub Actions 위에서 자동으로 돌아갑니다. 서버도, 데이터베이스도, 추적기도 없습니다.
permalink: /about/
---
<ol class="pipe" aria-label="자동화 파이프라인">
  <li class="pipe__step" data-reveal>
    <span class="pipe__no mono">01 · COLLECT</span>
    <h2 class="pipe__t">수집</h2>
    <p class="pipe__d">국내(보안뉴스·데일리시큐·KISA 보호나라)와 해외(The Hacker News·BleepingComputer·SecurityWeek·The Record) RSS, 그리고 실제 악용 중인 취약점 목록 CISA KEV에서 최근 36시간 기사를 모읍니다.</p>
  </li>
  <li class="pipe__step" data-reveal>
    <span class="pipe__no mono">02 · SELECT</span>
    <h2 class="pipe__t">선정</h2>
    <p class="pipe__d">Gemini가 피해 규모·악용 여부·국내외 균형·분야(취약점/사고/정책) 기준으로 오늘의 5건을 고릅니다. 이미 다룬 기사는 제외합니다.</p>
  </li>
  <li class="pipe__step" data-reveal>
    <span class="pipe__no mono">03 · SUMMARIZE</span>
    <h2 class="pipe__t">요약</h2>
    <p class="pipe__d">기사 본문을 읽고 핵심·배경·영향, 위험도, 핵심 수치, CVE를 정해진 JSON 스키마로 만듭니다. 기사에 없는 사실은 쓰지 않도록 지시합니다.</p>
  </li>
  <li class="pipe__step" data-reveal>
    <span class="pipe__no mono">04 · PUBLISH</span>
    <h2 class="pipe__t">게시</h2>
    <p class="pipe__d">보안 테스트를 통과한 경우에만 포스트를 커밋하고, GitHub Pages가 정적 사이트로 배포합니다.</p>
  </li>
  <li class="pipe__step" data-reveal>
    <span class="pipe__no mono">05 · NOTIFY</span>
    <h2 class="pipe__t">알림</h2>
    <p class="pipe__d">배포가 끝나면 Discord로 5건 요약과 링크를 보냅니다. 실패하면 실패 알림이 옵니다.</p>
  </li>
</ol>

<div class="prose about-sec" id="metrics">
<h2>지표 읽는 법</h2>
<p>브리핑의 숫자는 출처가 두 종류입니다. <b>공식 데이터</b>(CVE·CVSS·EPSS·KEV)는 매일 각 기관의 공개 API에서 직접 조회하고, <b>AI 평가</b>(위험도·위협 수준)는 기사를 읽은 AI의 판단이라 별도로 표시합니다.</p>
</div>
<div class="guide">
  {%- assign metric_keys = "cve,cvss,epss,kev,severity,threat" | split: "," -%}
  {%- for key in metric_keys -%}
  {%- assign m = site.data.metrics[key] -%}
  <div class="tcard" data-reveal>
    <p class="tcard__t">{{ m.title | escape }}</p>
    <p class="tcard__e">{{ m.sub | escape }}</p>
    <p class="tcard__d">{{ m.body | escape }}</p>
    {%- if key == "cvss" -%}
    <div class="scale" aria-label="CVSS 등급 구간">
      <span data-cvss="LOW">낮음<small>0.1–3.9</small></span>
      <span data-cvss="MEDIUM">중간<small>4.0–6.9</small></span>
      <span data-cvss="HIGH">높음<small>7.0–8.9</small></span>
      <span data-cvss="CRITICAL">치명적<small>9.0–10</small></span>
    </div>
    {%- endif -%}
  </div>
  {%- endfor -%}
</div>
<div class="prose about-sec">
<table>
  <thead><tr><th>지표</th><th>출처</th><th>갱신</th></tr></thead>
  <tbody>
    <tr><td>CVE 존재 여부 · CVSS</td><td>미국 NIST <a href="https://nvd.nist.gov/" rel="noopener noreferrer">NVD API</a></td><td>발행 시점 조회</td></tr>
    <tr><td>EPSS</td><td><a href="https://www.first.org/epss/" rel="noopener noreferrer">FIRST EPSS API</a></td><td>매일</td></tr>
    <tr><td>KEV</td><td><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noopener noreferrer">CISA KEV 카탈로그</a></td><td>수시</td></tr>
    <tr><td>위험도 · 위협 수준</td><td>Gemini (AI 평가, 공식 아님)</td><td>매일 09:00</td></tr>
  </tbody>
</table>
<p>AI가 기사에서 고른 CVE 번호는 NVD에서 조회해 실제로 존재할 때만 표시합니다. NVD에 아직 없는 새 CVE는 기사 원문에 그대로 적혀 있을 때만 '미등록'으로 표시하고, 둘 다 아니면 버립니다.</p>

<h2>보안 설계</h2>
<p>이 사이트의 글은 외부 뉴스와 AI가 만든 <b>신뢰할 수 없는 입력</b>입니다. 그래서 다음을 지킵니다.</p>
<table>
  <thead><tr><th>위협</th><th>대응</th></tr></thead>
  <tbody>
    <tr><td>저장형 XSS</td><td>모든 외부·AI 텍스트를 출력 시 HTML 이스케이프</td></tr>
    <tr><td>프롬프트 인젝션 → 피싱 링크</td><td>본문은 데이터로만 취급하도록 지시, 출력의 링크 문법 무력화, 출처는 RSS 원본 링크만 사용</td></tr>
    <tr><td>악성 스크립트 삽입</td><td>외부 스크립트 0개, <code>script-src 'self'</code> 엄격한 CSP</td></tr>
    <tr><td>API 키 유출</td><td>GitHub Secrets 보관, URL이 아닌 헤더로 전송</td></tr>
    <tr><td>공급망 공격</td><td>Actions 커밋 SHA 고정, 의존성 버전 고정, Dependabot</td></tr>
  </tbody>
</table>
<p>요약은 AI가 작성하므로 정확한 내용은 각 글의 출처 원문을 확인해 주세요.</p>
</div>
