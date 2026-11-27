---
layout: briefing
title: "2026-11-28 보안 이슈 브리핑"
date: 2026-11-28 09:00:00 +0900
issue_no: 10
threat_level: 4
summary: "랜섬웨어 공격 급증과 주요 소프트웨어 취약점 및 계정 탈취 사고가 이어진 하루."
tags: ["사고", "위협동향", "취약점"]
description: "국내 랜섬웨어 공격 역대 최다 기록 / 과학기술인공제회 해킹으로 회원 정보 유출 / 네트워크 모니터링 툴 Cacti 제로데이 취약점 발견 / 소프트웨어 기업 SAP, 깃허브 보안 사고 확인 / 드루팔 코어 사이트 장악 취약점 긴급 보안 권고"
items: [{"title": "국내 랜섬웨어 공격 역대 최다 기록", "region": "국내", "category": "위협동향", "severity": null, "severity_method": "rule", "severity_basis": ["정책·동향 기사 → 위험도 대신 '참고'"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "국내 대상 랜섬웨어 누적 공격 86건 발생, 주요 산업 전반 영향", "core": "올해 국내 기업과 기관을 노린 랜섬웨어 공격 건수가 역대 최고치를 경신했다. 11월 기준 누적 86건으로 전년 동기 대비 2배 이상 급증했다. 인공지능(AI) 활용과 서비스형 랜섬웨어(RaaS) 분업화가 주요 원인으로 지목됐다.", "background": "랜섬웨어 그룹들이 AI를 활용해 공격을 자동화하고 진입장벽을 낮추면서 신생 조직들이 대거 등장했다. 또한 초기 접근 브로커와 협력하는 분업 구조가 정착되면서 공격이 더욱 빈번해졌다. 복호화 대가뿐만 아니라 데이터 비공개 대가를 동시에 요구하는 다각화된 협박 방식이 성행하고 있다.", "impact": "제조, 물류, IT 등 산업 전반에 심각한 피해를 유발하며 국가 경제에 큰 위협이 되고 있다. 기업은 중요 데이터의 물리적·논리적 분리 보관과 다중 인증(MFA) 적용 등 철저한 보안 조치를 즉시 시행해야 한다.", "key_figure": "86", "key_figure_label": "국내 누적 공격 건수", "cve": "", "cvss": 0.0, "source": "보안뉴스", "link": "https://www.boannews.com/news/articleView.html?idxno=147394", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.10.8", "2.10.9", "2.11.1"], "attack": ["T1486", "T1195"], "actions": ["중요 데이터 백업을 오프라인 및 불변 저장소에 분리", "주요 시스템 및 관리자 계정에 다중 인증(MFA) 적용", "EDR 및 XDR 솔루션을 통한 이상 행위 상시 모니터링"]}, {"title": "과학기술인공제회 해킹으로 회원 정보 유출", "region": "국내", "category": "사고", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "규모 중간 +1", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "medium", "domestic": true, "critical_sector": true, "factor_note": "과학기술인공제회 서버 침해사고로 회원 개인정보 유출 확인", "core": "과학기술인공제회 서버가 외부 해커의 보안 취약점 악용 공격을 받아 회원 개인정보가 유출되었다. 사고 발생일은 11월 8일이며, 회원번호, 주민등록번호(암호화), 연락처 등 16종의 정보가 포함됐다. 공제회는 인지 즉시 비인가 접근을 차단하고 관계기관에 신고했다.", "background": "해커는 서버의 취약점을 이용해 비인가 접근을 시도한 뒤 회원 정보를 조회한 것으로 파악됐다. 공제회는 과학기술인들의 복지와 금융 안정을 지원하는 공공 성격의 기관이다. 유출된 정보가 스피어피싱 등 2차 범죄에 악용될 우려가 커 주의가 필요하다.", "impact": "연구원과 기술인 등 다수의 개인정보가 유출되어 2차 피싱 공격 등 개인 피해로 이어질 수 있다. 피해 확산을 막기 위해 회원은 즉시 비밀번호를 변경하고 의심스러운 연락을 경계해야 한다.", "key_figure": "16", "key_figure_label": "유출된 정보 항목 수", "cve": "", "cvss": 0.0, "source": "보안뉴스", "link": "https://www.boannews.com/news/articleView.html?idxno=147598", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.10.8", "2.9.4", "2.11.5"], "attack": ["T1190"], "actions": ["공제회 홈페이지 로그인 비밀번호 즉시 변경", "사칭 문자 및 이메일의 링크 클릭 주의", "서버 보안 취약점 패치 및 접근 통제 강화"]}, {"title": "네트워크 모니터링 툴 Cacti 제로데이 취약점 발견", "region": "해외", "category": "취약점", "severity": 3, "severity_method": "rule", "severity_basis": ["공격 가능성 공개 +1", "규모 중간 +1", "국내 영향 +1"], "exploitation": "poc", "scale": "medium", "domestic": true, "critical_sector": false, "factor_note": "Cacti 오픈소스 툴 대상 원격 코드 실행 PoC 공개", "core": "오픈소스 네트워크 모니터링 도구인 Cacti에서 원격 코드 실행(RCE)이 가능한 새로운 제로데이 취약점이 발견됐다. 단 4번의 HTTP 요청과 게스트 권한만으로 시스템이 장악될 수 있는 공격 코드(PoC)가 공개됐다.", "background": "Cacti는 네트워크 장비 상태를 모니터링하기 위해 널리 쓰이는 오픈소스 프로그램이다. 아직 공식 패치나 정식 CVE 번호가 할당되지 않은 상태여서 주의가 요구된다. 외부 공격자가 인증 없이도 시스템 제어권을 탈취할 수 있는 구조적 약점이 확인됐다.", "impact": "Cacti를 사용하는 기업과 기관의 서버가 무단 제어될 경우 내부망 침투로 이어질 수 있다. 공식 보안 업데이트가 나올 때까지 외부 접근을 엄격히 통제하고 방화벽을 적용해야 한다.", "key_figure": "4", "key_figure_label": "필요한 HTTP 요청 횟수", "cve": "", "cvss": 0.0, "source": "The Hacker News", "link": "https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.10.3", "2.10.8", "2.11.2"], "attack": ["T1190", "T1059"], "actions": ["Cacti 서비스의 외부 인터넷 노출 여부 점검", "게스트 계정 접근 권한 비활성화 및 접근 통제", "제조사 보안 공지 확인 및 패치 적용 대기"]}, {"title": "소프트웨어 기업 SAP, 깃허브 보안 사고 확인", "region": "해외", "category": "사고", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "글로벌 소프트웨어 기업 SAP의 깃허브 환경 임직원 토큰 탈취 사고", "core": "글로벌 기업 SAP가 내부 IT 환경에서 의심스러운 활동을 감지하고 고객 보호 조치에 나섰다. 공격자는 임직원의 깃허브 계정 인증 토큰을 탈취해 소스 코드를 복사 및 수정하려 했다. SAP는 현재까지 고객 데이터 무단 유출 증거는 발견되지 않았다고 밝혔다.", "background": "SAP는 전 세계 수억 명의 가입자를 보유한 대형 기업용 소프트웨어 공급업체다. 최근 인공지능 도구를 악용한 지능형 공격과 공급망 위협이 증가하는 추세다. 이번 사고는 임직원의 인증 토큰이 탈취되면서 깃허브 환경이 침해된 정황을 보여준다.", "impact": "공급망 소프트웨어를 사용하는 수많은 글로벌 기업과 고객사로 피해가 확산될 잠재적 위험이 있다. 기업들은 개발 환경과 형상관리 시스템에 대한 인증 보안을 대폭 강화해야 한다.", "key_figure": "110000", "key_figure_label": "SAP 임직원 수", "cve": "", "cvss": 0.0, "source": "BleepingComputer", "link": "https://www.bleepingcomputer.com/news/security/sap-confirms-security-incident-after-suspicious-github-activity/", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.5.3", "2.5.5", "2.8.5"], "attack": ["T1528", "T1195.002"], "actions": ["개발자 계정 및 깃허브 접근 토큰 일제 재발급", "소스코드 저장소에 대한 다중 인증(MFA) 의무화", "이상 접속 로그 모니터링 및 세션 토큰 관리 강화"]}, {"title": "드루팔 코어 사이트 장악 취약점 긴급 보안 권고", "region": "해외", "category": "취약점", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2 (CISA KEV)", "대규모 +2", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": false, "factor_note": "Drupal Core 설치 관리자 관련 사이트 장악 취약점 KEV 등재", "core": "드루팔 코어(Drupal Core)에서 인증되지 않은 원격 공격자가 사이트를 장악할 수 있는 취약점이 발견됐다. 미 CISA는 해당 취약점을 KEV(공격 이용 취약점) 목록에 등재하고 연방기관에 긴급 조치를 명령했다. CVE 번호는 CVE-2026-136716이다.", "background": "드루팔은 세계적으로 널리 쓰이는 웹 콘텐츠 관리 시스템(CMS) 중 하나다. 사이트가 특정 비정상적이거나 불완전한 설치 상태에 있을 때 노출된 설치 관리자를 통해 비인가 접근이 가능하다. 예외 상황에 대한 부적절한 검증 로직이 원인이다.", "impact": "웹사이트 전체가 공격자에게 완전히 넘어가 서비스 중단이나 데이터 변조로 이어질 수 있다. 관리자는 즉시 공식 보안 패치를 적용하고 인터넷 노출 상태를 점검해야 한다.", "key_figure": "2026", "key_figure_label": "KEV 등재 연도", "cve": "CVE-2026-136716", "cvss": 9.8, "source": "CISA KEV", "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-136716", "cve_status": "nvd", "cvss_severity": "CRITICAL", "cvss_version": "3.1", "cvss_source": "CNA", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 1.21, "epss_percentile": 68.4, "epss_date": "2026-11-27", "kev": true, "kev_date": "2026-11-27", "kev_ransomware": false, "priority": "P1", "priority_reasons": ["CISA KEV 등재(실제 악용 확인)"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 쉬움", "level": "bad"}, {"k": "필요 권한", "v": "로그인 불필요", "level": "bad"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "영향 범위", "v": "해당 시스템에 한정", "level": "ok"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-754"], "isms": ["2.10.3", "2.10.8", "2.11.2"], "attack": ["T1190"], "actions": ["Drupal Core 최신 보안 패치 버전으로 즉시 업데이트", "외부에 노출된 설치 관리자 파일 및 경로 제거", "웹 애플리케이션 방화벽(WAF)을 통한 비정상 접근 차단"]}]
terms: [{"term": "랜섬웨어", "english": "Ransomware", "definition": "컴퓨터 파일을 암호화해 사용할 수 없게 만들고, 이를 인질 삼아 돈을 요구하는 악성 프로그램이다."}, {"term": "제로데이", "english": "Zero-Day", "definition": "보안 취약점이 발견되어 공식 패치가 나오기도 전에 그 허점을 이용해 감행되는 공격이다."}, {"term": "원격 코드 실행", "english": "Remote Code Execution (RCE)", "definition": "해커가 멀리 떨어진 곳에서 네트워크를 통해 다른 사람의 컴퓨터나 서버를 마음대로 조종할 수 있는 취약점이다."}, {"term": "인증 토큰", "english": "Authentication Token", "definition": "웹사이트나 프로그램에 로그인했을 때 열쇠 대신 내 신분을 증명하기 위해 발급받는 디지털 통행증이다."}, {"term": "스피어피싱", "english": "Spearphishing", "definition": "특정 사람을 미리 조사한 뒤, 그 사람이 관심 가질 만한 거짓 내용의 이메일 등을 보내 개인정보를 훔치는 해킹 기법이다."}]
---

> 오늘의 주요 보안 이슈 5건 (국내 2 · 해외 3)

## 📌 한눈에 보기

1. **[국내·위협동향]** 국내 랜섬웨어 공격 역대 최다 기록
2. **[국내·사고]** 과학기술인공제회 해킹으로 회원 정보 유출
3. **[해외·취약점]** 네트워크 모니터링 툴 Cacti 제로데이 취약점 발견
4. **[해외·사고]** 소프트웨어 기업 SAP, 깃허브 보안 사고 확인
5. **[해외·취약점]** 드루팔 코어 사이트 장악 취약점 긴급 보안 권고

---

## 1. 📡 국내 랜섬웨어 공격 역대 최다 기록

`국내` `위협동향` · 출처: [보안뉴스](https://www.boannews.com/news/articleView.html?idxno=147394)

**🎯 핵심**  
올해 국내 기업과 기관을 노린 랜섬웨어 공격 건수가 역대 최고치를 경신했다. 11월 기준 누적 86건으로 전년 동기 대비 2배 이상 급증했다. 인공지능(AI) 활용과 서비스형 랜섬웨어(RaaS) 분업화가 주요 원인으로 지목됐다.

**📖 배경**  
랜섬웨어 그룹들이 AI를 활용해 공격을 자동화하고 진입장벽을 낮추면서 신생 조직들이 대거 등장했다. 또한 초기 접근 브로커와 협력하는 분업 구조가 정착되면서 공격이 더욱 빈번해졌다. 복호화 대가뿐만 아니라 데이터 비공개 대가를 동시에 요구하는 다각화된 협박 방식이 성행하고 있다.

**💥 영향**  
제조, 물류, IT 등 산업 전반에 심각한 피해를 유발하며 국가 경제에 큰 위협이 되고 있다. 기업은 중요 데이터의 물리적·논리적 분리 보관과 다중 인증(MFA) 적용 등 철저한 보안 조치를 즉시 시행해야 한다.

---

## 2. 🚨 과학기술인공제회 해킹으로 회원 정보 유출

`국내` `사고` · 출처: [보안뉴스](https://www.boannews.com/news/articleView.html?idxno=147598)

**🎯 핵심**  
과학기술인공제회 서버가 외부 해커의 보안 취약점 악용 공격을 받아 회원 개인정보가 유출되었다. 사고 발생일은 11월 8일이며, 회원번호, 주민등록번호(암호화), 연락처 등 16종의 정보가 포함됐다. 공제회는 인지 즉시 비인가 접근을 차단하고 관계기관에 신고했다.

**📖 배경**  
해커는 서버의 취약점을 이용해 비인가 접근을 시도한 뒤 회원 정보를 조회한 것으로 파악됐다. 공제회는 과학기술인들의 복지와 금융 안정을 지원하는 공공 성격의 기관이다. 유출된 정보가 스피어피싱 등 2차 범죄에 악용될 우려가 커 주의가 필요하다.

**💥 영향**  
연구원과 기술인 등 다수의 개인정보가 유출되어 2차 피싱 공격 등 개인 피해로 이어질 수 있다. 피해 확산을 막기 위해 회원은 즉시 비밀번호를 변경하고 의심스러운 연락을 경계해야 한다.

---

## 3. 🛠️ 네트워크 모니터링 툴 Cacti 제로데이 취약점 발견

`해외` `취약점` · 출처: [The Hacker News](https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html)

**🎯 핵심**  
오픈소스 네트워크 모니터링 도구인 Cacti에서 원격 코드 실행(RCE)이 가능한 새로운 제로데이 취약점이 발견됐다. 단 4번의 HTTP 요청과 게스트 권한만으로 시스템이 장악될 수 있는 공격 코드(PoC)가 공개됐다.

**📖 배경**  
Cacti는 네트워크 장비 상태를 모니터링하기 위해 널리 쓰이는 오픈소스 프로그램이다. 아직 공식 패치나 정식 CVE 번호가 할당되지 않은 상태여서 주의가 요구된다. 외부 공격자가 인증 없이도 시스템 제어권을 탈취할 수 있는 구조적 약점이 확인됐다.

**💥 영향**  
Cacti를 사용하는 기업과 기관의 서버가 무단 제어될 경우 내부망 침투로 이어질 수 있다. 공식 보안 업데이트가 나올 때까지 외부 접근을 엄격히 통제하고 방화벽을 적용해야 한다.

---

## 4. 🚨 소프트웨어 기업 SAP, 깃허브 보안 사고 확인

`해외` `사고` · 출처: [BleepingComputer](https://www.bleepingcomputer.com/news/security/sap-confirms-security-incident-after-suspicious-github-activity/)

**🎯 핵심**  
글로벌 기업 SAP가 내부 IT 환경에서 의심스러운 활동을 감지하고 고객 보호 조치에 나섰다. 공격자는 임직원의 깃허브 계정 인증 토큰을 탈취해 소스 코드를 복사 및 수정하려 했다. SAP는 현재까지 고객 데이터 무단 유출 증거는 발견되지 않았다고 밝혔다.

**📖 배경**  
SAP는 전 세계 수억 명의 가입자를 보유한 대형 기업용 소프트웨어 공급업체다. 최근 인공지능 도구를 악용한 지능형 공격과 공급망 위협이 증가하는 추세다. 이번 사고는 임직원의 인증 토큰이 탈취되면서 깃허브 환경이 침해된 정황을 보여준다.

**💥 영향**  
공급망 소프트웨어를 사용하는 수많은 글로벌 기업과 고객사로 피해가 확산될 잠재적 위험이 있다. 기업들은 개발 환경과 형상관리 시스템에 대한 인증 보안을 대폭 강화해야 한다.

---

## 5. 🛠️ 드루팔 코어 사이트 장악 취약점 긴급 보안 권고

`해외` `취약점` · 출처: [CISA KEV](https://nvd.nist.gov/vuln/detail/CVE-2026-136716)

**🎯 핵심**  
드루팔 코어(Drupal Core)에서 인증되지 않은 원격 공격자가 사이트를 장악할 수 있는 취약점이 발견됐다. 미 CISA는 해당 취약점을 KEV(공격 이용 취약점) 목록에 등재하고 연방기관에 긴급 조치를 명령했다. CVE 번호는 CVE-2026-136716이다.

**📖 배경**  
드루팔은 세계적으로 널리 쓰이는 웹 콘텐츠 관리 시스템(CMS) 중 하나다. 사이트가 특정 비정상적이거나 불완전한 설치 상태에 있을 때 노출된 설치 관리자를 통해 비인가 접근이 가능하다. 예외 상황에 대한 부적절한 검증 로직이 원인이다.

**💥 영향**  
웹사이트 전체가 공격자에게 완전히 넘어가 서비스 중단이나 데이터 변조로 이어질 수 있다. 관리자는 즉시 공식 보안 패치를 적용하고 인터넷 노출 상태를 점검해야 한다.

---

## 📚 오늘의 보안 용어

- **랜섬웨어** (Ransomware): 컴퓨터 파일을 암호화해 사용할 수 없게 만들고, 이를 인질 삼아 돈을 요구하는 악성 프로그램이다.
- **제로데이** (Zero-Day): 보안 취약점이 발견되어 공식 패치가 나오기도 전에 그 허점을 이용해 감행되는 공격이다.
- **원격 코드 실행** (Remote Code Execution (RCE)): 해커가 멀리 떨어진 곳에서 네트워크를 통해 다른 사람의 컴퓨터나 서버를 마음대로 조종할 수 있는 취약점이다.
- **인증 토큰** (Authentication Token): 웹사이트나 프로그램에 로그인했을 때 열쇠 대신 내 신분을 증명하기 위해 발급받는 디지털 통행증이다.
- **스피어피싱** (Spearphishing): 특정 사람을 미리 조사한 뒤, 그 사람이 관심 가질 만한 거짓 내용의 이메일 등을 보내 개인정보를 훔치는 해킹 기법이다.

👉 지금까지 나온 용어는 [보안 용어 사전](../../glossary/)에서 볼 수 있어요.

---

<small>이 글은 공개된 보안 뉴스를 AI(Gemini)로 요약해 자동 작성했습니다. 정확한 내용은 각 출처 원문을 확인하세요.</small>
