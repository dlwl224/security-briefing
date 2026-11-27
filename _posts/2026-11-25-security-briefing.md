---
layout: briefing
title: "2026-11-25 보안 이슈 브리핑"
date: 2026-11-25 09:00:00 +0900
issue_no: 7
threat_level: 5
summary: "가상화 서버와 클라우드 등 핵심 인프라의 고위험 취약점 악용과 대규모 정보 유출 사고가 이어진 하루."
tags: ["사고", "취약점"]
description: "VMware vCenter 인증 우회 고위험 취약점 발견 / 화면 원격 제어 프로그램 취약점 악용 서버 해킹 / 하나저축은행 해킹으로 고객 개인신용정보 유출 / 국내 전력회사 한국전력공사 대규모 개인정보 유출 발생 / 노르웨이 에너지 기업 타깃 애저 클라우드 취약점 악용"
items: [{"title": "VMware vCenter 인증 우회 고위험 취약점 발견", "region": "해외", "category": "취약점", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "VMware 제품군 전반의 제로데이 악용 및 고위험 취약점", "core": "브로드컴이 VMware vCenter와 ESX 등을 포함한 23개의 보안 취약점을 해결하는 패치를 배포했다. 이 중 인증을 우회할 수 있는 CVE-2026-123903 취약점은 CVSS 점수 9.8점으로 매우 위험하다. 제로데이 공격에 악용된 정황이 있어 긴급한 업데이트가 필요하다.", "background": "소프트웨어 내부에서 사용자가 누구인지 확인하는 인증 과정을 건너뛰도록 만드는 결함이다. 공격자가 이 취약점을 이용하면 시스템 관리자 권한을 가로채어 마음대로 조작할 수 있게 된다. 복잡한 인증 절차를 설계상의 허점으로 무력화시키는 전형적인 보안 취약점이다.", "impact": "기업 내부 가상화 서버가 해커에게 통째로 넘어가면 대규모 데이터 유출이나 서비스 중단으로 이어진다. 관리자는 즉시 브로드컴이 제공하는 최신 보안 패치를 적용해야 한다.", "key_figure": "9.8", "key_figure_label": "CVSS 점수", "cve": "CVE-2026-123903", "cvss": 9.8, "source": "The Hacker News", "link": "https://thehackernews.com/2026/11/vmware-vcenter-hit-by-another-critical.html", "cve_status": "nvd", "cvss_severity": "CRITICAL", "cvss_version": "3.1", "cvss_source": "CNA", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 2.45, "epss_percentile": 85.1, "epss_date": "2026-11-27", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "P2", "priority_reasons": ["CVSS 9.8 ≥ 7.0", "EPSS 2.45% ≥ 1%"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 쉬움", "level": "bad"}, {"k": "필요 권한", "v": "로그인 불필요", "level": "bad"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "영향 범위", "v": "해당 시스템에 한정", "level": "ok"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-287"], "isms": ["2.10.8", "2.8.6"], "attack": ["T1190", "T1068"], "actions": ["VMware vCenter 및 ESX 즉시 최신 패치 적용", "외부 노출된 가상화 관리 포트 접근 제한"]}, {"title": "화면 원격 제어 프로그램 취약점 악용 서버 해킹", "region": "해외", "category": "취약점", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2 (CISA KEV)", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "ScreenConnect 클라이언트 취약점을 통한 실제 공격 발생", "core": "원격 관리 도구인 커넥트와이즈 스크린커넥트에서 악성 코드 실행이 가능한 고위험 취약점이 발견됐다. CVE-2026-84869로 등록된 이 취약점의 CVSS 점수는 9.9점이며, 공격자들이 실제 서버 공격에 악용하고 있다.", "background": "원격 지원을 위해 사용자가 연결된 상태에서 외부 프로그램이나 파일을 몰래 다운로드하고 실행할 수 있게 만드는 결함이다. 시스템 관리 권한을 가진 프로그램의 특성상 한번 뚫리면 내부망 전체가 위험해진다.", "impact": "원격 관리 업체를 표적 삼아 침투하는 공급망 공격으로 이어질 수 있어 산업 전반에 파장이 크다. 담당자는 해당 소프트웨어를 즉시 차단하거나 안전한 버전으로 업그레이드해야 한다.", "key_figure": "9.9", "key_figure_label": "CVSS 점수", "cve": "CVE-2026-84869", "cvss": 9.9, "source": "The Hacker News", "link": "https://thehackernews.com/2026/11/hackers-exploit-critical-screenconnect.html", "cve_status": "nvd", "cvss_severity": "CRITICAL", "cvss_version": "3.1", "cvss_source": "CNA", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "epss": 0.92, "epss_percentile": 58.7, "epss_date": "2026-11-27", "kev": true, "kev_date": "2026-09-11", "kev_ransomware": false, "priority": "P1", "priority_reasons": ["CISA KEV 등재(실제 악용 확인)"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 쉬움", "level": "bad"}, {"k": "필요 권한", "v": "일반 계정 필요", "level": "ok"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "영향 범위", "v": "다른 시스템까지 영향", "level": "bad"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-269", "CWE-862"], "isms": ["2.10.8", "2.6.6"], "attack": ["T1190", "T1204"], "actions": ["ScreenConnect 클라이언트 버전 업데이트", "원격 관리용 프로그램의 외부 접속 로그 점검"]}, {"title": "하나저축은행 해킹으로 고객 개인신용정보 유출", "region": "국내", "category": "사고", "severity": 4, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "소규모", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "small", "domestic": true, "critical_sector": true, "factor_note": "하나저축은행 고객 552명 정보 유출 사고 발생", "core": "하나저축은행이 외부 불법 침입을 받아 고객 552명의 주민등록번호와 주소 등 개인신용정보가 유출됐다. 모바일웹의 고객확인 재이행 시스템이 공격당했으며, 추가 피해 조사가 진행 중이다.", "background": "자금세탁방지를 위해 주기적으로 고객의 신원 정보를 확인하고 갱신하는 업무 시스템에 보안 허점이 발생했다. 주민등록번호나 직장 주소처럼 평소 바꾸기 어려운 민감한 정보가 대거 포함되어 있어 피해가 크다.", "impact": "유출된 정보가 보이스피싱이나 명의도용 같은 2차 금융 범죄에 악용될 우려가 높다. 고객은 안심차단 서비스를 신청하고, 기업은 외부 접점 시스템의 보안을 강화해야 한다.", "key_figure": "552", "key_figure_label": "피해 고객 수", "cve": "", "cvss": 0.0, "source": "데일리시큐", "link": "https://www.dailysecu.com/news/articleView.html?idxno=209707", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.10.3", "2.9.4", "3.1.1"], "attack": ["T1190"], "actions": ["고객 접점 모바일웹 및 시스템 취약점 전수 점검", "비정상 외부 IP 접근 차단 및 24시간 모니터링"]}, {"title": "국내 전력회사 한국전력공사 대규모 개인정보 유출 발생", "region": "해외", "category": "사고", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "국내 전력사 한국전력공사 150만 명 영향 데이터 유출", "core": "해외 보안 매체 보도에 따르면 한국전력공사에서 발생한 사이버 침해사고로 인해 150만 명 규모의 데이터가 유출되었다. 전력 인프라 관련 기업을 겨냥한 이번 사고로 대규모 정보가 외부로 노출됐다.", "background": "전력 공급이라는 핵심 공공 서비스를 운영하는 기관의 방어망이 뚫리면서 대규모 정보가 유출되는 심각한 상황이 발생했다. 공격자들은 기업의 방어벽을 우회하거나 관리자 계정을 탈취하여 내부 데이터베이스에 접근한 것으로 추정된다.", "impact": "국가 핵심 기반시설의 정보 유출은 국가 안보와 사회 전반의 에너지 공급 안정성을 흔들 수 있다. 관련 공공 및 에너지 기관은 즉시 보안 관제를 강화하고 비상 대응 체계를 점검해야 한다.", "key_figure": "150만", "key_figure_label": "영향받은 인원", "cve": "", "cvss": 0.0, "source": "SecurityWeek", "link": "https://www.securityweek.com/1-5-million-impacted-by-data-breach-at-south-korean-electric-company-kepco/", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.4.3", "2.9.4", "2.11.5"], "attack": ["T1190", "T1078"], "actions": ["핵심 데이터베이스 접근 권한 재검토 및 통제 강화", "비정상적인 대외 데이터 유출 시도 모니터링"]}, {"title": "노르웨이 에너지 기업 타깃 애저 클라우드 취약점 악용", "region": "해외", "category": "사고", "severity": 4, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "규모 중간 +1", "핵심 업종 +1"], "exploitation": "active", "scale": "medium", "domestic": false, "critical_sector": true, "factor_note": "노르웨이 에너지 기업 대상 클라우드 비밀 정보 탈취", "core": "노르웨이의 주요 에너지 기업들을 겨냥한 사이버 공격에서 마이크로소프트 애저 클라우드의 취약점이 악용되었다. 공격자들은 클라우드 내부에 숨겨진 중요 비밀 정보와 인증 키를 탈취했다.", "background": "클라우드 서비스 설정의 허점이나 시스템 결함을 이용해 내부 보안망을 우회하는 공격 기법이다. 에너지 산업처럼 고도의 보안이 필요한 분야의 클라우드 환경이 주요 표적이 되고 있다.", "impact": "에너지 공급망의 기밀 정보가 유출될 경우 국가 기반시설 운영에 치명적인 차질이 빚어질 수 있다. 기업들은 클라우드 환경 설정 상태를 점검하고 접근 제어를 엄격히 해야 한다.", "key_figure": "", "key_figure_label": "", "cve": "", "cvss": 0.0, "source": "SecurityWeek", "link": "https://www.securityweek.com/azure-flaw-exploited-to-target-secrets-at-norwegian-energy-firms/", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.10.2", "2.5.5", "2.6.2"], "attack": ["T1530", "T1552"], "actions": ["클라우드 서비스 설정 및 접근 권한 일제 점검", "외부 노출된 API 및 비밀 키(Secrets) 안전성 확인"]}]
terms: [{"term": "제로데이", "english": "Zero-Day", "definition": "보안 취약점이 세상에 공식적으로 알려지기도 전에 해커가 이를 먼저 찾아내어 공격에 사용하는 상태를 말한다."}, {"term": "CVSS", "english": "Common Vulnerability Scoring System", "definition": "컴퓨터 보안 취약점의 심각성을 0부터 10까지의 점수로 매겨 얼마나 위험한지 알려주는 객관적인 지표이다."}, {"term": "공급망 공격", "english": "Supply Chain Attack", "definition": "보안이 상대적으로 취약한 협력업체나 외부 소프트웨어를 먼저 감염시킨 뒤, 이를 통해 안전한 대기업이나 목표 기관을 침투하는 우회 공격 방법이다."}, {"term": "인증 우회", "english": "Authentication Bypass", "definition": "열쇠나 비밀번호를 정확히 입력하지 않고도 문을 열고 시스템에 들어갈 수 있도록 만든 보안상의 허점이다."}]
---

> 오늘의 주요 보안 이슈 5건 (국내 1 · 해외 4)

## 📌 한눈에 보기

1. **[해외·취약점]** VMware vCenter 인증 우회 고위험 취약점 발견
2. **[해외·취약점]** 화면 원격 제어 프로그램 취약점 악용 서버 해킹
3. **[국내·사고]** 하나저축은행 해킹으로 고객 개인신용정보 유출
4. **[해외·사고]** 국내 전력회사 한국전력공사 대규모 개인정보 유출 발생
5. **[해외·사고]** 노르웨이 에너지 기업 타깃 애저 클라우드 취약점 악용

---

## 1. 🛠️ VMware vCenter 인증 우회 고위험 취약점 발견

`해외` `취약점` · 출처: [The Hacker News](https://thehackernews.com/2026/11/vmware-vcenter-hit-by-another-critical.html)

**🎯 핵심**  
브로드컴이 VMware vCenter와 ESX 등을 포함한 23개의 보안 취약점을 해결하는 패치를 배포했다. 이 중 인증을 우회할 수 있는 CVE-2026-123903 취약점은 CVSS 점수 9.8점으로 매우 위험하다. 제로데이 공격에 악용된 정황이 있어 긴급한 업데이트가 필요하다.

**📖 배경**  
소프트웨어 내부에서 사용자가 누구인지 확인하는 인증 과정을 건너뛰도록 만드는 결함이다. 공격자가 이 취약점을 이용하면 시스템 관리자 권한을 가로채어 마음대로 조작할 수 있게 된다. 복잡한 인증 절차를 설계상의 허점으로 무력화시키는 전형적인 보안 취약점이다.

**💥 영향**  
기업 내부 가상화 서버가 해커에게 통째로 넘어가면 대규모 데이터 유출이나 서비스 중단으로 이어진다. 관리자는 즉시 브로드컴이 제공하는 최신 보안 패치를 적용해야 한다.

---

## 2. 🛠️ 화면 원격 제어 프로그램 취약점 악용 서버 해킹

`해외` `취약점` · 출처: [The Hacker News](https://thehackernews.com/2026/11/hackers-exploit-critical-screenconnect.html)

**🎯 핵심**  
원격 관리 도구인 커넥트와이즈 스크린커넥트에서 악성 코드 실행이 가능한 고위험 취약점이 발견됐다. CVE-2026-84869로 등록된 이 취약점의 CVSS 점수는 9.9점이며, 공격자들이 실제 서버 공격에 악용하고 있다.

**📖 배경**  
원격 지원을 위해 사용자가 연결된 상태에서 외부 프로그램이나 파일을 몰래 다운로드하고 실행할 수 있게 만드는 결함이다. 시스템 관리 권한을 가진 프로그램의 특성상 한번 뚫리면 내부망 전체가 위험해진다.

**💥 영향**  
원격 관리 업체를 표적 삼아 침투하는 공급망 공격으로 이어질 수 있어 산업 전반에 파장이 크다. 담당자는 해당 소프트웨어를 즉시 차단하거나 안전한 버전으로 업그레이드해야 한다.

---

## 3. 🚨 하나저축은행 해킹으로 고객 개인신용정보 유출

`국내` `사고` · 출처: [데일리시큐](https://www.dailysecu.com/news/articleView.html?idxno=209707)

**🎯 핵심**  
하나저축은행이 외부 불법 침입을 받아 고객 552명의 주민등록번호와 주소 등 개인신용정보가 유출됐다. 모바일웹의 고객확인 재이행 시스템이 공격당했으며, 추가 피해 조사가 진행 중이다.

**📖 배경**  
자금세탁방지를 위해 주기적으로 고객의 신원 정보를 확인하고 갱신하는 업무 시스템에 보안 허점이 발생했다. 주민등록번호나 직장 주소처럼 평소 바꾸기 어려운 민감한 정보가 대거 포함되어 있어 피해가 크다.

**💥 영향**  
유출된 정보가 보이스피싱이나 명의도용 같은 2차 금융 범죄에 악용될 우려가 높다. 고객은 안심차단 서비스를 신청하고, 기업은 외부 접점 시스템의 보안을 강화해야 한다.

---

## 4. 🚨 국내 전력회사 한국전력공사 대규모 개인정보 유출 발생

`해외` `사고` · 출처: [SecurityWeek](https://www.securityweek.com/1-5-million-impacted-by-data-breach-at-south-korean-electric-company-kepco/)

**🎯 핵심**  
해외 보안 매체 보도에 따르면 한국전력공사에서 발생한 사이버 침해사고로 인해 150만 명 규모의 데이터가 유출되었다. 전력 인프라 관련 기업을 겨냥한 이번 사고로 대규모 정보가 외부로 노출됐다.

**📖 배경**  
전력 공급이라는 핵심 공공 서비스를 운영하는 기관의 방어망이 뚫리면서 대규모 정보가 유출되는 심각한 상황이 발생했다. 공격자들은 기업의 방어벽을 우회하거나 관리자 계정을 탈취하여 내부 데이터베이스에 접근한 것으로 추정된다.

**💥 영향**  
국가 핵심 기반시설의 정보 유출은 국가 안보와 사회 전반의 에너지 공급 안정성을 흔들 수 있다. 관련 공공 및 에너지 기관은 즉시 보안 관제를 강화하고 비상 대응 체계를 점검해야 한다.

---

## 5. 🚨 노르웨이 에너지 기업 타깃 애저 클라우드 취약점 악용

`해외` `사고` · 출처: [SecurityWeek](https://www.securityweek.com/azure-flaw-exploited-to-target-secrets-at-norwegian-energy-firms/)

**🎯 핵심**  
노르웨이의 주요 에너지 기업들을 겨냥한 사이버 공격에서 마이크로소프트 애저 클라우드의 취약점이 악용되었다. 공격자들은 클라우드 내부에 숨겨진 중요 비밀 정보와 인증 키를 탈취했다.

**📖 배경**  
클라우드 서비스 설정의 허점이나 시스템 결함을 이용해 내부 보안망을 우회하는 공격 기법이다. 에너지 산업처럼 고도의 보안이 필요한 분야의 클라우드 환경이 주요 표적이 되고 있다.

**💥 영향**  
에너지 공급망의 기밀 정보가 유출될 경우 국가 기반시설 운영에 치명적인 차질이 빚어질 수 있다. 기업들은 클라우드 환경 설정 상태를 점검하고 접근 제어를 엄격히 해야 한다.

---

## 📚 오늘의 보안 용어

- **제로데이** (Zero-Day): 보안 취약점이 세상에 공식적으로 알려지기도 전에 해커가 이를 먼저 찾아내어 공격에 사용하는 상태를 말한다.
- **CVSS** (Common Vulnerability Scoring System): 컴퓨터 보안 취약점의 심각성을 0부터 10까지의 점수로 매겨 얼마나 위험한지 알려주는 객관적인 지표이다.
- **공급망 공격** (Supply Chain Attack): 보안이 상대적으로 취약한 협력업체나 외부 소프트웨어를 먼저 감염시킨 뒤, 이를 통해 안전한 대기업이나 목표 기관을 침투하는 우회 공격 방법이다.
- **인증 우회** (Authentication Bypass): 열쇠나 비밀번호를 정확히 입력하지 않고도 문을 열고 시스템에 들어갈 수 있도록 만든 보안상의 허점이다.

👉 지금까지 나온 용어는 [보안 용어 사전](../../glossary/)에서 볼 수 있어요.

---

<small>이 글은 공개된 보안 뉴스를 AI(Gemini)로 요약해 자동 작성했습니다. 정확한 내용은 각 출처 원문을 확인하세요.</small>
