---
layout: briefing
title: "2026-11-20 보안 이슈 브리핑"
date: 2026-11-20 09:00:00 +0900
issue_no: 3
threat_level: 4
summary: "서버 관리 프로그램과 기초 웹 언어의 치명적 취약점 패치 및 소상공인 개인정보 유출 사고가 발생한 하루"
tags: ["사고", "취약점"]
description: "가상화 서버 관리 콘솔 v센터에서 인증 우회 제로데이 취약점 발견 / PHP 재단, 원격 코드 실행 가능한 치명적 취약점 7건 패치 / 웹서버 프로그램 NGINX에서 서버 장악 가능한 고위험 취약점 발견 / 브로드컴, 가상화 관리 솔루션 v센터 보안 취약점 긴급 패치 권고 / 소상공인 공제 노란우산에서 고객 개인정보 36만여 건 유출"
items: [{"title": "가상화 서버 관리 콘솔 v센터에서 인증 우회 제로데이 취약점 발견", "region": "해외", "category": "취약점", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2 (CISA KEV)", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "중국 연계 해킹 그룹의 v센터 제로데이 실제 악용", "core": "중국 연계 해킹 그룹이 VM웨어 v센터 서버의 인증 우회 제로데이 취약점을 악용해 관리자 권한을 탈취하고 데이터를 훔쳤다. 해당 취약점은 CVE-2026-123890이며 CVSS 점수는 9.8점이다.", "background": "제로데이는 보안 패치가 아직 나오지 않은 아주 새로운 취약점을 말한다. 공격자는 이 약점을 이용해 보안 문을 거치지 않고 시스템 안으로 들어올 수 있다. v센터는 여러 가상 서버를 한곳에서 관리하는 중앙 통제실 같은 프로그램이다.", "impact": "기업의 클라우드와 서버 전체가 위험에 빠질 수 있어 산업계에 큰 충격을 준다. 관리자는 브로드컴이 제공하는 긴급 보안 업데이트를 서둘러 적용해야 한다.", "key_figure": "9.8", "key_figure_label": "CVSS 점수", "cve": "CVE-2026-123890", "cvss": 9.8, "source": "The Hacker News", "link": "https://thehackernews.com/2026/11/china-linked-hackers-exploit-critical.html", "cve_status": "nvd", "cvss_severity": "CRITICAL", "cvss_version": "3.1", "cvss_source": "CNA", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 3.53, "epss_percentile": 89.4, "epss_date": "2026-11-24", "kev": true, "kev_date": "2026-11-20", "kev_ransomware": false, "priority": "P1", "priority_reasons": ["CISA KEV 등재(실제 악용 확인)"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 쉬움", "level": "bad"}, {"k": "필요 권한", "v": "로그인 불필요", "level": "bad"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "영향 범위", "v": "해당 시스템에 한정", "level": "ok"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-288"], "isms": ["2.10.8", "2.11.2"], "attack": ["T1190"], "actions": ["vCenter 서버 버전 확인 후 즉시 패치 적용", "네트워크 접근 통제 및 비인가 접근 로그 점검"]}, {"title": "PHP 재단, 원격 코드 실행 가능한 치명적 취약점 7건 패치", "region": "해외", "category": "취약점", "severity": 3, "severity_method": "rule", "severity_basis": ["악용 확인 안 됨", "대규모 +2", "국내 영향 +1"], "exploitation": "none", "scale": "large", "domestic": true, "critical_sector": false, "factor_note": "PHP 생태계 전반에 영향을 미치는 다수 취약점 패치", "core": "PHP 재단이 웹서버를 원격에서 제어할 수 있게 만드는 치명적인 보안 결함 7건을 수정하는 업데이트를 발표했다. 대표적인 취약점으로는 CVE-2026-115560이 포함되었다.", "background": "원격 코드 실행은 해커가 멀리 떨어진 곳에서 인터넷을 통해 서버에 악성 명령어를 실행할 수 있는 위험한 상태를 뜻한다. PHP는 전 세계 수많은 웹사이트를 만드는 데 쓰이는 기초 프로그래밍 언어다.", "impact": "이 취약점이 방치되면 웹사이트가 통째로 해커의 손에 넘어갈 수 있다. 개발자와 기업은 사용하는 PHP 버전을 최신 버전으로 즉시 업데이트해야 한다.", "key_figure": "7", "key_figure_label": "패치된 취약점 수", "cve": "CVE-2026-115560", "cvss": 9.2, "source": "The Hacker News", "link": "https://thehackernews.com/2026/11/php-fixes-7-critical-flaws-including.html", "cve_status": "nvd", "cvss_severity": "CRITICAL", "cvss_version": "4.0", "cvss_source": "CNA", "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", "epss": 73.11, "epss_percentile": 99.5, "epss_date": "2026-11-24", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "P1", "priority_reasons": ["EPSS 73.11% ≥ 10%"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 조건 까다로움", "level": "ok"}, {"k": "전제 조건", "v": "특정 조건 필요", "level": "ok"}, {"k": "필요 권한", "v": "로그인 불필요", "level": "bad"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-20", "CWE-502"], "isms": ["2.10.8"], "attack": ["T1190"], "actions": ["사용 중인 PHP 버전 확인 및 최신 보안 패치 적용", "웹서버 응용프로그램 접근 기록 모니터링 강화"]}, {"title": "웹서버 프로그램 NGINX에서 서버 장악 가능한 고위험 취약점 발견", "region": "해외", "category": "취약점", "severity": 4, "severity_method": "rule", "severity_basis": ["공격 가능성 공개 +1", "대규모 +2", "국내 영향 +1"], "exploitation": "poc", "scale": "large", "domestic": true, "critical_sector": false, "factor_note": "수백만 대의 NGINX 서비스가 노출된 HTTP/2 취약점", "core": "널리 쓰이는 웹서버 프로그램 NGINX에서 공격자가 코드를 실행해 서버를 장악할 수 있는 취약점들이 발견되었다. 대표 취약점인 CVE-2026-123007은 HTTP/2 통신 과정의 메모리 오류를 유발한다.", "background": "NGINX는 인터넷 사용자가 웹사이트에 접속할 때 그 요청을 받아 페이지를 보여주는 도깨비 방망이 같은 프로그램이다. HTTP/2는 웹페이지를 더 빠르게 띄워주기 위해 만든 최신 통신 규칙이지만 복잡한 만큼 틈이 생기기 쉽다.", "impact": "전 세계 수많은 웹서버가 공격 대상이 될 수 있어 대규모 피해로 이어질 수 있다. 관리자는 즉시 NGINX를 최신 버전으로 업그레이드하거나 임시로 HTTP/2 기능을 꺼야 한다.", "key_figure": "8.8만", "key_figure_label": "노출된 NGINX 서비스 수", "cve": "CVE-2026-123007", "cvss": 8.1, "source": "BleepingComputer", "link": "https://www.bleepingcomputer.com/news/security/critical-nginx-nginx2root-bugs-let-attackers-hijack-servers/", "cve_status": "nvd", "cvss_severity": "HIGH", "cvss_version": "3.1", "cvss_source": "CNA", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 44.7, "epss_percentile": 98.8, "epss_date": "2026-11-24", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "P1", "priority_reasons": ["EPSS 44.7% ≥ 10%"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 조건 까다로움", "level": "ok"}, {"k": "필요 권한", "v": "로그인 불필요", "level": "bad"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "영향 범위", "v": "해당 시스템에 한정", "level": "ok"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-191", "CWE-787"], "isms": ["2.10.3", "2.10.8"], "attack": ["T1190"], "actions": ["NGINX를 최신 안정 버전으로 즉시 업그레이드", "필요시 HTTP/2 기능 일시 비활성화 검토"]}, {"title": "브로드컴, 가상화 관리 솔루션 v센터 보안 취약점 긴급 패치 권고", "region": "국내", "category": "취약점", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2 (CISA KEV)", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "none", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "브로드컴 v센터 최고 등급 인증 우회 결함 발생", "core": "브로드컴이 가상화 관리 프로그램인 v센터의 인증 우회 결함(CVE-2026-123890)을 해결하기 위한 긴급 업데이트를 발표했다. 이번 결함은 구글 맨디언트가 제보했으며 아직 실제 공격은 보고되지 않았다.", "background": "v센터는 여러 가상 컴퓨터를 효율적으로 관리하는 통합 제어판이다. 이 제어판에 인증 우회 구멍이 뚫리면 신원 확인 절차 없이도 해커가 관리 구역에 들어올 수 있게 된다.", "impact": "기업 인프라의 핵심인 가상화 환경이 무너질 수 있어 신속한 대응이 필수적이다. 관리자는 변경 관리 일정을 조정해서라도 즉시 패치를 적용해야 한다.", "key_figure": "361", "key_figure_label": "과거 유사 공격 침해 IP 수", "cve": "CVE-2026-123890", "cvss": 9.8, "source": "보안뉴스", "link": "https://www.boannews.com/news/articleView.html?idxno=147404", "cve_status": "nvd", "cvss_severity": "CRITICAL", "cvss_version": "3.1", "cvss_source": "CNA", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 3.53, "epss_percentile": 89.4, "epss_date": "2026-11-24", "kev": true, "kev_date": "2026-11-20", "kev_ransomware": false, "priority": "P1", "priority_reasons": ["CISA KEV 등재(실제 악용 확인)"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 쉬움", "level": "bad"}, {"k": "필요 권한", "v": "로그인 불필요", "level": "bad"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "영향 범위", "v": "해당 시스템에 한정", "level": "ok"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-288"], "isms": ["2.10.8", "2.11.2"], "attack": ["T1190"], "actions": ["vCenter 시스템 누적 업데이트 즉시 적용", "업데이트 전후 VCF 버전 호환성 사전 확인"]}, {"title": "소상공인 공제 노란우산에서 고객 개인정보 36만여 건 유출", "region": "국내", "category": "사고", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "노란우산 가입자 36만여 명의 개인 및 금융정보 유출", "core": "중소기업중앙회가 운영하는 노란우산 홈페이지에 외부 비인가자가 무단 접근해 고객 개인정보와 납부 계좌번호 등 36만여 건이 유출되었다. 중소기업중앙회는 피해 사실을 확인하고 관계 기관에 신고했다.", "background": "노란우산은 소상공인의 생활 안정을 돕기 위해 만든 공제 제도이다. 해커가 웹사이트의 허술한 틈을 타 몰래 정보를 긁어가는 무단 조회 방식으로 정보를 빼돌렸다.", "impact": "유출된 계좌번호와 납부 내역이 보이스피싱이나 기관 사칭 등 2차 금융범죄에 악용될 위험이 크다. 이용자는 출처가 불분명한 문자 속 링크를 절대 누르지 않도록 주의해야 한다.", "key_figure": "36만", "key_figure_label": "유출된 정보 건수", "cve": "", "cvss": 0.0, "source": "데일리시큐", "link": "https://www.dailysecu.com/news/articleView.html?idxno=209624", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.5.1", "2.9.4", "3.1.1"], "attack": ["T1190"], "actions": ["웹사이트 비정상 접근 차단 및 로그 기록 점검", "피해 고객 대상 개별 안내 및 고객센터 대응 체계 유지"]}]
terms: [{"term": "제로데이", "english": "Zero-Day", "definition": "보안 패치가 아직 나오지 않은 아주 새로운 취약점을 뜻하며, 집의 새로운 문틈을 발견했지만 아직 자물쇠가 만들어지지 않은 상태와 같다."}, {"term": "원격 코드 실행", "english": "Remote Code Execution", "definition": "멀리 떨어진 곳에서 인터넷을 통해 다른 사람의 컴퓨터나 서버에 나쁜 명령을 내려 마음대로 조종할 수 있게 되는 보안 약점이다."}, {"term": "인증 우회", "english": "Authentication Bypass", "definition": "로그인할 때 필요한 아이디나 비밀번호 검사 과정을 몰래 건너뛰어 신분 확인 없이 시스템에 들어가는 해킹 방식이다."}, {"term": "공급망 공격", "english": "Supply Chain Compromise", "definition": "튼튼한 본체 대신 프로그램이 만들어져 전달되는 유통 과정이나 관련 도구를 먼저 망가뜨려 그 속에 숨어 있던 사용자들까지 함께 피해를 보게 만드는 공격이다."}]
---

> 오늘의 주요 보안 이슈 5건 (국내 2 · 해외 3)

## 📌 한눈에 보기

1. **[해외·취약점]** 가상화 서버 관리 콘솔 v센터에서 인증 우회 제로데이 취약점 발견
2. **[해외·취약점]** PHP 재단, 원격 코드 실행 가능한 치명적 취약점 7건 패치
3. **[해외·취약점]** 웹서버 프로그램 NGINX에서 서버 장악 가능한 고위험 취약점 발견
4. **[국내·취약점]** 브로드컴, 가상화 관리 솔루션 v센터 보안 취약점 긴급 패치 권고
5. **[국내·사고]** 소상공인 공제 노란우산에서 고객 개인정보 36만여 건 유출

---

## 1. 🛠️ 가상화 서버 관리 콘솔 v센터에서 인증 우회 제로데이 취약점 발견

`해외` `취약점` · 출처: [The Hacker News](https://thehackernews.com/2026/11/china-linked-hackers-exploit-critical.html)

**🎯 핵심**  
중국 연계 해킹 그룹이 VM웨어 v센터 서버의 인증 우회 제로데이 취약점을 악용해 관리자 권한을 탈취하고 데이터를 훔쳤다. 해당 취약점은 CVE-2026-123890이며 CVSS 점수는 9.8점이다.

**📖 배경**  
제로데이는 보안 패치가 아직 나오지 않은 아주 새로운 취약점을 말한다. 공격자는 이 약점을 이용해 보안 문을 거치지 않고 시스템 안으로 들어올 수 있다. v센터는 여러 가상 서버를 한곳에서 관리하는 중앙 통제실 같은 프로그램이다.

**💥 영향**  
기업의 클라우드와 서버 전체가 위험에 빠질 수 있어 산업계에 큰 충격을 준다. 관리자는 브로드컴이 제공하는 긴급 보안 업데이트를 서둘러 적용해야 한다.

---

## 2. 🛠️ PHP 재단, 원격 코드 실행 가능한 치명적 취약점 7건 패치

`해외` `취약점` · 출처: [The Hacker News](https://thehackernews.com/2026/11/php-fixes-7-critical-flaws-including.html)

**🎯 핵심**  
PHP 재단이 웹서버를 원격에서 제어할 수 있게 만드는 치명적인 보안 결함 7건을 수정하는 업데이트를 발표했다. 대표적인 취약점으로는 CVE-2026-115560이 포함되었다.

**📖 배경**  
원격 코드 실행은 해커가 멀리 떨어진 곳에서 인터넷을 통해 서버에 악성 명령어를 실행할 수 있는 위험한 상태를 뜻한다. PHP는 전 세계 수많은 웹사이트를 만드는 데 쓰이는 기초 프로그래밍 언어다.

**💥 영향**  
이 취약점이 방치되면 웹사이트가 통째로 해커의 손에 넘어갈 수 있다. 개발자와 기업은 사용하는 PHP 버전을 최신 버전으로 즉시 업데이트해야 한다.

---

## 3. 🛠️ 웹서버 프로그램 NGINX에서 서버 장악 가능한 고위험 취약점 발견

`해외` `취약점` · 출처: [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-nginx-nginx2root-bugs-let-attackers-hijack-servers/)

**🎯 핵심**  
널리 쓰이는 웹서버 프로그램 NGINX에서 공격자가 코드를 실행해 서버를 장악할 수 있는 취약점들이 발견되었다. 대표 취약점인 CVE-2026-123007은 HTTP/2 통신 과정의 메모리 오류를 유발한다.

**📖 배경**  
NGINX는 인터넷 사용자가 웹사이트에 접속할 때 그 요청을 받아 페이지를 보여주는 도깨비 방망이 같은 프로그램이다. HTTP/2는 웹페이지를 더 빠르게 띄워주기 위해 만든 최신 통신 규칙이지만 복잡한 만큼 틈이 생기기 쉽다.

**💥 영향**  
전 세계 수많은 웹서버가 공격 대상이 될 수 있어 대규모 피해로 이어질 수 있다. 관리자는 즉시 NGINX를 최신 버전으로 업그레이드하거나 임시로 HTTP/2 기능을 꺼야 한다.

---

## 4. 🛠️ 브로드컴, 가상화 관리 솔루션 v센터 보안 취약점 긴급 패치 권고

`국내` `취약점` · 출처: [보안뉴스](https://www.boannews.com/news/articleView.html?idxno=147404)

**🎯 핵심**  
브로드컴이 가상화 관리 프로그램인 v센터의 인증 우회 결함(CVE-2026-123890)을 해결하기 위한 긴급 업데이트를 발표했다. 이번 결함은 구글 맨디언트가 제보했으며 아직 실제 공격은 보고되지 않았다.

**📖 배경**  
v센터는 여러 가상 컴퓨터를 효율적으로 관리하는 통합 제어판이다. 이 제어판에 인증 우회 구멍이 뚫리면 신원 확인 절차 없이도 해커가 관리 구역에 들어올 수 있게 된다.

**💥 영향**  
기업 인프라의 핵심인 가상화 환경이 무너질 수 있어 신속한 대응이 필수적이다. 관리자는 변경 관리 일정을 조정해서라도 즉시 패치를 적용해야 한다.

---

## 5. 🚨 소상공인 공제 노란우산에서 고객 개인정보 36만여 건 유출

`국내` `사고` · 출처: [데일리시큐](https://www.dailysecu.com/news/articleView.html?idxno=209624)

**🎯 핵심**  
중소기업중앙회가 운영하는 노란우산 홈페이지에 외부 비인가자가 무단 접근해 고객 개인정보와 납부 계좌번호 등 36만여 건이 유출되었다. 중소기업중앙회는 피해 사실을 확인하고 관계 기관에 신고했다.

**📖 배경**  
노란우산은 소상공인의 생활 안정을 돕기 위해 만든 공제 제도이다. 해커가 웹사이트의 허술한 틈을 타 몰래 정보를 긁어가는 무단 조회 방식으로 정보를 빼돌렸다.

**💥 영향**  
유출된 계좌번호와 납부 내역이 보이스피싱이나 기관 사칭 등 2차 금융범죄에 악용될 위험이 크다. 이용자는 출처가 불분명한 문자 속 링크를 절대 누르지 않도록 주의해야 한다.

---

## 📚 오늘의 보안 용어

- **제로데이** (Zero-Day): 보안 패치가 아직 나오지 않은 아주 새로운 취약점을 뜻하며, 집의 새로운 문틈을 발견했지만 아직 자물쇠가 만들어지지 않은 상태와 같다.
- **원격 코드 실행** (Remote Code Execution): 멀리 떨어진 곳에서 인터넷을 통해 다른 사람의 컴퓨터나 서버에 나쁜 명령을 내려 마음대로 조종할 수 있게 되는 보안 약점이다.
- **인증 우회** (Authentication Bypass): 로그인할 때 필요한 아이디나 비밀번호 검사 과정을 몰래 건너뛰어 신분 확인 없이 시스템에 들어가는 해킹 방식이다.
- **공급망 공격** (Supply Chain Compromise): 튼튼한 본체 대신 프로그램이 만들어져 전달되는 유통 과정이나 관련 도구를 먼저 망가뜨려 그 속에 숨어 있던 사용자들까지 함께 피해를 보게 만드는 공격이다.

👉 지금까지 나온 용어는 [보안 용어 사전](../../glossary/)에서 볼 수 있어요.

---

<small>이 글은 공개된 보안 뉴스를 AI(Gemini)로 요약해 자동 작성했습니다. 정확한 내용은 각 출처 원문을 확인하세요.</small>
