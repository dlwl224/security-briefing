---
layout: briefing
title: "2026-11-24 보안 이슈 브리핑"
date: 2026-11-24 09:00:00 +0900
issue_no: 6
threat_level: 4
summary: "에너지 공기업 대규모 정보 유출과 클라우드·네트워크 장비 취약점 악용이 잇따른 하루"
tags: ["사고", "취약점"]
description: "한국전력, 해킹으로 한전ON 및 조달시스템 152만 명 개인정보 유출 / 한국전력공사 150만 명 정보 유출 외신 보도 및 AI 공격 연루 의혹 / MS 애저 API 매니지먼트 취약점 악용…노르웨이 에너지 기업 기밀 탈취 / 스페인 프로축구 라리가 팬 서비스 플랫폼 해킹으로 개인정보 유출 / CISA, 악용 확인된 시스코 익스프레스웨이 원격 코드 실행 취약점 경고"
items: [{"title": "한국전력, 해킹으로 한전ON 및 조달시스템 152만 명 개인정보 유출", "region": "국내", "category": "사고", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "한전 고객 및 조달 이용자 152만 명 정보 유출, 국가 핵심 인프라", "core": "한국전력공사의 한전ON 및 전자조달시스템(SRM)에서 약 152만 명분의 고객 및 조달 관계자 개인정보가 해킹으로 유출되었다. 유출된 정보에는 성명, 주민등록번호, 계좌 및 카드정보, 사번 등이 포함되었으며 한전은 해커 협박 메일 수신 후 당국에 신고했다. 개인정보보호위원회와 한국인터넷진흥원은 초동대응반을 꾸려 현장 조사에 착수했다.", "background": "해커는 지난 11월 19일 다크웹 해킹 커뮤니티에 한전 데이터를 확보했다고 주장하며 한전 측에 협박 이메일을 발송했다. 한전은 20일 샘플 데이터를 확인한 후 22일 개인정보보호위원회에 사고를 공식 신고했다. 전자조달시스템(SRM)은 공공기관의 입찰과 계약을 다루는 시스템이며, 한전ON은 일반 국민이 전기 요금을 조회·납부하는 서비스다.", "impact": "주민등록번호와 금융 결제 정보가 유출되어 보이스피싱, 명의도용 등 심각한 2차 피해 발생 위험이 높다. 공공 인프라 운영 기관의 정보보안 신뢰도가 크게 훼손되었으며, 정부의 중대 과징금 부과 대상이 될 수 있다. 이용자는 출처 불명의 문자 링크 클릭을 피하고 결제 내역을 점검해야 한다.", "key_figure": "152만", "key_figure_label": "유출 인원", "cve": "", "cvss": 0.0, "source": "데일리시큐", "link": "https://www.dailysecu.com/news/articleView.html?idxno=209678", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.11.5", "3.1.3", "3.5.3"], "attack": ["T1078", "T1213"], "actions": ["고객 개인정보 DB 접근 제어 정책 및 반출 탐지 로그 점검", "연계된 대외 조달 시스템 및 고객 웹 플랫폼 외부 접근 통제", "유출 피해자 대상 통지 절차 이행 및 금융 사기 주의 안내"]}, {"title": "한국전력공사 150만 명 정보 유출 외신 보도 및 AI 공격 연루 의혹", "region": "해외", "category": "사고", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "국내 핵심 전력 공기업 한전 150만 명 개인정보 침해사고", "core": "한국 주요 전력 공기업인 한전이 해킹 침해사고로 150만 명 이상의 고객과 조달업체 정보를 유출당했다고 외신을 통해 공식화되었다. 한전은 공격자가 인공지능(AI)과 같은 첨단 기술을 활용해 침투했다고 밝혔으나 정확한 공격 경로는 공개하지 않았다. Noiem이라는 가명의 해커가 다크웹 포럼을 통해 데이터 탈취를 주장하고 있다.", "background": "한국전력(KEPCO)은 대한민국의 핵심 전력 공급을 책임지는 공기업이다. 침해를 당한 시스템은 전기 요금 정산 시스템인 한전ON과 계약·조달 포털인 SRM 두 곳이다. 한전은 11월 20일 비인가 접근을 확인하고 외부 IP 접속을 차단하며 해당 서비스 운영을 일시 중단했다.", "impact": "한국 핵심 인프라 기업에 대한 침해로 국가 에너지 안보 및 기업 운영 신뢰도에 위협이 발생했다. 탈취된 임직원 및 고객 데이터는 맞춤형 스피어 피싱과 계정 사칭 사기에 악용될 소지가 크다. 노출된 개인은 의심스러운 링크 클릭을 금지하고 인증코드 공유를 즉시 중단해야 한다.", "key_figure": "150만", "key_figure_label": "노출 인원", "cve": "", "cvss": 0.0, "source": "BleepingComputer", "link": "https://www.bleepingcomputer.com/news/security/south-koreas-power-giant-kepco-confirms-data-breach-impacting-15-million/", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.6.1", "2.11.1", "2.11.5"], "attack": ["T1190", "T1078"], "actions": ["외부 접점 서비스의 비정상 로그인 및 IP 차단 현황 전수 점검", "내부망과 조달 및 대고객 포털 간 망 분리 상태 점검", "공격자 사용 의심 IP 및 C2 통신 흔적 침해지표 대조 분석"]}, {"title": "MS 애저 API 매니지먼트 취약점 악용…노르웨이 에너지 기업 기밀 탈취", "region": "해외", "category": "취약점", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "규모 중간 +1", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "medium", "domestic": true, "critical_sector": true, "factor_note": "노르웨이 다수 에너지 기업 피해 및 국내 애저 APIM 이용 기업 영향", "core": "마이크로소프트 애저 API 매니지먼트(APIM) 클래식 계열에서 기밀 정보를 탈취할 수 있는 보안 취약점이 발견되어 실제 공격에 악용되었다. 노르웨이 국립보안청(NSM)은 에퀴노르 등 자국 에너지 기업들이 이 취약점으로 공격받았다고 밝혔다. MS는 11월 19일 서비스 측 완화 패치를 적용했으나 고객이 직접 자격증명을 교체해야 한다고 경고했다.", "background": "애저 API 매니지먼트는 클라우드 환경에서 다양한 프로그램(API)들을 중개하고 연결하는 통로 역할을 한다. 레거시 API의 인증 우회 취약점으로 인해 공격자가 관리자 토큰을 얻어 Azure Key Vault 등에 무단 접속할 수 있었다. 패치 전에 이미 노출된 토큰과 암호키는 서비스 측 조치만으로 무효화되지 않는다.", "impact": "공격자가 획득한 API 자격증명을 통해 백엔드 시스템 및 클라우드 내부 자원에 무단 침투할 위험이 발생했다. 특히 에너지 등 주요 기반 시설 기업들이 주요 표적이 되었으므로 공급망 마비로 이어질 우려가 있다. 애저 APIM 클래식을 사용하는 기업은 저장된 모든 토큰과 비밀키를 즉시 갱신해야 한다.", "key_figure": "11월 18일", "key_figure_label": "취약점 식별일", "cve": "", "cvss": 0.0, "source": "BleepingComputer", "link": "https://www.bleepingcomputer.com/news/security/microsoft-azure-flaw-exploited-to-steal-customers-api-credentials/", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.7.2", "2.10.2", "2.11.2"], "attack": ["T1190", "T1528", "T1552"], "actions": ["Azure APIM 클래식 인스턴스에 저장된 모든 API 시크릿 즉시 갱신", "Azure Key Vault의 관리자 토큰 비정상 로그인 감사 로그 확인", "APIM v2 티어로의 서비스 마이그레이션 계획 수립 및 전환 검토"]}, {"title": "스페인 프로축구 라리가 팬 서비스 플랫폼 해킹으로 개인정보 유출", "region": "해외", "category": "사고", "severity": 2, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2", "규모 불명"], "exploitation": "active", "scale": "unknown", "domestic": false, "critical_sector": false, "factor_note": "라리가 팬 서비스 플랫폼 침해사고, 정확한 유출 인원 미공개", "core": "스페인 최상위 축구 리그인 라리가(LaLiga)의 팬 서비스 기술 플랫폼이 해킹되어 축구 팬들의 개인정보가 유출되었다. 침해사고는 11월 14일부터 16일 사이에 발생했으며 공격자는 침투한 시스템에서 데이터를 탈취했다. 라리가는 무단 접근을 차단하고 스페인 데이터보호청과 경찰에 사건을 신고했다.", "background": "라리가는 레알 마드리드, 바르셀로나 등 세계적인 구단들이 소속된 스페인 프로축구 기구다. 공격자는 경기 운영 시스템이 아닌 팬 대상 디지털 서비스 플랫폼의 취약점을 노려 침입했다. 라리가 측은 비인가 접근 경로를 차단하고 관련 제휴 클럽들과 협력하여 피해 범위를 파악하고 있다.", "impact": "글로벌 축구 팬들의 개인정보가 유출되어 이를 악용한 사칭 피싱 메일이나 2차 사기 범죄가 발생할 수 있다. 스포츠 및 엔터테인먼트 플랫폼의 회원 데이터 보안 관리 필요성이 대두되었다. 해당 플랫폼 이용자는 비밀번호를 변경하고 라리가를 사칭한 이메일 링크를 열람하지 않아야 한다.", "key_figure": "", "key_figure_label": "", "cve": "", "cvss": 0.0, "source": "BleepingComputer", "link": "https://www.bleepingcomputer.com/news/security/spanish-laliga-confirms-hackers-stole-soccer-fans-personal-data/", "cve_status": "", "cvss_severity": "", "cvss_version": "", "cvss_source": "", "cvss_vector": "", "epss": 0.0, "epss_percentile": 0.0, "epss_date": "", "kev": false, "kev_date": "", "kev_ransomware": false, "priority": "", "priority_reasons": [], "cvss_factors": [], "cwe": [], "isms": ["2.6.3", "2.10.3", "2.11.5"], "attack": ["T1190", "T1005"], "actions": ["대고객 서비스 플랫폼 웹 취약점 점검 및 비인가 접근 경로 차단", "팬 서비스 시스템 접속 계정에 대한 비밀번호 강제 재설정 및 MFA 점검", "고객 개인정보 저장 DB의 이상 반출 및 쿼리 이력 집중 모니터링"]}, {"title": "CISA, 악용 확인된 시스코 익스프레스웨이 원격 코드 실행 취약점 경고", "region": "해외", "category": "취약점", "severity": 5, "severity_method": "rule", "severity_basis": ["실제 공격·악용 확인 +2 (CISA KEV)", "대규모 +2", "핵심 업종 +1", "국내 영향 +1"], "exploitation": "active", "scale": "large", "domestic": true, "critical_sector": true, "factor_note": "CISA KEV 등록 및 광범위하게 쓰이는 시스코 장비 악용 확인", "core": "미국 CISA는 시스코 엔터프라이즈 게이트웨이 제품군에서 원격 코드 실행 취약점(CVE-2026-76466)이 실제 공격에 악용되고 있다고 경고했다. 이 취약점은 하드코딩된 자격증명과 인증서 검증 결함으로 발생하며, 인증되지 않은 공격자가 루트 권한으로 임의 명령을 실행할 수 있다. CISA는 연방 기관에 긴급 패치 명령을 내렸다.", "background": "시스코 익스프레스웨이는 기업 내부의 음성·영상 통화 시스템과 외부망 원격 사용자를 안전하게 연결하는 네트워크 장비다. 연구진에 따르면 공격자들은 인공지능(AI) 어시스턴트를 활용해 인터넷에 노출된 장비를 뚫고 내부망으로 침투했다. 공격자들은 루트 권한을 얻은 후 파이썬 스크립트를 통해 내부 파일 공유 및 DB를 탐색하고 데이터를 탈취했다.", "impact": "인터넷에 노출된 장비가 공격 통로로 쓰여 내부 전체 전산망이 장악당하고 기밀 데이터가 통째로 빠져나갈 위험이 있다. 클라우드 및 온프레미스 협업 시스템의 신뢰성이 무너질 수 있다. 시스코 익스프레스웨이 장비를 운영 중인 기관과 기업은 시스코 공식 최신 보안 패치를 즉시 설치해야 한다.", "key_figure": "3일", "key_figure_label": "CISA 패치 기한", "cve": "CVE-2026-76466", "cvss": 9.8, "source": "BleepingComputer", "link": "https://www.bleepingcomputer.com/news/security/cisa-flags-critical-cisco-expressway-rce-flaw-as-actively-exploited/", "cve_status": "nvd", "cvss_severity": "CRITICAL", "cvss_version": "3.1", "cvss_source": "CNA", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "epss": 1.12, "epss_percentile": 65.7, "epss_date": "2026-11-25", "kev": true, "kev_date": "2026-11-20", "kev_ransomware": false, "priority": "P1", "priority_reasons": ["CISA KEV 등재(실제 악용 확인)"], "cvss_factors": [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, {"k": "공격 난이도", "v": "공격 쉬움", "level": "bad"}, {"k": "필요 권한", "v": "로그인 불필요", "level": "bad"}, {"k": "사용자 행동", "v": "클릭 등 불필요", "level": "bad"}, {"k": "영향 범위", "v": "해당 시스템에 한정", "level": "ok"}, {"k": "정보 유출", "v": "높음", "level": "bad"}, {"k": "데이터 변조", "v": "높음", "level": "bad"}, {"k": "서비스 마비", "v": "높음", "level": "bad"}], "cwe": ["CWE-798"], "isms": ["2.6.1", "2.10.8", "2.11.2"], "attack": ["T1190", "T1210", "T1059"], "actions": ["인터넷에 노출된 Cisco Expressway 장비 현황 파악 및 최신 패치 적용", "Expressway 클러스터 장비 관리자 계정 자격증명 및 인증서 전면 재발급", "장비 내부 파이썬 스크립트 실행 및 이상 SMB 스캔 행위 로그 조사"]}]
terms: [{"term": "다크웹", "english": "Dark Web", "definition": "특수한 전용 브라우저를 사용해야만 들어갈 수 있는 숨겨진 인터넷 공간으로, 해커들이 훔친 정보를 사고파는 암시장 역할을 한다."}, {"term": "API", "english": "Application Programming Interface", "definition": "서로 다른 소프트웨어가 대화를 나누고 데이터를 주고받을 수 있게 해주는 규칙이자 디지털 소통 창구다."}, {"term": "원격 코드 실행", "english": "Remote Code Execution (RCE)", "definition": "공격자가 멀리 떨어진 곳에서 인터넷을 통해 상대방 컴퓨터에 몰래 명령을 내려 마음대로 조종할 수 있는 치명적인 약점이다."}, {"term": "루트 권한", "english": "Root Privilege", "definition": "컴퓨터 시스템 내의 모든 파일과 설정을 마음대로 바꾸거나 삭제할 수 있는 절대적인 관리자 권한이다."}]
---

> 오늘의 주요 보안 이슈 5건 (국내 1 · 해외 4)

## 📌 한눈에 보기

1. **[국내·사고]** 한국전력, 해킹으로 한전ON 및 조달시스템 152만 명 개인정보 유출
2. **[해외·사고]** 한국전력공사 150만 명 정보 유출 외신 보도 및 AI 공격 연루 의혹
3. **[해외·취약점]** MS 애저 API 매니지먼트 취약점 악용…노르웨이 에너지 기업 기밀 탈취
4. **[해외·사고]** 스페인 프로축구 라리가 팬 서비스 플랫폼 해킹으로 개인정보 유출
5. **[해외·취약점]** CISA, 악용 확인된 시스코 익스프레스웨이 원격 코드 실행 취약점 경고

---

## 1. 🚨 한국전력, 해킹으로 한전ON 및 조달시스템 152만 명 개인정보 유출

`국내` `사고` · 출처: [데일리시큐](https://www.dailysecu.com/news/articleView.html?idxno=209678)

**🎯 핵심**  
한국전력공사의 한전ON 및 전자조달시스템(SRM)에서 약 152만 명분의 고객 및 조달 관계자 개인정보가 해킹으로 유출되었다. 유출된 정보에는 성명, 주민등록번호, 계좌 및 카드정보, 사번 등이 포함되었으며 한전은 해커 협박 메일 수신 후 당국에 신고했다. 개인정보보호위원회와 한국인터넷진흥원은 초동대응반을 꾸려 현장 조사에 착수했다.

**📖 배경**  
해커는 지난 11월 19일 다크웹 해킹 커뮤니티에 한전 데이터를 확보했다고 주장하며 한전 측에 협박 이메일을 발송했다. 한전은 20일 샘플 데이터를 확인한 후 22일 개인정보보호위원회에 사고를 공식 신고했다. 전자조달시스템(SRM)은 공공기관의 입찰과 계약을 다루는 시스템이며, 한전ON은 일반 국민이 전기 요금을 조회·납부하는 서비스다.

**💥 영향**  
주민등록번호와 금융 결제 정보가 유출되어 보이스피싱, 명의도용 등 심각한 2차 피해 발생 위험이 높다. 공공 인프라 운영 기관의 정보보안 신뢰도가 크게 훼손되었으며, 정부의 중대 과징금 부과 대상이 될 수 있다. 이용자는 출처 불명의 문자 링크 클릭을 피하고 결제 내역을 점검해야 한다.

---

## 2. 🚨 한국전력공사 150만 명 정보 유출 외신 보도 및 AI 공격 연루 의혹

`해외` `사고` · 출처: [BleepingComputer](https://www.bleepingcomputer.com/news/security/south-koreas-power-giant-kepco-confirms-data-breach-impacting-15-million/)

**🎯 핵심**  
한국 주요 전력 공기업인 한전이 해킹 침해사고로 150만 명 이상의 고객과 조달업체 정보를 유출당했다고 외신을 통해 공식화되었다. 한전은 공격자가 인공지능(AI)과 같은 첨단 기술을 활용해 침투했다고 밝혔으나 정확한 공격 경로는 공개하지 않았다. Noiem이라는 가명의 해커가 다크웹 포럼을 통해 데이터 탈취를 주장하고 있다.

**📖 배경**  
한국전력(KEPCO)은 대한민국의 핵심 전력 공급을 책임지는 공기업이다. 침해를 당한 시스템은 전기 요금 정산 시스템인 한전ON과 계약·조달 포털인 SRM 두 곳이다. 한전은 11월 20일 비인가 접근을 확인하고 외부 IP 접속을 차단하며 해당 서비스 운영을 일시 중단했다.

**💥 영향**  
한국 핵심 인프라 기업에 대한 침해로 국가 에너지 안보 및 기업 운영 신뢰도에 위협이 발생했다. 탈취된 임직원 및 고객 데이터는 맞춤형 스피어 피싱과 계정 사칭 사기에 악용될 소지가 크다. 노출된 개인은 의심스러운 링크 클릭을 금지하고 인증코드 공유를 즉시 중단해야 한다.

---

## 3. 🛠️ MS 애저 API 매니지먼트 취약점 악용…노르웨이 에너지 기업 기밀 탈취

`해외` `취약점` · 출처: [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-azure-flaw-exploited-to-steal-customers-api-credentials/)

**🎯 핵심**  
마이크로소프트 애저 API 매니지먼트(APIM) 클래식 계열에서 기밀 정보를 탈취할 수 있는 보안 취약점이 발견되어 실제 공격에 악용되었다. 노르웨이 국립보안청(NSM)은 에퀴노르 등 자국 에너지 기업들이 이 취약점으로 공격받았다고 밝혔다. MS는 11월 19일 서비스 측 완화 패치를 적용했으나 고객이 직접 자격증명을 교체해야 한다고 경고했다.

**📖 배경**  
애저 API 매니지먼트는 클라우드 환경에서 다양한 프로그램(API)들을 중개하고 연결하는 통로 역할을 한다. 레거시 API의 인증 우회 취약점으로 인해 공격자가 관리자 토큰을 얻어 Azure Key Vault 등에 무단 접속할 수 있었다. 패치 전에 이미 노출된 토큰과 암호키는 서비스 측 조치만으로 무효화되지 않는다.

**💥 영향**  
공격자가 획득한 API 자격증명을 통해 백엔드 시스템 및 클라우드 내부 자원에 무단 침투할 위험이 발생했다. 특히 에너지 등 주요 기반 시설 기업들이 주요 표적이 되었으므로 공급망 마비로 이어질 우려가 있다. 애저 APIM 클래식을 사용하는 기업은 저장된 모든 토큰과 비밀키를 즉시 갱신해야 한다.

---

## 4. 🚨 스페인 프로축구 라리가 팬 서비스 플랫폼 해킹으로 개인정보 유출

`해외` `사고` · 출처: [BleepingComputer](https://www.bleepingcomputer.com/news/security/spanish-laliga-confirms-hackers-stole-soccer-fans-personal-data/)

**🎯 핵심**  
스페인 최상위 축구 리그인 라리가(LaLiga)의 팬 서비스 기술 플랫폼이 해킹되어 축구 팬들의 개인정보가 유출되었다. 침해사고는 11월 14일부터 16일 사이에 발생했으며 공격자는 침투한 시스템에서 데이터를 탈취했다. 라리가는 무단 접근을 차단하고 스페인 데이터보호청과 경찰에 사건을 신고했다.

**📖 배경**  
라리가는 레알 마드리드, 바르셀로나 등 세계적인 구단들이 소속된 스페인 프로축구 기구다. 공격자는 경기 운영 시스템이 아닌 팬 대상 디지털 서비스 플랫폼의 취약점을 노려 침입했다. 라리가 측은 비인가 접근 경로를 차단하고 관련 제휴 클럽들과 협력하여 피해 범위를 파악하고 있다.

**💥 영향**  
글로벌 축구 팬들의 개인정보가 유출되어 이를 악용한 사칭 피싱 메일이나 2차 사기 범죄가 발생할 수 있다. 스포츠 및 엔터테인먼트 플랫폼의 회원 데이터 보안 관리 필요성이 대두되었다. 해당 플랫폼 이용자는 비밀번호를 변경하고 라리가를 사칭한 이메일 링크를 열람하지 않아야 한다.

---

## 5. 🛠️ CISA, 악용 확인된 시스코 익스프레스웨이 원격 코드 실행 취약점 경고

`해외` `취약점` · 출처: [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-critical-cisco-expressway-rce-flaw-as-actively-exploited/)

**🎯 핵심**  
미국 CISA는 시스코 엔터프라이즈 게이트웨이 제품군에서 원격 코드 실행 취약점(CVE-2026-76466)이 실제 공격에 악용되고 있다고 경고했다. 이 취약점은 하드코딩된 자격증명과 인증서 검증 결함으로 발생하며, 인증되지 않은 공격자가 루트 권한으로 임의 명령을 실행할 수 있다. CISA는 연방 기관에 긴급 패치 명령을 내렸다.

**📖 배경**  
시스코 익스프레스웨이는 기업 내부의 음성·영상 통화 시스템과 외부망 원격 사용자를 안전하게 연결하는 네트워크 장비다. 연구진에 따르면 공격자들은 인공지능(AI) 어시스턴트를 활용해 인터넷에 노출된 장비를 뚫고 내부망으로 침투했다. 공격자들은 루트 권한을 얻은 후 파이썬 스크립트를 통해 내부 파일 공유 및 DB를 탐색하고 데이터를 탈취했다.

**💥 영향**  
인터넷에 노출된 장비가 공격 통로로 쓰여 내부 전체 전산망이 장악당하고 기밀 데이터가 통째로 빠져나갈 위험이 있다. 클라우드 및 온프레미스 협업 시스템의 신뢰성이 무너질 수 있다. 시스코 익스프레스웨이 장비를 운영 중인 기관과 기업은 시스코 공식 최신 보안 패치를 즉시 설치해야 한다.

---

## 📚 오늘의 보안 용어

- **다크웹** (Dark Web): 특수한 전용 브라우저를 사용해야만 들어갈 수 있는 숨겨진 인터넷 공간으로, 해커들이 훔친 정보를 사고파는 암시장 역할을 한다.
- **API** (Application Programming Interface): 서로 다른 소프트웨어가 대화를 나누고 데이터를 주고받을 수 있게 해주는 규칙이자 디지털 소통 창구다.
- **원격 코드 실행** (Remote Code Execution (RCE)): 공격자가 멀리 떨어진 곳에서 인터넷을 통해 상대방 컴퓨터에 몰래 명령을 내려 마음대로 조종할 수 있는 치명적인 약점이다.
- **루트 권한** (Root Privilege): 컴퓨터 시스템 내의 모든 파일과 설정을 마음대로 바꾸거나 삭제할 수 있는 절대적인 관리자 권한이다.

👉 지금까지 나온 용어는 [보안 용어 사전](../../glossary/)에서 볼 수 있어요.

---

<small>이 글은 공개된 보안 뉴스를 AI(Gemini)로 요약해 자동 작성했습니다. 정확한 내용은 각 출처 원문을 확인하세요.</small>
