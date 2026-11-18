"""데이터 구조(스키마) 정의 — 파이프라인 단계마다 주고받는 데이터의 모양을 한곳에 적어 둔다.

흐름:  Candidate(수집) → Entry(AI 요약 + 공식 지표) → Item(검증·정화 후 게시) → 사이트(_posts front matter)
신뢰 경계: Candidate·Entry 의 문자열은 외부(RSS·AI·API)에서 왔으므로 '신뢰할 수 없음'.
          render.normalize / render.structured_item 을 통과한 Item 만 파일에 쓴다.
"""
from typing import Literal, TypedDict

Region = Literal["국내", "해외"]
Category = Literal["취약점", "사고", "정책", "위협동향"]
Exploitation = Literal["none", "poc", "active"]
Scale = Literal["unknown", "small", "medium", "large"]
Priority = Literal["P1", "P2", "P3", ""]
CvssSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE", ""]


class Candidate(TypedDict, total=False):
    """collect 단계: RSS·KEV 에서 모은 기사 후보 (신뢰할 수 없음)."""

    id: int
    source: str
    region: Region
    title: str
    link: str
    snippet: str
    published: str
    text: str            # 선정 후 가져온 본문
    kev: dict            # CISA KEV 원본 항목 (KEV 후보일 때만)


class Factor(TypedDict):
    """CVSS 벡터 해석 한 칸."""

    k: str               # 항목명 (예: 공격 경로)
    v: str               # 값 (예: 원격(인터넷) 공격 가능)
    level: Literal["bad", "ok"]


class Item(TypedDict):
    """게시되는 이슈 1건 (_posts 의 items 배열 원소). 모든 문자열은 평문이며, 레이아웃이 | escape 로 출력한다."""

    # 요약 (AI)
    title: str
    region: Region
    category: Category
    core: str
    background: str
    impact: str
    key_figure: str
    key_figure_label: str
    source: str
    link: str                       # http(s) 만
    # 위험도 (AI 는 요소만 판정, 점수는 consulting.severity 규칙)
    severity: int | None            # 1~5, 정책·동향은 None('참고')
    severity_method: Literal["rule", "ai"]
    severity_basis: list[str]
    exploitation: Exploitation | Literal[""]
    scale: Scale | Literal[""]
    domestic: bool
    critical_sector: bool
    factor_note: str
    # 공식 지표 (NVD · FIRST EPSS · CISA KEV)
    cve: str                        # CVE-YYYY-NNNN 형식만
    cve_status: Literal["nvd", "pending", ""]
    cvss: float                     # 0.0~10.0
    cvss_severity: CvssSeverity
    cvss_version: str
    cvss_source: Literal["NVD", "CNA", "기사", ""]
    cvss_vector: str
    epss: float                     # % (0~100)
    epss_percentile: float
    epss_date: str
    kev: bool
    kev_date: str
    kev_ransomware: bool
    # 컨설팅 뷰
    priority: Priority
    priority_reasons: list[str]
    cvss_factors: list[Factor]
    cwe: list[str]
    isms: list[str]                 # _data/isms_p.json 허용 목록 안의 값만
    attack: list[str]               # _data/attack.json 허용 목록 안의 값만
    actions: list[str]


class Term(TypedDict):
    term: str
    english: str
    definition: str
