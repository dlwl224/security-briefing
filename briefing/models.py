"""데이터 구조(스키마) 정의 — 파이프라인 단계마다 주고받는 데이터의 모양을 한곳에 적어 둔다."""

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
    text: str
    kev: dict


class Factor(TypedDict):
    """CVSS 벡터 해석 한 칸."""

    k: str
    v: str
    level: Literal["bad", "ok"]


class Item(TypedDict):
    """게시되는 이슈 1건 (_posts 의 items 배열 원소). 모든 문자열은 평문이며, 레이아웃이 | escape 로 출력한다."""

    title: str
    region: Region
    category: Category
    core: str
    background: str
    impact: str
    key_figure: str
    key_figure_label: str
    source: str
    link: str
    severity: int | None
    severity_method: Literal["rule", "ai"]
    severity_basis: list[str]
    exploitation: Exploitation | Literal[""]
    scale: Scale | Literal[""]
    domestic: bool
    critical_sector: bool
    factor_note: str
    cve: str
    cve_status: Literal["nvd", "pending", ""]
    cvss: float
    cvss_severity: CvssSeverity
    cvss_version: str
    cvss_source: Literal["NVD", "CNA", "기사", ""]
    cvss_vector: str
    epss: float
    epss_percentile: float
    epss_date: str
    kev: bool
    kev_date: str
    kev_ransomware: bool
    priority: Priority
    priority_reasons: list[str]
    cvss_factors: list[Factor]
    cwe: list[str]
    isms: list[str]
    attack: list[str]
    actions: list[str]


class Term(TypedDict):
    term: str
    english: str
    definition: str
