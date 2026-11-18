"""외부 URL 요청을 안전하게 하는 헬퍼 (OWASP A10: SSRF 방어).

RSS 에 들어 있는 기사 링크는 '신뢰할 수 없는 입력'이다. 악성 피드가 링크를
http://169.254.169.254/ (클라우드 메타데이터) 나 http://localhost:xxxx 로 바꿔 놓으면
GitHub Actions 러너가 내부 자원에 요청을 보내게 될 수 있다. 그래서:

- http/https 와 기본 포트(80/443)만 허용
- 호스트가 가리키는 모든 IP 가 공인(global) 주소일 때만 요청
- 리다이렉트는 자동으로 따라가지 않고, 매 단계 같은 검사를 다시 한다 (최대 3회)
- 응답 크기 상한을 두고 스트리밍으로 읽어 메모리 고갈을 막는다

남은 위험: DNS 를 확인한 뒤 실제 연결 사이에 DNS 응답이 바뀌는 'DNS rebinding' 은
완전히 막지 못한다. 러너는 매번 새로 만들어지고 비밀값은 환경변수로만 존재하므로 영향은 제한적이다.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

ALLOWED_PORTS = {None, 80, 443}


class UnsafeURLError(ValueError):
    pass


def check_url(url: str) -> str:
    """안전하지 않으면 UnsafeURLError 을 던진다."""
    p = urlparse(str(url or "").strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UnsafeURLError(f"허용되지 않는 URL: {url!r}")
    if p.username or p.password:
        raise UnsafeURLError("URL 에 계정 정보가 들어 있음")
    try:
        port = p.port
    except ValueError:
        raise UnsafeURLError("잘못된 포트") from None
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError(f"허용되지 않는 포트: {port}")
    try:
        infos = socket.getaddrinfo(p.hostname, port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeURLError(f"DNS 조회 실패: {p.hostname}") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeURLError(f"내부/예약 주소로 연결됨: {p.hostname} → {ip}")
    return url


def safe_get(
    session: requests.Session,
    url: str,
    *,
    max_bytes: int,
    timeout: int = 20,
    params: dict | None = None,
    max_redirects: int = 3,
) -> tuple[bytes, requests.Response]:
    """검사를 통과한 URL 만 요청하고, 본문을 max_bytes 까지만 읽어 (본문, 응답) 을 돌려준다."""
    for _ in range(max_redirects + 1):
        check_url(url)
        resp = session.get(url, params=params, timeout=timeout, stream=True, allow_redirects=False)
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            resp.close()
            if not location:
                raise UnsafeURLError("Location 없는 리다이렉트")
            url, params = urljoin(url, location), None
            continue
        try:
            resp.raise_for_status()
            body = resp.raw.read(max_bytes + 1, decode_content=True)
        finally:
            resp.close()
        if len(body) > max_bytes:
            raise UnsafeURLError(f"응답이 너무 큼 (>{max_bytes} bytes)")
        return body, resp
    raise UnsafeURLError("리다이렉트가 너무 많음")
