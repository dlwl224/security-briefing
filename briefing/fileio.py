"""파일 쓰기 공통 함수.

- 항상 UTF-8 + LF 로 쓴다 (Windows 에서 실행해도 CRLF 가 섞이지 않게).
- 임시 파일에 먼저 쓰고 교체한다 (쓰다가 실패해도 기존 파일이 반쯤 깨지지 않게).
"""
import json
import os
import tempfile
from pathlib import Path


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path


def write_json(path: Path, data: object, indent: int | None = 2) -> Path:
    return write_text(path, json.dumps(data, ensure_ascii=False, indent=indent) + "\n")


def read_json(path: Path, default: object = None) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))
