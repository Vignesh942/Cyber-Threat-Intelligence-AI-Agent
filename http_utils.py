from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def request_json(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    target_url = url
    if params:
        query = urlencode({key: value for key, value in params.items() if value is not None}, doseq=True)
        separator = "&" if "?" in url else "?"
        target_url = f"{url}{separator}{query}"

    request_data = None
    if json_body is not None:
        request_data = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")

    request = Request(target_url, data=request_data, headers=request_headers, method=method.upper())

    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc

    return json.loads(payload) if payload else {}


def request_text(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> str:
    request = Request(url, headers=headers or {}, method="GET")

    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc
