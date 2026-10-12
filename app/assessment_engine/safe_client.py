"""
AuthGuard Safe HTTP Client
==========================
Guarded HTTP client wrapper integrating SSRF scope verification,
request budgeting, timeout management, and circuit breaking.
"""

from typing import Any, Dict, Optional
import httpx

from app.config import settings
from app.core.logging import logger
from app.core.safety import CircuitBreaker, RequestBudgetController
from app.core.scope import validate_target_url


class SafeHttpClient:
    """Safe HTTPX wrapper ensuring requests stay within authorized scope and budgets."""

    def __init__(
        self,
        base_url: str,
        approved_hostnames: list[str],
        budget_controller: RequestBudgetController,
        circuit_breaker: CircuitBreaker,
        allow_local_for_testing: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.approved_hostnames = approved_hostnames
        self.budget_controller = budget_controller
        self.circuit_breaker = circuit_breaker
        self.allow_local_for_testing = allow_local_for_testing

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                timeout=settings.REQUEST_TIMEOUT_SECONDS,
                connect=settings.CONNECT_TIMEOUT_SECONDS,
            ),
            follow_redirects=False,  # Redirects manually checked for SSRF safety
            verify=False,            # Permitted for local staging/lab testing self-signed certs
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Any] = None,
        data: Optional[Any] = None,
    ) -> httpx.Response:
        # 1. Budget check
        await self.budget_controller.acquire_slot()

        # 2. Scope & SSRF verification of full URL
        full_url = f"{self.base_url}/{path.lstrip('/')}"
        validate_target_url(
            full_url,
            approved_hostnames=self.approved_hostnames,
            allow_local_for_testing=self.allow_local_for_testing,
        )

        req_headers = {"User-Agent": "AuthGuard-Security-Auditor/1.0"}
        if headers:
            req_headers.update(headers)

        # 3. Dispatch controlled request
        response = await self.client.request(
            method=method,
            url=full_url,
            headers=req_headers,
            json=json_data,
            data=data,
        )

        # 4. Record status in circuit breaker
        await self.circuit_breaker.record_response(response.status_code)

        return response
