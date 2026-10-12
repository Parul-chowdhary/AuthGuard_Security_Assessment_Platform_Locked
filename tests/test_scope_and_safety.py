"""
AuthGuard Test Suite: Scope Enforcement, SSRF Protection & Safety Controller
=============================================================================
"""

import pytest
from app.core.safety import (
    BudgetExhaustedError,
    CircuitBreaker,
    RequestBudgetController,
    TargetDegradedError,
)
from app.core.scope import ScopeValidationError, is_ip_allowed, validate_target_url


def test_ssrf_ip_filtering():
    # Cloud metadata IP must be strictly blocked
    allowed, reason = is_ip_allowed("169.254.169.254")
    assert allowed is False
    assert "metadata" in reason.lower()

    # Public IP must be allowed
    allowed_pub, _ = is_ip_allowed("8.8.8.8")
    assert allowed_pub is True

    # Loopback IP blocked when allow_local_for_testing is False
    allowed_loop, _ = is_ip_allowed("127.0.0.1", allow_local_for_testing=False)
    assert allowed_loop is False

    # Loopback IP permitted when explicit local testing flag is True
    allowed_loop_test, _ = is_ip_allowed("127.0.0.1", allow_local_for_testing=True)
    assert allowed_loop_test is True


def test_target_url_validation():
    # Invalid scheme
    with pytest.raises(ScopeValidationError):
        validate_target_url("ftp://example.com")

    # Hostname outside allowlist
    with pytest.raises(ScopeValidationError):
        validate_target_url("https://malicious.com", approved_hostnames=["authguard.local"])


@pytest.mark.asyncio
async def test_request_budget_controller():
    controller = RequestBudgetController(budget=3)
    assert controller.remaining_budget == 3

    slot1 = await controller.acquire_slot()
    slot2 = await controller.acquire_slot()
    slot3 = await controller.acquire_slot()

    assert slot3 == 3
    assert controller.remaining_budget == 0

    with pytest.raises(BudgetExhaustedError):
        await controller.acquire_slot()


@pytest.mark.asyncio
async def test_circuit_breaker():
    breaker = CircuitBreaker(failure_threshold=3)

    await breaker.record_response(200)
    assert breaker.consecutive_5xx == 0

    await breaker.record_response(500)
    await breaker.record_response(502)
    assert breaker.consecutive_5xx == 2

    # 3rd consecutive 5xx trips breaker
    with pytest.raises(TargetDegradedError):
        await breaker.record_response(503)
