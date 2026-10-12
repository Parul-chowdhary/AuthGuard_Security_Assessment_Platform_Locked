"""
AuthGuard Safety & Operational Constraints
==========================================
Enforces request budgets, concurrency limits, circuit breakers, and rate pacing
to prevent denial-of-service and protect target website stability.
"""

import asyncio
from typing import Optional
from app.core.logging import logger


class SafetyViolationError(Exception):
    """Base exception for assessment safety violations."""
    pass


class BudgetExhaustedError(SafetyViolationError):
    """Raised when assessment reaches or attempts to exceed allocated request budget."""
    pass


class TargetDegradedError(SafetyViolationError):
    """Raised when target exhibits consecutive server errors, tripping circuit breaker."""
    pass


class CancellationRequestedError(SafetyViolationError):
    """Raised when user or orchestrator requests assessment cancellation."""
    pass


class RequestBudgetController:
    """Manages thread-safe request counting against allocated budget."""

    def __init__(self, budget: int, max_budget: int = 1000):
        self.budget = min(max(1, budget), max_budget)
        self.requests_sent = 0
        self._lock = asyncio.Lock()

    async def acquire_slot(self) -> int:
        async with self._lock:
            if self.requests_sent >= self.budget:
                raise BudgetExhaustedError(
                    f"Assessment halted: Reached maximum allocated request budget ({self.budget} requests)."
                )
            self.requests_sent += 1
            return self.requests_sent

    @property
    def remaining_budget(self) -> int:
        return max(0, self.budget - self.requests_sent)


class CircuitBreaker:
    """Monitors consecutive HTTP 5xx responses and trips to prevent target outage."""

    def __init__(self, failure_threshold: int = 4):
        self.failure_threshold = failure_threshold
        self.consecutive_5xx = 0
        self._lock = asyncio.Lock()

    async def record_response(self, status_code: int) -> None:
        async with self._lock:
            if 500 <= status_code <= 599:
                self.consecutive_5xx += 1
                logger.warning(
                    f"Circuit breaker recorded 5xx error (status {status_code}). Streak: {self.consecutive_5xx}/{self.failure_threshold}"
                )
                if self.consecutive_5xx >= self.failure_threshold:
                    raise TargetDegradedError(
                        f"Circuit breaker tripped: Target responded with {self.consecutive_5xx} consecutive 5xx errors. Halted for safety."
                    )
            else:
                self.consecutive_5xx = 0
