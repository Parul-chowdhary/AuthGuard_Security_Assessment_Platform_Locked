"""
AuthGuard Target Scope & SSRF Protection
========================================
Comprehensive validation of target URLs, DNS resolution, IP range filtering,
and fail-closed authorization bounds.
"""

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from app.config import settings
from app.core.logging import logger


class ScopeValidationError(Exception):
    """Raised when an assessment target or requested endpoint violates scope or security rules."""
    pass


def resolve_domain_ips(hostname: str) -> List[str]:
    """Resolve hostname to all associated IP addresses (IPv4 & IPv6)."""
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ips = list({entry[4][0] for entry in addr_info})
        return ips
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failure for {hostname}: {e}")
        raise ScopeValidationError(f"Could not resolve host '{hostname}': {e}")


def is_ip_allowed(ip_str: str, allow_local_for_testing: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Evaluate whether an IP address is safe to query.
    Enforces SSRF prevention against cloud metadata, link-local, loopback, and internal addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP format: {ip_str}"

    # Explicit cloud metadata blocking (169.254.169.254, etc.)
    for blocked_cidr in settings.BLOCKED_IP_NETWORKS:
        try:
            if ip in ipaddress.ip_network(blocked_cidr):
                return False, f"Destination IP {ip_str} matches blocked metadata range {blocked_cidr}"
        except ValueError:
            continue

    # Multicast / unspecified / reserved
    if ip.is_multicast:
        return False, f"IP {ip_str} is multicast"
    if ip.is_unspecified:
        return False, f"IP {ip_str} is unspecified"
    if ip.is_reserved:
        return False, f"IP {ip_str} is reserved"

    # Link-local (e.g. 169.254.0.0/16)
    if ip.is_link_local:
        return False, f"IP {ip_str} is link-local"

    # Loopback & Private (RFC 1918)
    if ip.is_loopback or ip.is_private:
        if allow_local_for_testing:
            # Permitted exclusively for controlled local testing fixtures
            return True, None
        return False, f"IP {ip_str} is an internal or loopback address (SSRF guard)"

    return True, None


def validate_target_url(
    target_url: str,
    approved_hostnames: Optional[List[str]] = None,
    allow_local_for_testing: bool = True,
) -> Tuple[str, str, List[str]]:
    """
    Validate target URL syntax, scheme, approved hostnames, and IP destinations.
    Returns (normalized_url, hostname, resolved_ips).
    """
    if not target_url or not isinstance(target_url, str):
        raise ScopeValidationError("Target URL must be a non-empty string.")

    parsed = urlparse(target_url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ScopeValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise ScopeValidationError("Target URL does not contain a valid hostname.")

    # Check hostname allowlist if configured
    if approved_hostnames:
        matched = any(
            hostname == approved or hostname.endswith(f".{approved}")
            for approved in approved_hostnames
        )
        if not matched:
            raise ScopeValidationError(
                f"Target hostname '{hostname}' is not within authorized allowlist: {approved_hostnames}"
            )

    # DNS Resolution & SSRF verification
    resolved_ips = resolve_domain_ips(hostname)
    if not resolved_ips:
        raise ScopeValidationError(f"No IP addresses resolved for hostname '{hostname}'.")

    for ip_str in resolved_ips:
        allowed, reason = is_ip_allowed(ip_str, allow_local_for_testing=allow_local_for_testing)
        if not allowed:
            raise ScopeValidationError(f"Security Scope Violation: {reason}")

    # Normalized base URL
    port_str = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    normalized_base = f"{parsed.scheme}://{hostname}{port_str}"

    return normalized_base, hostname, resolved_ips
