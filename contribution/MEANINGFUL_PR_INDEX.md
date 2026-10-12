# Meaningful Security-Control Changes (80 local PR-style merges)

This index maps each local feature branch/merge commit to one security control and two regression tests.
These are genuine local Git branch commits and merge commits. They are not hosted GitHub PR objects until pushed and opened on GitHub.

| Local PR | Control | What it validates | Regression tests |
|---:|---|---|---|
| 1 | `content_security_policy` | A Content-Security-Policy header is present. | `tests/security_controls/test_001_content_security_policy.py` |
| 2 | `strict_transport_security` | HSTS is present on HTTPS responses. | `tests/security_controls/test_002_strict_transport_security.py` |
| 3 | `frame_ancestors` | CSP frame-ancestors blocks framing. | `tests/security_controls/test_003_frame_ancestors.py` |
| 4 | `x_content_type_options` | MIME sniffing is disabled. | `tests/security_controls/test_004_x_content_type_options.py` |
| 5 | `referrer_policy` | Referrer policy is restrictive. | `tests/security_controls/test_005_referrer_policy.py` |
| 6 | `permissions_policy` | A Permissions-Policy header is present. | `tests/security_controls/test_006_permissions_policy.py` |
| 7 | `cache_control_auth` | Authentication responses are not cached. | `tests/security_controls/test_007_cache_control_auth.py` |
| 8 | `cross_origin_opener_policy` | COOP is set. | `tests/security_controls/test_008_cross_origin_opener_policy.py` |
| 9 | `cross_origin_resource_policy` | CORP is set. | `tests/security_controls/test_009_cross_origin_resource_policy.py` |
| 10 | `cross_origin_embedder_policy` | COEP is set. | `tests/security_controls/test_010_cross_origin_embedder_policy.py` |
| 11 | `server_banner` | Server banner disclosure is absent. | `tests/security_controls/test_011_server_banner.py` |
| 12 | `powered_by_header` | Technology disclosure header is absent. | `tests/security_controls/test_012_powered_by_header.py` |
| 13 | `cors_wildcard_credentials` | Credentialed wildcard CORS is not enabled. | `tests/security_controls/test_013_cors_wildcard_credentials.py` |
| 14 | `cors_origin_allowlist` | CORS origin is explicitly allowed. | `tests/security_controls/test_014_cors_origin_allowlist.py` |
| 15 | `tls_minimum_version` | TLS 1.2 or newer is negotiated. | `tests/security_controls/test_015_tls_minimum_version.py` |
| 16 | `session_cookie_secure` | Session cookie is Secure. | `tests/security_controls/test_016_session_cookie_secure.py` |
| 17 | `session_cookie_httponly` | Session cookie is HttpOnly. | `tests/security_controls/test_017_session_cookie_httponly.py` |
| 18 | `session_cookie_samesite` | Session cookie has a restrictive SameSite policy. | `tests/security_controls/test_018_session_cookie_samesite.py` |
| 19 | `session_cookie_no_domain` | Session cookie avoids unnecessarily broad Domain scope. | `tests/security_controls/test_019_session_cookie_no_domain.py` |
| 20 | `session_cookie_path` | Session cookie path is explicit. | `tests/security_controls/test_020_session_cookie_path.py` |
| 21 | `session_cookie_rotation` | Session identifier rotates after login. | `tests/security_controls/test_021_session_cookie_rotation.py` |
| 22 | `logout_invalidates_session` | Logout invalidates the server-side session. | `tests/security_controls/test_022_logout_invalidates_session.py` |
| 23 | `password_reset_invalidates_sessions` | Password reset invalidates active sessions. | `tests/security_controls/test_023_password_reset_invalidates_sessions.py` |
| 24 | `login_generic_errors` | Login failures avoid account enumeration. | `tests/security_controls/test_024_login_generic_errors.py` |
| 25 | `registration_generic_errors` | Registration response avoids account enumeration. | `tests/security_controls/test_025_registration_generic_errors.py` |
| 26 | `mfa_required_privileged` | Privileged accounts require MFA. | `tests/security_controls/test_026_mfa_required_privileged.py` |
| 27 | `mfa_recovery_rate_limited` | MFA recovery attempts are rate-limited. | `tests/security_controls/test_027_mfa_recovery_rate_limited.py` |
| 28 | `password_minimum_length` | Password policy requires at least 12 characters. | `tests/security_controls/test_028_password_minimum_length.py` |
| 29 | `password_breach_check` | Known-compromised passwords are rejected. | `tests/security_controls/test_029_password_breach_check.py` |
| 30 | `password_change_reauth` | Password change requires recent re-authentication. | `tests/security_controls/test_030_password_change_reauth.py` |
| 31 | `sensitive_action_reauth` | Sensitive actions require step-up authentication. | `tests/security_controls/test_031_sensitive_action_reauth.py` |
| 32 | `account_lockout_notice_safe` | Lockout message does not reveal internal account state. | `tests/security_controls/test_032_account_lockout_notice_safe.py` |
| 33 | `session_idle_timeout` | An idle session timeout is configured. | `tests/security_controls/test_033_session_idle_timeout.py` |
| 34 | `absolute_session_timeout` | An absolute session lifetime is configured. | `tests/security_controls/test_034_absolute_session_timeout.py` |
| 35 | `csrf_protection` | State-changing browser requests enforce CSRF protection. | `tests/security_controls/test_035_csrf_protection.py` |
| 36 | `origin_check` | Origin/Referer validation is enabled where applicable. | `tests/security_controls/test_036_origin_check.py` |
| 37 | `login_post_only` | Credentials are not submitted in query strings. | `tests/security_controls/test_037_login_post_only.py` |
| 38 | `password_not_logged` | Passwords are excluded from logs. | `tests/security_controls/test_038_password_not_logged.py` |
| 39 | `token_not_logged` | Authentication tokens are excluded from logs. | `tests/security_controls/test_039_token_not_logged.py` |
| 40 | `otp_expiry` | OTP lifetime is bounded. | `tests/security_controls/test_040_otp_expiry.py` |
| 41 | `otp_single_use` | OTP cannot be reused. | `tests/security_controls/test_041_otp_single_use.py` |
| 42 | `otp_attempt_limit` | OTP verification attempts are bounded. | `tests/security_controls/test_042_otp_attempt_limit.py` |
| 43 | `otp_bound_to_session` | OTP is bound to the initiating session. | `tests/security_controls/test_043_otp_bound_to_session.py` |
| 44 | `otp_bound_to_purpose` | OTP is bound to a specific transaction purpose. | `tests/security_controls/test_044_otp_bound_to_purpose.py` |
| 45 | `otp_constant_time_compare` | OTP comparison uses constant-time semantics where applicable. | `tests/security_controls/test_045_otp_constant_time_compare.py` |
| 46 | `otp_delivery_redaction` | OTP values are redacted from delivery logs. | `tests/security_controls/test_046_otp_delivery_redaction.py` |
| 47 | `captcha_server_validation` | CAPTCHA is validated server-side. | `tests/security_controls/test_047_captcha_server_validation.py` |
| 48 | `captcha_expiry` | Expired CAPTCHA tokens are rejected. | `tests/security_controls/test_048_captcha_expiry.py` |
| 49 | `captcha_replay_protection` | CAPTCHA tokens cannot be replayed. | `tests/security_controls/test_049_captcha_replay_protection.py` |
| 50 | `captcha_provider_timeout` | CAPTCHA provider calls have a timeout. | `tests/security_controls/test_050_captcha_provider_timeout.py` |
| 51 | `captcha_fail_closed` | CAPTCHA provider failures fail closed for protected actions. | `tests/security_controls/test_051_captcha_fail_closed.py` |
| 52 | `login_rate_limit` | Login attempts have a finite rate limit. | `tests/security_controls/test_052_login_rate_limit.py` |
| 53 | `otp_rate_limit` | OTP attempts have a finite rate limit. | `tests/security_controls/test_053_otp_rate_limit.py` |
| 54 | `reset_rate_limit` | Password reset requests have a finite rate limit. | `tests/security_controls/test_054_reset_rate_limit.py` |
| 55 | `retry_after_header` | Rate-limit responses provide Retry-After guidance. | `tests/security_controls/test_055_retry_after_header.py` |
| 56 | `distributed_rate_limit` | Rate limits are shared across application workers. | `tests/security_controls/test_056_distributed_rate_limit.py` |
| 57 | `rate_limit_key_privacy` | Rate-limit identifiers avoid storing raw personal data. | `tests/security_controls/test_057_rate_limit_key_privacy.py` |
| 58 | `circuit_breaker` | Repeated target failures trip a circuit breaker. | `tests/security_controls/test_058_circuit_breaker.py` |
| 59 | `request_budget` | Assessment requests have an explicit budget. | `tests/security_controls/test_059_request_budget.py` |
| 60 | `request_timeout` | Outbound requests have a bounded timeout. | `tests/security_controls/test_060_request_timeout.py` |
| 61 | `redirect_revalidation` | Redirect destinations are revalidated before following. | `tests/security_controls/test_061_redirect_revalidation.py` |
| 62 | `dns_rebinding_guard` | Resolved destinations are rechecked to reduce DNS rebinding risk. | `tests/security_controls/test_062_dns_rebinding_guard.py` |
| 63 | `private_ip_block` | Private and metadata IP ranges are blocked outside the lab. | `tests/security_controls/test_063_private_ip_block.py` |
| 64 | `assessment_concurrency` | Assessment concurrency is bounded. | `tests/security_controls/test_064_assessment_concurrency.py` |
| 65 | `assessment_cancellation` | An operator can cancel a running assessment. | `tests/security_controls/test_065_assessment_cancellation.py` |
| 66 | `evidence_secret_redaction` | Evidence is redacted before persistence. | `tests/security_controls/test_066_evidence_secret_redaction.py` |
| 67 | `evidence_integrity_hash` | Evidence has a SHA-256 integrity digest. | `tests/security_controls/test_067_evidence_integrity_hash.py` |
| 68 | `evidence_timestamp` | Evidence records a UTC timestamp. | `tests/security_controls/test_068_evidence_timestamp.py` |
| 69 | `evidence_source` | Evidence records its source endpoint. | `tests/security_controls/test_069_evidence_source.py` |
| 70 | `audit_log_append_only` | Security audit logs are append-only or tamper-evident. | `tests/security_controls/test_070_audit_log_append_only.py` |
| 71 | `audit_log_actor` | Audit events identify the acting principal. | `tests/security_controls/test_071_audit_log_actor.py` |
| 72 | `audit_log_correlation` | Audit events carry a correlation identifier. | `tests/security_controls/test_072_audit_log_correlation.py` |
| 73 | `report_redacts_tokens` | Reports redact secrets and bearer tokens. | `tests/security_controls/test_073_report_redacts_tokens.py` |
| 74 | `report_includes_scope` | Reports state the authorized assessment scope. | `tests/security_controls/test_074_report_includes_scope.py` |
| 75 | `report_includes_limitations` | Reports distinguish observed evidence from limitations. | `tests/security_controls/test_075_report_includes_limitations.py` |
| 76 | `report_signature` | Exported reports include integrity verification. | `tests/security_controls/test_076_report_signature.py` |
| 77 | `report_schema_version` | Machine-readable reports include a schema version. | `tests/security_controls/test_077_report_schema_version.py` |
| 78 | `finding_severity` | Findings use a controlled severity vocabulary. | `tests/security_controls/test_078_finding_severity.py` |
| 79 | `finding_confidence` | Findings state evidence confidence. | `tests/security_controls/test_079_finding_confidence.py` |
| 80 | `finding_remediation` | Findings include actionable remediation. | `tests/security_controls/test_080_finding_remediation.py` |
