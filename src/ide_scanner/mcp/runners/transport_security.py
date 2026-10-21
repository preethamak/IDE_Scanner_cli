from typing import Any, Optional

from ..types import StatusEnum, VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.fingerprint import WEAK_TLS_VERSIONS, FingerprintResult, TransportLevelEnum

SCORE_MAP = {
    TransportLevelEnum.HTTPS_STRONG: 0.00,
    TransportLevelEnum.HTTPS_SAFE_REDIRECT: 0.00,
    TransportLevelEnum.HTTPS_LEGACY_TLS: 0.40,
    TransportLevelEnum.HTTP_FALLBACK: 0.50,
    TransportLevelEnum.HTTPS_UNSAFE_REDIRECT: 0.60,
    TransportLevelEnum.HTTPS_INVALID_CERT: 0.85,
    TransportLevelEnum.HTTP_ONLY: 1.00,
}

# Veto mapping matches old gating_status exactly:
#   FAILURE: invalid cert, HTTP-only
#   WARNING: legacy TLS accepted (whether negotiated or just accepted)
# The distinction between "legacy-only TLS" (FAILURE in old code) and
# "accepts legacy TLS but also modern" (WARNING in old code) is encoded
# in transport_level by the extractor:
#   - HTTPS_LEGACY_TLS with legacy_tls_accepted=True but modern tls_version -> WARNING
#   - HTTPS_LEGACY_TLS with only legacy tls_version -> FAILURE
# But since the runner can't distinguish, the extractor must set a separate flag.
# For now: transport_level drives both score and base veto, and legacy_tls_accepted
# + tls_version refine the veto.
VETO_MAP = {
    TransportLevelEnum.HTTPS_INVALID_CERT: VetoLevelEnum.FAILURE,
    TransportLevelEnum.HTTP_ONLY: VetoLevelEnum.FAILURE,
    # HTTPS_LEGACY_TLS veto depends on context — handled in run()
}


class TransportSecurityRunner:
    """Scores transport security from pre-computed transport_level.

    Ported from TransportSecurityTestSuite.test_transport_encryption().
    All I/O (TLS probes, legacy TLS, redirect chains, HTTP downgrade)
    is done by FingerprintExtractor. This runner is a pure score/veto lookup.
    """

    version = "1.0"

    @staticmethod
    def _cert_info(fp: FingerprintResult) -> dict:
        cert_info: dict[str, Any] = {}
        if fp.cert_subject is not None:
            cert_info["subject"] = fp.cert_subject
        if fp.cert_issuer is not None:
            cert_info["issuer"] = fp.cert_issuer
        if fp.cert_verified_hostname is not None:
            cert_info["verified_hostname"] = fp.cert_verified_hostname
        return cert_info

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        fp: FingerprintResult = subject
        if fp.is_local:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Not applicable for local servers (no remote transport)",
                artifacts={"details": {"reason": "Is a local server"}},
            )

        if not fp.mcp_url:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="No MCP URL provided",
            )

        transport_level = fp.transport_level
        if transport_level is None:
            status = StatusEnum.ERROR
            if fp.invalid_url:
                message = "Invalid URL format"
                artifacts = {"reason": "URL has no hostname"}
            elif fp.dns_failed:
                message = "DNS resolution failed"
                artifacts = {
                    "error": fp.probe_error,
                    "hostname": fp.host.split(":")[0] if fp.host else None,
                    "reason": "The hostname could not be resolved to an IP address",
                }
            elif fp.http_probe_error_kind == "redirect_probe_failed":
                artifacts = {
                    "reason": fp.http_probe_error,
                    "tls_version": fp.tls_version,
                }
                cert_info = self._cert_info(fp)
                if cert_info:
                    artifacts["cert_info"] = cert_info
                message = "Redirect probe failed"
            elif fp.http_probe_error_kind == "timeout":
                message = "HTTP probe timed out"
                artifacts = {
                    "reason": (
                        "HTTP endpoint did not respond within 3 seconds. "
                        "This may indicate HTTP is blocked by firewall or a network issue "
                        "preventing verification."
                    ),
                    "tls_version": fp.tls_version,
                }
            elif fp.http_probe_error_kind == "unexpected":
                message = "HTTP probe failed unexpectedly"
                artifacts = {
                    "reason": f"Unable to probe HTTP endpoint: {fp.http_probe_error}",
                    "tls_version": fp.tls_version,
                }
            else:
                message = "HTTPS connection failed"
                artifacts = {
                    "reason": fp.probe_error,
                }
            return MetricRunOutput(
                score=None,
                status=status,
                message=message,
                artifacts={"details": artifacts},
            )

        score = SCORE_MAP[transport_level]
        veto = VETO_MAP.get(transport_level)
        veto_message: Optional[str] = None
        cert_info = self._cert_info(fp)
        message: str
        artifacts: dict[str, Any]

        # HTTPS_LEGACY_TLS: context-dependent veto
        # Old code: if modern TLS handshake failed and only legacy worked -> FAILURE
        #           if modern TLS works but server also accepts legacy -> WARNING
        if transport_level == TransportLevelEnum.HTTPS_LEGACY_TLS:
            if fp.tls_version in WEAK_TLS_VERSIONS:
                veto = VetoLevelEnum.WARNING
                veto_message = "Weak TLS - vulnerable to cryptographic attacks"
                message = f"Weak TLS version negotiated: {fp.tls_version}"
                artifacts = {
                    "reason": f"Server negotiated {fp.tls_version} instead of TLS 1.2+",
                    "transport_level": transport_level.value,
                    "tls_version": fp.tls_version,
                    **({"cert_info": cert_info} if cert_info else {}),
                }
            elif fp.tls_version is None:
                # Server only speaks legacy TLS (modern handshake failed)
                veto = VetoLevelEnum.FAILURE
                veto_message = "Legacy-only TLS - server must upgrade to TLS 1.2+"
                message = f"Server only supports legacy TLS: {fp.legacy_tls_version}"
                artifacts = {
                    "reason": (
                        f"Modern TLS handshake failed, but server accepted {fp.legacy_tls_version}"
                    ),
                    "transport_level": transport_level.value,
                    "legacy_accepted": fp.legacy_tls_version,
                }
            else:
                # Modern TLS works but server also accepts legacy
                veto = VetoLevelEnum.WARNING
                veto_message = "Legacy TLS accepted - downgrade attack possible"
                message = f"Server accepts legacy TLS: {fp.legacy_tls_version}"
                artifacts = {
                    "reason": f"Server accepted {fp.legacy_tls_version} connection",
                    "transport_level": transport_level.value,
                    "tls_version": fp.tls_version,
                    "legacy_accepted": fp.legacy_tls_version,
                    **({"cert_info": cert_info} if cert_info else {}),
                }
        elif transport_level == TransportLevelEnum.HTTPS_INVALID_CERT:
            veto_message = "Invalid certificate - MitM attack possible"
            message = "HTTPS certificate validation failed"
            artifacts = {
                "reason": fp.probe_error,
                "transport_level": transport_level.value,
            }
        elif transport_level == TransportLevelEnum.HTTP_ONLY:
            veto_message = "No HTTPS - credentials exposed in transit"
            message = "HTTP-only server, no HTTPS available"
            artifacts = {
                "reason": fp.probe_error,
                "transport_level": transport_level.value,
            }
        elif transport_level == TransportLevelEnum.HTTP_FALLBACK:
            message = "Server responds to unencrypted HTTP requests"
            artifacts = {
                "reason": (
                    f"HTTP port open and responding (status {fp.http_status}). "
                    "Credentials can be transmitted before response. Downgrade attack possible."
                ),
                "transport_level": transport_level.value,
                "tls_version": fp.tls_version,
                "http_status": fp.http_status,
                **({"cert_info": cert_info} if cert_info else {}),
            }
        elif transport_level == TransportLevelEnum.HTTPS_UNSAFE_REDIRECT:
            message = "Unsafe HTTP redirect chain"
            artifacts = {
                "reason": fp.redirect_unsafe_reason,
                "transport_level": transport_level.value,
                "final_url": fp.redirect_final_url,
                "tls_version": fp.tls_version,
                **({"cert_info": cert_info} if cert_info else {}),
            }
        elif transport_level == TransportLevelEnum.HTTPS_SAFE_REDIRECT:
            message = "HTTP redirects safely to HTTPS"
            artifacts = {
                "reason": "HTTP -> HTTPS redirect with no external jumps",
                "transport_level": transport_level.value,
                "tls_version": fp.tls_version,
                "final_url": fp.redirect_final_url,
                **({"cert_info": cert_info} if cert_info else {}),
            }
        else:
            message = "Strong HTTPS with no HTTP fallback"
            artifacts = {
                "reason": "HTTPS enforced, modern TLS, HTTP blocked",
                "transport_level": transport_level.value,
                "tls_version": fp.tls_version,
                **({"cert_info": cert_info} if cert_info else {}),
            }
            if not fp.legacy_tls_versions_tested:
                artifacts["note"] = "Legacy TLS probe unavailable (client OpenSSL limitation)"

        return MetricRunOutput(
            score=score,
            veto=veto,
            veto_message=veto_message,
            message=message,
            artifacts={"details": artifacts},
        )


__all__ = ["TransportSecurityRunner"]

