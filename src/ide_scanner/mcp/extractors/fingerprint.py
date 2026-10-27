"""FingerprintExtractor — TLS probing, redirect chain auditing, HTTP fingerprinting."""

import asyncio
import logging
import socket
import ssl
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import tldextract
from pydantic import BaseModel, Field

from ..base import BaseExtractor
from .utils import strip_cache_noise

logger = logging.getLogger(__name__)

WEAK_TLS_VERSIONS = frozenset({"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"})


class TransportLevelEnum(str, Enum):
    """Pre-computed transport security classification."""

    HTTPS_STRONG = "https_strong"
    HTTPS_SAFE_REDIRECT = "https_safe_redirect"
    HTTPS_LEGACY_TLS = "https_legacy_tls"
    HTTPS_UNSAFE_REDIRECT = "https_unsafe_redirect"
    HTTPS_INVALID_CERT = "https_invalid_cert"
    HTTP_FALLBACK = "http_fallback"
    HTTP_ONLY = "http_only"


class FingerprintResult(BaseModel):
    """TLS and HTTP fingerprint data for transport security assessment."""

    mcp_url: Optional[str] = None
    is_local: bool = False

    transport_level: Optional[TransportLevelEnum] = None
    probe_error: Optional[str] = None

    scheme: Optional[str] = None
    host: Optional[str] = None
    server_header: Optional[str] = None
    cdn_hint: Optional[str] = None
    security_headers: Optional[dict[str, str]] = None
    tls_issuer_cn: Optional[str] = None
    tls_subject_cn: Optional[str] = None
    tls_version: Optional[str] = None
    cert_valid: Optional[bool] = None
    cert_subject: Optional[dict] = None
    cert_issuer: Optional[dict] = None
    cert_verified_hostname: Optional[str] = None
    legacy_tls_accepted: Optional[bool] = None
    legacy_tls_version: Optional[str] = None
    legacy_tls_versions_tested: list[str] = Field(default_factory=list)
    invalid_url: bool = False
    dns_failed: bool = False
    http_status: Optional[int] = None
    redirect_final_url: Optional[str] = None
    redirect_unsafe_reason: Optional[str] = None
    http_probe_error: Optional[str] = None
    http_probe_error_kind: Optional[str] = None


class FingerprintExtractor(BaseExtractor):
    """Extracts TLS/HTTP fingerprint and classifies transport security."""

    name = "fingerprint"
    version = "1.0"
    cache_key_fn = staticmethod(strip_cache_noise)

    TLS_PROBE_TIMEOUT = 5.0
    LEGACY_TLS_PROBE_TIMEOUT = 3.0
    HTTP_PROBE_TIMEOUT = 3.0

    async def _compute(self, subject: Any, **kwargs) -> FingerprintResult:
        mcp_url = subject.get("mcp_url") if isinstance(subject, dict) else None
        is_local = subject.get("is_local", False) if isinstance(subject, dict) else False

        if is_local or not mcp_url:
            return FingerprintResult(mcp_url=mcp_url, is_local=True)

        parsed = urlparse(mcp_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname

        if not hostname:
            return FingerprintResult(
                mcp_url=mcp_url,
                probe_error="URL has no hostname",
                scheme=scheme,
                invalid_url=True,
            )

        port = parsed.port or (443 if scheme == "https" else 80)

        # For HTTP URLs, probe HTTPS availability on 443
        if scheme == "http":
            port = 443 if (parsed.port is None or parsed.port == 80) else parsed.port

        # --- TLS probe (sync, wrapped in thread) ---
        tls_result = await asyncio.to_thread(self._probe_tls_connection, hostname, port)

        # Build partial result with raw HTTP fingerprint data
        fingerprint = FingerprintResult(mcp_url=mcp_url, scheme=scheme, host=hostname)

        # DNS failure
        if tls_result.get("dns_failed"):
            fingerprint.probe_error = tls_result.get("error", "DNS resolution failed")
            fingerprint.dns_failed = True
            return fingerprint

        # TLS connection failed
        if not tls_result.get("success"):
            # Cert verification failure
            if tls_result.get("cert_verification_failed"):
                fingerprint.transport_level = TransportLevelEnum.HTTPS_INVALID_CERT
                fingerprint.cert_valid = False
                fingerprint.probe_error = tls_result.get("error")
                return fingerprint

            # SSL handshake failure -- check legacy TLS
            if tls_result.get("ssl_handshake_failed"):
                legacy_result = await asyncio.to_thread(self._probe_legacy_tls, hostname, port)
                fingerprint.legacy_tls_versions_tested = legacy_result.get("versions_tested", [])
                if legacy_result.get("legacy_accepted"):
                    fingerprint.transport_level = TransportLevelEnum.HTTPS_LEGACY_TLS
                    fingerprint.legacy_tls_accepted = True
                    fingerprint.legacy_tls_version = legacy_result.get("version_accepted")
                    return fingerprint

            # HTTP URL with no HTTPS
            if scheme == "http":
                fingerprint.transport_level = TransportLevelEnum.HTTP_ONLY
                fingerprint.probe_error = tls_result.get("error")
                return fingerprint

            # HTTPS URL with operational failure
            fingerprint.probe_error = tls_result.get("error")
            return fingerprint

        # TLS succeeded — populate cert fields
        fingerprint.tls_version = tls_result.get("tls_version")
        fingerprint.cert_valid = True
        cert_info = tls_result.get("cert_info", {})
        fingerprint.cert_subject = cert_info.get("subject")
        fingerprint.cert_issuer = cert_info.get("issuer")
        fingerprint.cert_verified_hostname = cert_info.get("verified_hostname")
        fingerprint.tls_subject_cn = cert_info.get("subject_cn")
        fingerprint.tls_issuer_cn = cert_info.get("issuer_cn")

        # Check weak negotiated TLS
        if fingerprint.tls_version in WEAK_TLS_VERSIONS:
            fingerprint.transport_level = TransportLevelEnum.HTTPS_LEGACY_TLS
            fingerprint.legacy_tls_accepted = True
            fingerprint.legacy_tls_version = fingerprint.tls_version
            return fingerprint

        # Probe legacy TLS acceptance
        legacy_result = await asyncio.to_thread(self._probe_legacy_tls, hostname, port)
        fingerprint.legacy_tls_accepted = legacy_result.get("legacy_accepted", False)
        fingerprint.legacy_tls_version = legacy_result.get("version_accepted")
        fingerprint.legacy_tls_versions_tested = legacy_result.get("versions_tested", [])

        if legacy_result.get("legacy_accepted"):
            fingerprint.transport_level = TransportLevelEnum.HTTPS_LEGACY_TLS
            return fingerprint

        # HTTP fingerprint (for server header, CDN hint, security headers)
        await self._collect_http_fingerprint(fingerprint, mcp_url)

        # HTTP downgrade check
        http_port = 80 if port == 443 else port
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        downgraded_url = f"http://{hostname}:{http_port}{parsed.path or ''}{query}{fragment}"

        downgrade_result = await asyncio.to_thread(
            self._check_http_downgrade, downgraded_url, hostname
        )
        fingerprint.transport_level = downgrade_result.get("transport_level")
        fingerprint.http_status = downgrade_result.get("http_status")
        fingerprint.redirect_final_url = downgrade_result.get("final_url")
        fingerprint.redirect_unsafe_reason = downgrade_result.get("unsafe_reason")
        fingerprint.http_probe_error = downgrade_result.get("probe_error")
        fingerprint.http_probe_error_kind = downgrade_result.get("probe_error_kind")
        return fingerprint

    # --- Sync probe methods (run via asyncio.to_thread) ---

    def _probe_tls_connection(self, hostname: str, port: int) -> dict:
        """Probe HTTPS connection with certificate validation."""
        result: dict = {"success": False}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.TLS_PROBE_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["success"] = True
                    result["tls_version"] = ssock.version()

                    cert = ssock.getpeercert()
                    cert_info: dict = {}
                    if cert:
                        cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                        cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                        cert_info["verified_hostname"] = hostname
                        subject = cert.get("subject") or []
                        issuer = cert.get("issuer") or []
                        cert_info["subject_cn"] = next(
                            (v for attrs in subject for (k, v) in attrs if k == "commonName"),
                            None,
                        )
                        cert_info["issuer_cn"] = next(
                            (v for attrs in issuer for (k, v) in attrs if k == "commonName"),
                            None,
                        )
                    result["cert_info"] = cert_info

        except ssl.SSLCertVerificationError as e:
            result["error"] = f"Certificate verification failed: {e}"
            result["cert_verification_failed"] = True
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {e}"
            result["ssl_handshake_failed"] = True
        except socket.timeout:
            result["error"] = "Connection timeout"
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
        except socket.gaierror as e:
            result["dns_failed"] = True
            result["error"] = f"DNS resolution failed: {e}"
        except OSError as e:
            result["error"] = f"Connection failed: {e}"
        return result

    def _probe_legacy_tls(self, hostname: str, port: int) -> dict:
        """Attempt TLS 1.0/1.1 connection to detect legacy protocol support."""
        result: dict = {"legacy_accepted": False, "versions_tested": []}
        legacy_versions = [
            (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
            (ssl.TLSVersion.TLSv1, "TLSv1.0"),
        ]

        for tls_version, version_name in legacy_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_default_certs()

                try:
                    context.minimum_version = tls_version
                    context.maximum_version = tls_version
                except (ValueError, ssl.SSLError):
                    continue

                result["versions_tested"].append(version_name)

                with socket.create_connection(
                    (hostname, port), timeout=self.LEGACY_TLS_PROBE_TIMEOUT
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        result["legacy_accepted"] = True
                        result["version_accepted"] = ssock.version()
                        return result

            except ssl.SSLError as e:
                error_str = str(e).lower()
                if any(
                    msg in error_str
                    for msg in [
                        "protocol_version",
                        "unsupported protocol",
                        "alert protocol",
                        "wrong version",
                        "handshake failure",
                    ]
                ):
                    continue
                result["error"] = str(e)
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
        return result

    @staticmethod
    def _get_registrable_domain(hostname: str) -> str:
        extracted = tldextract.extract(hostname)
        return f"{extracted.domain}.{extracted.suffix}".lower()

    def _audit_redirect_chain(self, start_url: str, expected_hostname: str) -> dict:
        """Follow redirects and validate no external jumps or protocol flips."""
        result: dict = {"followed": False, "safe": True, "final_url": None, "chain": []}

        try:
            with httpx.Client(
                timeout=self.HTTP_PROBE_TIMEOUT, follow_redirects=True, max_redirects=10
            ) as client:
                resp = client.get(start_url)
                result["followed"] = True
                result["final_url"] = str(resp.url)

                previous_scheme = urlparse(start_url).scheme
                for historical_resp in resp.history:
                    hop_url = str(historical_resp.url)
                    hop_parsed = urlparse(hop_url)
                    location = historical_resp.headers.get("location", "")
                    location_parsed = urlparse(location) if location else None

                    result["chain"].append(
                        {
                            "url": hop_url,
                            "status": historical_resp.status_code,
                            "location": location,
                        }
                    )

                    if location_parsed:
                        redirect_host = location_parsed.hostname or hop_parsed.hostname
                        expected_domain = self._get_registrable_domain(expected_hostname)
                        redirect_domain = (
                            self._get_registrable_domain(redirect_host) if redirect_host else ""
                        )

                        if redirect_domain and redirect_domain != expected_domain:
                            result["safe"] = False
                            result["unsafe_reason"] = (
                                f"External redirect: {expected_hostname} -> {redirect_host}"
                            )
                            return result

                        redirect_scheme = location_parsed.scheme or hop_parsed.scheme
                        if previous_scheme == "https" and redirect_scheme == "http":
                            result["safe"] = False
                            result["unsafe_reason"] = (
                                f"Protocol downgrade: HTTPS -> HTTP at {hop_url}"
                            )
                            return result
                        previous_scheme = redirect_scheme

        except httpx.TooManyRedirects:
            result["safe"] = False
            result["unsafe_reason"] = "Too many redirects (possible loop)"
        except Exception as e:
            result["followed"] = False
            result["probe_failed"] = True
            result["probe_error"] = str(e)
            return result

        if result["final_url"]:
            final_parsed = urlparse(result["final_url"])
            if final_parsed.scheme != "https":
                result["safe"] = False
                result["unsafe_reason"] = f"Redirect ends at HTTP: {result['final_url']}"

        return result

    def _check_http_downgrade(self, downgraded_url: str, hostname: str) -> dict:
        """Check HTTP downgrade resistance and return raw transport facts."""
        try:
            with httpx.Client(timeout=self.HTTP_PROBE_TIMEOUT, follow_redirects=False) as client:
                resp = client.get(downgraded_url)

                # Server accepts HTTP without redirect
                if not (300 <= resp.status_code < 400):
                    return {
                        "transport_level": TransportLevelEnum.HTTP_FALLBACK,
                        "http_status": resp.status_code,
                    }

                # Audit redirect chain
                redirect_result = self._audit_redirect_chain(downgraded_url, hostname)

                if redirect_result.get("probe_failed"):
                    return {
                        "probe_error_kind": "redirect_probe_failed",
                        "probe_error": redirect_result.get("probe_error"),
                    }

                if not redirect_result.get("safe", True):
                    return {
                        "transport_level": TransportLevelEnum.HTTPS_UNSAFE_REDIRECT,
                        "unsafe_reason": redirect_result.get("unsafe_reason"),
                        "final_url": redirect_result.get("final_url"),
                    }

                return {
                    "transport_level": TransportLevelEnum.HTTPS_SAFE_REDIRECT,
                    "final_url": redirect_result.get("final_url"),
                }

        except httpx.ConnectError:
            # HTTP port blocked — best case
            return {
                "transport_level": TransportLevelEnum.HTTPS_STRONG,
            }
        except httpx.TimeoutException:
            return {
                "probe_error_kind": "timeout",
            }
        except Exception as e:
            return {
                "probe_error_kind": "unexpected",
                "probe_error": str(e),
            }

    async def _collect_http_fingerprint(self, fingerprint: FingerprintResult, mcp_url: str):
        """Collect HTTP headers for server/CDN/security header fingerprinting."""
        parsed = urlparse(mcp_url)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        transport = httpx.AsyncHTTPTransport(verify=ctx)

        try:
            async with httpx.AsyncClient(transport=transport, timeout=10) as client:
                resp = await client.get(mcp_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                fingerprint.server_header = headers.get("server")

                # CDN detection
                if "cf-ray" in headers or "cf-cache-status" in headers:
                    fingerprint.cdn_hint = "cloudflare"
                elif "x-served-by" in headers or "fastly-debug-digest" in headers:
                    fingerprint.cdn_hint = "fastly"

                fingerprint.security_headers = {
                    k: v
                    for k, v in headers.items()
                    if k.startswith("x-")
                    or k.startswith("strict-")
                    or k.startswith("content-security-policy")
                }
        except Exception as e:
            logger.warning(f"Failed to collect HTTP fingerprint for {mcp_url} - {e}")


__all__ = [
    "FingerprintExtractor",
    "FingerprintResult",
    "TransportLevelEnum",
    "WEAK_TLS_VERSIONS",
]

