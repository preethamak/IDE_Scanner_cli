from enum import Enum
from typing import Any

from ..types import AuthModeEnum
from ..types import StatusEnum, VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.auth_modes import AuthModesResult


class AuthStrengthEnum(str, Enum):
    STRONG = "strong"
    INSECURE_MECHANISMS = "insecure_mechanisms"
    UNKNOWN = "unknown"
    NO_AUTH = "no_auth"


SCORE_STRONG = 0.00
SCORE_INSECURE = 0.60
SCORE_UNKNOWN_OR_NO_AUTH = 1.00


class AuthStrengthRunner:
    """Scores authentication strength based on detected auth modes.

    Ported from RemoteAuthTestSuite.test_auth_strength().
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        auth: AuthModesResult = subject

        # Skip for local servers
        if auth.is_local:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Not applicable for local servers",
            )

        # Error if modes couldn't be detected
        if auth.modes is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.ERROR,
                message=auth.summary or "Error during authentication detection",
            )

        AUTH_MODE_PRIORITY = {
            AuthModeEnum.OAUTH: 0,
            AuthModeEnum.PAT: 1,
            AuthModeEnum.API_KEY: 2,
            AuthModeEnum.UNKNOWN: 3,
            AuthModeEnum.NO_AUTH: 4,
        }

        modes = sorted(auth.modes, key=lambda m: AUTH_MODE_PRIORITY.get(m, 99))
        has_oauth = AuthModeEnum.OAUTH in modes
        has_api_key = AuthModeEnum.API_KEY in modes
        has_pat = AuthModeEnum.PAT in modes

        # OAuth only → strong
        if modes == [AuthModeEnum.OAUTH]:
            return MetricRunOutput(
                score=SCORE_STRONG,
                message=auth.summary,
                artifacts={
                    "details": {"auth_strength": AuthStrengthEnum.STRONG.value, "auth_modes": [m.value for m in modes],
                                "summary": auth.summary}},
            )

        # OAuth with other mechanisms
        if has_oauth:
            return MetricRunOutput(
                score=SCORE_INSECURE,
                message=auth.summary,
                artifacts={"details": {"auth_strength": AuthStrengthEnum.INSECURE_MECHANISMS.value,
                                       "auth_modes": [m.value for m in modes], "summary": auth.summary}},
            )

        # API key or PAT without OAuth
        if has_api_key or has_pat:
            return MetricRunOutput(
                score=SCORE_INSECURE,
                veto=VetoLevelEnum.WARNING,
                veto_message="Insecure authentication mechanisms in use with no OAuth",
                message=auth.summary or "Insecure authentication mechanisms in use with no OAuth",
                artifacts={"details": {"auth_strength": AuthStrengthEnum.INSECURE_MECHANISMS.value,
                                       "auth_modes": [m.value for m in modes], "summary": auth.summary}},
            )

        # UNKNOWN or NO_AUTH
        if AuthModeEnum.NO_AUTH in modes:
            auth_strength = AuthStrengthEnum.NO_AUTH
            msg = "No authentication mechanism detected"
            veto_msg = "No authentication mechanism detected"
        else:
            auth_strength = AuthStrengthEnum.UNKNOWN
            msg = "OAuth was not detected and other authentication mechanisms couldn't be detected"
            veto_msg = "OAuth was not detected and other authentication mechanisms couldn't be detected"

        return MetricRunOutput(
            score=SCORE_UNKNOWN_OR_NO_AUTH,
            veto=VetoLevelEnum.WARNING,
            veto_message=veto_msg,
            message=msg,
            artifacts={"details": {"auth_strength": auth_strength.value, "auth_modes": [m.value for m in modes],
                                   "summary": auth.summary}},
        )


__all__ = ["AuthStrengthRunner"]

