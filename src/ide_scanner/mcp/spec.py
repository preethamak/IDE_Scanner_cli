from __future__ import annotations

from .models import MetricSpec


# The metric tree is deliberately explicit: it is the public contract for the
# MCP assessment report and keeps weights reviewable beside the implementation.
MCP_CATALOG_RISK_SPEC = MetricSpec(
    name="server-catalog",
    title="Server Catalog Risk Assessment",
    weight=1.0,
    children=(
        MetricSpec("hosting-operator-class", "Hosting/Operator Class", 3.0, "hosting_operator_class"),
        MetricSpec("transport-security", "Transport Security", 1.0, "transport_security"),
        MetricSpec(
            "remote-auth",
            "Remote Authentication",
            1.0,
            children=(
                MetricSpec("auth-strength", "Authentication Strength", 6.0, "auth_strength"),
                MetricSpec("pkce-validation", "PKCE Validation", 3.0, "pkce_validation"),
                MetricSpec("dynamic-client-reg", "Dynamic Client Registration", 1.0, "dynamic_client_registration"),
            ),
        ),
        MetricSpec(
            "source-code-risk",
            "Source Code Risk",
            2.0,
            children=(
                MetricSpec("source-opacity", "Source Opacity", 2.0, "source_opacity"),
                MetricSpec("malicious-deps", "Malicious Dependencies", 4.0, "malicious_dependencies"),
                MetricSpec("vulnerability-risk", "Vulnerability Risk", 4.0, "vulnerability_risk"),
                MetricSpec("mcp-cve", "MCP Package CVEs", 2.0, "mcp_package_cves"),
            ),
        ),
        MetricSpec(
            "tool-capability-risk",
            "Tool Capability Risk",
            2.0,
            children=(
                MetricSpec("metadata-security", "Metadata Security", 3.5, "metadata_security"),
                MetricSpec("tool-source-code-security", "Tool Source Code Security", 6.5, "tool_source_code_security"),
            ),
        ),
        MetricSpec("secrets-risk", "Secrets Risk", 1.0, "secrets_risk"),
    ),
)


def leaf_specs(spec: MetricSpec = MCP_CATALOG_RISK_SPEC) -> list[MetricSpec]:
    leaves: list[MetricSpec] = []
    for child in spec.children:
        leaves.extend(leaf_specs(child) if child.is_module else [child])
    return leaves


__all__ = ["MCP_CATALOG_RISK_SPEC", "leaf_specs"]
