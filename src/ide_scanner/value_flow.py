from __future__ import annotations

import re
from typing import Any

MAX_VALUE_PROPAGATION_ROUNDS = 32
MAX_FUNCTION_SUMMARIES = 1_000
_IDENT = r"[A-Za-z_$][\w$]*"
_ASSIGNMENT = re.compile(rf"\b(?:const|let|var)\s+(?P<target>{_IDENT})\s*=\s*(?P<expression>[^;\n]{{1,2000}})")
_PROPERTY_ASSIGNMENT = re.compile(
    rf"\b(?P<object>{_IDENT})\s*\.\s*(?P<property>{_IDENT})\s*=\s*(?P<expression>[^;\n]{{1,2000}})"
)
_CREDENTIAL_READ = re.compile(
    r"fs\.(?:promises\.)?(?:readFile|readFileSync)\s*\([^)]*(?:\.ssh|id_(?:rsa|ed25519)|\.aws|\.npmrc|\.git-credentials|wallet|mnemonic|seed.?phrase|[/\\]\.env\b)",
    re.I,
)
_TRANSFORM = re.compile(r"(?:JSON\.stringify|Buffer\.from|createGzip|createCipheriv)\s*\((?P<source>[^)]{1,500})\)")
_NETWORK_SINKS = (
    re.compile(r"\b(?:request|req)\.write\s*\((?P<value>[^)]{1,500})\)"),
    re.compile(r"\baxios\.(?:post|put)\s*\([^,]{1,500},\s*(?P<value>[^)]{1,500})\)"),
    re.compile(r"\bfetch\s*\([^,]{1,500},\s*\{[^}]{0,1000}\bbody\s*:\s*(?P<value>[^,}\n]{1,500})", re.S),
)
_FUNCTION_HEADER = re.compile(rf"\b(?:async\s+)?function\s+(?P<name>{_IDENT})\s*\((?P<params>[^)]{{0,1000}})\)\s*\{{")
_CALL = re.compile(rf"\b(?P<name>{_IDENT})\s*\((?P<args>[^)]{{0,2000}})\)")


def credential_value_flow(text: str) -> dict[str, Any] | None:
    """Track simple identifier assignments from credential reads to network bodies."""
    assignments = [
        (match.group("target"), match.group("expression"), match.start())
        for match in _ASSIGNMENT.finditer(text)
    ]
    functions = _function_summaries(text)
    tainted: dict[str, dict[str, Any]] = {}
    for target, expression, position in assignments:
        if _CREDENTIAL_READ.search(expression):
            tainted[target] = {
                "source_variable": target,
                "path": [target],
                "source_position": position,
                "last_position": position,
            }

    for _ in range(MAX_VALUE_PROPAGATION_ROUNDS):
        changed = False
        for target, expression, assignment_position in assignments:
            if target in tainted:
                continue
            source, returned_transform, function_handoff = _assignment_taint_source(
                expression, tainted, functions, assignment_position
            )
            if source is None:
                continue
            transform = _TRANSFORM.search(expression)
            path = [*tainted[source]["path"]]
            if function_handoff:
                path.append(function_handoff)
            path.append(target)
            tainted[target] = {
                **tainted[source],
                "path": path,
                "transformed": bool(transform) or returned_transform or bool(tainted[source].get("transformed")),
                "last_position": assignment_position,
            }
            changed = True
        for match in _PROPERTY_ASSIGNMENT.finditer(text):
            container = match.group("object")
            position = match.start()
            source = _first_tainted_identifier(match.group("expression"), tainted, before=position)
            if source is None:
                continue
            property_path = f"{container}.{match.group('property')}"
            existing = tainted.get(container)
            if existing is not None and int(existing["last_position"]) <= position:
                continue
            tainted[container] = {
                **tainted[source],
                "path": [*tainted[source]["path"], property_path, container],
                "last_position": position,
                "object_property": property_path,
            }
            changed = True
        if not changed:
            break

    for sink in _NETWORK_SINKS:
        for match in sink.finditer(text):
            source = _first_tainted_identifier(match.group("value"), tainted, before=match.start())
            if source is not None:
                flow = tainted[source]
                return {
                    "source_variable": flow["source_variable"],
                    "sink_variable": source,
                    "variable_path": flow["path"],
                    "transformed": bool(flow.get("transformed")),
                    "source_position": flow["source_position"],
                    "sink_position": match.start(),
                    "correlation": "same-file-identifier-value-flow",
                }
    for call in _CALL.finditer(text):
        summary = functions.get(call.group("name"))
        if not summary:
            continue
        args = [item.strip() for item in call.group("args").split(",")]
        for parameter_index in summary["network_sink_parameters"]:
            if parameter_index >= len(args):
                continue
            source = _first_tainted_identifier(args[parameter_index], tainted, before=call.start())
            if source is None:
                continue
            flow = tainted[source]
            return {
                "source_variable": flow["source_variable"],
                "sink_variable": source,
                "variable_path": [*flow["path"], f"{call.group('name')}:{summary['parameters'][parameter_index]}"],
                "transformed": bool(flow.get("transformed")),
                "source_position": flow["source_position"],
                "sink_position": call.start(),
                "correlation": "same-file-function-parameter-value-flow",
                "function": call.group("name"),
                "parameter": summary["parameters"][parameter_index],
            }
    return None


def _first_tainted_identifier(
    expression: str,
    tainted: dict[str, dict[str, Any]],
    before: int | None = None,
) -> str | None:
    identifiers = set(re.findall(rf"\b({_IDENT})\b", expression))
    return next(
        (
            name for name, flow in tainted.items()
            if name in identifiers and (before is None or int(flow["last_position"]) <= before)
        ),
        None,
    )


def _assignment_taint_source(
    expression: str,
    tainted: dict[str, dict[str, Any]],
    functions: dict[str, dict[str, Any]],
    position: int,
) -> tuple[str | None, bool, str | None]:
    stripped = expression.strip()
    if re.fullmatch(_IDENT, stripped):
        return _first_tainted_identifier(stripped, tainted, before=position), False, None
    transform = _TRANSFORM.fullmatch(stripped)
    if transform:
        return _first_tainted_identifier(transform.group("source"), tainted, before=position), True, None
    call = _CALL.fullmatch(stripped)
    if call and (summary := functions.get(call.group("name"))):
        args = [item.strip() for item in call.group("args").split(",")]
        for parameter_index in summary["return_parameters"]:
            if parameter_index >= len(args):
                continue
            source = _first_tainted_identifier(args[parameter_index], tainted, before=position)
            if source is not None:
                parameter = summary["parameters"][parameter_index]
                return source, parameter_index in summary["transformed_return_parameters"], f"{call.group('name')}:{parameter}:return"
    return None, False, None


def _function_summaries(text: str) -> dict[str, dict[str, Any]]:
    summaries: dict[str, dict[str, Any]] = {}
    for header in _FUNCTION_HEADER.finditer(text):
        if len(summaries) >= MAX_FUNCTION_SUMMARIES:
            break
        body = _balanced_body(text, header.end() - 1)
        if body is None:
            continue
        parameters = [item.strip() for item in header.group("params").split(",") if re.fullmatch(_IDENT, item.strip())]
        sink_parameters = [
            index for index, parameter in enumerate(parameters)
            if any(
                re.search(pattern.pattern.replace("(?P<value>[^)]{1,500})", re.escape(parameter)), body, pattern.flags)
                for pattern in _NETWORK_SINKS[:2]
            )
            or re.search(rf"\bbody\s*:\s*{re.escape(parameter)}\b", body)
        ]
        return_parameters: list[int] = []
        transformed_return_parameters: list[int] = []
        for index, parameter in enumerate(parameters):
            if re.search(rf"\breturn\s+{re.escape(parameter)}\s*;?", body):
                return_parameters.append(index)
            if re.search(
                rf"\breturn\s+(?:JSON\.stringify|Buffer\.from|createGzip|createCipheriv)\s*\(\s*{re.escape(parameter)}\s*\)",
                body,
            ):
                return_parameters.append(index)
                transformed_return_parameters.append(index)
        summaries[header.group("name")] = {
            "parameters": parameters,
            "network_sink_parameters": sink_parameters,
            "return_parameters": sorted(set(return_parameters)),
            "transformed_return_parameters": sorted(set(transformed_return_parameters)),
        }
    return summaries


def _balanced_body(text: str, opening_brace: int) -> str | None:
    depth = 0
    for index in range(opening_brace, min(len(text), opening_brace + 100_000)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening_brace + 1:index]
    return None
