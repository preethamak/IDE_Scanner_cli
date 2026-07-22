from __future__ import annotations

import json


def strip_json_comments(text: str) -> str:
    out: list[str] = []
    in_string = False
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                in_string = False
            index += 1
            continue
        if char in {"'", '"'}:
            in_string = True
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "/" and nxt == "/":
            while index < len(text) and text[index] != "\n":
                index += 1
            out.append("\n")
            continue
        if char == "/" and nxt == "*":
            index += 2
            while index + 1 < len(text) and not (text[index] == "*" and text[index + 1] == "/"):
                index += 1
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def loads_jsonc(text: str) -> object:
    return json.loads(strip_json_comments(text))
