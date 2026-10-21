import asyncio
import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit


def get_schema(data):
    """
    Recursively traverses a dictionary or list to generate its schema.

    Args:
        data: The dictionary or list to analyze.

    Returns:
        A dictionary representing the schema of the input data.
    """
    # Base case: if the data is not a dict or list, return its type name
    if not isinstance(data, (dict, list)):
        return type(data).__name__

    # --- Recursive step for dictionaries ---
    if isinstance(data, dict):
        return {key: get_schema(value) for key, value in data.items()}

    # --- Recursive step for lists ---
    if isinstance(data, list):
        # If the list is empty, its schema is an empty list
        if not data:
            return []

        # Get the schema for all items in the list
        item_schemas = [get_schema(item) for item in data]

        # Find the unique schemas within the list
        unique_schemas = []
        for schema in item_schemas:
            if schema not in unique_schemas:
                unique_schemas.append(schema)

        # If there's only one unique schema, represent it as a list with one item
        if len(unique_schemas) == 1:
            return [unique_schemas[0]]

        # Otherwise, return the list of all unique schemas found
        return unique_schemas


def serialize_for_json(obj: object):
    import enum

    if isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, date):
        return obj.isoformat()
    elif isinstance(obj, enum.Enum):
        return obj.value
    else:
        return obj


def normalize_data(data):
    """
    Recursively sorts lists within a nested data structure
    to create a canonical representation.
    """
    if isinstance(data, dict):
        # Sort keys and normalize values
        return {k: normalize_data(v) for k, v in sorted(data.items())}
    if isinstance(data, list):
        # Normalize each item in the list and then sort the list.
        # We sort based on the JSON string representation of each item
        # to handle complex objects like dictionaries inside the list.
        return sorted([normalize_data(item) for item in data], key=lambda x: json.dumps(x))

    # Return the item if it's not a dict or list
    return data


async def run_subprocess_exec(
        args: list[str],
        cwd: Optional[str | Path] = None,
        timeout: Optional[int] = 10,
) -> tuple[bytes, bytes, int]:
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return stdout, stderr, process.returncode
    except (asyncio.TimeoutError, asyncio.CancelledError):
        if process:
            try:
                process.kill()
                await process.wait()
            except (ProcessLookupError, OSError):
                pass
        raise


def find_matching_files(
        repo_path: str, target_files: list[str], extra_ignores: list[str] = []
) -> list[str]:
    files = []
    default_ignores = {
        ".git",
        "node_modules",
        "__pycache__",
        "venv",
        ".env",
        "dist",
        "build",
        ".idea",
        ".vscode",
    }
    final_ignore_dirs = default_ignores.union(extra_ignores)
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in final_ignore_dirs]
        for filename in filenames:
            if filename in target_files:
                files.append(os.path.join(root, filename))
    return files


def normalize_url(url: str) -> str:
    parts = urlsplit(url)
    cleaned = parts._replace(query="", fragment="")
    path = cleaned.path.rstrip("/")
    cleaned = cleaned._replace(path=path)
    return str(urlunsplit(cleaned))


__all__ = [
    "get_schema",
    "serialize_for_json",
    "normalize_data",
    "run_subprocess_exec",
    "find_matching_files",
    "normalize_url",
]

