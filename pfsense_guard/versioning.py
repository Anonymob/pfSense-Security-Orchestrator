from __future__ import annotations

import re


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+){0,3}", value)
    if not match:
        raise ValueError(f"No numeric version could be parsed from {value!r}.")
    return tuple(int(piece) for piece in match.group(0).split("."))


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def at_or_below(candidate: str, threshold: str) -> bool:
    a, b = _pad(version_tuple(candidate), version_tuple(threshold))
    return a <= b


def below(candidate: str, threshold: str) -> bool:
    a, b = _pad(version_tuple(candidate), version_tuple(threshold))
    return a < b
