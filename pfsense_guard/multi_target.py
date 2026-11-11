from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Sequence, TypeVar

from .config import TargetConfig

T = TypeVar("T")


class MultiTargetRunner:
    """Bounded runner for independent targets; not enabled by the single-target CLI yet."""

    def __init__(self, max_workers: int = 3) -> None:
        if not 1 <= max_workers <= 10:
            raise ValueError("max_workers must be between 1 and 10.")
        self.max_workers = max_workers

    def run(self, targets: Sequence[TargetConfig], worker: Callable[[TargetConfig], T]) -> dict[str, T | Exception]:
        keys = [f"{item.host}:{item.port}" for item in targets]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate firewall target supplied; refuse concurrent sessions to one appliance.")

        results: dict[str, T | Exception] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="pfso") as pool:
            futures = {pool.submit(worker, target): f"{target.host}:{target.port}" for target in targets}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:  # report per-target errors without hiding other results
                    results[key] = exc
        return results
