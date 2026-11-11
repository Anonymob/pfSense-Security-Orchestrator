from __future__ import annotations

from importlib.metadata import entry_points

from .modules.base import AuditModule


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: list[AuditModule] = []
        self._names: set[str] = set()

    def register(self, module: AuditModule) -> None:
        name = getattr(module, "name", None)
        if not isinstance(name, str) or not name.strip():
            raise ValueError("An audit plugin must define a non-empty 'name'.")
        if name in self._names:
            raise ValueError(f"Duplicate audit module name: {name}")
        if not callable(getattr(module, "run", None)):
            raise TypeError(f"Audit module {name!r} must implement run(ssh, report).")
        self._modules.append(module)
        self._names.add(name)

    def load_community_plugins(self, enabled: bool = False) -> list[str]:
        """Load installed Python entry-point plugins only after explicit opt-in."""
        if not enabled:
            return []
        loaded: list[str] = []
        discovered = entry_points()
        candidates = discovered.select(group="pfsense_guard.modules") if hasattr(discovered, "select") else discovered.get("pfsense_guard.modules", [])
        for point in candidates:
            plugin_factory = point.load()  # importing a plugin executes trusted local package code
            module = plugin_factory() if isinstance(plugin_factory, type) else plugin_factory
            self.register(module)
            loaded.append(module.name)
        return loaded

    @property
    def modules(self) -> tuple[AuditModule, ...]:
        return tuple(self._modules)
