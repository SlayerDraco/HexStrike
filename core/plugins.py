"""
HexStrike v2 - Plugin Loader
Auto-discovers and loads plugins from /plugins directory.
Each plugin must implement the HexPlugin interface.
"""

from __future__ import annotations
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Type
from rich.console import Console

console = Console()


class HexPlugin:
    """
    Base class for all HexStrike plugins.
    Plugins must subclass this and implement `run()`.
    """
    name: str = "unnamed_plugin"
    description: str = ""
    version: str = "1.0.0"
    author: str = "unknown"
    # Which phase this plugin runs in: recon | exploit | report | post
    phase: str = "exploit"
    # If True, auto-triggered by Auto Decision Engine when condition is met
    auto_trigger: bool = False
    trigger_condition: str = ""  # e.g. "api_detected", "login_found"

    def run(self, graph, session, profile, console):
        """
        Main entry point.

        Args:
            graph:   ScanGraph — read/write the central data graph
            session: HexSession — auth-aware HTTP session
            profile: Profile — current scan profile
            console: Rich Console
        Returns:
            dict: plugin results (merged into graph.metadata)
        """
        raise NotImplementedError("Plugin must implement run()")

    def can_run(self, graph) -> bool:
        """Override to add pre-conditions before run() is called."""
        return True


class PluginRegistry:
    """Discovers, loads, and manages plugins."""

    def __init__(self, plugin_dir: Optional[str] = None):
        self._plugins: Dict[str, Type[HexPlugin]] = {}
        self.plugin_dir = Path(plugin_dir or Path(__file__).parent.parent / "plugins")

    def discover(self):
        """Scan plugin directory and load all valid plugins."""
        if not self.plugin_dir.exists():
            return
        for path in sorted(self.plugin_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            self._load_file(path)

    def _load_file(self, path: Path):
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, HexPlugin) and obj is not HexPlugin:
                    instance_name = getattr(obj, "name", path.stem)
                    self._plugins[instance_name] = obj
                    console.print(f"  [dim]Plugin loaded: [cyan]{instance_name}[/cyan][/dim]")
        except Exception as e:
            console.print(f"  [yellow]⚠ Failed to load plugin {path.name}: {e}[/yellow]")

    def register(self, plugin_cls: Type[HexPlugin]):
        """Manually register a plugin class."""
        self._plugins[plugin_cls.name] = plugin_cls

    def get(self, name: str) -> Optional[Type[HexPlugin]]:
        return self._plugins.get(name)

    def all(self) -> List[Type[HexPlugin]]:
        return list(self._plugins.values())

    def by_phase(self, phase: str) -> List[Type[HexPlugin]]:
        return [p for p in self._plugins.values() if p.phase == phase]

    def auto_triggered(self, condition: str) -> List[Type[HexPlugin]]:
        return [
            p for p in self._plugins.values()
            if p.auto_trigger and p.trigger_condition == condition
        ]

    def list_plugins(self) -> List[dict]:
        return [
            {
                "name": p.name, "description": p.description,
                "phase": p.phase, "version": p.version, "author": p.author,
                "auto_trigger": p.auto_trigger,
            }
            for p in self._plugins.values()
        ]

    def run_phase(self, phase: str, graph, session, profile, console):
        """Run all loaded plugins for a given phase."""
        results = {}
        for plugin_cls in self.by_phase(phase):
            plugin = plugin_cls()
            if not plugin.can_run(graph):
                continue
            console.print(f"\n[cyan]→ Plugin:[/cyan] [bold]{plugin.name}[/bold]")
            try:
                result = plugin.run(graph, session, profile, console)
                if result:
                    results[plugin.name] = result
                    graph.metadata[f"plugin_{plugin.name}"] = result
            except Exception as e:
                console.print(f"[red]✘ Plugin {plugin.name} failed: {e}[/red]")
        return results
