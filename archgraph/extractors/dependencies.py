"""Dependency extractor — parses package manager files to extract external dependencies."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from archgraph.extractors.base import BaseExtractor
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType

logger = logging.getLogger(__name__)


class DependencyExtractor(BaseExtractor):
    """Extracts dependencies from package manager manifest files."""

    # Maps filename -> parser method name
    _PARSERS: dict[str, str] = {
        "Cargo.toml": "_parse_cargo_toml",
        "go.mod": "_parse_go_mod",
        "package.json": "_parse_package_json",
        "build.gradle": "_parse_gradle",
        "build.gradle.kts": "_parse_gradle",
        "Podfile": "_parse_podfile",
        "CMakeLists.txt": "_parse_cmake",
        "conanfile.txt": "_parse_conan",
        "vcpkg.json": "_parse_vcpkg",
        "Package.swift": "_parse_swift_package",
    }

    # Directories to skip during manifest collection
    _SKIP_DIRS = frozenset({"vendor", "third_party", "node_modules", ".git", "__pycache__"})

    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        graph = GraphData()

        # Single os.walk traversal to collect all manifests
        manifests: list[tuple[Path, str, str]] = []  # (path, filename, method_name)
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in self._SKIP_DIRS]
            for fname in filenames:
                method_name = self._PARSERS.get(fname)
                if method_name:
                    manifests.append((Path(root) / fname, fname, method_name))

        for manifest, filename, method_name in manifests:
            try:
                rel = str(manifest.relative_to(repo_path)).replace("\\", "/")
                method = getattr(self, method_name)
                deps = method(manifest)
                rel_parent = rel.rsplit("/", 1)[0] if "/" in rel else "."
                module_name = rel_parent if rel_parent != "." else filename
                module_id = f"module:{module_name}"
                graph.add_node(module_id, NodeLabel.MODULE, name=module_name, path=rel)

                for dep in deps:
                    dep_id = f"dep:{dep['name']}"
                    graph.add_node(
                        dep_id,
                        NodeLabel.DEPENDENCY,
                        name=dep["name"],
                        version=dep.get("version", ""),
                        source=dep.get("source", filename),
                    )
                    graph.add_edge(module_id, dep_id, EdgeType.DEPENDS_ON)

            except Exception:
                logger.exception("Error parsing %s", manifest)

        return graph

    def _parse_cargo_toml(self, path: Path) -> list[dict[str, str]]:
        """Parse Rust Cargo.toml for dependencies."""
        try:
            import toml

            data = toml.loads(path.read_text(encoding="utf-8", errors="replace"))
        except ImportError:
            # Fallback: simple regex parsing
            return self._parse_cargo_toml_regex(path)

        deps: list[dict[str, str]] = []
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            section_deps = data.get(section, {})
            for name, spec in section_deps.items():
                version = ""
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    version = spec.get("version", "")
                deps.append({"name": name, "version": version, "source": "Cargo.toml"})
        return deps

    def _parse_cargo_toml_regex(self, path: Path) -> list[dict[str, str]]:
        """Fallback Cargo.toml parsing with regex."""
        text = path.read_text(encoding="utf-8", errors="replace")
        deps: list[dict[str, str]] = []
        # Match lines like: name = "version" or name = { version = "..." }
        for match in re.finditer(r'^(\w[\w-]*)\s*=\s*"([^"]+)"', text, re.MULTILINE):
            name, version = match.groups()
            if name not in ("name", "version", "edition", "rust-version", "description",
                            "license", "repository", "homepage", "readme"):
                deps.append({"name": name, "version": version, "source": "Cargo.toml"})
        return deps

    def _parse_go_mod(self, path: Path) -> list[dict[str, str]]:
        """Parse Go go.mod for require directives."""
        text = path.read_text(encoding="utf-8", errors="replace")
        deps: list[dict[str, str]] = []

        in_require = False
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                parts = line.replace("require ", "").strip().split()
                if len(parts) >= 2 and not parts[0].startswith("//"):
                    deps.append({"name": parts[0], "version": parts[1], "source": "go.mod"})
        return deps

    def _parse_package_json(self, path: Path) -> list[dict[str, str]]:
        """Parse Node.js package.json."""
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        deps: list[dict[str, str]] = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append({"name": name, "version": version, "source": "package.json"})
        return deps

    def _parse_gradle(self, path: Path) -> list[dict[str, str]]:
        """Parse Gradle build files for dependencies."""
        text = path.read_text(encoding="utf-8", errors="replace")
        deps: list[dict[str, str]] = []

        # Match: implementation 'group:artifact:version'
        # or: implementation("group:artifact:version")
        pattern = r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*['\(\"]+([^'\")\s]+)['\")]*"
        for match in re.finditer(pattern, text):
            coord = match.group(1)
            parts = coord.split(":")
            if len(parts) >= 2:
                name = f"{parts[0]}:{parts[1]}"
                version = parts[2] if len(parts) > 2 else ""
                deps.append({"name": name, "version": version, "source": "gradle"})
        return deps

    def _parse_podfile(self, path: Path) -> list[dict[str, str]]:
        """Parse iOS Podfile for CocoaPods dependencies."""
        text = path.read_text(encoding="utf-8", errors="replace")
        deps: list[dict[str, str]] = []

        # Match: pod 'Name', '~> 1.0'
        for match in re.finditer(r"pod\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", text):
            name = match.group(1)
            version = match.group(2) or ""
            deps.append({"name": name, "version": version, "source": "Podfile"})
        return deps

    def _parse_cmake(self, path: Path) -> list[dict[str, str]]:
        """Parse CMakeLists.txt for find_package and FetchContent."""
        text = path.read_text(encoding="utf-8", errors="replace")
        deps: list[dict[str, str]] = []

        # find_package(Name VERSION)
        for match in re.finditer(r"find_package\s*\(\s*(\w+)(?:\s+(\S+))?", text):
            name = match.group(1)
            version = match.group(2) or ""
            deps.append({"name": name, "version": version, "source": "CMakeLists.txt"})

        # FetchContent_Declare(name ...)
        for match in re.finditer(r"FetchContent_Declare\s*\(\s*(\w+)", text):
            deps.append({"name": match.group(1), "version": "", "source": "CMakeLists.txt"})

        return deps

    def _parse_conan(self, path: Path) -> list[dict[str, str]]:
        """Parse Conan conanfile.txt."""
        text = path.read_text(encoding="utf-8", errors="replace")
        deps: list[dict[str, str]] = []
        in_requires = False

        for line in text.splitlines():
            line = line.strip()
            if line == "[requires]":
                in_requires = True
                continue
            if line.startswith("["):
                in_requires = False
                continue
            if in_requires and "/" in line:
                parts = line.split("/")
                name = parts[0]
                version = parts[1] if len(parts) > 1 else ""
                deps.append({"name": name, "version": version, "source": "conanfile.txt"})
        return deps

    def _parse_vcpkg(self, path: Path) -> list[dict[str, str]]:
        """Parse vcpkg.json manifest."""
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        deps: list[dict[str, str]] = []
        for dep in data.get("dependencies", []):
            if isinstance(dep, str):
                deps.append({"name": dep, "version": "", "source": "vcpkg.json"})
            elif isinstance(dep, dict):
                deps.append({
                    "name": dep.get("name", ""),
                    "version": dep.get("version>=", dep.get("version", "")),
                    "source": "vcpkg.json",
                })
        return deps

    def _parse_swift_package(self, path: Path) -> list[dict[str, str]]:
        """Parse Swift Package.swift for dependencies."""
        text = path.read_text(encoding="utf-8", errors="replace")
        deps: list[dict[str, str]] = []

        # Match .package(url: "...", from: "...")
        for match in re.finditer(r'\.package\s*\(\s*url:\s*"([^"]+)"', text):
            url = match.group(1)
            name = url.rstrip("/").split("/")[-1].replace(".git", "")
            deps.append({"name": name, "version": "", "source": "Package.swift"})
        return deps
