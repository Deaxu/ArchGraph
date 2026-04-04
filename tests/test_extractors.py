"""Tests for git, dependency, annotation, and security label extractors."""

import json
import textwrap
from pathlib import Path

import pytest

from archgraph.extractors.annotations import AnnotationExtractor
from archgraph.extractors.dependencies import DependencyExtractor
from archgraph.extractors.git import GitExtractor
from archgraph.extractors.security_labels import SecurityLabeler
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType


# ── Dependency Extractor Tests ──────────────────────────────────────────────


class TestDependencyExtractor:
    pytestmark = pytest.mark.core

    def test_parse_cargo_toml(self, tmp_path):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(textwrap.dedent("""\
            [package]
            name = "mylib"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            tokio = { version = "1.0", features = ["full"] }

            [dev-dependencies]
            criterion = "0.5"
        """))

        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)

        dep_names = {n.properties["name"] for n in graph.nodes if n.label == NodeLabel.DEPENDENCY}
        assert "serde" in dep_names
        assert "tokio" in dep_names
        assert "criterion" in dep_names

    def test_parse_package_json(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "myapp",
            "dependencies": {"express": "^4.18.0", "lodash": "^4.17.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }))

        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)

        dep_names = {n.properties["name"] for n in graph.nodes if n.label == NodeLabel.DEPENDENCY}
        assert "express" in dep_names
        assert "lodash" in dep_names
        assert "jest" in dep_names

    def test_parse_go_mod(self, tmp_path):
        gomod = tmp_path / "go.mod"
        gomod.write_text(textwrap.dedent("""\
            module example.com/myapp

            go 1.21

            require (
                github.com/gin-gonic/gin v1.9.1
                google.golang.org/protobuf v1.31.0
            )
        """))

        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)

        dep_names = {n.properties["name"] for n in graph.nodes if n.label == NodeLabel.DEPENDENCY}
        assert "github.com/gin-gonic/gin" in dep_names
        assert "google.golang.org/protobuf" in dep_names

    def test_parse_cmake(self, tmp_path):
        cmake = tmp_path / "CMakeLists.txt"
        cmake.write_text(textwrap.dedent("""\
            cmake_minimum_required(VERSION 3.14)
            project(mylib)

            find_package(OpenSSL REQUIRED)
            find_package(ZLIB 1.2.11)

            FetchContent_Declare(
                googletest
                GIT_REPOSITORY https://github.com/google/googletest.git
            )
        """))

        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)

        dep_names = {n.properties["name"] for n in graph.nodes if n.label == NodeLabel.DEPENDENCY}
        assert "OpenSSL" in dep_names
        assert "ZLIB" in dep_names
        assert "googletest" in dep_names

    def test_parse_podfile(self, tmp_path):
        podfile = tmp_path / "Podfile"
        podfile.write_text(textwrap.dedent("""\
            platform :ios, '14.0'

            target 'MyApp' do
              pod 'Alamofire', '~> 5.0'
              pod 'SwiftyJSON'
            end
        """))

        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)

        dep_names = {n.properties["name"] for n in graph.nodes if n.label == NodeLabel.DEPENDENCY}
        assert "Alamofire" in dep_names
        assert "SwiftyJSON" in dep_names

    def test_depends_on_edges(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "^4.0"}}))

        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)

        edges = [e for e in graph.edges if e.type == EdgeType.DEPENDS_ON]
        assert len(edges) == 1


# ── Annotation Extractor Tests ──────────────────────────────────────────────


class TestAnnotationExtractor:
    pytestmark = pytest.mark.core

    def test_extract_annotations(self, tmp_path):
        src = tmp_path / "test.c"
        src.write_text(textwrap.dedent("""\
            // TODO: fix this later
            void foo() {
                // HACK: workaround for bug #123
                int x = 0;
                // FIXME: potential buffer overflow
                memcpy(buf, src, len);
            }

            // UNSAFE: raw pointer usage
            void bar(void *ptr) {}
        """))

        ext = AnnotationExtractor()
        graph = ext.extract(tmp_path)

        ann_types = {n.properties["type"] for n in graph.nodes if n.label == NodeLabel.ANNOTATION}
        assert "TODO" in ann_types
        assert "HACK" in ann_types
        assert "FIXME" in ann_types
        assert "UNSAFE" in ann_types

    def test_annotation_edges(self, tmp_path):
        src = tmp_path / "test.c"
        src.write_text("// TODO: something\n")

        ext = AnnotationExtractor()
        graph = ext.extract(tmp_path)

        edges = [e for e in graph.edges if e.type == EdgeType.HAS_ANNOTATION]
        assert len(edges) == 1

    def test_no_annotations(self, tmp_path):
        src = tmp_path / "clean.c"
        src.write_text("int main() { return 0; }\n")

        ext = AnnotationExtractor()
        graph = ext.extract(tmp_path)

        ann_nodes = [n for n in graph.nodes if n.label == NodeLabel.ANNOTATION]
        assert len(ann_nodes) == 0


# ── Security Labeler Tests ──────────────────────────────────────────────────


class TestSecurityLabeler:
    pytestmark = pytest.mark.security

    def _make_func_graph(self, names: list[str]) -> GraphData:
        graph = GraphData()
        for name in names:
            graph.add_node(f"func:{name}", NodeLabel.FUNCTION, name=name)
        return graph

    def test_input_source_label(self):
        graph = self._make_func_graph(["recv", "read", "getenv", "innocent"])
        labeler = SecurityLabeler()
        count = labeler.label(graph)

        labeled = {
            n.properties["name"]
            for n in graph.nodes
            if n.properties.get("is_input_source")
        }
        assert "recv" in labeled
        assert "read" in labeled
        assert "getenv" in labeled
        assert "innocent" not in labeled

    def test_dangerous_sink_label(self):
        graph = self._make_func_graph(["memcpy", "strcpy", "system", "safe_func"])
        labeler = SecurityLabeler()
        labeler.label(graph)

        labeled = {
            n.properties["name"]
            for n in graph.nodes
            if n.properties.get("is_dangerous_sink")
        }
        assert "memcpy" in labeled
        assert "strcpy" in labeled
        assert "system" in labeled
        assert "safe_func" not in labeled

    def test_allocator_label(self):
        graph = self._make_func_graph(["malloc", "calloc", "free", "printf"])
        labeler = SecurityLabeler()
        labeler.label(graph)

        labeled = {
            n.properties["name"]
            for n in graph.nodes
            if n.properties.get("is_allocator")
        }
        assert "malloc" in labeled
        assert "free" in labeled
        assert "printf" not in labeled

    def test_crypto_label(self):
        graph = self._make_func_graph(["EVP_EncryptInit", "SHA256", "main"])
        labeler = SecurityLabeler()
        labeler.label(graph)

        labeled = {
            n.properties["name"]
            for n in graph.nodes
            if n.properties.get("is_crypto")
        }
        assert "EVP_EncryptInit" in labeled
        assert "SHA256" in labeled
        assert "main" not in labeled

    def test_parser_label(self):
        graph = self._make_func_graph(["JSON.parse", "deserialize", "add"])
        labeler = SecurityLabeler()
        labeler.label(graph)

        labeled = {
            n.properties["name"]
            for n in graph.nodes
            if n.properties.get("is_parser")
        }
        assert "JSON.parse" in labeled
        assert "deserialize" in labeled
        assert "add" not in labeled

    def test_unsafe_pattern(self):
        graph = GraphData()
        graph.add_node(
            "func:unsafe_fn", NodeLabel.FUNCTION,
            name="do_unsafe_cast", params="(void *ptr, size_t len)"
        )
        labeler = SecurityLabeler()
        labeler.label(graph)

        node = graph.nodes[0]
        assert node.properties.get("touches_unsafe") is True


# ── Git Extractor Tests ─────────────────────────────────────────────────────


class TestGitExtractor:
    pytestmark = pytest.mark.core

    def test_no_git_dir(self, tmp_path):
        ext = GitExtractor()
        graph = ext.extract(tmp_path)
        assert graph.node_count == 0

    def test_with_git_repo(self, tmp_path):
        """Integration test with a real git repo."""
        import subprocess

        # Create a git repo
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        subprocess.run(
            ["git", "-C", str(tmp_path), "config", "user.email", "test@test.com"],
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(tmp_path), "config", "user.name", "Test"],
            capture_output=True,
        )

        # Create a file and commit
        (tmp_path / "main.c").write_text("int main() { return 0; }\n")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], capture_output=True)
        subprocess.run(
            ["git", "-C", str(tmp_path), "commit", "-m", "Initial commit"],
            capture_output=True,
        )

        ext = GitExtractor()
        graph = ext.extract(tmp_path)

        # Should have at least 1 commit and 1 author
        commit_nodes = [n for n in graph.nodes if n.label == NodeLabel.COMMIT]
        author_nodes = [n for n in graph.nodes if n.label == NodeLabel.AUTHOR]
        assert len(commit_nodes) >= 1
        assert len(author_nodes) >= 1

    def test_security_commit_detection(self, tmp_path):
        """Test that security-related commits are detected."""
        import subprocess

        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        subprocess.run(
            ["git", "-C", str(tmp_path), "config", "user.email", "test@test.com"],
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(tmp_path), "config", "user.name", "Test"],
            capture_output=True,
        )

        (tmp_path / "vuln.c").write_text("void vuln() {}\n")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], capture_output=True)
        subprocess.run(
            ["git", "-C", str(tmp_path), "commit", "-m", "Fix buffer overflow in parser CVE-2024-1234"],
            capture_output=True,
        )

        ext = GitExtractor()
        graph = ext.extract(tmp_path)

        secfix_nodes = [n for n in graph.nodes if n.label == NodeLabel.SECURITY_FIX]
        assert len(secfix_nodes) >= 1
