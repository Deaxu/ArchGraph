"""Tests for code body extraction feature."""

import textwrap
from pathlib import Path

import pytest

from archgraph.config import ExtractConfig


class TestBodyConfig:
    """Test include_body and max_body_size config fields."""

    def test_include_body_default_true(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"))
        assert config.include_body is True

    def test_max_body_size_default(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"))
        assert config.max_body_size == 51_200

    def test_include_body_override(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"), include_body=False)
        assert config.include_body is False

    def test_max_body_size_override(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"), max_body_size=10_000)
        assert config.max_body_size == 10_000
