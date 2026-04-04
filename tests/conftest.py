"""Shared pytest fixtures for ArchGraph tests."""

import textwrap
from pathlib import Path

import pytest

from archgraph.extractors.treesitter import TreeSitterExtractor


@pytest.fixture
def tmp_c_project(tmp_path: Path) -> Path:
    """Create a C project with src/ subdirectory, multiple functions, header with macros.

    Contains:
        src/main.c  — three functions: parse_data, process_input, validate
        src/util.h  — include guard, macros, function declaration
    """
    src = tmp_path / "src"
    src.mkdir()

    (src / "main.c").write_text(textwrap.dedent("""\
        #include <stdio.h>
        #include <string.h>
        #include "util.h"

        struct ParseResult {
            int status;
            char message[256];
        };

        int parse_data(const char *input, int len) {
            if (len <= 0) return -1;
            struct ParseResult result;
            result.status = 0;
            strncpy(result.message, input, sizeof(result.message) - 1);
            return result.status;
        }

        char *process_input(char *buf, size_t size) {
            if (buf == NULL) return NULL;
            memcpy(buf, "processed", size < 10 ? size : 10);
            return buf;
        }

        int validate(int value) {
            if (value < MIN_VAL) return 0;
            if (value > MAX_VAL) return 0;
            return 1;
        }

        int main(int argc, char *argv[]) {
            const char *data = "test";
            int result = parse_data(data, strlen(data));
            char buf[64];
            process_input(buf, sizeof(buf));
            return validate(result);
        }
    """))

    (src / "util.h").write_text(textwrap.dedent("""\
        #ifndef UTIL_H
        #define UTIL_H

        #define MAX_VAL 1000
        #define MIN_VAL 0

        void do_something(void);
        int helper_func(int x);

        #endif /* UTIL_H */
    """))

    return tmp_path


@pytest.fixture
def tmp_rust_project(tmp_path: Path) -> Path:
    """Create a Rust project with src/ subdirectory, pub fn, structs, impl blocks.

    Contains:
        src/lib.rs — struct Config, impl Config, pub fn parse_input, private helper
    """
    src = tmp_path / "src"
    src.mkdir()

    (src / "lib.rs").write_text(textwrap.dedent("""\
        use std::collections::HashMap;

        pub struct Config {
            pub name: String,
            pub values: HashMap<String, i32>,
        }

        impl Config {
            pub fn new(name: &str) -> Self {
                Config {
                    name: name.to_string(),
                    values: HashMap::new(),
                }
            }

            pub fn get(&self, key: &str) -> Option<&i32> {
                self.values.get(key)
            }

            pub fn set(&mut self, key: String, value: i32) {
                self.values.insert(key, value);
            }
        }

        pub fn parse_input(input: &str) -> Result<Config, String> {
            if input.is_empty() {
                return Err("empty input".to_string());
            }
            Ok(Config::new(input))
        }

        fn internal_helper(x: i32) -> i32 {
            x * 2 + 1
        }

        pub fn process(config: &Config) -> Vec<String> {
            config.values.keys().cloned().collect()
        }
    """))

    return tmp_path


@pytest.fixture
def tmp_multi_lang_project(tmp_path: Path) -> Path:
    """Create a multi-language project with C, TypeScript, and Python files in subdirectories.

    Contains:
        src/main.c     — C function calling helpers
        src/utils.ts   — TypeScript function exports
        src/helper.py  — Python class and function definitions
    """
    src = tmp_path / "src"
    src.mkdir()

    (src / "main.c").write_text(textwrap.dedent("""\
        #include <stdio.h>

        int compute(int x, int y) {
            return x + y;
        }

        void display(const char *msg) {
            printf("%s\\n", msg);
        }

        int main(void) {
            int result = compute(3, 4);
            display("done");
            return result;
        }
    """))

    (src / "utils.ts").write_text(textwrap.dedent("""\
        export interface Config {
            name: string;
            value: number;
        }

        export function createConfig(name: string): Config {
            return { name, value: 0 };
        }

        export function processConfig(config: Config): string {
            return `${config.name}: ${config.value}`;
        }

        function internalHelper(): void {
            console.log("helper");
        }
    """))

    (src / "helper.py").write_text(textwrap.dedent("""\
        class DataProcessor:
            def __init__(self, name: str) -> None:
                self.name = name
                self.data: list[int] = []

            def add(self, value: int) -> None:
                self.data.append(value)

            def total(self) -> int:
                return sum(self.data)

        def transform(items: list[str]) -> list[str]:
            return [item.upper() for item in items]

        def validate(value: int) -> bool:
            return 0 <= value <= 1000
    """))

    return tmp_path


@pytest.fixture
def treesitter_extractor() -> TreeSitterExtractor:
    """Return a fresh TreeSitterExtractor instance."""
    return TreeSitterExtractor()
