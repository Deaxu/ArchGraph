"""Configuration constants and settings for ArchGraph."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# Supported languages and their tree-sitter module names
LANGUAGE_MODULES: dict[str, str] = {
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "rust": "tree_sitter_rust",
    "java": "tree_sitter_java",
    "go": "tree_sitter_go",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "python": "tree_sitter_python",
    # Optional (extras)
    "kotlin": "tree_sitter_kotlin",
    "swift": "tree_sitter_swift",
    "objc": "tree_sitter_objc",
}

# File extensions to language mapping
EXTENSION_MAP: dict[str, str] = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".hh": "cpp",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".go": "go",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".pyi": "python",
    ".m": "objc",
    ".mm": "objc",
}

# Security-related function patterns
INPUT_SOURCES = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets",
    "scanf", "fscanf", "sscanf", "getenv", "getline", "getdelim",
    "accept", "listen", "WSARecv", "ReadFile",
    # Rust
    "read_to_string", "read_to_end", "stdin",
    # Go
    "ReadAll", "ReadFull", "Copy",
    # Java
    "getInputStream", "getParameter", "getHeader", "readLine",
    # JS/TS
    "fetch", "XMLHttpRequest", "addEventListener",
})

DANGEROUS_SINKS = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "system", "popen", "exec", "execve", "execvp", "execl",
    "eval", "dlopen", "dlsym", "LoadLibrary",
    "fprintf", "printf",
    # SQL
    "sqlite3_exec", "mysql_query", "PQexec",
    # Rust
    "from_raw_parts", "transmute",
    # Go
    "Exec", "Command",
    # Java
    "Runtime.exec", "ProcessBuilder",
    # JS
    "eval", "Function", "innerHTML", "outerHTML", "document.write",
})

ALLOCATORS = frozenset({
    "malloc", "calloc", "realloc", "free", "alloca",
    "new", "delete", "mmap", "munmap", "VirtualAlloc", "VirtualFree",
    "HeapAlloc", "HeapFree",
    # Rust
    "alloc", "dealloc", "Box::new", "Vec::with_capacity",
    # Go
    "make", "append",
    # Java
    "ByteBuffer.allocate", "ByteBuffer.allocateDirect",
})

CRYPTO_FUNCTIONS = frozenset({
    "encrypt", "decrypt", "hash", "sign", "verify",
    "HMAC", "hmac", "EVP_EncryptInit", "EVP_DecryptInit",
    "EVP_DigestInit", "EVP_SignInit", "EVP_VerifyInit",
    "AES_encrypt", "AES_decrypt", "RSA_sign", "RSA_verify",
    "SHA256", "SHA512", "MD5", "SHA1",
    # Rust
    "Aes128", "Aes256", "Sha256", "Sha512",
    # Go
    "cipher.NewGCM", "hmac.New", "sha256.New",
})

PARSER_FUNCTIONS = frozenset({
    "parse", "decode", "deserialize", "unmarshal",
    "from_json", "from_xml", "from_yaml", "from_bytes",
    "JSON.parse", "json.loads", "json.Unmarshal",
    "protobuf", "flatbuffers",
    "xml_parse", "xmlParseMemory", "htmlParseDoc",
})

# Annotation patterns to scan for
ANNOTATION_PATTERNS: dict[str, str] = {
    "TODO": r"\bTODO\b",
    "HACK": r"\bHACK\b",
    "UNSAFE": r"\bUNSAFE\b|unsafe\s*\{",
    "FIXME": r"\bFIXME\b",
    "BUG": r"\bBUG\b",
    "XXX": r"\bXXX\b",
    "SECURITY": r"\bSECURITY\b",
    "VULNERABILITY": r"\bVULNERABILITY\b|\bVULN\b",
}

# Git security-related commit message patterns
SECURITY_COMMIT_PATTERNS = [
    r"(?i)\bCVE-\d{4}-\d+\b",
    r"(?i)\bsecurity\s+fix\b",
    r"(?i)\bfix\b.*\b(vuln|overflow|injection|xss|csrf|rce|dos)\b",
    r"(?i)\bbuffer\s+overflow\b",
    r"(?i)\buse[- ]after[- ]free\b",
    r"(?i)\bheap[- ]overflow\b",
    r"(?i)\binteger[- ]overflow\b",
    r"(?i)\bout[- ]of[- ]bounds\b",
    r"(?i)\bnull[- ]pointer\b",
    r"(?i)\bremote\s+code\s+execution\b",
    r"(?i)\bprivilege\s+escalation\b",
    r"(?i)\binformation\s+(leak|disclosure)\b",
]

# Directories to skip during scanning
SKIP_DIRS = frozenset({
    ".git", ".archgraph", "node_modules", "__pycache__", ".tox", ".venv", "venv",
    "vendor", "third_party", "3rdparty", "external", "deps",
    "build", "dist", "out", "target", "cmake-build-debug",
    "cmake-build-release", ".idea", ".vscode",
})

# Files to skip
SKIP_FILES = frozenset({
    "package-lock.json", "yarn.lock", "Cargo.lock", "go.sum",
    "poetry.lock", "Gemfile.lock", "composer.lock",
})

# Neo4j batch sizes
NEO4J_BATCH_SIZE = 20000

# OSV API settings
OSV_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_TIMEOUT = 30  # seconds

# Map dependency source file → OSV ecosystem name
SOURCE_TO_OSV_ECOSYSTEM: dict[str, str] = {
    "Cargo.toml": "crates.io",
    "package.json": "npm",
    "go.mod": "Go",
    "gradle": "Maven",
    "Podfile": "CocoaPods",
    "conanfile.txt": "ConanCenter",
    "Package.swift": "SwiftURL",
}


@dataclass
class ExtractConfig:
    """Configuration for a single extraction run."""

    repo_path: Path
    languages: list[str] = field(
        default_factory=lambda: [
            "c", "cpp", "rust", "java", "go",
            "javascript", "typescript", "python",
        ]
    )
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "archgraph"
    neo4j_database: str = "neo4j"
    include_git: bool = True
    include_deps: bool = True
    include_annotations: bool = True
    include_security_labels: bool = True
    max_file_size: int = 1_000_000  # 1MB
    git_max_commits: int = 10_000
    include_clang: bool = True  # graceful skip if libclang not installed
    clang_compile_commands: Path | None = None
    clang_extra_args: list[str] = field(default_factory=list)
    include_deep: bool = True
    workers: int = 0  # 0=auto (min(cpu_count, 8)), 1=sequential
    include_cve: bool = False
    osv_batch_size: int = 1000
    incremental: bool = False
    include_clustering: bool = False
    include_process: bool = False
    include_skills: bool = False
    include_scip: bool = True  # Run SCIP compiler-backed call resolution
    include_body: bool = True  # Store source code in graph nodes
    max_body_size: int = 51_200  # 50KB max per node, truncate beyond
