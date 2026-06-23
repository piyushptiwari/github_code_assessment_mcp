"""Deterministic repository file-selection engine.

Decides which files are in scope for static analysis, which are kept only for
dependency (SCA) parsing, and which are skipped with an explicit reason. The
output drives an honest coverage ledger and is pushed down into each scanner so
they do less work and use less memory on large or noisy repositories.

Approach (matches current market practice in Semgrep, ripgrep, osv-scanner):
- Prefer ``git ls-files`` so .gitignore'd content is excluded for free.
- Layer a default-exclude list (seeded from Semgrep's default.semgrepignore) for
  junk that gets committed anyway (node_modules, vendor, dist, min.js, ...).
- Skip binary files (null-byte heuristic + known binary extensions).
- Skip files above a size cap (Semgrep's default is 1 MB).
- Keep dependency lockfiles/manifests for SCA even though they are not SAST source.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

from .config import (
    EXCLUDE_DIRS,
    MAX_FILE_KB,
    RESPECT_GITIGNORE,
)

# Directories that are version-control metadata. Always skipped.
VCS_DIRS = {".git", ".svn", ".hg", "_darcs", "cvs"}

# Binary / asset extensions that are never useful for SAST. Lowercase, no dot.
BINARY_EXTS = {
    # images
    "png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "ico", "webp", "svg", "psd", "ai", "eps",
    # audio / video
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "mp4", "mov", "avi", "mkv", "webm", "wmv", "flv",
    # fonts
    "ttf", "otf", "woff", "woff2", "eot",
    # archives
    "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "jar", "war", "ear", "apk", "deb", "rpm", "dmg", "iso",
    # compiled / objects
    "pyc", "pyo", "class", "o", "obj", "so", "a", "dll", "dylib", "exe", "bin", "wasm", "node",
    # documents / data blobs
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "db", "sqlite", "sqlite3", "mo",
    # ml / model artifacts
    "pt", "pth", "onnx", "h5", "pb", "tflite", "pkl", "npy", "npz", "parquet",
}

# Generated / minified assets: present as text but not human-authored source.
GENERATED_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".map", "-lock.json")

# Dependency manifests / lockfiles. Skipped for SAST, kept for SCA.
LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "poetry.lock", "pipfile.lock", "requirements.txt", "pipfile", "setup.py", "setup.cfg", "pyproject.toml",
    "go.sum", "go.mod", "cargo.lock", "cargo.toml", "composer.lock", "composer.json",
    "gemfile.lock", "gemfile", "packages.lock.json", "gradle.lockfile", "pom.xml",
}

# Recognized source-code extensions, mapped to a language label for reporting.
LANGUAGE_EXTS = {
    "py": "python", "pyi": "python",
    "js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "typescript", "tsx": "typescript",
    "java": "java", "kt": "kotlin", "kts": "kotlin", "scala": "scala", "groovy": "groovy",
    "go": "go", "rs": "rust", "rb": "ruby", "php": "php", "phtml": "php",
    "c": "c", "h": "c", "cc": "cpp", "cpp": "cpp", "cxx": "cpp", "hpp": "cpp", "hh": "cpp",
    "cs": "csharp", "swift": "swift", "m": "objective-c", "mm": "objective-c",
    "sh": "shell", "bash": "shell", "zsh": "shell", "ps1": "powershell",
    "tf": "terraform", "hcl": "hcl",
    "yaml": "yaml", "yml": "yaml", "json": "json", "toml": "toml",
    "tpl": "template", "j2": "template", "jinja": "template", "jinja2": "template",
    "html": "html", "htm": "html", "vue": "vue", "svelte": "svelte",
    "sql": "sql", "dockerfile": "dockerfile", "ex": "elixir", "exs": "elixir", "dart": "dart",
    "pl": "perl", "pm": "perl", "lua": "lua", "r": "r",
}

# Special filenames (no extension) that are still source/config worth scanning.
SOURCE_FILENAMES = {"dockerfile", "makefile", "jenkinsfile", "vagrantfile", "rakefile"}


@dataclass
class Selection:
    """Result of categorizing every discovered file in a repository."""

    total_discovered: int = 0
    in_scope_sast: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    languages: dict[str, int] = field(default_factory=dict)
    exclude_dirs: list[str] = field(default_factory=list)
    used_git: bool = False

    @property
    def in_scope(self) -> int:
        return len(self.in_scope_sast)

    @property
    def skipped_total(self) -> int:
        return sum(self.skipped.values())

    def add_skip(self, category: str) -> None:
        self.skipped[category] = self.skipped.get(category, 0) + 1


def _ext_of(name: str) -> str:
    base = name.lower()
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[1]


def _git_tracked(workdir: str) -> set[str] | None:
    """Return the set of git-tracked repo-relative paths, or None if not a git repo."""
    try:
        completed = subprocess.run(
            ["git", "-C", workdir, "ls-files", "-z"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception:  # noqa: BLE001
        return None
    if completed.returncode != 0:
        return None
    entries = [item for item in completed.stdout.split("\0") if item]
    return {entry.replace("\\", "/") for entry in entries}


def _is_binary(path: str) -> bool:
    """Null-byte heuristic, the same signal git uses to classify binary files."""
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(8000)
    except OSError:
        return True
    return b"\0" in chunk


def _in_excluded_dir(rel_path: str) -> bool:
    parts = {part.lower() for part in rel_path.split("/")[:-1]}
    if parts & VCS_DIRS:
        return True
    return bool(parts & EXCLUDE_DIRS)


def select_files(workdir: str) -> Selection:
    """Walk the repository and categorize every file for scanning."""
    selection = Selection()
    max_bytes = MAX_FILE_KB * 1024

    tracked = _git_tracked(workdir) if RESPECT_GITIGNORE else None
    selection.used_git = tracked is not None

    for directory, subdirectories, files in os.walk(workdir):
        # Prune VCS and excluded directories in-place so os.walk does not descend.
        subdirectories[:] = [
            sub for sub in subdirectories
            if sub.lower() not in VCS_DIRS and sub.lower() not in EXCLUDE_DIRS
        ]
        for filename in files:
            absolute = os.path.join(directory, filename)
            rel_path = os.path.relpath(absolute, workdir).replace("\\", "/")
            selection.total_discovered += 1

            if _in_excluded_dir(rel_path):
                selection.add_skip("excluded_dir")
                continue
            if tracked is not None and rel_path not in tracked:
                selection.add_skip("gitignored_untracked")
                continue

            lowered = filename.lower()
            extension = _ext_of(filename)

            if lowered in LOCKFILE_NAMES:
                selection.lockfiles.append(rel_path)
                selection.add_skip("lockfile_sast")
                continue
            if extension in BINARY_EXTS:
                selection.add_skip("binary")
                continue
            if any(lowered.endswith(suffix) for suffix in GENERATED_SUFFIXES):
                selection.add_skip("generated_minified")
                continue

            try:
                size = os.path.getsize(absolute)
            except OSError:
                selection.add_skip("unreadable")
                continue
            if size > max_bytes:
                selection.add_skip("too_large")
                continue

            language = LANGUAGE_EXTS.get(extension) or (LANGUAGE_EXTS.get(lowered) if lowered in SOURCE_FILENAMES else None)
            if language is None:
                # Unknown extension: skip, but confirm it is not an undetected binary.
                if _is_binary(absolute):
                    selection.add_skip("binary")
                else:
                    selection.add_skip("unsupported_language")
                continue
            if _is_binary(absolute):
                selection.add_skip("binary")
                continue

            selection.in_scope_sast.append(rel_path)
            selection.languages[language] = selection.languages.get(language, 0) + 1

    selection.exclude_dirs = sorted(EXCLUDE_DIRS | VCS_DIRS)
    return selection
