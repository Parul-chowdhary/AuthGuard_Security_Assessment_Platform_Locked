#!/usr/bin/env python3
"""
AuthGuard Official Line of Code (LOC) Measurement & Verification Utility
========================================================================

Reproducible measurement script and documented counting rules for AuthGuard.
Supports strict mode, threshold checking, baseline comparison, and JSON/human-readable outputs.

Usage:
    python scripts/measure_loc.py --root . --strict --minimum 500000
    python scripts/measure_loc.py --root . --save-baseline baseline_loc.json
    python scripts/measure_loc.py --root . --baseline baseline_loc.json
"""

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Supported source file extensions and language mappings
SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".html": "HTML",
    ".htm": "HTML",
    ".jinja": "Jinja2 Template",
    ".jinja2": "Jinja2 Template",
    ".css": "CSS",
    ".sql": "SQL",
    ".json": "JSON / Config",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown Docs",
}

# Directories to exclude from official project LOC measurement
EXCLUDED_DIR_NAMES = {
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "env",
    ".env",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "coverage",
    "htmlcov",
    ".idea",
    ".vscode",
    ".system_generated",
    ".user_uploaded",
    "scratch",
}

# Excluded file suffixes or exact names
EXCLUDED_PATTERNS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".png",
    ".jpg",
    ".jpeg",
    ".ico",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".log",
}


@dataclass
class FileMetric:
    rel_path: str
    language: str
    raw_lines: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    code_lines: int = 0  # Non-blank, non-comment lines
    nonblank_lines: int = 0  # All non-blank lines (code + comments)
    sha256_hash: str = ""
    is_duplicate: bool = False


@dataclass
class MeasurementSummary:
    root_path: str
    total_files: int = 0
    total_raw_lines: int = 0
    total_blank_lines: int = 0
    total_comment_lines: int = 0
    total_code_lines: int = 0
    total_nonblank_lines: int = 0
    duplicate_files_count: int = 0
    by_language: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_directory: Dict[str, Dict[str, int]] = field(default_factory=dict)
    files: List[FileMetric] = field(default_factory=list)


def is_comment_line(line: str, lang: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if lang in ("Python", "YAML", "TOML"):
        return stripped.startswith("#")
    if lang in ("JavaScript", "CSS"):
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
    if lang in ("HTML", "Jinja2 Template"):
        return stripped.startswith("<!--") or stripped.startswith("{#")
    if lang == "SQL":
        return stripped.startswith("--") or stripped.startswith("/*")
    return False


def compute_file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return ""


def measure_file(path: Path, root: Path) -> Optional[FileMetric]:
    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return None

    lang = SUPPORTED_EXTENSIONS[ext]
    rel_path = str(path.relative_to(root)).replace("\\", "/")

    raw = 0
    blank = 0
    comments = 0
    code = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw += 1
                stripped = line.strip()
                if not stripped:
                    blank += 1
                elif is_comment_line(line, lang):
                    comments += 1
                else:
                    code += 1
    except Exception as e:
        print(f"Warning: Failed reading {rel_path}: {e}", file=sys.stderr)
        return None

    nonblank = comments + code
    file_hash = compute_file_hash(path)

    return FileMetric(
        rel_path=rel_path,
        language=lang,
        raw_lines=raw,
        blank_lines=blank,
        comment_lines=comments,
        code_lines=code,
        nonblank_lines=nonblank,
        sha256_hash=file_hash,
    )


def should_skip_dir(dirname: str) -> bool:
    if dirname in EXCLUDED_DIR_NAMES:
        return True
    if dirname.endswith(".egg-info"):
        return True
    return False


def measure_codebase(root_dir: Path) -> MeasurementSummary:
    summary = MeasurementSummary(root_path=str(root_dir.resolve()))
    seen_hashes: Dict[str, str] = {}

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Filter directories in place
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            metric = measure_file(file_path, root_dir)
            if not metric:
                continue

            # Duplicate check
            if metric.sha256_hash and metric.sha256_hash in seen_hashes:
                metric.is_duplicate = True
                summary.duplicate_files_count += 1
            elif metric.sha256_hash:
                seen_hashes[metric.sha256_hash] = metric.rel_path

            summary.files.append(metric)
            summary.total_files += 1
            summary.total_raw_lines += metric.raw_lines
            summary.total_blank_lines += metric.blank_lines
            summary.total_comment_lines += metric.comment_lines
            summary.total_code_lines += metric.code_lines
            summary.total_nonblank_lines += metric.nonblank_lines

            # By language
            lang = metric.language
            if lang not in summary.by_language:
                summary.by_language[lang] = {
                    "files": 0,
                    "raw": 0,
                    "blank": 0,
                    "comments": 0,
                    "code": 0,
                    "nonblank": 0,
                }
            summary.by_language[lang]["files"] += 1
            summary.by_language[lang]["raw"] += metric.raw_lines
            summary.by_language[lang]["blank"] += metric.blank_lines
            summary.by_language[lang]["comments"] += metric.comment_lines
            summary.by_language[lang]["code"] += metric.code_lines
            summary.by_language[lang]["nonblank"] += metric.nonblank_lines

            # By top-level directory
            parts = Path(metric.rel_path).parts
            top_dir = parts[0] if len(parts) > 1 else "(root)"
            if top_dir not in summary.by_directory:
                summary.by_directory[top_dir] = {
                    "files": 0,
                    "raw": 0,
                    "blank": 0,
                    "comments": 0,
                    "code": 0,
                    "nonblank": 0,
                }
            summary.by_directory[top_dir]["files"] += 1
            summary.by_directory[top_dir]["raw"] += metric.raw_lines
            summary.by_directory[top_dir]["blank"] += metric.blank_lines
            summary.by_directory[top_dir]["comments"] += metric.comment_lines
            summary.by_directory[top_dir]["code"] += metric.code_lines
            summary.by_directory[top_dir]["nonblank"] += metric.nonblank_lines

    return summary


def print_summary(summary: MeasurementSummary, minimum: int = 0) -> None:
    print("\n" + "=" * 78)
    print(" AuthGuard Source Code LOC Measurement Report")
    print("=" * 78)
    print(f" Root Directory:     {summary.root_path}")
    print(f" Total Source Files: {summary.total_files}")
    print(f" Duplicate Files:    {summary.duplicate_files_count}")
    print("-" * 78)
    print(f" Raw Lines:          {summary.total_raw_lines:,}")
    print(f" Blank Lines:        {summary.total_blank_lines:,}")
    print(f" Comment Lines:      {summary.total_comment_lines:,}")
    print(f" Executable/Code:    {summary.total_code_lines:,}")
    print(f" Non-Blank LOC:      {summary.total_nonblank_lines:,}")
    print("=" * 78)

    print("\nBreakdown by Language:")
    print(f"{'Language':<20} {'Files':>8} {'Raw':>10} {'Blank':>10} {'Comments':>10} {'Non-Blank':>12}")
    print("-" * 74)
    for lang, counts in sorted(summary.by_language.items(), key=lambda x: x[1]["nonblank"], reverse=True):
        print(
            f"{lang:<20} {counts['files']:>8} {counts['raw']:>10,} {counts['blank']:>10,} "
            f"{counts['comments']:>10,} {counts['nonblank']:>12,}"
        )

    print("\nBreakdown by Directory:")
    print(f"{'Directory':<20} {'Files':>8} {'Raw':>10} {'Blank':>10} {'Comments':>10} {'Non-Blank':>12}")
    print("-" * 74)
    for dir_name, counts in sorted(summary.by_directory.items(), key=lambda x: x[1]["nonblank"], reverse=True):
        print(
            f"{dir_name:<20} {counts['files']:>8} {counts['raw']:>10,} {counts['blank']:>10,} "
            f"{counts['comments']:>10,} {counts['nonblank']:>12,}"
        )

    if minimum > 0:
        gap = max(0, minimum - summary.total_nonblank_lines)
        pct = (summary.total_nonblank_lines / minimum) * 100 if minimum else 0
        print("\nThreshold Verification:")
        print(f" Target Minimum Non-Blank LOC: {minimum:,}")
        print(f" Actual Non-Blank LOC:         {summary.total_nonblank_lines:,} ({pct:.2f}%)")
        if gap > 0:
            print(f" Status:                       NOT MET (Remaining Gap: {gap:,} LOC)")
        else:
            print(" Status:                       VERIFIED (Threshold Met/Exceeded)")
    print("=" * 78 + "\n")


def compare_with_baseline(current: MeasurementSummary, baseline_path: Path) -> None:
    if not baseline_path.exists():
        print(f"Warning: Baseline file not found at {baseline_path}")
        return

    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            base = json.load(f)
    except Exception as e:
        print(f"Error loading baseline: {e}")
        return

    base_nonblank = base.get("total_nonblank_lines", 0)
    diff = current.total_nonblank_lines - base_nonblank
    sign = "+" if diff >= 0 else ""
    print("\nBaseline Comparison:")
    print(f" Baseline Non-Blank LOC: {base_nonblank:,}")
    print(f" Current Non-Blank LOC:  {current.total_nonblank_lines:,}")
    print(f" Delta:                  {sign}{diff:,} LOC")
    print("-" * 40)


def main():
    parser = argparse.ArgumentParser(description="AuthGuard LOC Measurement Utility")
    parser.add_argument("--root", type=str, default=".", help="Root directory to measure")
    parser.add_argument("--minimum", type=int, default=500000, help="Minimum non-blank LOC threshold")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if threshold not met")
    parser.add_argument("--output-json", type=str, default=None, help="Save summary report to JSON")
    parser.add_argument("--save-baseline", type=str, default=None, help="Save baseline metric to JSON")
    parser.add_argument("--baseline", type=str, default=None, help="Compare against an existing baseline JSON")

    args = parser.parse_args()
    root_dir = Path(args.root).resolve()

    if not root_dir.exists():
        print(f"Error: Directory '{root_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    summary = measure_codebase(root_dir)
    print_summary(summary, minimum=args.minimum)

    if args.baseline:
        compare_with_baseline(summary, Path(args.baseline))

    if args.save_baseline:
        base_path = Path(args.save_baseline)
        base_path.parent.mkdir(parents=True, exist_ok=True)
        with open(base_path, "w", encoding="utf-8") as f:
            json.dump(asdict(summary), f, indent=2)
        print(f"Baseline saved to {base_path}")

    if args.output_json:
        out_path = Path(args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(asdict(summary), f, indent=2)
        print(f"JSON report saved to {out_path}")

    if args.strict and summary.total_nonblank_lines < args.minimum:
        print(
            f"STRICT MODE FAILURE: Non-blank LOC {summary.total_nonblank_lines:,} is below required {args.minimum:,}",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
