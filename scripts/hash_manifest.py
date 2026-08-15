#!/usr/bin/env python3
"""Create and verify deterministic SHA-256 evidence for Git trees and release files.

The tool hashes raw bytes, never prints file contents, and stores only repository-
relative paths or a release file's base name. Exit codes: 0 pass, 1 mismatch,
2 invalid input or an unavailable Git object.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = 1
ALGORITHM = "sha256"


class ManifestError(RuntimeError):
    """A safe, user-facing manifest error that contains no file contents."""


def run_git(repo: Path, args: list[str]) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ManifestError("Git is unavailable.") from exc
    if proc.returncode != 0:
        raise ManifestError("Git could not resolve or read the requested object.")
    return proc.stdout


def resolve_commit(repo: Path, ref: str) -> str:
    value = run_git(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"]).decode("ascii", errors="strict").strip()
    if len(value) != 40 or any(character not in "0123456789abcdefABCDEF" for character in value):
        raise ManifestError("Git returned an invalid commit identifier.")
    return value.lower()


def canonical_tree_digest(files: list[dict[str, object]]) -> str:
    encoded = json.dumps(files, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_tree_manifest(repo: Path, ref: str) -> dict[str, object]:
    if not repo.is_dir():
        raise ManifestError("Repository path is not a directory.")
    commit_sha = resolve_commit(repo, ref)
    tree_output = run_git(repo, ["ls-tree", "-r", "-z", "--full-tree", commit_sha])
    files: list[dict[str, object]] = []

    for record in (item for item in tree_output.split(b"\0") if item):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            _mode, object_type, object_id = metadata.split(b" ", 2)
        except ValueError as exc:
            raise ManifestError("Git returned an invalid tree record.") from exc
        if object_type != b"blob":
            continue
        data = run_git(repo, ["cat-file", "blob", object_id.decode("ascii")])
        path = raw_path.decode("utf-8", errors="surrogateescape")
        files.append({"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    files.sort(key=lambda item: str(item["path"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "git-tree",
        "algorithm": ALGORITHM,
        "repository_label": repo.name,
        "commit_sha": commit_sha,
        "file_count": len(files),
        "files": files,
        "tree_manifest_sha256": canonical_tree_digest(files),
    }


def build_artifact_manifest(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ManifestError("Artifact path is not a file.")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ManifestError("Artifact could not be read.") from exc
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "artifact",
        "algorithm": ALGORITHM,
        "filename": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def load_manifest(path: Path, expected_kind: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("Manifest could not be read as UTF-8 JSON.") from exc
    if not isinstance(value, dict):
        raise ManifestError("Manifest root must be a JSON object.")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != expected_kind or value.get("algorithm") != ALGORITHM:
        raise ManifestError("Manifest schema, kind, or algorithm is unsupported.")
    return value


def write_or_print(manifest: dict[str, object], output: str | None) -> None:
    rendered = json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if output:
        destination = Path(output).expanduser().resolve()
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(rendered, encoding="utf-8", newline="\n")
        except OSError as exc:
            raise ManifestError("Manifest output could not be written.") from exc
        print(json.dumps({"status": "created", "kind": manifest["kind"], "output_label": destination.name}, sort_keys=True))
    else:
        print(rendered, end="")


def compare_tree(actual: dict[str, object], expected: dict[str, object]) -> dict[str, object]:
    expected_files = expected.get("files")
    expected_count = expected.get("file_count")
    expected_digest = expected.get("tree_manifest_sha256")
    if not isinstance(expected_files, list) or expected_count != len(expected_files) or not isinstance(expected_digest, str):
        raise ManifestError("Git-tree manifest fields are invalid.")

    expected_by_path = {
        item.get("path"): item
        for item in expected_files
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    if len(expected_by_path) != len(expected_files):
        raise ManifestError("Git-tree manifest contains invalid or duplicate paths.")
    actual_files = actual["files"]
    assert isinstance(actual_files, list)
    actual_by_path = {item["path"]: item for item in actual_files}

    missing = sorted(set(expected_by_path) - set(actual_by_path))
    extra = sorted(set(actual_by_path) - set(expected_by_path))
    changed = sorted(
        path
        for path in set(expected_by_path) & set(actual_by_path)
        if expected_by_path[path].get("size") != actual_by_path[path].get("size")
        or expected_by_path[path].get("sha256") != actual_by_path[path].get("sha256")
    )
    commit_match = expected.get("commit_sha") == actual.get("commit_sha")
    digest_match = expected_digest == actual.get("tree_manifest_sha256")
    passed = commit_match and digest_match and not missing and not extra and not changed
    return {
        "status": "pass" if passed else "fail",
        "kind": "git-tree-verification",
        "commit_match": commit_match,
        "tree_manifest_match": digest_match,
        "expected_file_count": len(expected_files),
        "actual_file_count": len(actual_files),
        "missing_paths": missing,
        "extra_paths": extra,
        "changed_paths": changed,
    }


def compare_artifact(path: Path, expected: dict[str, object]) -> dict[str, object]:
    if not isinstance(expected.get("size"), int) or not isinstance(expected.get("sha256"), str):
        raise ManifestError("Artifact manifest fields are invalid.")
    actual = build_artifact_manifest(path)
    size_match = actual["size"] == expected["size"]
    hash_match = actual["sha256"] == expected["sha256"]
    passed = size_match and hash_match
    return {
        "status": "pass" if passed else "fail",
        "kind": "artifact-verification",
        "filename_match": actual["filename"] == expected.get("filename"),
        "size_match": size_match,
        "sha256_match": hash_match,
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create or verify SHA-256 manifests without printing file contents.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    tree = subparsers.add_parser("git-tree", help="Create a manifest from raw blobs in an exact Git commit.")
    tree.add_argument("--repo", default=".")
    tree.add_argument("--ref", required=True)
    tree.add_argument("--output")

    verify_tree = subparsers.add_parser("verify-tree", help="Verify an exact Git commit against a saved manifest.")
    verify_tree.add_argument("--repo", default=".")
    verify_tree.add_argument("--ref", required=True)
    verify_tree.add_argument("--manifest", required=True)

    artifact = subparsers.add_parser("artifact", help="Create a manifest for one release file.")
    artifact.add_argument("--file", required=True)
    artifact.add_argument("--output")

    verify_artifact = subparsers.add_parser("verify-artifact", help="Verify one downloaded release file.")
    verify_artifact.add_argument("--file", required=True)
    verify_artifact.add_argument("--manifest", required=True)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "git-tree":
            manifest = build_tree_manifest(Path(args.repo).expanduser().resolve(), args.ref)
            write_or_print(manifest, args.output)
            return 0
        if args.command == "verify-tree":
            expected = load_manifest(Path(args.manifest).expanduser().resolve(), "git-tree")
            actual = build_tree_manifest(Path(args.repo).expanduser().resolve(), args.ref)
            result = compare_tree(actual, expected)
        elif args.command == "artifact":
            manifest = build_artifact_manifest(Path(args.file).expanduser().resolve())
            write_or_print(manifest, args.output)
            return 0
        else:
            expected = load_manifest(Path(args.manifest).expanduser().resolve(), "artifact")
            result = compare_artifact(Path(args.file).expanduser().resolve(), expected)
    except ManifestError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
