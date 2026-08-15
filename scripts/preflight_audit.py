#!/usr/bin/env python3
"""Privacy-first GitHub publication preflight.

The scanner intentionally reports categories and relative paths, never matched values.
It uses only Python's standard library and Git when a repository is present.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "coverage",
}

SAFE_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "invalid",
    "localhost",
}

TEXT_SIZE_LIMIT = 4 * 1024 * 1024
HISTORY_SCAN_LIMIT = 64 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Audit:
    def __init__(self, repo: Path, release_ready: bool, public: bool, ci_mode: bool) -> None:
        self.repo = repo
        self.release_ready = release_ready
        self.public = public
        self.ci_mode = ci_mode
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str]] = set()
        self.files_scanned = 0
        self.binary_files = 0
        self.skipped_large_files = 0
        self.git_repository = False
        self.manifest_rows: list[str] = []

    def add(self, severity: str, code: str, path: str, message: str) -> None:
        key = (severity, code, path)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(Finding(severity, code, path, message))


def run_git(repo: Path, args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def is_private_email(value: str) -> bool:
    value = value.strip().lower()
    if not value or "@" not in value:
        return False
    local, domain = value.rsplit("@", 1)
    return "noreply" in local or "noreply" in domain or domain in SAFE_EMAIL_DOMAINS


EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,}|localhost)(?![\w.-])", re.I)
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
CN_ID_RE = re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")
WINDOWS_USER_RE = re.compile(r"[A-Za-z]:\\Users\\[^\\\s'\"<>]+", re.I)
UNIX_USER_RE = re.compile(r"/(?:Users|home)/[^/\s'\"<>]+")


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe-live-key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b")),
    (
        "generic-secret-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b"
            r"\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
        ),
    ),
    ("credential-in-url", re.compile(r"https?://[^/\s:@]+:[^/\s@]+@", re.I)),
    (
        "private-key-material",
        re.compile("-" * 5 + r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY" + "-" * 5),
    ),
]

PLACEHOLDER_RE = re.compile(
    r"(?i)(?:example|sample|placeholder|dummy|redacted|changeme|replace[_-]?me|your[_-]?(?:key|token|secret|password)|<[^>]+>)"
)


def safe_rel(path: Path, repo: Path) -> str:
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return "<outside-repository>"


def collect_files(audit: Audit) -> list[Path]:
    repo = audit.repo
    git_probe = run_git(repo, ["rev-parse", "--is-inside-work-tree"])
    audit.git_repository = git_probe.returncode == 0 and git_probe.stdout.strip() == "true"

    if audit.git_repository:
        proc = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            audit.add("BLOCKER", "git-file-list-failed", ".", "Git could not enumerate tracked and untracked publication files.")
            return []
        raw_paths = [item for item in proc.stdout.split(b"\0") if item]
        paths = [repo / os.fsdecode(item) for item in raw_paths]
    else:
        paths = []
        for root, dirs, names in os.walk(repo):
            dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
            paths.extend(Path(root) / name for name in names)

    unique: dict[str, Path] = {}
    for path in paths:
        rel = safe_rel(path, repo)
        if rel == "<outside-repository>" or any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        unique[rel] = path
    return [unique[key] for key in sorted(unique)]


def scan_sensitive_name(audit: Audit, path: Path) -> None:
    rel = safe_rel(path, audit.repo)
    name = path.name.lower()
    suffix = path.suffix.lower()

    safe_env = name in {".env.example", ".env.sample", ".env.template"}
    if (name == ".env" or name.startswith(".env.")) and not safe_env:
        audit.add("BLOCKER", "sensitive-filename", rel, "A live environment file must not be published.")
    if name in {"id_rsa", "id_dsa", "id_ed25519", "credentials.json", "service-account.json"}:
        audit.add("BLOCKER", "sensitive-filename", rel, "A credential or private-key filename is present.")
    if suffix in {".pem", ".p12", ".pfx", ".key", ".keystore", ".jks"}:
        audit.add("BLOCKER", "sensitive-filename", rel, "A key or certificate container requires removal or explicit review.")
    if suffix in {".db", ".sqlite", ".sqlite3", ".bak", ".dump"}:
        audit.add("WARNING", "data-file", rel, "A database or backup file requires explicit data-rights and privacy review.")
    if suffix in {".zip", ".7z", ".rar", ".tar", ".gz", ".bundle"}:
        audit.add("WARNING", "archive-file", rel, "An archive may hide files from normal review; inspect its contents before publication.")


def scan_line(audit: Audit, rel: str, line: str, history: bool = False) -> None:
    source = "reachable Git history" if history else "current file"

    for code, pattern in SECRET_PATTERNS:
        match = pattern.search(line)
        if match and not PLACEHOLDER_RE.search(match.group(0)):
            audit.add("BLOCKER", f"{code}-in-history" if history else code, rel, f"Potential sensitive material exists in {source}; value suppressed.")

    for match in EMAIL_RE.finditer(line):
        address = match.group(0)
        if not is_private_email(address):
            audit.add("BLOCKER", "personal-email-in-history" if history else "personal-email", rel, f"A non-placeholder personal email exists in {source}; value suppressed.")
            break

    if PHONE_RE.search(line):
        audit.add("BLOCKER", "phone-number-in-history" if history else "phone-number", rel, f"A phone-number pattern exists in {source}; value suppressed.")
    if CN_ID_RE.search(line):
        audit.add("BLOCKER", "identity-number-in-history" if history else "identity-number", rel, f"An identity-number pattern exists in {source}; value suppressed.")
    if WINDOWS_USER_RE.search(line) or UNIX_USER_RE.search(line):
        audit.add("BLOCKER", "local-user-path-in-history" if history else "local-user-path", rel, f"A local user path exists in {source}; value suppressed.")


def scan_workflow_and_commands(audit: Audit, rel: str, text: str) -> None:
    normalized = text.replace("\r\n", "\n")
    is_workflow = rel.startswith(".github/workflows/") and Path(rel).suffix.lower() in {".yml", ".yaml"}

    remote_pipe = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:ba|z|k)?sh\b")
    destructive_unix = re.compile(r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+/(?:\s|$)")
    destructive_windows = re.compile(r"(?i)\bformat\s+[A-Za-z]:")
    if remote_pipe.search(normalized):
        audit.add("BLOCKER", "remote-code-pipe", rel, "Remote content is piped directly to a shell.")
    if destructive_unix.search(normalized) or destructive_windows.search(normalized):
        audit.add("BLOCKER", "broad-destructive-command", rel, "A broad destructive command requires removal or tightly scoped redesign.")

    if is_workflow:
        if re.search(r"(?im)^\s*permissions\s*:\s*write-all\s*$", normalized):
            audit.add("BLOCKER", "workflow-write-all", rel, "GitHub Actions grants write-all permission.")
        if re.search(r"(?im)^\s*pull_request_target\s*:", normalized):
            audit.add("WARNING", "pull-request-target", rel, "pull_request_target requires an explicit untrusted-code and secrets review.")
        if re.search(r"(?im)^\s*uses\s*:\s*[^\s#]+@(main|master|latest)\s*(?:#.*)?$", normalized):
            audit.add("WARNING", "mutable-action-ref", rel, "A GitHub Action uses a mutable branch or latest reference.")
        if re.search(r"(?i)\b(?:Invoke-Expression|\biex\s+\()", normalized):
            audit.add("WARNING", "dynamic-command-execution", rel, "Dynamic command execution requires explicit review.")


def scan_file(audit: Audit, path: Path) -> None:
    rel = safe_rel(path, audit.repo)
    scan_sensitive_name(audit, path)

    if path.is_symlink():
        audit.add("BLOCKER", "symlink", rel, "A symbolic link may expose or reference content outside the intended publication tree.")
        return

    try:
        size = path.stat().st_size
    except OSError:
        audit.add("BLOCKER", "unreadable-file", rel, "A publication file could not be read.")
        return

    if size > TEXT_SIZE_LIMIT:
        audit.skipped_large_files += 1
        audit.add("WARNING", "large-file", rel, "A file exceeds the text-scan limit and requires separate review.")
        return

    try:
        data = path.read_bytes()
    except OSError:
        audit.add("BLOCKER", "unreadable-file", rel, "A publication file could not be read.")
        return

    audit.files_scanned += 1
    audit.manifest_rows.append(f"{rel}\0{hashlib.sha256(data).hexdigest()}")

    if b"\0" in data[:8192]:
        audit.binary_files += 1
        return

    text = data.decode("utf-8", errors="replace")
    if path.resolve() != Path(__file__).resolve():
        for line in text.splitlines():
            scan_line(audit, rel, line)
        scan_workflow_and_commands(audit, rel, text)


def scan_git_metadata(audit: Audit) -> None:
    if not audit.git_repository:
        audit.add("WARNING", "not-a-git-repository", ".", "The project has no Git repository; initialize Git before publication.")
        return

    status = run_git(audit.repo, ["status", "--porcelain"])
    if status.returncode != 0:
        audit.add("BLOCKER", "git-status-failed", ".", "Git status could not be read.")
    elif status.stdout.strip():
        severity = "BLOCKER" if audit.release_ready else "WARNING"
        audit.add(severity, "working-tree-not-clean", ".", "The working tree contains uncommitted or untracked publication changes.")

    shallow = run_git(audit.repo, ["rev-parse", "--is-shallow-repository"])
    if shallow.returncode == 0 and shallow.stdout.strip().lower() == "true":
        severity = "BLOCKER" if audit.ci_mode else "WARNING"
        audit.add(severity, "shallow-git-history", ".git", "Reachable history is shallow; a complete publication history scan requires a full clone.")

    config_email = run_git(audit.repo, ["config", "--local", "--get", "user.email"])
    configured = config_email.stdout.strip()
    if not configured:
        if audit.ci_mode:
            audit.add("INFO", "ci-git-email-not-required", ".git/config", "CI does not create release commits, so repository-local Git identity is not required in this checkout.")
        else:
            severity = "BLOCKER" if audit.release_ready else "WARNING"
            audit.add(severity, "missing-private-git-email", ".git/config", "Repository-local Git email is not configured; global identity may leak into a future commit.")
    elif not is_private_email(configured):
        audit.add("BLOCKER", "non-private-git-email", ".git/config", "Repository-local Git email is not privacy-preserving; value suppressed.")

    log_emails = run_git(audit.repo, ["log", "--all", "--format=%ae%n%ce"])
    if log_emails.returncode == 0:
        non_private = [line for line in log_emails.stdout.splitlines() if line.strip() and not is_private_email(line)]
        if non_private:
            audit.add("BLOCKER", "non-private-email-in-commits", ".git", f"Reachable commit metadata contains {len(non_private)} non-private author/committer entries; values suppressed.")
    else:
        audit.add("WARNING", "git-history-unavailable", ".git", "Reachable commit metadata could not be inspected.")

    remotes = run_git(audit.repo, ["remote", "-v"])
    if remotes.returncode != 0 or not remotes.stdout.strip():
        audit.add("WARNING", "missing-remote", ".git/config", "No Git remote is configured.")
    elif re.search(r"https?://[^\s/]+@", remotes.stdout, re.I):
        audit.add("BLOCKER", "credential-in-remote", ".git/config", "A Git remote URL appears to contain credentials; value suppressed.")

    scan_git_history_patch(audit)


def scan_git_history_patch(audit: Audit) -> None:
    command = ["git", "-C", str(audit.repo), "log", "--all", "--no-color", "--format=", "--patch", "--no-ext-diff"]
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        audit.add("WARNING", "history-scan-unavailable", ".git", "Git history content could not be scanned.")
        return

    assert proc.stdout is not None
    scanned = 0
    current = ".git/history"
    for raw in proc.stdout:
        scanned += len(raw)
        if scanned > HISTORY_SCAN_LIMIT:
            proc.kill()
            audit.add("WARNING", "history-scan-truncated", ".git", "History content exceeded the scan limit and requires a dedicated history scanner.")
            break
        line = raw.decode("utf-8", errors="replace")
        if line.startswith("diff --git a/"):
            match = re.match(r"diff --git a/(.+?) b/(.+)\s*$", line)
            if match:
                current = match.group(2)
            continue
        if line.startswith(("+++ ", "--- ")):
            continue
        if line.startswith(("+", "-")):
            scan_line(audit, current, line[1:], history=True)
    if proc.poll() is None:
        proc.wait()


def check_expected_project_files(audit: Audit, rel_paths: set[str]) -> None:
    lower = {item.lower() for item in rel_paths}
    has_readme = any(Path(item).name.startswith("readme") for item in lower)
    has_license = any(Path(item).name.startswith(("license", "licence", "copying")) for item in lower)
    has_security = "security.md" in lower or ".github/security.md" in lower
    has_gitignore = ".gitignore" in lower

    required_severity = "BLOCKER" if audit.release_ready and audit.public else "WARNING"
    if not has_readme:
        audit.add(required_severity, "missing-readme", ".", "A public-ready repository needs a clear README.")
    if not has_license:
        audit.add(required_severity, "missing-license", ".", "A public-ready repository needs an explicit license or rights statement.")
    if not has_security:
        audit.add("WARNING", "missing-security-policy", ".", "A public repository should provide a SECURITY.md reporting policy.")
    if not has_gitignore:
        audit.add("WARNING", "missing-gitignore", ".", "A .gitignore should exclude credentials, local state, databases, and generated artifacts.")

    if ".gitignore" in lower:
        gitignore = audit.repo / ".gitignore"
        try:
            text = gitignore.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            text = ""
        for label, candidates in {
            "environment files": [".env"],
            "private keys": ["*.key", "*.pem"],
            "local databases": ["*.db", "*.sqlite"],
        }.items():
            if not any(item in text for item in candidates):
                audit.add("WARNING", "gitignore-coverage", ".gitignore", f".gitignore does not explicitly cover {label}.")


def build_result(audit: Audit) -> dict[str, object]:
    findings = sorted(audit.findings, key=lambda f: ({"BLOCKER": 0, "WARNING": 1, "INFO": 2}.get(f.severity, 3), f.code, f.path))
    blockers = sum(item.severity == "BLOCKER" for item in findings)
    warnings = sum(item.severity == "WARNING" for item in findings)
    manifest = "\n".join(sorted(audit.manifest_rows)).encode("utf-8")
    head = None
    branch = None
    if audit.git_repository:
        head_proc = run_git(audit.repo, ["rev-parse", "HEAD"])
        branch_proc = run_git(audit.repo, ["branch", "--show-current"])
        head = head_proc.stdout.strip() or None
        branch = branch_proc.stdout.strip() or None
    return {
        "status": "pass" if blockers == 0 else "fail",
        "repository_label": audit.repo.name,
        "release_ready_mode": audit.release_ready,
        "public_target": audit.public,
        "ci_mode": audit.ci_mode,
        "git_repository": audit.git_repository,
        "branch": branch,
        "head": head,
        "files_scanned": audit.files_scanned,
        "binary_files": audit.binary_files,
        "large_files_needing_review": audit.skipped_large_files,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "blockers": blockers,
        "warnings": warnings,
        "findings": [asdict(item) for item in findings],
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit a project before publishing it to GitHub without echoing sensitive values.")
    parser.add_argument("--repo", default=".", help="Project directory to audit (default: current directory).")
    parser.add_argument("--release-ready", action="store_true", help="Treat a dirty tree or missing private Git identity as a blocker.")
    parser.add_argument("--public", action="store_true", help="Apply public-repository documentation and license gates.")
    parser.add_argument("--ci", action="store_true", help="Apply CI-specific gates, including a full-history requirement, without requiring commit identity in the checkout.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        print(json.dumps({"status": "fail", "error": "repository path is not a directory"}))
        return 2
    if shutil.which("git") is None:
        print(json.dumps({"status": "fail", "error": "git executable is required for history and metadata checks"}))
        return 2

    audit = Audit(repo, release_ready=args.release_ready, public=args.public, ci_mode=args.ci)
    paths = collect_files(audit)
    for path in paths:
        scan_file(audit, path)
    check_expected_project_files(audit, {safe_rel(path, repo) for path in paths})
    scan_git_metadata(audit)
    result = build_result(audit)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"GitHub publication preflight: {str(result['status']).upper()}")
        print(f"Files scanned: {result['files_scanned']} | Blockers: {result['blockers']} | Warnings: {result['warnings']}")
        for item in result["findings"]:
            print(f"[{item['severity']}] {item['code']} — {item['path']}: {item['message']}")
        print(f"Manifest SHA-256: {result['manifest_sha256']}")
        print("Sensitive matched values are intentionally suppressed.")

    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
