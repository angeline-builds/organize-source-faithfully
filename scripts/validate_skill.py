from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "organize-source-faithfully"
SKILL_DIR = ROOT / "skills" / SKILL_NAME
SKILL_MD = SKILL_DIR / "SKILL.md"
OPENAI_YAML = SKILL_DIR / "agents" / "openai.yaml"
REFERENCE_PATHS = {
    SKILL_DIR / "references" / "coverage-and-output-schema.md",
    SKILL_DIR / "references" / "safety-and-integrity-checklist.md",
}

REQUIRED_PATHS = {
    ROOT / ".gitattributes",
    ROOT / ".github" / "workflows" / "validate.yml",
    ROOT / ".gitignore",
    ROOT / "LICENSE",
    ROOT / "README.md",
    ROOT / "README.zh-CN.md",
    ROOT / "SECURITY.md",
    ROOT / "scripts" / "hash_manifest.py",
    ROOT / "scripts" / "preflight_audit.py",
    ROOT / "scripts" / "validate_skill.py",
    SKILL_MD,
    OPENAI_YAML,
    *REFERENCE_PATHS,
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", text, re.DOTALL)
    if not match:
        fail("SKILL.md must start with YAML frontmatter")
    result: dict[str, str] = {}
    for raw_line in match.group(1).splitlines():
        if not raw_line.strip():
            continue
        if ":" not in raw_line:
            fail(f"invalid frontmatter line: {raw_line}")
        key, value = raw_line.split(":", 1)
        result[key.strip()] = value.strip().strip("\"'")
    return result


def validate_structure() -> None:
    missing = sorted(str(path.relative_to(ROOT)) for path in REQUIRED_PATHS if not path.is_file())
    if missing:
        fail("missing required paths:\n- " + "\n- ".join(missing))

    skill_text = SKILL_MD.read_text(encoding="utf-8")
    frontmatter = parse_frontmatter(skill_text)
    if set(frontmatter) != {"name", "description"}:
        fail("frontmatter must contain only name and description")
    if frontmatter["name"] != SKILL_NAME:
        fail("frontmatter name must match the skill folder")
    if not frontmatter["description"]:
        fail("frontmatter description must not be empty")
    if len(skill_text.splitlines()) > 500:
        fail("SKILL.md must stay under 500 lines")
    if re.search(r"TODO|\[TODO|Structuring This Skill|�", skill_text):
        fail("SKILL.md contains draft or encoding residue")

    interface_text = OPENAI_YAML.read_text(encoding="utf-8")
    short_match = re.search(r'^\s*short_description:\s*"([^"]+)"\s*$', interface_text, re.MULTILINE)
    if not short_match or not 25 <= len(short_match.group(1)) <= 64:
        fail("short_description must be quoted and contain 25-64 characters")
    if f"${SKILL_NAME}" not in interface_text:
        fail("default_prompt must mention the skill invocation")

    readme_en = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_zh = (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")
    if "README.zh-CN.md" not in readme_en or "README.md" not in readme_zh:
        fail("README language links are incomplete")


SECRET_PATTERNS = {
    "email address": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "OpenAI-style secret": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "personal Windows path": re.compile(r"C:\\Users\\[^\\\s]+", re.IGNORECASE),
    "personal Unix path": re.compile(r"/(?:Users|home)/[^/\s]+", re.IGNORECASE),
}


def validate_sensitive_content() -> None:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: {label}")
    if findings:
        fail("potential sensitive content found:\n- " + "\n- ".join(findings))


def main() -> None:
    validate_structure()
    validate_sensitive_content()
    print("Organize Source Faithfully structure and sensitive-content checks passed.")


if __name__ == "__main__":
    main()
