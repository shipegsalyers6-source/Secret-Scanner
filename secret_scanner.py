import argparse
import logging
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger("SecretScanner")

SECRET_PATTERNS = {
    "Google API key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "GitHub classic token": r"\bghp_[0-9A-Za-z]{36}\b",
    "GitHub fine-grained token": r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
    "Stripe secret key": r"\bsk_(?:live|test)_[0-9A-Za-z]{24,99}\b",
    "Slack bot token": (
        r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-"
        r"[0-9A-Za-z]{24,34}\b"
    ),
    "JWT token": (
        r"\bey[A-Za-z0-9_-]{10,}\."
        r"ey[A-Za-z0-9/_-]{10,}\."
        r"[A-Za-z0-9/_-]{10,}\b"
    ),
    "Private key header": (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
        r"PRIVATE KEY-----"
    ),
    "Generic password assignment": (
        r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*"""
        r"""["']?([^\s"'#;,]{4,})"""
    ),
    "Generic API key or token assignment": (
        r"""(?i)\b(?:api[_-]?key|access[_-]?token|"""
        r"""auth[_-]?token|secret[_-]?key)\s*[:=]\s*"""
        r"""["']?([A-Za-z0-9_./+=-]{8,})"""
    ),
}


def scan_file(file_path):
    """Scan a text file and return potential secret findings."""
    findings = []

    try:
        with file_path.open(
            "r", encoding="utf-8", errors="replace"
        ) as file:
            for line_number, line in enumerate(file, start=1):
                for secret_type, pattern in SECRET_PATTERNS.items():
                    for match in re.finditer(pattern, line):
                        matched_text = (
                            match.group(1)
                            if match.lastindex
                            else match.group(0)
                        )

                        findings.append({
                            "filename": str(file_path),
                            "line": line_number,
                            "type": secret_type,
                            "match": matched_text,
                        })

    except (OSError, UnicodeError) as error:
        logger.warning("Could not read %s: %s", file_path, error)

    return findings


def collect_files(input_path):
    """Return supported file paths from a file or directory."""
    if input_path.is_file():
        return [input_path]

    if input_path.is_dir():
        ignored_dirs = {
            ".git", ".venv", "venv", "__pycache__",
            "node_modules"
        }

        return sorted(
            path
            for path in input_path.rglob("*")
            if path.is_file()
            and not any(part in ignored_dirs for part in path.parts)
        )

    raise FileNotFoundError(
        f"Input path does not exist: {input_path}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan files or directories for possible hardcoded secrets."
        )
    )
    parser.add_argument(
        "path",
        help="Path to a file or directory to scan"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show debug logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    input_path = Path(args.path)

    try:
        files = collect_files(input_path)
    except (OSError, FileNotFoundError) as error:
        logger.error("%s", error)
        return 2

    logger.info("Scanning %d file(s)...", len(files))

    findings = []
    for file_path in files:
        logger.debug("Scanning %s", file_path)
        findings.extend(scan_file(file_path))

    if findings:
        print("\nPotential secrets found:")
        print("-" * 80)

        for finding in findings:
            print(
                f"File: {finding['filename']}\n"
                f"Line: {finding['line']}\n"
                f"Type: {finding['type']}\n"
                f"Match: {finding['match']}\n"
                f"{'-' * 80}"
            )

        print(f"Total findings: {len(findings)}")
        return 1

    print("No potential secrets found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
