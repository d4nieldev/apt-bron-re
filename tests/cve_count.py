import re
from pathlib import Path

# === Paths ===
base_dir = Path("data/converted_reports")
text_dir = base_dir / "texts"
md_dir = base_dir / "markdown"

# === CVE Pattern ===
cve_pattern = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)

# === Counters ===
txt_total = 0
md_total = 0

# === Scan TXT files ===
for file in text_dir.glob("*.txt"):
    try:
        content = file.read_text(encoding="utf-8")
        matches = set(cve_pattern.findall(content))  # unique per file
        txt_total += len(matches)
    except Exception as e:
        print(f"[!] Failed to read {file.name}: {e}")

# === Scan MD files ===
for file in md_dir.glob("*.md"):
    try:
        content = file.read_text(encoding="utf-8")
        matches = set(cve_pattern.findall(content))  # unique per file
        md_total += len(matches)
    except Exception as e:
        print(f"[!] Failed to read {file.name}: {e}")

# === Print results ===
print("\n=== CVE PER-REPORT COUNTS (UNIQUE IN EACH REPORT) ===")
print(f"[TXT] Total CVEs across all TXT reports: {txt_total}")
print(f"[MD ] Total CVEs across all MD reports: {md_total}")
