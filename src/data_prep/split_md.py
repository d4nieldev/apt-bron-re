
from pathlib import Path

# Set up paths
REPO_ROOT = Path(__file__).resolve().parents[2]
MD_DIR = REPO_ROOT / "data" / "converted_reports" / "markdown"
SPLIT_REPORTS_DIR = REPO_ROOT / "data" / "split_reports"
SPLIT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

for md_file in MD_DIR.glob("*.md"):
    report_name = md_file.stem
    report_split_dir = SPLIT_REPORTS_DIR / report_name
    report_split_dir.mkdir(parents=True, exist_ok=True)

    # Read the markdown file
    lines = md_file.read_text(encoding="utf-8").splitlines(keepends=True)

    sections = []
    current_section = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Check if it's a heading (## ...)
        if line.strip().startswith("## "):
            # If current_section not empty, save it
            if current_section:
                sections.append("".join(current_section).strip())
                current_section = []

            # Merge consecutive headings, ignoring blank lines
            while i < len(lines) and (lines[i].strip() == "" or lines[i].strip().startswith("## ")):
                if lines[i].strip().startswith("## "):
                    current_section.append(lines[i])
                i += 1

            # Add all lines until next heading
            while i < len(lines) and not lines[i].strip().startswith("## "):
                current_section.append(lines[i])
                i += 1
        else:
            current_section.append(line)
            i += 1

    # Save last section
    if current_section:
        sections.append("".join(current_section).strip())

    # Write each section to a separate file
    for idx, section in enumerate(sections):
        section_file = report_split_dir / f"section_{idx + 1}.md"
        section_file.write_text(section, encoding="utf-8")

print(f"[✓] Finished splitting markdown files (including consecutive titles separated by blank lines) and saved in {SPLIT_REPORTS_DIR}")
