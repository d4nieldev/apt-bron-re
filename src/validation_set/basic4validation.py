import json
from pathlib import Path
from datetime import datetime
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'nodes_extraction')))

from basic import (
    process_folder,
    deduplicate_entity_hits,
    compare_differences
)

# === Paths ===
tables_md = Path("data/validation_set/only_tables_from_reports")
reports_md = Path("data/validation_set/md_reports_without_the_tables")
output_tables_dir = Path("data/validation_set/only_tables_from_reports")
output_reports_dir = Path("data/validation_set/md_reports_without_the_tables")
comparisons_dir = Path("data/validation_set/comparisons")

output_tables_dir.mkdir(parents=True, exist_ok=True)
output_reports_dir.mkdir(parents=True, exist_ok=True)
comparisons_dir.mkdir(parents=True, exist_ok=True)

def write_global_summary(json_path: Path, dataset_name: str):
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to read {json_path}: {e}")
        return []

    totals = {}
    for report_data in data.values():
        for category, entries in report_data.items():
            totals[category] = totals.get(category, 0) + len(entries)

    summary_txt = [f"=== {dataset_name} ===\n"]
    for category, count in sorted(totals.items()):
        summary_txt.append(f"{category}: {count}")

    return summary_txt

if __name__ == "__main__":
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    combined_summary_path = comparisons_dir / f"{timestamp}_summary.txt"

    # === Process tables-only reports
    output_tables_json = output_tables_dir / "zzz_all_reports_output.json"
    process_folder(tables_md, "md")  # call your processing
    deduplicate_entity_hits(output_tables_dir)
    tables_summary = write_global_summary(output_tables_json, "Only Tables Reports")

    # === Process full reports (no tables)
    output_reports_json = output_reports_dir / "zzz_all_reports_output.json"
    process_folder(reports_md, "md")
    deduplicate_entity_hits(output_reports_dir)
    reports_summary = write_global_summary(output_reports_json, "Full Reports Without Tables")

    # === Write combined summary
    combined_summary = ["=== Global Summary ===", ""] + tables_summary + [""] + reports_summary
    combined_summary_text = "\n".join(combined_summary)
    combined_summary_path.write_text(combined_summary_text, encoding="utf-8")

    # === Compare differences
    diffs_output_path = comparisons_dir / "differences.json"
    compare_differences(output_tables_json, output_reports_json, diffs_output_path)

    print(f"Combined summary saved to {combined_summary_path}")
    print(f"Differences saved to {diffs_output_path}")
