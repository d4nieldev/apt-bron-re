import json
from pathlib import Path

# Load both global summaries
v2_path = Path("data/entity_hits_v2/global_summary.json")
v3_path = Path("data/entity_hits_v3/global_summary.json")

with open(v2_path, encoding="utf-8") as f:
    v2_summary = json.load(f)

with open(v3_path, encoding="utf-8") as f:
    v3_summary = json.load(f)

# Aggregate counts for each version
def aggregate_counts(summary_data):
    totals = {}
    for report in summary_data.values():
        for section in ("txt_counts", "md_counts"):
            for label, count in report.get(section, {}).items():
                totals[label] = totals.get(label, 0) + count
    return totals

v2_totals = aggregate_counts(v2_summary)
v3_totals = aggregate_counts(v3_summary)

# Combine into comparison JSON
comparison = {}
all_keys = set(v2_totals) | set(v3_totals)
for key in sorted(all_keys):
    comparison[key] = {
        "v2_total": v2_totals.get(key, 0),
        "v3_total": v3_totals.get(key, 0)
    }

# Save the comparison JSON
comparison_path = Path("data/entity_hits_v3/compare_v2_v3_summary.json")
with open(comparison_path, "w", encoding="utf-8") as f:
    json.dump(comparison, f, indent=2)

comparison_path.name
