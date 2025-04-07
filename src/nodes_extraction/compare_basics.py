import json
from pathlib import Path

# === Paths ===
v2_dir = Path("data/entity_hits_v2")
v3_dir = Path("data/entity_hits_v3")
diff_output_path = v3_dir / "differences_by_report.json"

# === Load JSON safely
def load_json_safe(path):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# === Extract unique keys (CVE: value, others: original_id), exclude "technique"
def extract_keys(data, label):
    keys = set()
    if label == "technique":
        return keys  # skip techniques
    entries = data.get(label, [])
    for entry in entries:
        if label == "cve":
            val = entry.get("value", "").upper()
            if val:
                keys.add(val)
        else:
            val = entry.get("original_id", "").upper()
            if val:
                keys.add(val)
    return keys

# === Merge .txt and .md for a given version
def combined_keys(report_dir, label):
    combined = set()
    for file_name in ["txt.json", "md.json"]:
        file_path = report_dir / file_name
        data = load_json_safe(file_path)
        if data and label in data:
            combined.update(extract_keys(data, label))
    return combined

# === Compare per report
differences = {}
report_dirs = set(p.name for p in v2_dir.iterdir() if p.is_dir()) & set(p.name for p in v3_dir.iterdir() if p.is_dir())

for report_name in sorted(report_dirs):
    report_v2 = v2_dir / report_name
    report_v3 = v3_dir / report_name

    all_labels = set()
    for file_name in ["txt.json", "md.json"]:
        v2_data = load_json_safe(report_v2 / file_name) or {}
        v3_data = load_json_safe(report_v3 / file_name) or {}
        all_labels.update(v2_data.keys())
        all_labels.update(v3_data.keys())

    report_diff = {}

    for label in all_labels:
        if label == "technique":
            continue  # skip techniques

        v2_keys = combined_keys(report_v2, label)
        v3_keys = combined_keys(report_v3, label)

        only_in_v2 = sorted(v2_keys - v3_keys)
        only_in_v3 = sorted(v3_keys - v2_keys)

        if only_in_v2 or only_in_v3:
            report_diff[label] = {}
            if only_in_v2:
                report_diff[label]["only_in_v2"] = only_in_v2
            if only_in_v3:
                report_diff[label]["only_in_v3"] = only_in_v3

    if report_diff:
        differences[report_name] = report_diff

# === Save output
diff_output_path.write_text(json.dumps(differences, indent=2), encoding="utf-8")
print(f"[✓] Differences (excluding techniques) written to {diff_output_path}")
