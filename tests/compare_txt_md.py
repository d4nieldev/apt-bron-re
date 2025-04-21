import json
from pathlib import Path

# === Paths ===
base_dir = Path(__file__).resolve().parents[1]
entity_hits_dir = base_dir / "data" / "entity_hits_v2"  # Each subfolder = report name

# === Get all report folders
report_dirs = [p for p in entity_hits_dir.iterdir() if p.is_dir()]


def load_json_safe(path):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def compare_json(a, b, path=""):
    diffs = []

    if type(a) != type(b):
        diffs.append(f"{path}: Type mismatch ({type(a).__name__} vs {type(b).__name__})")
        return diffs

    if isinstance(a, dict):
        all_keys = set(a.keys()) | set(b.keys())
        for key in all_keys:
            new_path = f"{path}.{key}" if path else key
            if key not in a:
                diffs.append(f"{new_path}: Only in md JSON")
            elif key not in b:
                diffs.append(f"{new_path}: Only in txt JSON")
            else:
                diffs.extend(compare_json(a[key], b[key], new_path))
    elif isinstance(a, list):
        len_a = len(a)
        len_b = len(b)
        if len_a != len_b:
            diffs.append(f"{path}: List length mismatch ({len_a} vs {len_b})")
        for i in range(min(len_a, len_b)):
            new_path = f"{path}[{i}]"
            diffs.extend(compare_json(a[i], b[i], new_path))
    else:
        if a != b:
            diffs.append(f"{path}: Value mismatch ('{a}' vs '{b}')")

    return diffs


# === Main loop
for report_dir in report_dirs:
    name = report_dir.name
    txt_json = report_dir / "txt.json"
    md_json = report_dir / "md.json"

    txt_data = load_json_safe(txt_json)
    md_data = load_json_safe(md_json)

    if not txt_data or not md_data:
        continue

    differences = compare_json(txt_data, md_data)

    if differences:
        print(f"\n[↔] Differences found in {name}:")
        for diff in differences:
            print(f"  - {diff}")
