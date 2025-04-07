import json
import re
from pathlib import Path
from collections import defaultdict
from statistics import mean

# === Paths ===
text_dir = Path("data/converted_reports/texts")
layer_file = Path("data/layers_nodes/tactic.json")
output_path = Path("data/statistical_entity_scores")
output_path.mkdir(parents=True, exist_ok=True)

# === Load only "tactic" layer
if not layer_file.exists():
    raise FileNotFoundError(f"[!] Could not find: {layer_file}")

with open(layer_file, encoding="utf-8") as f:
    tactic_nodes = json.load(f)

# === File reader
def read_file(file_path: Path):
    try:
        return file_path.read_text(encoding="utf-8").lower()
    except Exception as e:
        print(f"[!] Failed to read {file_path.name}: {e}")
        return ""

# === Normalize entity names
def normalize_name(name: str) -> list:
    base = name.lower()
    variants = {base, base.replace("-", " "), base.replace(" ", ""), base.replace(" ", "-")}
    if base.endswith("s"):
        singular = base[:-1]
        variants.update({
            singular,
            singular.replace("-", " "),
            singular.replace(" ", ""),
            singular.replace(" ", "-")
        })
    return list(variants)


# # ======== option 1 - without patterns ========

# === Count occurrences of tactic names in each doc
def count_tactic_mentions():
    doc_entity_counts = defaultdict(lambda: defaultdict(int))  # doc -> tactic_name -> count

    for txt_file in text_dir.glob("*.txt"):
        doc_name = txt_file.stem
        text = read_file(txt_file)

        for node in tactic_nodes:
            name = node.get("name", "").lower()
            for variant in normalize_name(name):
                count = text.count(variant)
                if count > 0:
                    doc_entity_counts[doc_name][name] += count

    return doc_entity_counts

# # ======== option 2 - with patterns ========

# # === Count occurrences of tactic names and patterns in each doc
# def count_tactic_mentions():
#     doc_entity_counts = defaultdict(lambda: defaultdict(int))  # doc -> tactic_name -> count
#
#     for txt_file in text_dir.glob("*.txt"):
#         doc_name = txt_file.stem
#         text = read_file(txt_file)
#
#         for node in tactic_nodes:
#             name = node.get("name", "").lower()
#
#             # Match by name variants
#             for variant in normalize_name(name):
#                 count = text.count(variant)
#                 if count > 0:
#                     doc_entity_counts[doc_name][name] += count
#
#             # Match by regex patterns (if present)
#             for pattern in node.get("patterns", []):
#                 try:
#                     matches = re.findall(pattern.lower(), text)
#                     if matches:
#                         doc_entity_counts[doc_name][name] += len(matches)
#                 except re.error as e:
#                     print(f"[!] Invalid regex for tactic '{name}': {pattern} – {e}")
#
#     return doc_entity_counts

# === Compute score vs. other docs
def compute_significance_scores(doc_entity_counts):
    all_docs = list(doc_entity_counts.keys())
    results = defaultdict(dict)

    for doc in all_docs:
        current_doc_data = doc_entity_counts[doc]
        for tactic_name, count_in_doc in current_doc_data.items():
            # Count of this tactic in other docs
            others = [
                doc_entity_counts[other].get(tactic_name, 0)
                for other in all_docs if other != doc
            ]
            if not others:
                continue
            avg_in_others = mean(others)
            score = count_in_doc / avg_in_others if avg_in_others else float('inf')
            results[doc][tactic_name] = {
                "count_in_doc": count_in_doc,
                "avg_in_others": round(avg_in_others, 2),
                "score": round(score, 2)
            }

    return results

# === Main
if __name__ == "__main__":
    print("[*] Counting tactic mentions...")
    counts = count_tactic_mentions()

    print("[*] Computing statistical scores...")
    scores = compute_significance_scores(counts)

    print("[*] Writing results...")
    for doc_name, tactic_data in scores.items():
        with open(output_path / f"{doc_name}_tactic_stats.json", "w", encoding="utf-8") as f:
            json.dump(tactic_data, f, indent=2)

    print("[✓] All tactic statistics computed and saved.")
