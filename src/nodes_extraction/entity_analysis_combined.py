# This script analyzes text reports to detect MITRE tactics, techniques, and groups
# using multiple matching strategies — exact keywords, regex patterns, and semantic similarity (BM25) —
# and computes a normalized significance score for each entity based on document length and comparison to other documents.

import json
import re
from pathlib import Path
from collections import defaultdict
from statistics import mean
from rank_bm25 import BM25Okapi
from difflib import get_close_matches
import shutil

# === Clear previous output (optional — uncomment if you want to start clean every run)
# def clear_output_folder(path: Path):
#     if path.exists() and path.is_dir():
#         shutil.rmtree(path)
#         print(f"[*] Cleared existing folder: {path}")

# === Paths ===
text_dir = Path("../data/texts")
layer_dir = Path("../layers_nodes")
included_layers = ["tactic", "technique", "group"]
layer_map = {}

for label in included_layers:
    file_path = layer_dir / f"{label}.json"
    if file_path.exists():
        with open(file_path, encoding="utf-8") as f:
            layer_map[label] = json.load(f)
    else:
        print(f"[!] Missing layer file: {file_path}")

output_path = Path("../data/statistical_combined_entity_scores")
output_path.mkdir(parents=True, exist_ok=True)

# === Helpers
def read_file(file_path: Path):
    try:
        return file_path.read_text(encoding="utf-8").lower()
    except Exception as e:
        print(f"[!] Failed to read {file_path.name}: {e}")
        return ""

def normalize_name(name: str):
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

def validate_against_graph(candidate_name: str, entity_list: list[str], cutoff=0.75):
    match = get_close_matches(candidate_name.lower(), entity_list, n=1, cutoff=cutoff)
    return match[0] if match else None

def extract_entities_bm25(text: str, entity_list: list[str]):
    sentences = [s.strip() for s in re.split(r'[.!?]', text) if s.strip()]
    bm25 = BM25Okapi([t.split() for t in entity_list])
    entity_hits = defaultdict(int)

    for sentence in sentences:
        scores = bm25.get_scores(sentence.split())
        best_idx = scores.argmax()
        if scores[best_idx] > 2:
            best_match = entity_list[best_idx]
            entity_hits[best_match.lower()] += 1

    return dict(entity_hits)

# === Combined Extraction Function

def count_entity_mentions_combined():
    doc_entity_counts = defaultdict(lambda: defaultdict(int))
    doc_lengths = {}  # store document word counts

    # Create a flattened list of all entity names for BM25
    all_entity_names = []
    entity_lookup = {}
    for label, nodes in layer_map.items():
        for node in nodes:
            name = node["name"].lower()
            all_entity_names.append(name)
            entity_lookup[name] = label  # for reverse lookup

    for txt_file in text_dir.glob("*.txt"):
        doc_name = txt_file.stem
        text = read_file(txt_file)
        total_words = len(text.split())
        doc_lengths[doc_name] = total_words

        for label, nodes in layer_map.items():
            for node in nodes:
                name = node["name"].lower()

                # Name Matching
                for variant in normalize_name(name):
                    count = text.count(variant)
                    if count > 0:
                        doc_entity_counts[doc_name][f"{label}:{name}"] += count

                # Pattern Matching
                for pattern in node.get("patterns", []):
                    try:
                        matches = re.findall(pattern.lower(), text)
                        if matches:
                            doc_entity_counts[doc_name][f"{label}:{name}"] += len(matches)
                    except re.error:
                        continue

        # BM25 Matching + Graph Validation
        bm25_hits = extract_entities_bm25(text, all_entity_names)
        for candidate, score in bm25_hits.items():
            validated = validate_against_graph(candidate, all_entity_names)
            if validated:
                label = entity_lookup.get(validated, "unknown")
                doc_entity_counts[doc_name][f"{label}:{validated}"] += score

    return doc_entity_counts, doc_lengths

# === Score Computation with Normalization

def compute_significance_scores(doc_entity_counts, doc_lengths):
    all_docs = list(doc_entity_counts.keys())
    results = defaultdict(dict)

    for doc in all_docs:
        current_doc_data = doc_entity_counts[doc]
        total_words = doc_lengths[doc]

        for entity_name, count_in_doc in current_doc_data.items():
            freq_in_doc = count_in_doc / total_words if total_words else 0

            others = [
                (doc_entity_counts[other].get(entity_name, 0) / doc_lengths[other])
                for other in all_docs if other != doc and doc_lengths[other] > 0
            ]

            if not others:
                continue

            avg_freq = mean(others)
            score = freq_in_doc / avg_freq if avg_freq else float('inf')

            results[doc][entity_name] = {
                "count_in_doc": count_in_doc,
                "doc_length": total_words,
                "normalized_freq": round(freq_in_doc, 4),
                "avg_normalized_freq": round(avg_freq, 4),
                "score": round(score, 2)
            }

    return results

# === Run Everything
if __name__ == "__main__":
    print("[*] Extracting tactic, technique, and group mentions using keywords, patterns, BM25, and validation...")
    counts, lengths = count_entity_mentions_combined()

    print("[*] Computing significance scores with normalization by doc length...")
    scores = compute_significance_scores(counts, lengths)

    print("[*] Saving results...")
    for doc_name, entity_data in scores.items():
        with open(output_path / f"{doc_name}_entity_stats.json", "w", encoding="utf-8") as f:
            json.dump(entity_data, f, indent=2)

    print("[✓] All done.")
