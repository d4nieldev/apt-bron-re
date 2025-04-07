import json
import re
from pathlib import Path
from collections import defaultdict
from statistics import mean
from rank_bm25 import BM25Okapi
from difflib import get_close_matches
import shutil

# === Clear previous output
def clear_output_folder(path: Path):
    if path.exists() and path.is_dir():
        shutil.rmtree(path)
        print(f"[*] Cleared existing folder: {path}")


# === Paths ===
text_dir = Path("data/converted_reports/texts")
layer_file = Path("data/layers_nodes/tactic.json")
output_path = Path("data/statistical_combined_entity_scores")
clear_output_folder(output_path)
output_path.mkdir(parents=True, exist_ok=True)

# === Load tactic layer
with open(layer_file, encoding="utf-8") as f:
    tactic_nodes = json.load(f)

tactic_names = [node["name"].lower() for node in tactic_nodes]

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

def validate_against_graph(candidate_name: str, tactic_list: list[str], cutoff=0.75):
    match = get_close_matches(candidate_name.lower(), tactic_list, n=1, cutoff=cutoff)
    return match[0] if match else None

def extract_entities_bm25(text: str, tactic_list: list[str]):
    sentences = [s.strip() for s in re.split(r'[.!?]', text) if s.strip()]
    bm25 = BM25Okapi([t.split() for t in tactic_list])
    entity_hits = defaultdict(int)

    for sentence in sentences:
        scores = bm25.get_scores(sentence.split())
        best_idx = scores.argmax()
        if scores[best_idx] > 2:
            best_match = tactic_list[best_idx]
            entity_hits[best_match.lower()] += 1

    return dict(entity_hits)

# === Combined Extraction Function

def count_tactic_mentions_combined():
    doc_entity_counts = defaultdict(lambda: defaultdict(int))
    doc_lengths = {}  # store document word counts

    for txt_file in text_dir.glob("*.txt"):
        doc_name = txt_file.stem
        text = read_file(txt_file)
        total_words = len(text.split())
        doc_lengths[doc_name] = total_words

        for node in tactic_nodes:
            name = node["name"].lower()

            # Name Matching
            for variant in normalize_name(name):
                count = text.count(variant)
                if count > 0:
                    doc_entity_counts[doc_name][name] += count

            # Pattern Matching
            for pattern in node.get("patterns", []):
                try:
                    matches = re.findall(pattern.lower(), text)
                    if matches:
                        doc_entity_counts[doc_name][name] += len(matches)
                except re.error:
                    continue

        # BM25 Matching + Graph Validation
        bm25_hits = extract_entities_bm25(text, tactic_names)
        for candidate, score in bm25_hits.items():
            validated = validate_against_graph(candidate, tactic_names)
            if validated:
                doc_entity_counts[doc_name][validated] += score

    return doc_entity_counts, doc_lengths

# === Score Computation with Normalization

def compute_significance_scores(doc_entity_counts, doc_lengths):
    all_docs = list(doc_entity_counts.keys())
    results = defaultdict(dict)

    for doc in all_docs:
        current_doc_data = doc_entity_counts[doc]
        total_words = doc_lengths[doc]

        for tactic_name, count_in_doc in current_doc_data.items():
            freq_in_doc = count_in_doc / total_words if total_words else 0

            others = [
                (doc_entity_counts[other].get(tactic_name, 0) / doc_lengths[other])
                for other in all_docs if other != doc and doc_lengths[other] > 0
            ]

            if not others:
                continue

            avg_freq = mean(others)
            score = freq_in_doc / avg_freq if avg_freq else float('inf')

            results[doc][tactic_name] = {
                "count_in_doc": count_in_doc,
                "doc_length": total_words,
                "normalized_freq": round(freq_in_doc, 4),
                "avg_normalized_freq": round(avg_freq, 4),
                "score": round(score, 2)
            }

    return results

# === Run Everything
if __name__ == "__main__":
    print("[*] Extracting tactic mentions using keywords, patterns, BM25, and validation...")
    counts, lengths = count_tactic_mentions_combined()

    print("[*] Computing significance scores with normalization by doc length...")
    scores = compute_significance_scores(counts, lengths)

    print("[*] Saving results...")
    for doc_name, tactic_data in scores.items():
        with open(output_path / f"{doc_name}_tactic_stats.json", "w", encoding="utf-8") as f:
            json.dump(tactic_data, f, indent=2)





    print("[✓] All done.")
