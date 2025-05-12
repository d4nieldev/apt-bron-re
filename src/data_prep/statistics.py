from pathlib import Path
from collections import defaultdict
from math import log
import re
import json
from nodes_extraction.constants import TEXT_DIR


def add_bm25_score(base_dir: Path, k1=1.5, b=0.75):
    """
    Adds a BM25-based score to each entity hit in entity_hits_v3,
    scoring: group, tactic, technique, software, capec, cwe.
    """

    print("[*] Calculating BM25 scores...")

    doc_lengths = {}
    freq_map = defaultdict(lambda: defaultdict(int))     # (label → (report, key) → freq)
    doc_freq = defaultdict(lambda: defaultdict(int))     # (label → key → doc_count)

    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue
        text_path = TEXT_DIR / f"{report_dir.name}.txt"
        if not text_path.exists():
            continue
        try:
            tokens = re.findall(r"\b\w+\b", text_path.read_text(encoding="utf-8").lower())
            doc_lengths[report_dir.name] = len(tokens)
            for file_type in ["txt", "md"]:
                json_path = report_dir / f"{file_type}.json"
                if not json_path.exists():
                    continue
                with open(json_path, encoding="utf-8") as f:
                    data = json.load(f)
                for label in ["group", "tactic", "technique", "software", "capec", "cwe", "cpe_versioned"]:
                    for entry in data.get(label, []):
                        key = entry.get("original_id", entry.get("name", "")).lower()
                        freq_map[label][(report_dir.name, key)] += 1
        except Exception as e:
            print(f"[!] Failed to process {report_dir.name}: {e}")

    m = len(doc_lengths)
    avgdl = sum(doc_lengths.values()) / m if m else 1

    for label, entity_freqs in freq_map.items():
        seen_docs = defaultdict(set)
        for (doc_name, key), _ in entity_freqs.items():
            seen_docs[key].add(doc_name)
        for key, docset in seen_docs.items():
            doc_freq[label][key] = len(docset)

    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue
        for file_type in ["txt", "md"]:
            json_path = report_dir / f"{file_type}.json"
            if not json_path.exists():
                continue
            try:
                with open(json_path, encoding="utf-8") as f:
                    data = json.load(f)
                dl = doc_lengths.get(report_dir.name, avgdl)
                for label in ["group", "tactic", "technique", "software", "capec", "cwe", "cpe_versioned"]:
                    for entry in data.get(label, []):
                        key = entry.get("original_id", entry.get("name", "")).lower()
                        f_ij = freq_map[label].get((report_dir.name, key), 0)
                        n = doc_freq[label].get(key, 0)
                        idf = log((m - n + 0.5) / (n + 0.5) + 1)
                        denom = f_ij + k1 * (1 - b + b * (dl / avgdl))
                        entry["bm25_score"] = round(idf * ((f_ij * (k1 + 1)) / denom), 4) if denom else 0
                    if label in data:
                        data[label].sort(key=lambda x: x.get("bm25_score", 0), reverse=True)
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"[!] Failed to update {json_path.name}: {e}")