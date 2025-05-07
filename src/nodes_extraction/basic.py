import re
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
import ahocorasick
from datetime import datetime
import matplotlib.pyplot as plt

# paths
text_dir = Path("data/converted_reports/texts")
md_dir = Path("data/converted_reports/markdown")
layer_dir = Path("data/layers_nodes")
output_dir = Path("data/entity_hits_v3")
output_dir.mkdir(parents=True, exist_ok=True)

""" create a dictionary with keys as layer type (group, tactic, etc.) 
and values as lists of the relevant entities """
layer_map = {}
for layer_file in layer_dir.glob("*.json"):
    label = layer_file.stem
    with open(layer_file, encoding="utf-8") as f:
        layer_map[label] = json.load(f)


def generate_variants(text):
    """
    generates simple variants, to enable entities (names or ids) to appear
    in more manners
    """
    base = text.lower()
    variants = {
        base,
        base.replace("-", " "),
        base.replace(" ", ""),
        base.replace(" ", "-")
    }

    plural_forms = set()
    for v in variants:
        if not v.endswith("s"):
            plural_forms.add(v + "s")
            plural_forms.add(v + "'s")

    return variants.union(plural_forms)


""" building automatas, one for each layer type (besides CVE and CPE) to be later
 used by the aho-corasick algorithm """
automata_map = {}

""" variant_to_node acts as a lookup dictionary, matching variant strings to the full node objects
    "technique": {
        "t1059": { "name": "Command and Scripting Interpreter", "original_id": "T1059" },
        "powershell": { "name": "PowerShell", "original_id": "T1059.001" },
    } """
variant_to_node = {}
technique_id_to_node = {}
technique_id_pattern = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.IGNORECASE)

for label, nodes in layer_map.items():
    A = ahocorasick.Automaton()
    node_map = {}

    for node in nodes:
        if label == "technique":  # adds only the names of the techniques, not ids, to the automaton
            for variant in generate_variants(node["name"]):
                if variant not in node_map:
                    node_map[variant] = node
                    A.add_word(variant, variant)
            technique_id_to_node[node["original_id"].lower()] = node
        else:
            name_variants = generate_variants(node["name"])
            id_variants = generate_variants(node["original_id"])
            for variant in name_variants.union(id_variants):
                if variant not in node_map:
                    node_map[variant] = node
                    A.add_word(variant, variant)

    A.make_automaton()
    automata_map[label] = A
    variant_to_node[label] = node_map

# regex patterns for CVE and CPE
cve_pattern = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)
cpe_pattern = re.compile(r"\bcpe:(?:2\.3:|/)[aoh]:[^\s:]+:[^\s:]+(?::[^\s:]*){0,10}", re.IGNORECASE)


def match_variants(text, category, automaton):
    """
    uses the automaton built on category (node type),
    to match the entities in the text (converted report)
    also saving the index of where it was found in the text
    """
    text_lower = text.lower()
    found = set()
    results = []

    for end_idx, variant_str in automaton.iter(text_lower):
        start_idx = end_idx - len(variant_str) + 1
        before = text_lower[start_idx - 1] if start_idx > 0 else " "
        after = text_lower[end_idx + 1] if end_idx + 1 < len(text_lower) else " "
        if not before.isalnum() and not after.isalnum():
            if variant_str not in found:
                found.add(variant_str)
                node = variant_to_node[category][variant_str]
                hit = {
                    "name": node["name"],
                    "original_id": node["original_id"],
                    "index": start_idx
                }
                if category == "software" and "software_type" in node:
                    hit["software_type"] = node["software_type"]
                results.append(hit)
    return results


def match_technique_ids(text):
    """
    Uses regex to find technique IDs (T#### or T####.###)
    and maps them to their node objects.
    """
    results = []
    for match in technique_id_pattern.finditer(text):
        tid = match.group().lower()
        if tid in technique_id_to_node:
            node_found = technique_id_to_node[tid]
            results.append({
                "name": node_found["name"],
                "original_id": node_found["original_id"],
                "index": match.start()
            })
    return results


# CVE and CPE matching
def match_cve(text):
    """
    finds matches using regex on the structure of cves
    and returns the nodes in uppercase (how it appears in BRON, e.g. CVE-2007-4240)
    """
    return [
        {"value": m.group().upper(), "index": m.start()}
        for m in cve_pattern.finditer(text.lower())
    ]


def match_cpe(text):
    """
    finds matches using regex on the structure of cpe
    and returns the nodes in lowercase (how it appears in BRON, e.g. cpe:2.3:a:bmc:patrol_agent)
    """
    return [
        {"value": m.group().lower(), "index": m.start()}
        for m in cpe_pattern.finditer(text.lower())
    ]


def process_folder(folder, suffix):
    """
    runs the automata and regex matches on the folders of converted reports,
    stores the entity hits in data/entity_hits_v3
    """
    for file in folder.glob(f"*.{suffix}"):
        base_name = file.stem
        report_dir = output_dir / base_name
        report_dir.mkdir(parents=True, exist_ok=True)
        try:
            text = file.read_text(encoding="utf-8")
            results = {}

            for layer_type, automaton in automata_map.items():
                if layer_type == "technique":
                    name_hits = match_variants(text, layer_type, automaton)
                    id_hits = match_technique_ids(text)
                    combined = {json.dumps(hit, sort_keys=True): hit for hit in name_hits + id_hits}
                    if combined:
                        results["technique"] = list(combined.values())
                else:
                    hits = match_variants(text, layer_type, automaton)
                    if hits:
                        results[layer_type] = hits

            cves = match_cve(text)
            cpes = match_cpe(text)
            if cves:
                results["cve"] = cves
            if cpes:
                results["cpe"] = cpes

            out_path = report_dir / f"{suffix}.json"
            out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"Failed to process {file.name}: {e}")


def deduplicate_entity_hits(base_dir_path: str):
    """
    removes duplicate nodes that were extracted,
    from the output files created by process_folder
    """
    base_dir = Path(base_dir_path)
    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue

        for file_name in ["txt.json", "md.json"]:
            file_path = report_dir / file_name
            if not file_path.exists():
                continue

            try:
                with open(file_path, encoding="utf-8") as output_file:
                    data = json.load(output_file)
            except Exception as e:
                print(f"Failed to read {file_path}: {e}")
                continue

            deduped = {}
            for category, entries in data.items():
                seen = set()
                deduped[category] = []
                for entry in entries:
                    key = json.dumps(entry, sort_keys=True)
                    if key not in seen:
                        seen.add(key)
                        deduped[category].append(entry)

            with open(file_path, "w", encoding="utf-8") as output_f:
                json.dump(deduped, output_f, indent=2)


def write_summary_counts(report_dir: Path):
    """
    compares between the outputs originating from both types of filetypes to which the report was converted,
    inserts the summary of that comparison into summary_counts.json, on the same report_dir (dir named after the report)
    """
    summary = {}
    for json_file in ["txt.json", "md.json"]:
        path = report_dir / json_file
        if path.exists():
            with open(path, encoding="utf-8") as j_file:
                data = json.load(j_file)
            summary_key = "txt_counts" if "txt" in json_file else "md_counts"
            summary[summary_key] = {category: len(entries) for category, entries in data.items()}
    if summary:
        with open(report_dir / "summary_counts.json", "w", encoding="utf-8") as sum_file:
            json.dump(summary, sum_file, indent=2)
    return summary


def add_context_sentences_to_hits():
    """
    For each entity in txt.json/md.json files in entity_hits_v3,
    adds a 'sentence' field that shows up to n words before/after
    the match (or bounded by periods).
    """
    n = 15
    for report_dir in output_dir.iterdir():
        if not report_dir.is_dir():
            continue

        for suffix in ["txt", "md"]:
            json_path = report_dir / f"{suffix}.json"
            source_path = (text_dir if suffix == "txt" else md_dir) / f"{report_dir.name}.{suffix}"
            if not json_path.exists() or not source_path.exists():
                continue

            try:
                text = source_path.read_text(encoding="utf-8")
                with open(json_path, encoding="utf-8") as output_file:
                    data = json.load(output_file)

                for category, entries in data.items():
                    for entry in entries:
                        idx = entry.get("index")
                        if idx is None:
                            continue

                        before = text[:idx]
                        after = text[idx:]

                        before_words = re.findall(r"\b\w+\b", before)
                        before_limit = max(0, len(before_words) - n)
                        before_snippet = " ".join(before_words[before_limit:])

                        if "." in before_snippet:
                            before_snippet = before_snippet.split(".")[-1].strip()

                        after_words = re.findall(r"\b\w+\b", after)
                        after_limit = min(n, len(after_words))
                        after_snippet = " ".join(after_words[:after_limit])

                        if "." in after_snippet:
                            after_snippet = after_snippet.split(".")[0].strip()

                        entry["sentence"] = f"{before_snippet} {after_snippet}".strip()

                with open(json_path, "w", encoding="utf-8") as out_file:
                    json.dump(data, out_file, indent=2)

            except Exception as e:
                print(f"Failed to add sentence to {json_path.name}: {e}")


def write_summary_for_entity_hits_v3(base_dir: Path):
    """
    writes a timestamped global summary of the nodes extraction, to compare with previous attempts
    to be inserted to entity_hits_v3/summaries, and also a summary/comparison between the number of entities
    in the reports, stored in entity_hits_v3/global_summary.json
    """
    global_summary = {}
    for report_dir in base_dir.iterdir():
        if report_dir.is_dir():
            summary = write_summary_counts(report_dir)
            if summary:
                global_summary[report_dir.name] = summary

    summary_dir = base_dir / "summaries"
    summary_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    summary_txt = ["=== Total Entity Counts Across All Reports ===\n"]
    txt_totals = {}
    md_totals = {}

    for report in global_summary.values():
        for category, count in report.get("txt_counts", {}).items():
            txt_totals[category] = txt_totals.get(category, 0) + count
        for category, count in report.get("md_counts", {}).items():
            md_totals[category] = md_totals.get(category, 0) + count

    summary_txt.append("[TXT]")
    for category, count in sorted(txt_totals.items()):
        summary_txt.append(f"{category}: {count}")
    summary_txt.append("\n[MD]")
    for category, count in sorted(md_totals.items()):
        summary_txt.append(f"{category}: {count}")

    summary_path = summary_dir / f"{timestamp}_summary.txt"
    summary_path.write_text("\n".join(summary_txt), encoding="utf-8")

    global_summary_path = base_dir / "global_summary.json"
    with open(global_summary_path, "w", encoding="utf-8") as global_file:
        json.dump(global_summary, global_file, indent=2)


def compare_differences(tables_json_path: Path, reports_json_path: Path, output_comparison_path: Path):
    """
    Compares entities between tables-only and full-reports, finding nodes
    that exist only in one of them (by original_id, regardless of name/index).
    Saves the differences to output_comparison_path as JSON.
    """
    try:
        with open(tables_json_path, encoding="utf-8") as f:
            tables_data = json.load(f)
        with open(reports_json_path, encoding="utf-8") as f:
            reports_data = json.load(f)
    except Exception as e:
        print(f"Failed to load input JSONs: {e}")
        return

    comparison = {}
    all_report_names = set(tables_data.keys()).union(reports_data.keys())

    for report_name in all_report_names:
        tables_report = tables_data.get(report_name, {})
        reports_report = reports_data.get(report_name, {})

        only_table = {}
        only_report = {}

        all_categories = set(tables_report.keys()).union(reports_report.keys())

        for category in all_categories:
            tables_nodes = tables_report.get(category, [])
            reports_nodes = reports_report.get(category, [])

            tables_ids = {entry.get("original_id", entry.get("value", "")).lower() for entry in tables_nodes}
            reports_ids = {entry.get("original_id", entry.get("value", "")).lower() for entry in reports_nodes}

            table_extras = tables_ids - reports_ids
            report_extras = reports_ids - tables_ids

            if table_extras:
                only_table[category] = sorted(list(table_extras))
            if report_extras:
                only_report[category] = sorted(list(report_extras))

        if only_table or only_report:
            comparison[report_name] = {
                "only table": only_table,
                "only report": only_report
            }

    output_comparison_path.write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    print(f"Differences saved to {output_comparison_path}")


from math import log


def add_bm25_score(base_dir: Path, k1=1.5, b=0.75):
    """
    Adds a BM25-based score to each entity hit in entity_hits_v3.
    This score estimates the relevance of the entity based on its frequency,
    document length, and how often the entity appears in other documents.

    BM25 formula:
        score = IDF * ((f * (k1 + 1)) / (f + k1 * (1 - b + b * (dl / avgdl))))

    Where:
        f = frequency of term in document
        dl = document length
        avgdl = average document length across all documents
        IDF = log((N - n + 0.5) / (n + 0.5) + 1)
            N = total number of documents
            n = number of documents where the term appears
    """

    #✅ Higher score = entity is frequent in this document and rare in others ⇒ important
    # ❌ Lower score = entity is either rare overall, or very common everywhere ⇒ less distinctive

    print("[*] Calculating BM25 scores...")

    # Step 1: Collect frequency data
    doc_lengths = {}
    freq_map = {"group": defaultdict(int), "tactic": defaultdict(int), "technique": defaultdict(int), "software": defaultdict(int), "capec": defaultdict(int), "cwe": defaultdict(int)}
    doc_freq = {"group": defaultdict(int), "tactic": defaultdict(int), "technique": defaultdict(int),  "software": defaultdict(int), "capec": defaultdict(int), "cwe": defaultdict(int)}

    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue
        text_path = text_dir / f"{report_dir.name}.txt"
        if not text_path.exists():
            continue
        try:
            text = text_path.read_text(encoding="utf-8")
            tokens = re.findall(r"\b\w+\b", text.lower())

            doc_lengths[report_dir.name] = len(tokens)

            for file_type in ["txt", "md"]:
                json_path = report_dir / f"{file_type}.json"
                if not json_path.exists():
                    continue
                with open(json_path, encoding="utf-8") as f:
                    data = json.load(f)

                for label in ["group", "tactic", "technique","software", "capec", "cwe"]:
                    for entry in data.get(label, []):
                        key = entry.get("original_id", entry.get("name", "")).lower()
                        freq_map[label][(report_dir.name, key)] += 1

        except Exception as e:
            print(f"[!] Failed to read or process {text_path.name}: {e}")

    N = len(doc_lengths)
    avgdl = sum(doc_lengths.values()) / N if N else 1

    for label in freq_map:
        seen_docs = defaultdict(set)
        for (doc_name, entity_key), count in freq_map[label].items():
            seen_docs[entity_key].add(doc_name)
        for entity_key, docs in seen_docs.items():
            doc_freq[label][entity_key] = len(docs)

    # Step 2: Add BM25 score to JSONs
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

                for label in ["group", "tactic", "technique", "software", "capec", "cwe"]:
                    for entry in data.get(label, []):
                        key = entry.get("original_id", entry.get("name", "")).lower()
                        f = freq_map[label].get((report_dir.name, key), 0)
                        n = doc_freq[label].get(key, 0)
                        idf = log((N - n + 0.5) / (n + 0.5) + 1)
                        denom = f + k1 * (1 - b + b * (dl / avgdl))
                        bm25_score = idf * ((f * (k1 + 1)) / denom) if denom else 0
                        entry["bm25_score"] = round(bm25_score, 4)
                        #
                        # if label == "group" and entry.get("name", "").lower() == "patchwork" and bm25_score > 1:
                        #     print(f"[!] Report '{report_dir.name}' has group 'patchwork' with BM25 > 1 → score: {round(bm25_score, 4)}")
                        #
                        # if file_type == "txt" and label == "group" and entry.get("name", "").lower() == "silence" and bm25_score > 1:
                        #     print(f"[!] Report '{report_dir.name}' has group 'silence' with BM25 > 1 → score: {round(bm25_score, 4)}")
                        #
                        # if label == "group" and entry.get("name", "").lower() == "platinum" and bm25_score > 1:
                        #     print(f"[!] Report '{report_dir.name}' has group 'platinum' with BM25 > 1 → score: {round(bm25_score, 4)}")
                        #
                        # if label == "group" and entry.get("name", "").lower() == "bitter" and bm25_score > 1:
                        #     print(f"[!] Report '{report_dir.name}' has group 'bitter' with BM25 > 1 → score: {round(bm25_score, 4)}")
                        #
                        # if label == "group" and entry.get("name", "").lower() == "equation" and bm25_score > 1:
                        #     print(f"[!] Report '{report_dir.name}' has group 'equation' with BM25 > 1 → score: {round(bm25_score, 4)}")
                        #
                        # if label == "software" and entry.get("name", "").lower() == "at" and bm25_score > 1:
                        #     print(
                        #         f"[!] Report '{report_dir.name}' has software 'at' with BM25 > 1 → score: {round(bm25_score, 4)}")
                        #
                    # Sort entries by bm25_score descending
                    if label in data:
                        data[label].sort(key=lambda x: x.get("bm25_score", 0), reverse=True)

                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

            except Exception as e:
                print(f"[!] Failed to update {json_path.name}: {e}")

    print("[✓] BM25 scores added to group, tactic, technique, software, capec and cwe entities.")

def summarize_problematic_names(base_dir: Path, threshold=1.0, max_above_ratio=0.5):
    """
    Finds names for which more than 90% of their BM25 scores are under the threshold,
    and writes a summary including the few cases where they appear with higher scores.
    """

    # Structure: {label: {name: [("report_id", score), ...]}}
    score_map = defaultdict(lambda: defaultdict(list))

    # Gather all scores per name
    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue
        json_path = report_dir / "txt.json"
        if not json_path.exists():
            continue

        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)

            for label in ["group", "tactic", "technique", "software", "capec", "cwe"]:
                for entry in data.get(label, []):
                    name = entry.get("name", "").strip().lower()
                    score = entry.get("bm25_score", 0)
                    if name:
                        score_map[label][name].append((report_dir.name, score))
        except Exception as e:
            print(f"[!] Failed to read or parse {json_path}: {e}")

    # Analyze and write results
    lines = ["=== BM25 Problematic Names Summary ===\n"]
    for label in sorted(score_map.keys()):
        lines.append(f"\n>>> Category: {label.upper()}")
        for name, score_list in sorted(score_map[label].items()):
            total = len(score_list)
            under = sum(1 for _, s in score_list if s < threshold)
            ratio_under = under / total if total else 0

            if ratio_under >= (1 - max_above_ratio):
                lines.append(f"\n  - {name} ({under}/{total} under {threshold})")
                for report_id, s in score_list:
                    if s >= threshold:
                        lines.append(f"      [✓] Report: {report_id}, score: {s:.4f}")

    # Save summary
    output_path = Path("data/bm25_problematic_names_summary.txt")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[✓] Summary written to {output_path}")


def generate_bm25_statistics_and_histograms(base_dir: Path, min_occurrences: int = 5, threshold: float = 1.0):
    """
    For each vertex type (group, tactic, etc.), calculates average BM25 and standard deviation,
    writes summary statistics sorted by mean score (descending), and generates histograms
    for entities that appear more than `min_occurrences` times.

    Output:
    - Text summary to 'data/bm25_statistics_summary.txt'
    - Histogram images in 'data/bm25_histograms/'
    """

    name_scores = defaultdict(lambda: defaultdict(list))  # {label: {name: [score1, score2, ...]}}
    stats_lines = ["=== BM25 Mean & Std Dev + Histograms ===\n"]

    hist_dir = Path("data/bm25_histograms")
    hist_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Collect BM25 scores from txt.json
    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue
        json_path = report_dir / "txt.json"
        if not json_path.exists():
            continue

        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)

            for label in ["group", "tactic", "technique", "software", "capec", "cwe"]:
                for entry in data.get(label, []):
                    name = entry.get("name", "").strip().lower()
                    score = entry.get("bm25_score", 0)
                    if name:
                        name_scores[label][name].append(score)
        except Exception as e:
            print(f"[!] Failed to read or parse {json_path}: {e}")

    # Step 2: Analyze and write stats
    for label in sorted(name_scores.keys()):
        stats_lines.append(f"\n>>> Category: {label.upper()}")

        sorted_items = sorted(
            name_scores[label].items(),
            key=lambda item: mean(item[1]),
            reverse=True
        )

        for name, scores in sorted_items:
            if len(scores) < 2:
                continue  # skip nodes with insufficient stats

            avg = mean(scores)
            std = stdev(scores)
            above = sum(1 for s in scores if s >= threshold)
            below = len(scores) - above
            ratio_above = above / len(scores)

            if ratio_above == 1:
                continue  # Skip if 100% are above threshold (i.e., always dominant)

            stats_lines.append(
                f"\n  - {name} (n={len(scores)}, μ={avg:.4f}, σ={std:.4f}, above {threshold}: {above}, below: {below}, ratio_above: {ratio_above:.1%})"
            )

            # if len(scores) >= min_occurrences:
            #     safe_name = name.replace(" ", "_").replace("/", "_")
            #     plt.figure()
            #     plt.hist(scores, bins=20, alpha=0.7, edgecolor='black')
            #     plt.title(f"{label.upper()} - {name}")
            #     plt.xlabel("BM25 Score")
            #     plt.ylabel("Frequency")
            #     plt.grid(True)
            #     plt.tight_layout()
            #     plt.savefig(hist_dir / f"{label}_{safe_name}.png")
            #     plt.close()

    # Step 3: Save statistics summary
    output_path = Path("data/bm25_statistics_summary.txt")
    output_path.write_text("\n".join(stats_lines), encoding="utf-8")
    print(f"[✓] Statistics written to {output_path}")
    print(f"[✓] Histograms saved to {hist_dir}")

if __name__ == "__main__":
    process_folder(text_dir, "txt")
    process_folder(md_dir, "md")
    deduplicate_entity_hits("data/entity_hits_v3")
    print("Finished extracting nodes from the reports, results are in: data/entity_hits_v3 ")
    write_summary_for_entity_hits_v3(output_dir)
    print(f"Global and timestamped summary written to entity_hits_v3/summaries")
    add_context_sentences_to_hits()
    print("Sentence context added to entity hits")
    add_bm25_score(output_dir)
    print("bm25 score added to entity hits")
    summarize_problematic_names(output_dir)
    generate_bm25_statistics_and_histograms(output_dir)



