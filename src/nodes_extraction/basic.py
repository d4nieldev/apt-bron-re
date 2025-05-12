import re
import json
from pathlib import Path
import ahocorasick
from collections import defaultdict
from math import log
from datetime import datetime

from ner import prepare_ner_lookup, ner_score

summary_root = Path("data/summaries")
summary_root.mkdir(parents=True, exist_ok=True)
timestamp_dir = summary_root / datetime.now().strftime("%Y%m%d_%H%M")
timestamp_dir.mkdir(exist_ok=True)

text_dir = Path("data/converted_reports/texts")
md_dir = Path("data/converted_reports/markdown")
layer_dir = Path("data/layers_nodes")
output_dir = Path("data/entity_hits_v3")
output_dir.mkdir(parents=True, exist_ok=True)

""" create a dictionary with keys as layer type (group, tactic, etc.) and 
values as lists of the relevant entities using the nodes extracted from BRON """
layer_map = {}
for layer_file in layer_dir.glob("*.json"):
    label = layer_file.stem
    with open(layer_file, encoding="utf-8") as f:
        layer_map[label] = json.load(f)


def generate_variants(text):
    """
    generates simple variants, to enable entities (names or ids) to appear
    in more than one manner
    """
    base = text.lower()
    variants = {
        base,
        base.replace("-", " "),
        base.replace(" ", ""),
        base.replace(" ", "-")
    }

    plural_forms = set()
    for var in variants:
        if not var.endswith("s"):
            plural_forms.add(var + "s")
            plural_forms.add(var + "'s")

    return variants.union(plural_forms)


""" building automatas, one for each layer type (besides CVE and CPE) to be later
 used by the aho-corasick algorithm """
automata_map = {}

""" variant_to_node is a dictionary of dictionaries, mapping variants to their nodes, for example:
{
    "technique": {
        "command line":      { node: {...}, ... },
        "command-line":      { node: {...}, ... },
        "commandline":       { node: {...}, ... },
        ...
    },
    "group": {
        "lazarus":            { node: {...}, alias: None },
        "hidden cobra":       { node: {...}, alias: "Hidden Cobra" },
        ...
    },
    ...
}
"""
variant_to_node = {}


""" technique_id_to_node is a dict mapping technique ids to their full node entry, for example
{
    "t1059":     { "name": "Command and Scripting Interpreter", "original_id": "T1059", ... },
    "t1003.001": { "name": "LSASS Memory", "original_id": "T1003.001", ... },
    ...
}
"""
technique_id_to_node = {}

technique_id_pattern = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.IGNORECASE)
cve_pattern = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)
cpe_pattern = re.compile(r"\bcpe:(?:2\.3:|/)[aoh]:[^\s:]+:[^\s:]+(?::[^\s:]*){0,10}", re.IGNORECASE)


""" Build automatas, one for each type of layer, besides cve and cpe
to use Aho-Corasick algorithm (bag of words keyword search)
"""
for label, nodes in layer_map.items():
    if label in ("cve", "cpe"):
        continue  # handled separately via regex, no need for Aho-Corasick
    A = ahocorasick.Automaton()  # Automaton for every entity type
    node_map = {}

    for node in nodes:
        if label == "technique":  # add only names of techniques to automaton. ids will be found using regex.
            for variant in generate_variants(node["name"]):
                if variant not in node_map:
                    node_map[variant] = node
                    A.add_word(variant, variant)
            technique_id_to_node[node["original_id"].lower()] = node
        elif label == "group":
            name_variants = generate_variants(node["name"])
            id_variants = generate_variants(node["original_id"])

            for alias_field in ("MITRE_aliases", "malpedia_aliases"):
                for alias in node.get(alias_field, []):
                    for v in generate_variants(alias):
                        if v not in node_map:
                            node_map[v] = {"node": node, "alias": alias}  # ← keep alias
                            A.add_word(v, v)

            for v in name_variants.union(id_variants):
                if v not in node_map:
                    node_map[v] = {"node": node, "alias": None}
                    A.add_word(v, v)

        else:
            name_variants = generate_variants(node["name"])
            id_variants = generate_variants(node["original_id"])
            for variant in name_variants.union(id_variants):
                if variant not in node_map:
                    node_map[variant] = {"node": node, "hit_by": label}
                    A.add_word(variant, variant)

    A.make_automaton()
    automata_map[label] = A
    variant_to_node[label] = node_map


def match_variants(text, category, automaton):
    """
    uses the automaton built on category (node type),
    to match the entities in the text (converted report) and their variants,
    also saving the index of where it was found in the text
    """
    text_lower = text.lower()
    found = set()
    results = []

    for end_idx, variant_str in automaton.iter(text_lower):
        # These 3 lines are to avoid accepting partial word matches
        start_idx = end_idx - len(variant_str) + 1
        before = text_lower[start_idx - 1] if start_idx > 0 else " "
        after = text_lower[end_idx + 1] if end_idx + 1 < len(text_lower) else " "
        if not before.isalnum() and not after.isalnum():
            if variant_str not in found:
                found.add(variant_str)
                node_info = variant_to_node[category][variant_str]
                node = node_info["node"] if isinstance(node_info, dict) and "node" in node_info else node_info

                hit = {
                    "name": node["name"],
                    "original_id": node["original_id"],
                    "index": start_idx
                }

                if category == "group":
                    hit["alias"] = node_info.get("alias")

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


def process_folder(folder: Path, suffix: str, add_ner_score: bool, exact_score: float,
                   diff_score: float, untrained_score: float):
    """
    Iterate over *folder* (txt or md). For every report:
    1. extracts structured entity nodes, using regex or Aho-Corasick
    2. runs NER on the raw text, if add_NER_score = True, and scores the matches based on ner_score
    3. writes results to entity_hits_v3/<report>/<suffix>.json
    """
    for file in folder.glob(f"*.{suffix}"):

        base_name = file.stem
        report_dir = output_dir / base_name
        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            text = file.read_text(encoding="utf-8")

            ner_lookup = prepare_ner_lookup(text) if add_ner_score else {}

            results: dict[str, list[dict]] = {}

            for layer_type, automaton in automata_map.items():
                if layer_type == "technique":
                    name_hits = match_variants(text, layer_type, automaton)
                    id_hits = match_technique_ids(text)
                    combined = {json.dumps(h, sort_keys=True): h for h in (*name_hits, *id_hits)}
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

            for category, entries in results.items():
                for ent in entries:
                    if add_ner_score and ner_lookup:
                        ent["NER_score"] = ner_score(ent, category, ner_lookup, exact_score,
                                                     diff_score, untrained_score)
                    else:
                        ent["NER_score"] = 0.0

            out_path = report_dir / f"{suffix}.json"
            out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

        except Exception as e:
            print(f"[ERROR] Failed to process {file.name}: {e}")


def deduplicate_entity_hits(base_dir_path: Path):
    """
    removes duplicate nodes that were extracted,
    from the output files created by process_folder.
    meaning, for a single report, we won't extract the same
    node twice. however, we do extract duplicates if they
    differ by index.
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
                    key = json.dumps(entry, sort_keys=True)  # this is the entire node, including index
                    if key not in seen:
                        seen.add(key)
                        deduped[category].append(entry)

            with open(file_path, "w", encoding="utf-8") as output_f:
                json.dump(deduped, output_f, indent=2)


def add_context_sentences_to_hits():
    """
    For each entity in txt.json/md.json files in entity_hits_v3,
    adds a 'sentence' field that shows up to n words before and after
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
        text_path = text_dir / f"{report_dir.name}.txt"
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
                for label in ["group", "tactic", "technique", "software", "capec", "cwe"]:
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
                for label in ["group", "tactic", "technique", "software", "capec", "cwe"]:
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
