import re
import json
from pathlib import Path
import ahocorasick
from datetime import datetime

#  imports for NER
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
_NER_USER = os.getenv("ner_username")
_NER_PASS = os.getenv("ner_password")

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


group_id_to_alias_variants = {}
for g in layer_map.get("group", []):
    alias_vars = set()
    for alias_field in ("MITRE_aliases", "malpedia_aliases"):
        for a in g.get(alias_field, []):
            alias_vars.update(generate_variants(a))
    group_id_to_alias_variants[g["original_id"].lower()] = alias_vars


def _find_entities(text: str) -> dict:
    """
    Call the local NER API exactly like `ner_test.py` does and return the raw JSON.
    """
    resp = requests.post(
        url="https://127.0.0.1:8890/tagging/get_tags_from_text",
        json={"text": text, "search_mode": "Combined"},
        auth=HTTPBasicAuth(_NER_USER, _NER_PASS),
        verify=False,                    # same self-signed cert warning suppression
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def _variants_for_entry(category: str, entry: dict) -> set[str]:
    """
    Given an extracted node, return all of the textual variants that should
    be searched for inside the NER output.
    """
    vars_set = set()

    if category in {"cve", "cpe"}:
        token = entry.get("value", "")
        vars_set.update(generate_variants(token))
        return vars_set

    # name + id
    vars_set.update(generate_variants(entry.get("name", "")))
    vars_set.update(generate_variants(entry.get("original_id", "")))

    # aliases for groups
    if category == "group":
        oid = entry.get("original_id", "").lower()
        vars_set.update(group_id_to_alias_variants.get(oid, set()))

    return vars_set


def _flat_ner_terms(ner_json: dict) -> set[str]:
    """
    Flatten the NER output to a single lower-cased set of strings so look-ups
    are O(1).  (We don’t print it any more.)
    """
    flat: set[str] = set()
    for terms in ner_json.values():
        flat.update(t.lower() for t in terms)
    return flat


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
        elif label == "group":
            name_variants = generate_variants(node["name"])
            id_variants = generate_variants(node["original_id"])
            alias_variants = set()

            for alias_field in ["MITRE_aliases", "malpedia_aliases"]:
                for alias in node.get(alias_field, []):
                    alias_variants.update(generate_variants(alias))

            for variant in name_variants.union(id_variants):
                if variant not in node_map:
                    node_map[variant] = {"node": node, "hit_by": "group"}
                    A.add_word(variant, variant)

            for variant in alias_variants:
                if variant not in node_map:
                    node_map[variant] = {"node": node, "hit_by": "alias"}
                    A.add_word(variant, variant)

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
                node_info = variant_to_node[category][variant_str]
                node = node_info["node"] if isinstance(node_info, dict) and "node" in node_info else node_info

                hit = {
                    "name": node["name"],
                    "original_id": node["original_id"],
                    "index": start_idx
                }

                if category == "group" and isinstance(node_info, dict) and "hit_by" in node_info:
                    hit["hit by"] = node_info["hit_by"]

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


def process_folder(folder: Path, suffix: str):
    """
    Iterate over *folder* (txt or md). For every report:
    1. run NER once and flatten its terms
    2. run the old extraction logic
    3. for every extracted node add `"NER_hit": True/False`
    4. write results to entity_hits_v3/<report>/<suffix>.json
    """
    for file in folder.glob(f"*.{suffix}"):
        base_name = file.stem
        report_dir = output_dir / base_name
        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            text = file.read_text(encoding="utf-8")

            # ---------- 1. NER (silent) ---------------------------------
            try:
                ner_json = _find_entities(text)
                ner_terms_flat = _flat_ner_terms(ner_json)
            except Exception as ner_err:                    # NER failed – continue without it
                print(f"NER call failed for {file.name}: {ner_err}")
                ner_terms_flat = set()

            # ---------- 2. original extraction --------------------------
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

            # ---------- 3. add NER_hit ---------------------------------
            for category, entries in results.items():
                for entry in entries:
                    variants = _variants_for_entry(category, entry)
                    entry["NER_hit"] = any(v in ner_terms_flat for v in variants)

            # ---------- 4. save ----------------------------------------
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


if __name__ == "__main__":
    process_folder(text_dir, "txt")
    process_folder(md_dir, "md")
    deduplicate_entity_hits("data/entity_hits_v3")
    print("Finished extracting nodes from the reports, results are in: data/entity_hits_v3 ")
    write_summary_for_entity_hits_v3(output_dir)
    print(f"Global and timestamped summary written to entity_hits_v3/summaries")
    add_context_sentences_to_hits()
    print("Sentence context added to entity hits")