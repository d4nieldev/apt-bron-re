import re
import json
from pathlib import Path
import ahocorasick
from datetime import datetime

# paths
tables_md = Path("data/validation_set/only_tables_from_reports")
layer_dir = Path("data/layers_nodes")
output_tables_dir = Path("data/validation_set/only_tables_from_reports")
output_tables_dir.mkdir(parents=True, exist_ok=True)

reports_md = Path("data/validation_set/md_reports_without_the_tables")
output_reports_dir = Path("data/validation_set/md_reports_without_the_tables")
output_reports_dir.mkdir(parents=True, exist_ok=True)


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
                results.append({
                    "name": node["name"],
                    "original_id": node["original_id"],
                    "index": start_idx
                })
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


def process_folder(folder: Path, suffix: str, output_file: Path):
    """
    Processes the folder of converted reports,
    collects all entity hits into a single JSON object,
    and saves it to a specified output file.
    """
    all_reports_data = {}

    for file in folder.glob(f"*.{suffix}"):
        base_name = file.stem
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

            if results:  # Only save non-empty results
                all_reports_data[base_name] = results

        except Exception as e:
            print(f"Failed to process {file.name}: {e}")

    # Save the entire accumulated results to one file
    output_file.write_text(json.dumps(all_reports_data, indent=2), encoding="utf-8")
    print(f"Finished processing {len(all_reports_data)} reports into {output_file}")


def deduplicate_entity_hits(json_path: Path):
    """
    removes duplicate nodes that were extracted,
    from the output files created by process_folder
    """
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to read {json_path}: {e}")
        return

    deduped_data = {}

    for report_name, report_data in data.items():
        deduped_report = {}
        for category, entries in report_data.items():
            seen = set()
            deduped_entries = []
            for entry in entries:
                key = json.dumps(entry, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    deduped_entries.append(entry)
            deduped_report[category] = deduped_entries
        deduped_data[report_name] = deduped_report

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(deduped_data, f, indent=2)


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


def write_global_summary(json_path: Path, dataset_name: str):
    """
    Summarizes total entity counts for a dataset,
    returns the summary text as a list of lines.
    """
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to read {json_path}: {e}")
        return []

    totals = {}

    for report_data in data.values():
        for category, entries in report_data.items():
            totals[category] = totals.get(category, 0) + len(entries)

    summary_txt = [f"=== {dataset_name} ===\n"]

    for category, count in sorted(totals.items()):
        summary_txt.append(f"{category}: {count}")

    return summary_txt


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
    comparisons_dir = Path("data/validation_set/comparisons")
    comparisons_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    combined_summary_path = comparisons_dir / f"{timestamp}_summary.txt"

    # Process reports with only tables
    output_tables_json = output_tables_dir / "zzz_all_reports_output.json"
    process_folder(tables_md, "md", output_tables_json)
    deduplicate_entity_hits(output_tables_json)
    tables_summary = write_global_summary(output_tables_json, "Only Tables Reports")

    # Process full reports without tables
    output_reports_json = output_reports_dir / "zzz_all_reports_output.json"
    process_folder(reports_md, "md", output_reports_json)
    deduplicate_entity_hits(output_reports_json)
    reports_summary = write_global_summary(output_reports_json, "Full Reports Without Tables")

    # Save combined text summary
    combined_summary = ["=== Global Summary ===", ""] + tables_summary + [""] + reports_summary
    combined_summary_text = "\n".join(combined_summary)
    combined_summary_path.write_text(combined_summary_text, encoding="utf-8")

    # Compare differences between the two datasets
    diffs_output_path = comparisons_dir / f"differences.json"
    compare_differences(output_tables_json, output_reports_json, diffs_output_path)

    print(f"Combined summary saved to {combined_summary_path}")
