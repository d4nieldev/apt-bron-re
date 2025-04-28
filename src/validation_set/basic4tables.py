import re
import json
from pathlib import Path
import ahocorasick
from datetime import datetime

# paths
md_dir = Path("data/validation_set/only_tables_from_reports")
layer_dir = Path("data/layers_nodes")
output_dir = Path("data/validation_set/only_tables_from_reports")
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

    print(f"Deduplication finished for {json_path}")


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


def write_global_summary(json_path: Path, output_summary_dir: Path):
    """
    writes a timestamped global summary of the nodes extraction, to compare with previous attempts
    to be inserted to entity_hits_v3/summaries, and also a summary/comparison between the number of entities
    in the reports, stored in entity_hits_v3/global_summary.json
    """
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to read {json_path}: {e}")
        return

    txt_totals = {}
    md_totals = {}  # In your new setup, no real txt/md split, but I keep both for compatibility.

    for report_data in data.values():
        for category, entries in report_data.items():
            txt_totals[category] = txt_totals.get(category, 0) + len(entries)
            md_totals[category] = md_totals.get(category, 0) + len(entries)  # same values now

    # Timestamped text summary
    output_summary_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    summary_txt = ["=== Total Entity Counts Across All Reports ===\n"]

    summary_txt.append("[TOTAL]")
    for category, count in sorted(txt_totals.items()):
        summary_txt.append(f"{category}: {count}")

    summary_path = output_summary_dir / f"{timestamp}_summary.txt"
    summary_path.write_text("\n".join(summary_txt), encoding="utf-8")


if __name__ == "__main__":
    output_json = output_dir / "all_reports_output.json"
    process_folder(md_dir, "md", output_json)
    deduplicate_entity_hits(output_json)
    write_global_summary(output_json, output_dir / "summaries")
