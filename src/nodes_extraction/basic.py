import re
import json
from pathlib import Path
import ahocorasick
from datetime import datetime

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
    return {
        base,
        base.replace("-", " "),
        base.replace(" ", ""),
        base.replace(" ", "-")
    }


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
        if label == "technique":
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
    uses the automaton built on label (node type),
    to match the entities in the text (converted report)
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
                results.append(variant_to_node[category][variant_str])
    return results


def match_technique_ids(text):
    """
    Uses regex to find technique IDs (T#### or T####.###)
    and maps them to their node objects.
    """
    matched_ids = set()
    results = []
    for match in technique_id_pattern.findall(text):
        tid = match.lower()
        if tid not in matched_ids and tid in technique_id_to_node:
            matched_ids.add(tid)
            results.append(technique_id_to_node[tid])
    return results


# CVE and CPE matching
def match_cve(text):
    """
    finds matches using regex on the structure of cves
    and returns the nodes in uppercase (how it appears in BRON, e.g. CVE-2007-4240)
    """
    return [{"value": m.upper()} for m in cve_pattern.findall(text.lower())]


def match_cpe(text):
    """
    finds matches using regex on the structure of cpe
    and returns the nodes in lowercase (how it appears in BRON, e.g. cpe:2.3:a:bmc:patrol_agent)
    """
    return [{"value": m.lower()} for m in cpe_pattern.findall(text.lower())]


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


def write_global_summary(base_dir: Path):
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


if __name__ == "__main__":
    process_folder(text_dir, "txt")
    process_folder(md_dir, "md")
    deduplicate_entity_hits("data/entity_hits_v3")
    print("Finished extracting nodes from the reports, results are in: data/entity_hits_v3 ")
    write_global_summary(output_dir)
    print(f"Global and timestamped summary written to entity_hits_v3/summaries")
