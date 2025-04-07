import re
import json
from pathlib import Path
import ahocorasick
from datetime import datetime

# === Paths ===
text_dir = Path("data/converted_reports/texts")
md_dir = Path("data/converted_reports/markdown")
layer_dir = Path("data/layers_nodes")
output_dir = Path("data/entity_hits_v3")
output_dir.mkdir(parents=True, exist_ok=True)

# === Load all layers ===
layer_map = {}
for layer_file in layer_dir.glob("*.json"):
    label = layer_file.stem
    with open(layer_file, encoding="utf-8") as f:
        layer_map[label] = json.load(f)

# === Generate variants ===
def generate_variants(text):
    base = text.lower()
    return {
        base,
        base.replace("-", " "),
        base.replace(" ", ""),
        base.replace(" ", "-")
    }

# === Build automata for each layer except CVE/CPE ===
automata_map = {}
variant_to_node = {}

for label, nodes in layer_map.items():
    if label in {"cve", "cpe"}:
        continue
    A = ahocorasick.Automaton()
    node_map = {}
    for node in nodes:
        name_variants = generate_variants(node["name"])
        id_variants = generate_variants(node["original_id"])
        for variant in name_variants.union(id_variants):
            if variant not in node_map:
                node_map[variant] = node
                A.add_word(variant, variant)
    A.make_automaton()
    automata_map[label] = A
    variant_to_node[label] = node_map

# === Regex patterns for CVE and CPE ===
cve_pattern = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)
cpe_pattern = re.compile(r"\bcpe:(?:2\.3:|/)[aoh]:[^\s:]+:[^\s:]+(?::[^\s:]*){0,10}", re.IGNORECASE)

# === Matching function ===
def match_variants(text, label, automaton):
    found = set()
    results = []
    for end_idx, variant in automaton.iter(text.lower()):
        if variant not in found:
            found.add(variant)
            results.append(variant_to_node[label][variant])
    return results

# === CVE and CPE matchers ===
def match_cve(text):
    return [{"value": m.upper()} for m in cve_pattern.findall(text)]

def match_cpe(text):
    return [{"value": m.lower()} for m in cpe_pattern.findall(text)]

# === Process a folder (.txt or .md) ===
def process_folder(folder, suffix):
    for file in folder.glob(f"*.{suffix}"):
        base_name = file.stem
        report_dir = output_dir / base_name
        report_dir.mkdir(parents=True, exist_ok=True)
        try:
            text = file.read_text(encoding="utf-8")
            results = {}

            for label, automaton in automata_map.items():
                hits = match_variants(text, label, automaton)
                if hits:
                    results[label] = hits

            cves = match_cve(text)
            cpes = match_cpe(text)
            if cves:
                results["cve"] = cves
            if cpes:
                results["cpe"] = cpes

            out_path = report_dir / f"{suffix}.json"
            out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[!] Failed to process {file.name}: {e}")

# === Deduplicate entries in JSONs ===
def deduplicate_entity_hits(base_dir_path: str):
    base_dir = Path(base_dir_path)

    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue

        for file_name in ["txt.json", "md.json"]:
            file_path = report_dir / file_name
            if not file_path.exists():
                continue

            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                print(f"[!] Failed to read {file_path}: {e}")
                continue

            deduped = {}
            for label, entries in data.items():
                seen = set()
                deduped[label] = []
                for entry in entries:
                    key = json.dumps(entry, sort_keys=True)
                    if key not in seen:
                        seen.add(key)
                        deduped[label].append(entry)

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(deduped, f, indent=2)

    print(f"[✓] Deduplication completed in: {base_dir_path}")


# === Add per-report summary_counts.json and global timestamped summary ===
def write_summary_counts(report_dir: Path):
    summary = {}
    for json_file in ["txt.json", "md.json"]:
        path = report_dir / json_file
        if path.exists():
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            summary_key = "txt_counts" if "txt" in json_file else "md_counts"
            summary[summary_key] = {label: len(entries) for label, entries in data.items()}
    if summary:
        with open(report_dir / "summary_counts.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    return summary

def write_global_summary(base_dir: Path):
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
        for label, count in report.get("txt_counts", {}).items():
            txt_totals[label] = txt_totals.get(label, 0) + count
        for label, count in report.get("md_counts", {}).items():
            md_totals[label] = md_totals.get(label, 0) + count

    summary_txt.append("[TXT]")
    for label, count in sorted(txt_totals.items()):
        summary_txt.append(f"{label}: {count}")
    summary_txt.append("\n[MD]")
    for label, count in sorted(md_totals.items()):
        summary_txt.append(f"{label}: {count}")

    summary_path = summary_dir / f"{timestamp}_summary.txt"
    summary_path.write_text("\n".join(summary_txt), encoding="utf-8")

    global_summary_path = base_dir / "global_summary.json"
    with open(global_summary_path, "w", encoding="utf-8") as f:
        json.dump(global_summary, f, indent=2)

    print(f"[✓] Global summary written to: {summary_path.name}")


# === MAIN ENTRY POINT ===
if __name__ == "__main__":
    process_folder(text_dir, "txt")
    process_folder(md_dir, "md")
    deduplicate_entity_hits("data/entity_hits_v3")
    print("✓ All reports processed and saved to data/entity_hits_v3 with CVE/CPE and node hits.")
    write_global_summary(output_dir)

