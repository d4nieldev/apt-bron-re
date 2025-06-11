import json
from pathlib import Path
from collections import defaultdict
from copy import deepcopy


# Define base directory
base_dir = Path("data") / "entity_hits_v3"
layer_dir = Path("data") / "layers_nodes"
output_filename = "combined.json"

# Files to be combined
target_files = [
    "md.json",
    "txt.json",
     "md_ner_intersection.json",
     "txt_ner_intersection.json",
]

# Iterate over all folders in entity_hits_v3
max_reports = 4  # Change this number as needed

# === Load enriched nodes from LAYER_DIR ===
def load_layer_nodes():
    enriched_nodes = {}
    for json_file in layer_dir.glob("*.json"):
        label = json_file.stem
        with json_file.open(encoding="utf-8") as f:
            data = json.load(f)
            enriched_nodes[label] = {
                (node.get("original_id") or node.get("name")): deepcopy(node)
                for node in data
            }
    return enriched_nodes



# === Merge by "name", adding missing fields and enriching ===
def merge_nodes_by_name(existing_nodes, new_nodes, enriched_layer=None):
    name_to_node = {node["name"]: node for node in existing_nodes if "name" in node}

    for new_node in new_nodes:
        name = new_node.get("name")
        if not name:
            continue

        # Find enrichment if available
        match_key = new_node.get("original_id") or new_node.get("name")
        enriched = enriched_layer.get(match_key) if enriched_layer else None

        if name in name_to_node:
            merged = name_to_node[name]
            for k, v in new_node.items():
                if k not in merged:
                    merged[k] = v
            if enriched:
                for k, v in enriched.items():
                    if k not in merged:
                        merged[k] = v

        else:
            if enriched:
                for k, v in enriched.items():
                    if k not in new_node:
                        new_node[k] = v
            name_to_node[name] = new_node


    return list(name_to_node.values())


# === Main processing function ===
def process_and_merge_reports():
    enriched_data = load_layer_nodes()
    processed = 0

    for report_dir in sorted(base_dir.iterdir()):
        if not report_dir.is_dir():
            continue
        # if processed >= max_reports:
            # break

        merged_data = defaultdict(list)

        for filename in target_files:
            file_path = report_dir / filename
            if not file_path.exists():
                continue

            try:
                with file_path.open(encoding="utf-8") as f:
                    content = json.load(f)
                    for layer_type, entries in content.items():
                        if isinstance(entries, list):
                            enriched_layer = enriched_data.get(layer_type, {})
                            merged_data[layer_type] = merge_nodes_by_name(
                                merged_data[layer_type], entries, enriched_layer
                            )
            except Exception as e:
                print(f"Failed to load {file_path}: {e}")

        # Special handling: unify aliases for group nodes
        if "group" in merged_data:
            for group_node in merged_data["group"]:
                all_aliases = set()
                for field in ["MITRE_aliases", "malpedia_aliases", "aliases"]:
                    aliases = group_node.get(field, [])
                    if isinstance(aliases, list):
                        all_aliases.update(aliases)
                group_node["all_aliases"] = sorted(all_aliases)
                for field in ["MITRE_aliases", "malpedia_aliases", "aliases"]:
                    group_node.pop(field, None)

        # Save merged result
        output_path = report_dir / output_filename
        try:
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(dict(merged_data), f, indent=2)
            # print(f"Created {output_filename} in {report_dir.name}")
        except Exception as e:
            print(f"Failed to write {output_filename} in {report_dir.name}: {e}")

        processed += 1

    print(f"\nFinished merging reports with enrichment and alias unification.")

# === Run ===
process_and_merge_reports()