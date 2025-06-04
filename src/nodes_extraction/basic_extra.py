import json
from copy import deepcopy
from .constants import OUTPUT_DIR, LAYER_DIR


# Load enriched nodes from LAYER_DIR
def load_layer_nodes():
    enriched_nodes = {}
    for json_file in LAYER_DIR.glob("*.json"):
        label = json_file.stem
        with json_file.open(encoding="utf-8") as f:
            data = json.load(f)
            enriched_nodes[label] = {
                (node.get("original_id") or node.get("name")): deepcopy(node)
                for node in data
            }
    return enriched_nodes

# Update OUTPUT_DIR report files with missing enriched fields
def update_report_entities_with_details():
    enriched_data = load_layer_nodes()
    updated_files = 0

    for report_dir in OUTPUT_DIR.iterdir():
        if not report_dir.is_dir():
            continue

        for suffix in ["txt", "md"]:
            json_path = report_dir / f"{suffix}.json"
            if not json_path.exists():
                continue

            try:
                with open(json_path, encoding="utf-8") as f:
                    report_data = json.load(f)

                updated = False

                for layer_type, entries in report_data.items():
                    if layer_type not in enriched_data:
                        continue

                    for entry in entries:
                        match_key = entry.get("original_id") or entry.get("name")
                        enriched = enriched_data[layer_type].get(match_key)
                        if not enriched:
                            continue

                        for k, v in enriched.items():
                            if k not in entry:
                                entry[k] = v
                                updated = True

                if updated:
                    with open(json_path, "w", encoding="utf-8") as f:
                        json.dump(report_data, f, indent=2)
                    updated_files += 1
                    print(f"Updated: {json_path.name} in {report_dir.name}")

            except Exception as e:
                print(f"Failed to update {json_path}: {e}")

    print(f"\nFinished. Updated {updated_files} report files.")

# Unite aliases into a single set (for all enriched layer files)
def aliases_to_set():
    group_file = LAYER_DIR / "group.json"
    if not group_file.exists():
        print("group.json not found in LAYER_DIR.")
        return

    try:
        with group_file.open(encoding="utf-8") as f:
            data = json.load(f)

        for node in data:
            all_aliases = set()
            for field in ["MITRE_aliases", "malpedia_aliases", "aliases"]:
                aliases = node.get(field, [])
                if isinstance(aliases, list):
                    all_aliases.update(aliases)
            node["all_aliases"] = sorted(all_aliases)

            # Remove original alias fields
            for field in ["MITRE_aliases", "malpedia_aliases", "aliases"]:
                node.pop(field, None)

        with group_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print("Processed aliases in group.json")

    except Exception as e:
        print(f"Error processing group.json: {e}")


update_report_entities_with_details()
aliases_to_set()

