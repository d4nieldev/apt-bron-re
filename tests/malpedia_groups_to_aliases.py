import requests
import json
from pathlib import Path
import time

# === Load group.json ===
group_path = Path("data/layers_nodes/group.json")
with group_path.open("r", encoding="utf-8") as f:
    groups = json.load(f)

# === Manual needle overrides ===
manual_needles = {
    "Sandworm Team": "Sandworm",
    "Threat Group-3390": "APT27"
}


# === Malpedia API search ===
def search_actor_aliases(needle):
    url = f"https://malpedia.caad.fkie.fraunhofer.de/api/find/actor/{needle}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []
        return response.json()
    except Exception as e:
        print(f"Connection error for {needle}: {e}")
        return []


# === Collect aliases from best match ===
def extract_aliases(entry, original_name):
    raw_aliases = set(entry.get("synonyms", []))
    raw_aliases.update([entry.get("name", ""), entry.get("common_name", "")])
    cleaned = {alias for alias in raw_aliases if alias and alias.lower() != original_name.lower()}
    return sorted(cleaned)


# === Query and update group aliases ===
for group in groups:
    name = group["name"]
    group["malpedia_aliases"] = []

    # Use override if exists, else use the group name
    base_needle = manual_needles.get(name, name)
    query_variants = [base_needle, base_needle.capitalize(), base_needle.title(), base_needle.upper(),
                      base_needle.lower()]

    found = False
    for variant in query_variants:
        results = search_actor_aliases(variant)
        time.sleep(1)

        if results:
            entry = results[0]  # Assume first match is relevant
            aliases = extract_aliases(entry, name)
            group["malpedia_aliases"] = aliases
            found = True
            break

    if not found:
        print(f"Failed to match group: {name}")

# === Save updated group.json ===
with group_path.open("w", encoding="utf-8") as f:
    json.dump(groups, f, indent=2, ensure_ascii=False)

print("Done updating malpedia_aliases including synonyms, name, and common_name.")
