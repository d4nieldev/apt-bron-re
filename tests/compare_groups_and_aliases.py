import json
from pathlib import Path
import ahocorasick

# Paths
text_dir = Path("data/converted_reports/texts")
group_json_path = Path("data/layers_nodes/group.json")
output_json = Path("data/group_aliases_results/group_alias_extraction_comparison.json")
output_txt = Path("data/group_aliases_results/group_aliases_comparison.txt")
output_json.parent.mkdir(parents=True, exist_ok=True)

# Load updated group data with malpedia_aliases and mitre_aliases
with group_json_path.open(encoding="utf-8") as f:
    group_data = json.load(f)

# Prepare Aho-Corasick automatons
group_auto = ahocorasick.Automaton()
mitre_auto = ahocorasick.Automaton()
malpedia_auto = ahocorasick.Automaton()

group_variant_map = {}
mitre_variant_map = {}
malpedia_variant_map = {}

def generate_variants(text):
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

# Build automatons
for group in group_data:
    group_name = group["name"]
    mitre_aliases = group.get("MITRE_aliases", [])
    malpedia_aliases = group.get("malpedia_aliases", [])

    for variant in generate_variants(group_name):
        group_variant_map[variant] = group_name
        group_auto.add_word(variant, variant)

    for alias in mitre_aliases:
        for variant in generate_variants(alias):
            mitre_variant_map[variant] = group_name
            mitre_auto.add_word(variant, variant)

    for alias in malpedia_aliases:
        for variant in generate_variants(alias):
            malpedia_variant_map[variant] = group_name
            malpedia_auto.add_word(variant, variant)

group_auto.make_automaton()
mitre_auto.make_automaton()
malpedia_auto.make_automaton()

# Match function
def match_variants(text, automaton, variant_map):
    text_lower = text.lower()
    found = set()
    for end_idx, variant in automaton.iter(text_lower):
        start_idx = end_idx - len(variant) + 1
        before = text_lower[start_idx - 1] if start_idx > 0 else " "
        after = text_lower[end_idx + 1] if end_idx + 1 < len(text_lower) else " "
        if not before.isalnum() and not after.isalnum():
            found.add(variant_map[variant])
    return sorted(set(found))

# Scan reports
summary = {}
global_hit_counter = {"group name hits": 0, "mitre aliases hits": 0, "malpedia aliases hits": 0}

for file in text_dir.glob("*.txt"):
    try:
        text = file.read_text(encoding="utf-8")
        group_hits = match_variants(text, group_auto, group_variant_map)
        mitre_hits = match_variants(text, mitre_auto, mitre_variant_map)
        malpedia_hits = match_variants(text, malpedia_auto, malpedia_variant_map)

        all_group_hits = set(group_hits)
        all_mitre_hits = set(mitre_hits)
        all_malpedia_hits = set(malpedia_hits)

        alias_hits_total = all_mitre_hits.union(all_malpedia_hits)
        alias_without_group = bool(alias_hits_total - all_group_hits)

        summary[file.stem] = {
            "group name hits": len(all_group_hits),
            "mitre aliases hits": len(all_mitre_hits),
            "malpedia aliases hits": len(all_malpedia_hits),
            "alias_without_group_hit": alias_without_group
        }

        # Update global counters without double-counting per field
        global_hit_counter["group name hits"] += len(all_group_hits)
        global_hit_counter["mitre aliases hits"] += len(all_mitre_hits)
        global_hit_counter["malpedia aliases hits"] += len(all_malpedia_hits)

    except Exception as e:
        summary[file.stem] = {"error": str(e)}

# Save JSON summary
with output_json.open("w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

# Save TXT summary
with output_txt.open("w", encoding="utf-8") as f:
    for field in ["group name hits", "mitre aliases hits", "malpedia aliases hits"]:
        f.write(f"{field}: {global_hit_counter[field]}\n")

output_json, output_txt
