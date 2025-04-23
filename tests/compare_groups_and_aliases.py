import json
from pathlib import Path
import ahocorasick

text_dir = Path("data/converted_reports/texts")
alias_file = Path("data/test_results/group_to_aliases_mapping.json")
output_file = Path("data/test_results/group_alias_extraction_comparison_summary.json")
output_file.parent.mkdir(parents=True, exist_ok=True)

# load aliases
with open(alias_file, encoding="utf-8") as f:
    group_aliases = json.load(f)


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


# Aho-Corasick Automatons
group_auto = ahocorasick.Automaton()
alias_auto = ahocorasick.Automaton()
group_variant_map = {}
alias_variant_map = {}

for group_name, aliases in group_aliases.items():
    for variant in generate_variants(group_name):
        if variant not in group_variant_map:
            group_variant_map[variant] = group_name
            group_auto.add_word(variant, variant)

    for alias in aliases:
        for variant in generate_variants(alias):
            if variant not in alias_variant_map:
                alias_variant_map[variant] = alias
                alias_auto.add_word(variant, variant)

group_auto.make_automaton()
alias_auto.make_automaton()


def match_variants(text, automaton, variant_map):
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
                results.append(variant_map[variant_str])
    return sorted(set(results))


summary = {}

for file in text_dir.glob("*.txt"):
    try:
        text = file.read_text(encoding="utf-8")
        groups = match_variants(text, group_auto, group_variant_map)
        aliases = match_variants(text, alias_auto, alias_variant_map)
        summary[file.stem] = {
            "group_name_hits": len(groups),
            "group_names_found": groups,
            "alias_hits": len(aliases),
            "aliases_found": aliases
        }
    except Exception as e:
        summary[file.stem] = {"error": str(e)}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

with open(output_file, encoding="utf-8") as f:
    summary = json.load(f)

with open(alias_file, encoding="utf-8") as f:
    group_aliases = json.load(f)

for report, data in summary.items():
    if "error" in data:
        continue  # skip errored reports

    group_names_found = set(data.get("group_names_found", []))
    aliases_found = set(data.get("aliases_found", []))

    alias_without_group = False

    for group, aliases in group_aliases.items():
        if group not in group_names_found:
            if any(alias in aliases_found for alias in aliases):
                alias_without_group = True
                break

    data["alias_without_group_hit"] = alias_without_group

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

print(f"alias_without_group_hit added and saved to: {output_file}")