import re
import json
from pathlib import Path

# === Paths ===
text_dir = Path("data/converted_reports/texts")
md_dir = Path("data/converted_reports/markdown")
output_base_dir = Path("data/entity_hits_v2")
layer_dir = Path("data/layers_nodes")  # the jsons to compare with

# === Load all layers except cve/cpe ===
excluded_layers = {"cve", "cpe"}
layer_map = {}

for layer_file in layer_dir.glob("*.json"):
    label = layer_file.stem
    if label not in excluded_layers:
        with open(layer_file, encoding="utf-8") as f:
            layer_map[label] = json.load(f)

# === Regex patterns ===
cve_pattern = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)
cpe_pattern = re.compile(r"\bcpe:(?:2\.3:|/)[aoh]:[^\s:]+:[^\s:]+(?::[^\s:]*){0,10}", re.IGNORECASE)


def read_file(file_path: Path):
    try:
        return file_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[!] Failed to read {file_path.name}: {e}")
        return ""


def normalize_name(name: str) -> list:
    base = name.lower()
    variants = {base, base.replace("-", " "), base.replace(" ", ""), base.replace(" ", "-")}

    if base.endswith("s"):
        singular = base[:-1]
        variants.update({
            singular,
            singular.replace("-", " "),
            singular.replace(" ", ""),
            singular.replace(" ", "-")
        })

    return list(variants)


def split_sentences(text):
    # Avoid splitting on common abbreviations and inside parentheses
    pattern = r"""
        (?<!\w\.\w.)           # Ignore abbreviations like e.g.
        (?<![A-Z][a-z]\.)      # Ignore Dr. Mr. etc.
        (?<!\bvs\.)            # vs.
        (?<!\bfig\.)           # fig.
        (?<!\bet\ al\.)        # et al.
        (?<!\bNo\.)            # No.
        (?<=\.|\?|!)           # Split at ., ?, or !
        \s+(?=[A-Z(])          # Followed by a capital letter or open parenthesis
    """
    return re.split(pattern, text, flags=re.VERBOSE)


def has_missing_context(results: dict) -> bool:
    for entities in results.values():
        if isinstance(entities, list):
            for item in entities:
                if isinstance(item, dict):
                    if item.get("line") is None or item.get("sentence") is None:
                        return True
    return False


def extract_context(text: str, entity_name: str, original_id: str = "", is_markdown=False):
    lines = text.splitlines()
    flat_text = " ".join(lines)

    variants = normalize_name(entity_name)
    if original_id:
        variants.append(original_id.lower())

    # Also check bag-of-words match
    name_words = set(entity_name.lower().replace("-", " ").split())

    line_number = None
    table_row = None

    for i in range(len(lines)):
        chunk_lines = lines[i:i+5]
        chunk_text = " ".join(chunk_lines).lower()
        chunk_words = set(chunk_text.split())

        # Match by word bag or ID or name variant
        if (
            name_words.issubset(chunk_words)
            or any(variant in chunk_text for variant in variants)
        ):
            line_number = i
            if is_markdown and lines[i].strip().startswith("|") and lines[i].strip().endswith("|"):
                table_row = lines[i].strip()
            break

    # Sentence extraction
    text_for_sentences = re.sub(r'\n+', ' ', text)
    sentences = split_sentences(text_for_sentences)
    sentence = None
    for s in sentences:
        if any(variant in s.lower() for variant in variants):
            sentence = s.strip()
            break

    result = {"line": line_number, "sentence": sentence}
    if table_row:
        result["table_row"] = table_row
    return result


def match_nodes(text: str, nodes: list[dict], is_markdown=False, raw_text=""):
    seen = set()
    hits = []
    for node in nodes:
        name = node.get("name", "").lower()
        original_id = node.get("original_id", "").lower()
        suffix = node.get("_id", "").split("/")[-1].lower()

        name_variants = normalize_name(name)

        if any(n in text for n in name_variants) or original_id in text or suffix in text:
            key = json.dumps(node, sort_keys=True)
            if key not in seen:
                seen.add(key)

                # Extract context from raw_text
                ctx = extract_context(raw_text, name, original_id, is_markdown)
                enriched_node = dict(node)
                enriched_node.update(ctx)

                hits.append(enriched_node)
    return hits


# === Process all .txt and .md files
for txt_file in text_dir.glob("*.txt"):
    base_name = txt_file.stem
    md_file = md_dir / f"{base_name}.md"
    if not md_file.exists():
        print(f"[!] Missing Markdown for: {base_name}")
        continue

    report_output_dir = output_base_dir / base_name
    report_output_dir.mkdir(parents=True, exist_ok=True)

    txt_raw = read_file(txt_file)
    md_raw = read_file(md_file)

    txt_text = txt_raw.lower()
    md_text = md_raw.lower()

    txt_results = {}
    md_results = {}

    # === Extract hits from all layers (except CVE/CPE)
    for label, nodes in layer_map.items():
        txt_hits = match_nodes(txt_text, nodes, is_markdown=False, raw_text=txt_raw)
        md_hits = match_nodes(md_text, nodes, is_markdown=True, raw_text=md_raw)
        if txt_hits:
            txt_results[label] = txt_hits
        if md_hits:
            md_results[label] = md_hits

    # === Extract CVEs
    txt_cves = sorted(set(cve_pattern.findall(txt_text)))
    md_cves = sorted(set(cve_pattern.findall(md_text)))
    if txt_cves:
        txt_results["cve"] = [{"value": cve.upper(), **extract_context(txt_raw, cve)} for cve in txt_cves]
    if md_cves:
        md_results["cve"] = [{"value": cve.upper(), **extract_context(md_raw, cve, is_markdown=True)} for cve in md_cves]

    # === Extract CPEs
    txt_cpes = sorted(set(cpe_pattern.findall(txt_text)))
    md_cpes = sorted(set(cpe_pattern.findall(md_text)))
    if txt_cpes:
        print("found in txt")
        txt_results["cpe"] = [{"value": cpe.lower(), **extract_context(txt_raw, cpe)} for cpe in txt_cpes]
    if md_cpes:
        print("found in md")
        md_results["cpe"] = [{"value": cpe.lower(), **extract_context(md_raw, cpe, is_markdown=True)} for cpe in md_cpes]

    # === Write results
    with open(report_output_dir / "txt.json", "w", encoding="utf-8") as f:
        json.dump(txt_results, f, indent=2)

    with open(report_output_dir / "md.json", "w", encoding="utf-8") as f:
        json.dump(md_results, f, indent=2)

    if has_missing_context(txt_results):
        print(f"[!] Missing context in TXT JSON: {base_name}")
    if has_missing_context(md_results):
        print(f"[!] Missing context in MD JSON: {base_name}")

    print(f"[✓] Processed: {base_name}")
