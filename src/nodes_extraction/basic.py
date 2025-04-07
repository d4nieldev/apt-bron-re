import re
import json
from pathlib import Path
from datetime import datetime

# === Paths ===
text_dir = Path("data/converted_reports/texts")
md_dir = Path("data/converted_reports/markdown")
output_base_dir = Path("data/entity_hits_v2")
layer_dir = Path("data/layers_nodes")  # the jsons to compare with

# === Load all layers except cve/cpe into a dictionary ===
excluded_layers = {"cve", "cpe"}
layer_map = {}

for layer_file in layer_dir.glob("*.json"):
    label = layer_file.stem
    if label not in excluded_layers:
        with open(layer_file, encoding="utf-8") as f:
            layer_map[label] = json.load(f)

# === Load Techniques and sub-techniques into a dictionary, key is parent-technique, the values lists is the sub-techniques===
technique_sub_map = {}
if "technique" in layer_map:
    for node in layer_map["technique"]:
        tid = node.get("original_id", "").upper()
        if "." in tid:
            parent = tid.split(".")[0]
            technique_sub_map.setdefault(parent, []).append(tid)

# === Regex patterns ===
cve_pattern = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)  # captures cve-YYYY-at_least_one_digit
cpe_pattern = re.compile(r"\bcpe:(?:2\.3:|/)[aoh]:[^\s:]+:[^\s:]+(?::[^\s:]*){0,10}", re.IGNORECASE)  # cpe standard formats


def write_summary_totals_txt(global_summary_path: Path, output_base_dir: Path):
    if not global_summary_path.exists():
        print(f"[!] global_summary.json not found at {global_summary_path}")
        return

    with open(global_summary_path, encoding="utf-8") as f:
        global_summary = json.load(f)

    txt_totals = {}
    md_totals = {}

    for report in global_summary.values():
        for label, count in report.get("txt_counts", {}).items():
            txt_totals[label] = txt_totals.get(label, 0) + count
        for label, count in report.get("md_counts", {}).items():
            md_totals[label] = md_totals.get(label, 0) + count

    lines = ["=== Total Entity Counts Across All Reports ===\n"]

    lines.append("[TXT]")
    for label, count in sorted(txt_totals.items()):
        lines.append(f"{label}: {count}")

    lines.append("\n[MD]")
    for label, count in sorted(md_totals.items()):
        lines.append(f"{label}: {count}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    output_path = output_base_dir / f"{timestamp}_summary.txt"
    output_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"[✓] Wrote summary totals to: {output_path.name}")


def read_file(file_path: Path):
    try:
        return file_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[!] Failed to read {file_path.name}: {e}")
        return ""


def normalize_name(name: str) -> list:
    base = name.lower()
    variants = {base, base.replace("-", " "), base.replace(" ", ""), base.replace(" ", "-")}
    return list(variants)


def split_sentences(text):
    # Avoid splitting on common abbreviations and inside parentheses, used to add "sentence" field to the output json
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


def normalize_id(id_str: str) -> str:
    # Lowercase, remove non-alphanumerics (except underscore), strip leading zeros
    return re.sub(r'\b0+(\d+)', r'\1', id_str.lower())


def match_nodes(text: str, nodes: list[dict], label: str, is_markdown=False, raw_text=""):
    seen = set()
    hits = []

    lines = raw_text.splitlines()
    sentences = split_sentences(re.sub(r'\n+', ' ', raw_text))  # Cleaned for sentence extraction

    for node in nodes:
        name = node.get("name", "").lower()
        original_id = node.get("original_id", "").lower()
        if label == "technique" and original_id:
            original_id_upper = original_id.upper()
            if "." not in original_id_upper:
                subs = technique_sub_map.get(original_id_upper, [])
                parent_pattern = re.compile(rf"\b{re.escape(original_id.lower())}\b")
                parent_appears = parent_pattern.search(text)

                sub_appears = any(
                    re.search(rf"\b{re.escape(sub.lower())}\b", text) for sub in subs
                )

                if not parent_appears and sub_appears:
                    continue  # only skip if sub appears and parent doesn't

            pattern = re.compile(rf"\b{re.escape(original_id)}\b")
            if not pattern.search(text):
                continue  # skip if exact technique ID not found

        name_variants = normalize_name(name)
        if original_id:
            name_variants.append(original_id)

        found_by = []
        line_number = None
        matched_sentence = None
        matched_line_text = None

        # === Special handling for techniques ===
        if label == "technique" and original_id:
            pattern = re.compile(rf"\b{re.escape(original_id)}\b")
            if not pattern.search(text):
                continue  # skip if exact ID not found

        # Step 1: Find the line number
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(re.search(rf"\b{re.escape(variant)}\b", line_lower) for variant in name_variants):
                line_number = i
                matched_line_text = line_lower
                break

        if line_number is not None:
            # Step 2: Find the sentence that contains the variant
            for s in sentences:
                s_lower = s.lower()
                if any(re.search(rf"\b{re.escape(variant)}\b", s_lower) for variant in name_variants):
                    matched_sentence = s.strip()
                    break

            # Step 3: Confirm why it matched (name/original_id)
            if any(re.search(rf"\b{re.escape(variant)}\b", matched_line_text) for variant in name_variants):
                found_by.append("name")
            if original_id and re.search(rf"\b{re.escape(normalize_id(original_id))}\b", matched_line_text):
                found_by.append("original_id")

            key = json.dumps(node, sort_keys=True)
            if key not in seen:
                seen.add(key)
                enriched_node = dict(node)
                enriched_node.update({
                    "line": line_number,
                    "sentence": matched_sentence,
                    "found_by": found_by
                })
                hits.append(enriched_node)

    return hits


def find_line_and_sentence_exact(text: str, matches: list[str]) -> dict:
    lines = text.splitlines()
    flat_text = re.sub(r'\n+', ' ', text)
    sentences = split_sentences(flat_text)
    result = {}

    for match in matches:
        pattern = re.compile(rf"\b{re.escape(match.lower())}\b")
        line_number = None
        sentence = None

        for i, line in enumerate(lines):
            if pattern.search(line.lower()):
                line_number = i
                break

        for s in sentences:
            if pattern.search(s.lower()):
                sentence = s.strip()
                break

        result[match.lower()] = {
            "line": line_number,
            "sentence": sentence
        }

    return result


if __name__ == "__main__":
    all_summaries = {}

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
            txt_hits = match_nodes(txt_text, nodes, label=label, is_markdown=False, raw_text=txt_raw)
            md_hits = match_nodes(md_text, nodes, label=label, is_markdown=True, raw_text=md_raw)
            if txt_hits:
                txt_results[label] = txt_hits
            if md_hits:
                md_results[label] = md_hits

        # === Extract CVEs
        txt_cves = sorted(set(cve_pattern.findall(txt_text)))
        md_cves = sorted(set(cve_pattern.findall(md_text)))

        txt_cpes = sorted(set(cpe_pattern.findall(txt_text)))
        md_cpes = sorted(set(cpe_pattern.findall(md_text)))

        if txt_cves:
            ctx_map = find_line_and_sentence_exact(txt_raw, txt_cves)
            txt_results["cve"] = [
                {
                    "value": cve.upper(),
                    "line": ctx_map.get(cve.lower(), {}).get("line"),
                    "sentence": ctx_map.get(cve.lower(), {}).get("sentence")
                }
                for cve in txt_cves
            ]

        if md_cves:
            ctx_map = find_line_and_sentence_exact(md_raw, md_cves)
            md_results["cve"] = [
                {
                    "value": cve.upper(),
                    "line": ctx_map.get(cve, {}).get("line"),
                    "sentence": ctx_map.get(cve, {}).get("sentence")
                }
                for cve in md_cves
            ]

        if txt_cpes:
            print("found in txt")
            ctx_map = find_line_and_sentence_exact(txt_raw, txt_cpes)
            txt_results["cpe"] = [
                {
                    "value": cpe.lower(),
                    "line": ctx_map.get(cpe, {}).get("line"),
                    "sentence": ctx_map.get(cpe, {}).get("sentence")
                }
                for cpe in txt_cpes
            ]

        if md_cpes:
            print("found in md")
            ctx_map = find_line_and_sentence_exact(md_raw, md_cpes)
            md_results["cpe"] = [
                {
                    "value": cpe.lower(),
                    "line": ctx_map.get(cpe, {}).get("line"),
                    "sentence": ctx_map.get(cpe, {}).get("sentence")
                }
                for cpe in md_cpes
            ]

        # === Write results
        with open(report_output_dir / "txt.json", "w", encoding="utf-8") as f:
            json.dump(txt_results, f, indent=2)

        with open(report_output_dir / "md.json", "w", encoding="utf-8") as f:
            json.dump(md_results, f, indent=2)

        # === Count entity types per document ===
        txt_summary = {label: len(items) for label, items in txt_results.items()}
        md_summary = {label: len(items) for label, items in md_results.items()}

        summary = {
            "txt_counts": txt_summary,
            "md_counts": md_summary
        }

        with open(report_output_dir / "summary_counts.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        all_summaries[base_name] = summary

        print(f"[✓] Processed: {base_name}")

    global_summary_path = output_base_dir / "global_summary.json"
    with open(global_summary_path, "w", encoding="utf-8") as f:
        json.dump(all_summaries, f, indent=2)
    write_summary_totals_txt(global_summary_path, output_base_dir)
