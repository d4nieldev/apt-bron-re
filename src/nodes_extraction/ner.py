import os
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from pathlib import Path
import json
from torch import tensor
import torch
from concurrent.futures import ThreadPoolExecutor, as_completed
from sentence_transformers import SentenceTransformer, util
from .constants import OUTPUT_DIR

# Disable insecure request warnings for local HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
_NER_USER = os.getenv("ner_username")
_NER_PASS = os.getenv("ner_password")

device = "cuda" if torch.cuda.is_available() else "cpu"

def generate_variants(text):
    """
    generates simple variants, to enable entities (names or ids) to appear
    in more than one manner
    """
    base = text.lower()
    variants = {
        base,
        base.replace("-", " "),
        base.replace("_", " "),
        base.replace(" ", "_"),
        base.replace(" ", ""),
        base.replace(" ", "-")
    }
    return variants


def _find_entities(text: str):
    url = "https://127.0.0.1:8890/tagging/get_tags_from_text"
    auth = HTTPBasicAuth(_NER_USER, _NER_PASS)
    response = requests.post(
        url=url,
        json={"text": text, "search_mode": "Lookup_Table"},
        verify=False,
        auth=auth
    )
    return response.json()


def _build_ner_lookup(ner_json: dict) -> dict[str, set[str]]:
    """
    Collapse *all* NER hits into a single set so the lookup is:
        {"all": {"apt28", "t1557.003", "cve-2023-1234", ...}}
    Every value is lower-cased to make look-ups case-insensitive.
    """
    all_terms: set[str] = set()

    for values in ner_json.values():          # ignore the original categories
        for val in values:
            all_terms.add(val.lower())

    return {"all": all_terms}


def map_ner_results(raw_ner: dict) -> dict[str, list[str]]:
    """
    Re-map raw NER output categories into simplified buckets that correspond with BRON.
    All values are preserved, only keys (categories) are changed.
    """

    category_map = {
        "TECHNIQUE": "technique",
        "OS": "others",
        "PROTOCOL": "others",
        "SOFTWARE": "software",
        "THREAT_ACTOR": "group",
        "SECURITY_PRODUCT": "software",
        "PRODUCT": "software",
        "PROGRAMMING_LANGUAGE": "others",
        "VENDOR": "software",
        "OBSERVABLE": "technique",
        "OBSERVABLE-CVE": "cve",
        "OBSERVABLE-FILENAME": "software"
    }

    mapped = {}

    for category, values in raw_ner.items():
        new_key = category_map.get(category.upper(), "others")
        mapped.setdefault(new_key, []).extend(values)

    return mapped


def prepare_ner_lookup(text: str) -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    try:
        raw_ner = _find_entities(text)
        mapped_ner = map_ner_results(raw_ner)
        return _build_ner_lookup(mapped_ner), mapped_ner
    except Exception as e:
        print(f"[WARN] NER failed: {e}")
        return {}, {}


def ner_score(entry: dict, category: str, ner_lookup: dict[str, set[str]], match_score) -> float:
    """
    Return 1 if ANY of the node’s search terms appears in ANY NER output set,
    otherwise 0.
    """
    search_terms: set[str] = set()

    if category == "group" and entry.get("alias"):
        search_terms |= {v.lower() for v in generate_variants(entry["alias"])}
    elif category in ("cve", "cpe"):
        if entry.get("value"):
            search_terms.add(entry["value"].lower())
    else:
        if entry.get("name"):
            search_terms |= {v.lower() for v in generate_variants(entry["name"])}

    if entry.get("original_id"):
        search_terms.add(entry["original_id"].lower())

    if not search_terms:
        return 0   # nothing to look for

    for ner_set in ner_lookup.values():
        if search_terms & ner_set:
            return match_score
    return 0


def process_report_with_ner_intersection(report_dir, suffix, sbert_model, semantic_flag, sim_threshold, layer_map, node_embeddings):
    ner_file = report_dir / f"{suffix}_mapped_ner_filtered.json"
    if not ner_file.exists():
        return

    try:
        with open(ner_file, encoding="utf-8") as f:
            ner_data = json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load {ner_file.name}: {e}")
        return

    matched_nodes = {}

    for ner_label, ner_values in ner_data.items():
        ner_values = [v for v in ner_values if v.strip()]
        ner_lower = {v.lower() for v in ner_values}
        ner_embeds = []
        if semantic_flag:
            ner_embeds = [(v, sbert_model.encode(v, convert_to_tensor=True)) for v in ner_values]

        # === Variant Matching (same label)
        for node in layer_map.get(ner_label, []):
            node_variants = set()
            for field in ("name", "original_id"):
                if field in node:
                    node_variants.update(generate_variants(node[field]))
            if ner_label == "group":
                for alias_field in ("MITRE_aliases", "malpedia_aliases"):
                    for alias in node.get(alias_field, []):
                        node_variants.update(generate_variants(alias))

            overlap = ner_lower & node_variants
            if overlap:
                matched = dict(node)
                matched["ner"] = list(overlap)[0]
                matched["ner_score"] = 1.0
                matched["match_type"] = "variant"
                matched_nodes.setdefault(ner_label, []).append(matched)

        # === Variant Matching (cross-label)
        for other_label, other_nodes in layer_map.items():
            if other_label == ner_label:
                continue
            for node in other_nodes:
                node_variants = set()
                for field in ("name", "original_id"):
                    if field in node:
                        node_variants.update(generate_variants(node[field]))
                if other_label == "group":
                    for alias_field in ("MITRE_aliases", "malpedia_aliases"):
                        for alias in node.get(alias_field, []):
                            node_variants.update(generate_variants(alias))

                overlap = ner_lower & node_variants
                if overlap:
                    matched = dict(node)
                    matched["ner"] = list(overlap)[0]
                    matched["ner_score"] = 0.5
                    matched["match_type"] = "variant"
                    matched_nodes.setdefault(other_label, []).append(matched)

        # === Semantic Matching
        if semantic_flag:
            for ner_str, ner_emb in ner_embeds:
                for label, emb_list in node_embeddings.items():
                    for node_emb, node_obj, node_text in emb_list:
                        score = util.cos_sim(ner_emb, node_emb).item()
                        if score >= sim_threshold:
                            matched = dict(node_obj)
                            matched["ner"] = ner_str
                            matched["ner_score"] = 1.0 if label == ner_label else 0.5  # semantic match with the same label then 1
                            matched["semantic_score"] = round(score, 4)
                            matched["match_type"] = "semantic"
                            matched_nodes.setdefault(label, []).append(matched)

    # === Save results
    if matched_nodes:
        out_path = report_dir / f"{suffix}_ner_intersection.json"
        out_path.write_text(json.dumps(matched_nodes, indent=2), encoding="utf-8")
        merge_ner_intersection_results(report_dir, suffix)
    else:
        print(f"[INFO] No matches for {report_dir.name}/{suffix}")


def ner_layers_intersection(semantic_flag, sim_threshold):
    """
    Parallelized and GPU-accelerated version of the original ner_layers_intersection.
    Performs variant and optionally semantic matching using SBERT with CUDA.
    """
    embedding_cache_path = Path(__file__).resolve().parents[2] / "data" / "embeddings" / "precomputed_node_embeddings.json"
    if not embedding_cache_path.exists():
        raise FileNotFoundError("Precomputed node embeddings file is missing. Run embeddings.py first.")

    with open(embedding_cache_path, encoding="utf-8") as f:
        precomputed = json.load(f)

    layer_map = {}
    node_embeddings = {}

    for label, entries in precomputed.items():
        node_embeddings[label] = []
        for entry in entries:
            emb_tensor = tensor(entry["embedding"])
            node = entry["node"]
            text = entry["text"]
            node_embeddings[label].append((emb_tensor, node, text))
            layer_map.setdefault(label, []).append(node)

    # Initialize SBERT (use CUDA if available)
    sbert_model = SentenceTransformer('all-MiniLM-L6-v2', device=device)

    # Run all reports in parallel
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        for report_dir in OUTPUT_DIR.iterdir():
            if not report_dir.is_dir():
                continue
            for suffix in ["txt", "md"]:
                futures.append(executor.submit(
                    process_report_with_ner_intersection,
                    report_dir, suffix,
                    sbert_model, semantic_flag, sim_threshold,
                    layer_map, node_embeddings
                ))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[ERROR] Processing report failed: {e}")


def merge_ner_intersection_results(report_dir: Path, suffix: str):
    main_path = report_dir / f"{suffix}.json"
    intersection_path = report_dir / f"{suffix}_ner_intersection.json"

    if not main_path.exists() or not intersection_path.exists():
        return

    try:
        with open(main_path, encoding="utf-8") as f:
            original_data = json.load(f)
        with open(intersection_path, encoding="utf-8") as f:
            intersection_data = json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load JSONs for merging: {e}")
        return

    # Build lookup: original_id -> entry, per category
    existing_ids = {
        cat: {entry.get("original_id", "").lower(): entry for entry in entries}
        for cat, entries in original_data.items()
    }

    remaining = {}

    for cat, matches in intersection_data.items():
        unmatched = []

        for node in matches:
            oid = node.get("original_id", "").lower()
            found = False

            for entry in existing_ids.get(cat, {}).values():
                if entry.get("original_id", "").lower() == oid:
                    found = True
                    # Update fields if applicable
                    entry["ner"] = node.get("ner")
                    entry["match_type"] = node.get("match_type")
                    if "semantic_score" in node:
                        entry["semantic_score"] = node["semantic_score"]

                    # Replace NER score if higher
                    if "ner_score" in node:
                        old_score = entry.get("NER_score", 0)
                        if node["ner_score"] > old_score:
                            entry["NER_score"] = node["ner_score"]
                    break

            if not found:
                unmatched.append(node)

        if unmatched:
            remaining[cat] = unmatched

    # Save updates
    main_path.write_text(json.dumps(original_data, indent=2), encoding="utf-8")
    if remaining:
        intersection_path.write_text(json.dumps(remaining, indent=2), encoding="utf-8")
    else:
        intersection_path.unlink(missing_ok=True)
