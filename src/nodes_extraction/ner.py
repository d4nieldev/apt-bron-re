import os
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from pathlib import Path
import json

from .constants import OUTPUT_DIR, LAYER_DIR

# Disable insecure request warnings for local HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
_NER_USER = os.getenv("ner_username")
_NER_PASS = os.getenv("ner_password")


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


def ner_layers_intersection():
    """
    For each report and each suffix (txt/md), loads *_mapped_ner_filtered.json,
    intersects with corresponding nodes in LAYER_DIR (via variants),
    and writes results to <report_dir>/<suffix>_ner_intersection.json.
    """

    # Load all layer data once
    layer_map = {}
    for layer_file in LAYER_DIR.glob("*.json"):
        if layer_file.stem == "cpe_unversioned":
            continue
        with open(layer_file, encoding="utf-8") as f:
            layer_map[layer_file.stem] = json.load(f)

    for report_dir in OUTPUT_DIR.iterdir():
        if not report_dir.is_dir():
            continue

        for suffix in ["txt", "md"]:
            ner_file = report_dir / f"{suffix}_mapped_ner_filtered.json"
            if not ner_file.exists():
                continue

            try:
                with open(ner_file, encoding="utf-8") as f:
                    ner_data = json.load(f)
            except Exception as e:
                print(f"[WARN] Failed to load {ner_file.name}: {e}")
                continue

            matched_nodes = {}

            for label, nodes in layer_map.items():
                ner_candidates = set(ner_data.get(label, []))
                if not ner_candidates:
                    continue

                ner_candidates = {v.lower() for v in ner_candidates}
                matches = []

                for node in nodes:
                    node_variants = set()

                    # Basic fields
                    for field in ("name", "original_id"):
                        if field in node:
                            node_variants.update(generate_variants(node[field]))

                    # Group-specific aliases
                    if label == "group":
                        for alias_field in ("MITRE_aliases", "malpedia_aliases"):
                            for alias in node.get(alias_field, []):
                                node_variants.update(generate_variants(alias))

                    intersection = ner_candidates & node_variants
                    if intersection:
                        matched_node = dict(node)
                        matched_node["ner"] = list(intersection)[0]
                        matches.append(matched_node)

                if matches:
                    matched_nodes[label] = matches

            if matched_nodes:
                out_path = report_dir / f"{suffix}_ner_intersection.json"
                out_path.write_text(json.dumps(matched_nodes, indent=2), encoding="utf-8")
            else:
                print("no match found")
