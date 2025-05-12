import os
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from collections import defaultdict
from pathlib import Path

# Disable insecure request warnings for local HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
_NER_USER = os.getenv("ner_username")
_NER_PASS = os.getenv("ner_password")

CATEGORY_MAP = {
    "TECHNIQUE": "TECHNIQUE",
    "OS": "TECHNIQUE",
    "PROTOCOL": "TECHNIQUE",
    "PROGRAMMING_LANGUAGE": "TECHNIQUE",
    "THREAT_ACTOR": "GROUP",
    "SOFTWARE": "SOFTWARE",
    "SECURITY_PRODUCT": "SOFTWARE",
    "PRODUCT": "SOFTWARE",
}


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
    plural_forms = set()
    for var in variants:
        if not var.endswith("s"):
            plural_forms.add(var + "s")
            plural_forms.add(var + "'s")
    return variants.union(plural_forms)


def _find_entities(text: str):
    url = "https://127.0.0.1:8890/tagging/get_tags_from_text"
    auth = HTTPBasicAuth(_NER_USER, _NER_PASS)
    response = requests.post(
        url=url,
        json={"text": text, "search_mode": "Combined"},
        verify=False,
        auth=auth
    )
    return response.json()


def unify_categories(tag_dict: dict[str, list[str]]) -> dict[str, list[str]]:
    unified = {}

    def _add(cat: str, value: str):
        if cat not in unified:
            unified[cat] = []
        if value not in unified[cat]:
            unified[cat].append(value)
    for orig_cat, values in tag_dict.items():
        new_cat = CATEGORY_MAP.get(orig_cat, "OTHER")
        for val in values:
            _add(new_cat, val)
    return unified


def _build_ner_lookup(ner_json: dict) -> dict[str, set[str]]:
    lookup = defaultdict(set)
    for cat, values in ner_json.items():
        cat_lc = cat.lower()
        if cat_lc in ("technique", "tactic"):
            key = "technique"
        elif cat_lc == "group":
            key = "group"
        elif cat_lc == "software":
            key = "software"
        else:
            key = "other"
        for value in values:
            lookup[key].add(value.lower())
    return lookup


def prepare_ner_lookup(text: str) -> dict[str, set[str]]:
    try:
        raw_ner = _find_entities(text)
        ner_json = unify_categories(raw_ner)
        return _build_ner_lookup(ner_json)
    except Exception as e:
        print(f"[WARN] NER failed: {e}")
        return {}


def ner_score(entry: dict, category: str, ner_lookup: dict[str, set[str]], exact_match_score: float,
              different_category_score: float, untrained_categories_score: float) -> float:

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
        return 0.0

    if category in ("technique", "tactic"):
        same_family = "technique"
    elif category in ("software", "group"):
        same_family = category
    else:
        same_family = None

    if same_family:
        if any(term in ner_lookup.get(same_family, set()) for term in search_terms):
            return exact_match_score

    if any(term in s for term in search_terms for s in ner_lookup.values()):
        if category in ("capec", "cve", "cwe", "cpe"):
            return untrained_categories_score
        return different_category_score

    return 0.0
