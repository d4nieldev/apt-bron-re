import os
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from pathlib import Path

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
        json={"text": text, "search_mode": "Combined"},
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

def prepare_ner_lookup(text: str) -> dict[str, set[str]]:
    try:
        raw_ner = _find_entities(text)
        return _build_ner_lookup(raw_ner)
    except Exception as e:
        print(f"[WARN] NER failed: {e}")
        return {}


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
