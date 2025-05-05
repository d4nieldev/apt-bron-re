import json
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
from pathlib import Path
import os

ENV_PATH = Path(__file__).resolve().parents[1]
load_dotenv(ENV_PATH)

ner_username = os.getenv("ner_username")
ner_paswword = os.getenv("ner_password")

report_name = "ESET_WinorDLL64-Lazarus-arsenal(02-23-2023).txt"
file_path = Path("data/converted_reports/texts") / report_name


def find_entities(text: str):
  url = "https://127.0.0.1:8890/tagging/get_tags_from_text"
  auth = HTTPBasicAuth(ner_username, ner_paswword)

  keywords_dict = requests.post(
    url=url,
    json={
      'text': text,
      'search_mode': 'Combined'},
    verify=False,
    auth=auth
  ).json()

  return keywords_dict


# -------------- NO CHANGES ABOVE THIS LINE ------------------

# maps original categories ➜ unified buckets
CATEGORY_MAP = {
    # collapse to TECHNIQUE
    "TECHNIQUE": "TECHNIQUE",
    "OS": "TECHNIQUE",
    "PROTOCOL": "TECHNIQUE",
    "PROGRAMMING_LANGUAGE": "TECHNIQUE",
    # collapse to GROUP
    "THREAT_ACTOR": "GROUP",
    # collapse to SOFTWARE
    "SOFTWARE": "SOFTWARE",
    "SECURITY_PRODUCT": "SOFTWARE",
    "PRODUCT": "SOFTWARE",
}


def unify_categories(tag_dict: dict[str, list[str]]) -> dict[str, list[str]]:
    """
    Post-processes the raw tag output:
    • Maps categories according to CATEGORY_MAP
    • Puts everything else under 'OTHER'
    • Removes duplicates while preserving the original order
    """
    unified: dict[str, list[str]] = {}

    def _add(cat: str, value: str) -> None:
        if cat not in unified:
            unified[cat] = []
        # keep order but avoid duplicates
        if value not in unified[cat]:
            unified[cat].append(value)

    for orig_cat, values in tag_dict.items():
        new_cat = CATEGORY_MAP.get(orig_cat, "OTHER")
        for v in values:
            _add(new_cat, v)

    return unified


if __name__ == "__main__":
    with file_path.open(encoding="utf-8") as f:
        report_text = f.read()

    raw_response = find_entities(report_text)
    processed_response = unify_categories(raw_response)

    # Pretty-print the final JSON
    print(json.dumps(processed_response, indent=2))
