from constants import OUTPUT_DIR, TEXT_DIR
import os
import json


def load_entities_and_text(doc_id: str) -> tuple[str, dict]:
    entity_path = OUTPUT_DIR / doc_id / "md.json"
    text_path = TEXT_DIR / f"{doc_id}.txt"

    print(f"🔍 Looking for: {text_path}")
    if not text_path.exists():
        raise FileNotFoundError(f"Text file not found: {text_path}")
    if not entity_path.exists():
        raise FileNotFoundError(f"Entity file not found: {entity_path}")

    with text_path.open("r", encoding="utf-8") as f:
        text = f.read()
    with entity_path.open("r", encoding="utf-8") as f:
        entities = json.load(f)

    return text, entities
