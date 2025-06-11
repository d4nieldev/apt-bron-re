from constants import OUTPUT_DIR, TEXT_DIR
import os
import json


def load_entities_and_text(doc_id: str) -> tuple[str, dict]:
    entity_path = OUTPUT_DIR / doc_id / "combined.json"
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


def extract_text_between_indexes(text: str, index1: int, index2: int) -> str:
    """
    Extracts a substring from the full text between two indexes.
    Indexes refer to character positions in the full string.

    Parameters:
        text (str): The full document text.
        index1 (int): The first index (can be before or after index2).
        index2 (int): The second index.

    Returns:
        str: Substring of text between the two indexes.
    """
    if not (isinstance(index1, int) and isinstance(index2, int)):
        raise ValueError("Both indexes must be integers.")

    start = min(index1, index2)
    end = max(index1, index2)

    return text[start:end]
