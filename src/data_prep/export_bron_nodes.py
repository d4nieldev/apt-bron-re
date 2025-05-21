import os
import json
from pathlib import Path

from neo4j import GraphDatabase
from dotenv import load_dotenv

# === Load .env variables
load_dotenv()

URI = os.environ["NEO4J_URI"]
USERNAME = os.environ["NEO4J_USERNAME"]
PASSWORD = os.environ["NEO4J_PASSWORD"]

# === Node labels and properties
NODE_TYPES = {
    "tactic": ["name", "original_id"],
    "capec": ["name", "original_id"],
    "cwe": ["name", "original_id"],
    "group": ["name", "original_id"],
    "technique": ["name", "original_id"],
    "software": ["name", "original_id", "software_type"],
    "cpe": ["name", "original_id", "product", "vendor", "version"]
}

# === Save to: data/layer_nodes
base_dir = Path(__file__).resolve().parents[2]
output_dir = base_dir / "data" / "layers_nodes"
output_dir.mkdir(parents=True, exist_ok=True)

def extract_words(original_id: str, version: str = None, exclude_version: bool = False):
    """
    Extracts unique, non-* words from original_id.
    Optionally excludes the version string.
    """
    parts = original_id.split(":")[3:]  # Skip 'cpe:2.3:a'
    raw_words = [p for p in parts if p != "*" and p != "-"]

    seen = set()
    words = []
    for word in raw_words:
        if exclude_version and word == version:
            continue
        if word not in seen:
            seen.add(word)
            words.append(word)

    return words

# === Export nodes from Neo4j
with GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD)) as driver:
    driver.verify_connectivity()
    with driver.session() as session:
        for label, properties in NODE_TYPES.items():
            select_clause = ", ".join([f"n.{prop} AS {prop}" for prop in properties])
            order_by_clause = "n.name" if "name" in properties else properties[0]

            query = f"""
            MATCH (n:`{label}`)
            RETURN {select_clause}
            ORDER BY {order_by_clause}
            """

            result = session.run(query)

            values = []
            for record in result:
                obj = {}
                for prop in properties:
                    value = record.get(prop)
                    if value is not None:
                        obj[prop] = value
                values.append(obj)

            if label == "cpe":
                versioned = []
                unversioned = []

                for obj in values:
                    version = obj.get("version", "*")
                    original_id = obj.get("original_id")

                    if version not in ("*", "-"):
                        # CPE versioned
                        words = extract_words(original_id, version, exclude_version=True)
                        obj["words"] = words
                        obj["at_least"] = len(words) // 2 + 1
                        versioned.append(obj)
                    else:
                        # CPE unversioned
                        words = extract_words(original_id)
                        obj["words"] = words
                        obj["at_least"] = len(words) // 2 + 1
                        unversioned.append(obj)

                # Save both files
                path_versioned = output_dir / "cpe_versioned.json"
                path_unversioned = output_dir / "cpe_unversioned.json"

                with path_versioned.open("w", encoding="utf-8") as f:
                    json.dump(versioned, f, indent=2)
                with path_unversioned.open("w", encoding="utf-8") as f:
                    json.dump(unversioned, f, indent=2)

                print(f"✅ Saved {len(versioned):,} versioned CPE nodes to {path_versioned}")
                print(f"✅ Saved {len(unversioned):,} unversioned CPE nodes to {path_unversioned}")
            else:
                # Non-CPE: Save as usual
                output_path = output_dir / f"{label}.json"
                with output_path.open("w", encoding="utf-8") as f:
                    json.dump(values, f, indent=2)
                print(f"✅ Saved {len(values):,} {label} nodes to {output_path}")

print(f"🎉 All JSON files saved in {output_dir}")
