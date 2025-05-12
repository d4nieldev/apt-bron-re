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

# === Save to: data/layer_nodes (one level outside /src/)
base_dir = Path(__file__).resolve().parents[2]
output_dir = base_dir / "data" / "layers_nodes"
output_dir.mkdir(parents=True, exist_ok=True)

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

                # === Add `words` field for CPE entries
                if label == "cpe" and "original_id" in obj:
                    parts = obj["original_id"].split(":")[3:]  # Skip first 3 parts
                    raw_words = [p for p in parts if p != "*"]

                    seen = set()
                    words = []
                    for word in raw_words:
                        if word not in seen:
                            seen.add(word)
                            words.append(word)

                    obj["words"] = words
                    obj["at_least"] = len(words) // 2 + 1

                if obj:
                    values.append(obj)

            output_path = output_dir / f"{label}.json"
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(values, f, indent=2)

            print(f"✅ Saved {len(values):,} {label} nodes to {output_path}")

print(f"🎉 All JSON files saved in {output_dir}")
