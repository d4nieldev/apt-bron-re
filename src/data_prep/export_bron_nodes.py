import os
import json
from pathlib import Path

from neo4j import GraphDatabase
from dotenv import load_dotenv

# === Load credentials from .env
load_dotenv()

URI = os.environ["NEO4J_URI"]
USERNAME = os.environ["NEO4J_USERNAME"]
PASSWORD = os.environ["NEO4J_PASSWORD"]

# === Node labels and properties to export
NODE_TYPES = {
    "tactic": ["name", "_id", "original_id"],
    "capec": ["name", "_id", "original_id"],
    "cwe": ["name", "_id", "original_id"],
    "group": ["name", "_id", "original_id"],
    "technique": ["name", "_id", "original_id"],
    "cpe": ["_id"], 
    "cve": ["original_id"]
}

# === Output directory: data/layer_nodes
base_dir = Path(__file__).resolve().parents[2]  # Go up from src/data_prep/
output_dir = base_dir / "data" / "layers_nodes"
output_dir.mkdir(parents=True, exist_ok=True)

# === Neo4j connection and export logic
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
                if obj:  # only save non-empty entries
                    values.append(obj)

            output_path = output_dir / f"{label}.json"
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(values, f, indent=2)

            print(f"✅ Saved {len(values):,} {label} nodes to {output_path}")

print(f"🎉 All JSON files saved in {output_dir}")
