import os
import json

from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

URI = os.environ["NEO4J_URI"]
USERNAME = os.environ["NEO4J_USERNAME"]
PASSWORD = os.environ["NEO4J_PASSWORD"]

NODE_TYPES = {
    "tactic": ["name", "_id", "original_id"],
    "capec": ["name", "_id", "original_id"],
    "cwe": ["name", "_id", "original_id"],
    "group": ["name", "_id", "original_id"],
    "technique": ["name", "_id", "original_id"],
    "cpe": ["_id"],  # TODO unsure if usable for querying reports
    "cve": ["original_id"]
}

OUTPUT_DIR = "layers_nodes"
os.makedirs(OUTPUT_DIR, exist_ok=True)

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

            filename = os.path.join(OUTPUT_DIR, f"{label}.json")
            with open(filename, "w") as f:
                json.dump(values, f, indent=2)

            print(f"✅ Saved {len(values):,} {label} nodes to {filename}")

print("🎉 All JSON files saved in layers_nodes/")
