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

# Fields to enrich per node type
EXTRA_FIELDS = {
    "tactic": ["description"],
    "capec": ["description", "consequences", "skills_required", "likelihood_of_attack", "typical_severity"],
    "cwe": ["description", "common_consequences", "likelihood_of_exploit"],
    "group": ["description", "aliases"],
    "technique": ["description"],
    "software": ["description"]
}

# Define base directory
base_dir = Path(__file__).resolve().parents[2]
layers_dir = base_dir / "data" / "layers_nodes"

# Connect to Neo4j
driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))

with driver.session() as session:
    for node_type, extra_fields in EXTRA_FIELDS.items():
        json_path = layers_dir / f"{node_type}.json"
        if not json_path.exists():
            print(f"⚠️ Skipping {node_type} — file not found: {json_path}")
            continue

        # Load original JSON
        with json_path.open("r", encoding="utf-8") as f:
            nodes = json.load(f)

        # Prepare MATCH and RETURN clause
        match_key = "original_id" if any("original_id" in n for n in nodes) else "name"
        return_clause = ", ".join([f"n.{match_key} AS match_key"] + [f"n.{f} AS {f}" for f in extra_fields])

        query = f"""
        MATCH (n:`{node_type}`)
        RETURN {return_clause}
        """

        result = session.run(query)
        enrichments = {record["match_key"]: {f: record.get(f) for f in extra_fields} for record in result}

        # Update each node
        updated_count = 0
        for node in nodes:
            key = node.get("original_id") or node.get("name")
            if key in enrichments:
                node.update({k: v for k, v in enrichments[key].items() if v is not None})
                updated_count += 1

        # Overwrite the original file
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(nodes, f, indent=2)

        print(f"✅ Updated {updated_count:,} nodes in {json_path.name}")

driver.close()
print("🎉 All layers updated with extra fields.")