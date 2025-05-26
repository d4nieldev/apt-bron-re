import os
import json
from constants import OUTPUT_DIR, TEXT_DIR, EDGES_BASE_DIR

from entity_loader import load_entities_and_text
from watsonx_setup import get_llm
from prompt_builder import build_prompt

llm = get_llm("meta-llama/llama-3-3-70b-instruct")

# ENTITY_FOLDER = "../../data/entity_hits_v3"
# OUTPUT_BASE_DIR = "data/edges_hits"

ENTITY_FOLDER = OUTPUT_DIR
TEXT_FOLDER = TEXT_DIR
OUTPUT_BASE_DIR = EDGES_BASE_DIR

# List all document IDs (folder names under entity_hits_v3)
doc_ids = [
    folder for folder in os.listdir(ENTITY_FOLDER)
    if os.path.isdir(os.path.join(ENTITY_FOLDER, folder))
]

# Make sure the output base directory exists
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

for doc_id in doc_ids:
    try:
        print(f"\n📄 Processing document: {doc_id}")
        text, entities = load_entities_and_text(doc_id)

        doc_edges = []

        # Compare between all entity type pairs
        for src_type, src_list in entities.items():
            for tgt_type, tgt_list in entities.items():
                if src_type == tgt_type:
                    continue  # Skip same-type comparisons

                for src in src_list:
                    for tgt in tgt_list:
                        prompt = build_prompt(text, src["name"], tgt["name"])

                        response = llm.invoke(prompt)
                        result = response.content.strip()

                        print(f"  → [{src_type}:{src['name']}] → [{tgt_type}:{tgt['name']}]")
                        print(f"     {result}")

                        # Store edge information
                        doc_edges.append({
                            "source": src["name"],
                            "target": tgt["name"],
                            "source_type": src_type,
                            "target_type": tgt_type,
                            "has_edge": "Yes" if "yes" in result.lower() else "No",
                            "explanation": result
                        })

        # Save edges to individual file inside edges_hits/<doc_id>/edges.json
        output_dir = os.path.join(OUTPUT_BASE_DIR, doc_id)
        os.makedirs(output_dir, exist_ok=True)

        output_path = os.path.join(output_dir, "edges.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(doc_edges, f, indent=2)

        print(f"✅ Saved {len(doc_edges)} edges to {output_path}")

    except Exception as e:
        print(f"❌ Error processing {doc_id}: {e}")