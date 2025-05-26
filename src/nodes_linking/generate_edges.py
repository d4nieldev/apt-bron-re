import os
import json
from constants import OUTPUT_DIR, TEXT_DIR, EDGES_BASE_DIR

from entity_loader import load_entities_and_text
from watsonx_setup import get_llm
from prompt_builder import build_prompt

ENTITY_FOLDER = OUTPUT_DIR
TEXT_FOLDER = TEXT_DIR
OUTPUT_BASE_DIR = EDGES_BASE_DIR


def find_entity_line_index(text: str, entity_name: str) -> int:
    """
    Return the first line index (0-based) where the entity name appears.
    If not found, return -1.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if entity_name in line:
            return i
    return -1

def process_documents(doc_ids, max_docs=None):
    llm = get_llm("meta-llama/llama-3-3-70b-instruct")
    # Make sure the output base directory exists
    os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

    if max_docs is not None:
        doc_ids = doc_ids[:max_docs]

    for doc_id in doc_ids:
        try:
            print(f"\n📄 Processing document: {doc_id}")
            text, entities = load_entities_and_text(doc_id)
            good_edges = []
            seen_pairs = set()

            # Compare between all entity type pairs
            for src_type, src_list in entities.items():
                for tgt_type, tgt_list in entities.items():
                    if src_type == tgt_type:
                        continue  # Skip same-type comparisons

                    for src in src_list:
                        for tgt in tgt_list:

                            key = (src_type, src["name"], tgt_type, tgt["name"])
                            if key in seen_pairs:
                                continue
                            seen_pairs.add(key)

                            # Generate edge prompt
                            prompt = build_prompt(text, src["name"], tgt["name"])
                            response = llm.invoke(prompt)
                            result = response.content.strip()

                            # Print edge information if it's "yes" or "no"'
                            if "yes" in result.lower():
                                print(f"  → [{src_type}:{src['name']}] → [{tgt_type}:{tgt['name']}]")
                                print(f"     {result}")

                                # Store edge information
                                good_edges.append({
                                    "source": src["name"],
                                    "target": tgt["name"],
                                    "source_type": src_type,
                                    "target_type": tgt_type,
                                    # "has_edge": "Yes" if "yes" in result.lower() else "No",
                                    "explanation": result,
                                    "source_line": find_entity_line_index(text, src["name"]),
                                    "target_line": find_entity_line_index(text, tgt["name"])
                                })



            if good_edges:
                # Save edges to individual file inside edges_hits/<doc_id>/edges.json
                output_dir = os.path.join(OUTPUT_BASE_DIR, doc_id)
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, "edges.json")
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(good_edges, f, indent=2)
                print(f"✅ Saved {len(good_edges)} edges to {output_path}")
            else:
                print("ℹ️ No meaningful edges found. Skipping file save.")

        except Exception as e:
            print(f"❌ Error processing {doc_id}: {e}")

# List all document IDs (folder names under entity_hits_v3)
doc_ids = [
    folder for folder in os.listdir(ENTITY_FOLDER)
    if os.path.isdir(os.path.join(ENTITY_FOLDER, folder))
]

process_documents(doc_ids, max_docs=2)
