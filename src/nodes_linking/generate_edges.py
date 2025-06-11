import os
import json
import time
from constants import OUTPUT_DIR, TEXT_DIR, EDGES_BASE_DIR
from entity_loader import load_entities_and_text
from watsonx_setup import get_llm, generate_many
from prompt_builder import build_prompt, format_entity
from langchain_core.output_parsers import StrOutputParser

# === Define directory constants for input/output ===
ENTITY_FOLDER = OUTPUT_DIR
TEXT_FOLDER = TEXT_DIR
OUTPUT_BASE_DIR = EDGES_BASE_DIR

def process_documents(doc_ids, max_docs=None):
    start_time = time.time()
    llm = get_llm("meta-llama/llama-3-3-70b-instruct")
    # Make sure the output base directory exists
    os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

    # Limit the number of documents if specified
    if max_docs is not None:
        doc_ids = doc_ids[:max_docs]

    for doc_id in doc_ids:
        try:
            print(f"\nProcessing document: {doc_id}")
            text, entities = load_entities_and_text(doc_id)
            seen_pairs = set() # Keep track of already processed entity pairs
            prompts_inputs = [] # List to hold LLM prompt inputs
            pair_metadata = [] # Track metadata for each entity pair (types and names)

            # Compare between all entity type pairs
            for type_a, list_a in entities.items():
                for type_b, list_b in entities.items():
                    if type_a == type_b:
                        continue # Skip same-type comparisons

                    for ent_a in list_a:
                        for ent_b in list_b:
                            # Normalize to dictionary with 'name' if needed
                            ent_a = {"name": ent_a} if isinstance(ent_a, str) else ent_a
                            ent_b = {"name": ent_b} if isinstance(ent_b, str) else ent_b

                            # Sort keys to ensure symmetric uniqueness for (A, B) and (B, A)
                            key = tuple(sorted([(type_a, ent_a["name"]), (type_b, ent_b["name"])]))
                            if key in seen_pairs:
                                continue
                            seen_pairs.add(key)

                            entity_a_str = format_entity(ent_a, "Entity A")
                            entity_b_str = format_entity(ent_b, "Entity B")

                            # Prepare prompt input with article and entity JSONs
                            prompts_inputs.append({
                                "article_text": text,
                                "entity_a": entity_a_str,
                                "entity_b": entity_b_str
                            })
                            pair_metadata.append((type_a, ent_a["name"], type_b, ent_b["name"]))

            if not prompts_inputs:
                print("No entity pairs found for processing.")
                continue

            # Generate predictions in batch using generate_many
            results = generate_many(
                prompt=build_prompt(),
                inputs=prompts_inputs,
                llm=llm,
                output_parser=StrOutputParser(),
                description=f"Generating edges for {doc_id}"
            )
            # Extract valid "Yes" edges
            good_edges = []
            for result, (type_a, name_a, type_b, name_b) in zip(results, pair_metadata):
                if not result.result:
                    continue
                if "yes" in result.result.lower():
                    print(f"  -> [{type_a}:{name_a}] ~ [{type_b}:{name_b}]\n     {result.result}")
                    good_edges.append({
                        "entity_1": name_a,
                        "entity_2": name_b,
                        "type_1": type_a,
                        "type_2": type_b,
                        "explanation": result.result.strip()
                    })

            # Save output only if there are good edges
            if good_edges:
                output_dir = os.path.join(EDGES_BASE_DIR, doc_id)
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, "edges.json")
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(good_edges, f, indent=2)
                print(f"Saved {len(good_edges)} edges to {output_path}")
            else:
                print("No meaningful edges found. ")

        except Exception as e:
            print(f"Error processing {doc_id}: {e}")

    end_time = time.time()
    total_time = end_time - start_time
    print(f"Finished in {total_time} seconds.")

# List all document IDs (folder names under entity_hits_v3)
doc_ids = [
    folder for folder in os.listdir(ENTITY_FOLDER)
    if os.path.isdir(os.path.join(ENTITY_FOLDER, folder))
]

process_documents(doc_ids, max_docs=1)


