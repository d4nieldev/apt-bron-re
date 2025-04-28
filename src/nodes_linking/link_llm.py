# import json
# from pathlib import Path
# from collections import defaultdict
# import openai  # or use another LLM backend
#
# # === Paths ===
# # data_dir = Path("../data/entity_hits_v2")
# script_dir = Path(__file__).parent
# data_dir = script_dir.parent / "data" / "entity_hits_v2"
# output_dir = script_dir / "linked_entities"
# output_dir.mkdir(parents=True, exist_ok=True)
#
#
# # === Build prompt to send to LLM ===
# def build_prompt(e1, e2, context):
#     return f"""
# You are a cyber threat intelligence analyst.
#
# Given the sentence:
# "{context.strip()}"
#
# Entity 1: {e1['name']} ({e1.get('original_id', e1.get('_id', ''))})
# Entity 2: {e2['name']} ({e2.get('original_id', e2.get('_id', ''))})
#
# Do they describe connected concepts in the context of this attack? If so, explain how. If not, explain why not.
#
# Return JSON:
# {{
#   "linked": true/false,
#   "justification": "..."
# }}
# """
#
# client = openai.OpenAI()  # Create a client instance
#
#
# # === Call OpenAI or any other LLM ===
# def ask_llm(prompt):
#     # response = openai.ChatCompletion.create(
#     response = client.chat.completions.create(
#         model="gpt-4",
#         messages=[{"role": "user", "content": prompt}],
#         temperature=0
#     )
#     try:
#         return json.loads(response.choices[0].message.content)
#     except Exception as e:
#         print("[!] Failed to parse response:", e)
#         return {"linked": False, "justification": "Could not parse response"}
#
# # === Load sentence-entity mapping ===
# def load_entities(file_path):
#     with open(file_path, encoding="utf-8") as f:
#         data = json.load(f)
#     contexts = defaultdict(lambda: defaultdict(list))
#     for layer in data:
#         for entity in data[layer]:
#             sentence = entity.get("sentence")
#             if sentence:
#                 contexts[sentence][layer].append(entity)
#     return contexts
#
# # === Generate entity pairs ===
# def generate_pairs(contexts):
#     pairs = []
#     for sentence, layer_dict in contexts.items():
#         layers = list(layer_dict.keys())
#         for i in range(len(layers)):
#             for j in range(i+1, len(layers)):
#                 for e1 in layer_dict[layers[i]]:
#                     for e2 in layer_dict[layers[j]]:
#                         pairs.append({"e1": e1, "e2": e2, "context": sentence})
#     return pairs
#
# # === Main Process ===
# print(f"[DEBUG] Looking for files in: {data_dir.resolve()}")
# print(f"[DEBUG] Found files:", list(data_dir.glob("*/txt.json")))
#
# for json_file in data_dir.glob("*/txt.json"):
#     report_name = json_file.parent.name
#     print(f"[*] Processing: {report_name}")
#
#     contexts = load_entities(json_file)
#     pairs = generate_pairs(contexts)
#     links = []
#
#     for pair in pairs:
#         prompt = build_prompt(pair["e1"], pair["e2"], pair["context"])
#         result = ask_llm(prompt)
#
#         if result.get("linked"):
#             links.append({
#                 "from": pair["e1"].get("original_id", pair["e1"].get("_id")),
#                 "to": pair["e2"].get("original_id", pair["e2"].get("_id")),
#                 "from_name": pair["e1"]["name"],
#                 "to_name": pair["e2"]["name"],
#                 "justification": result["justification"],
#                 "context": pair["context"]
#             })
#
#     with open(output_dir / f"{report_name}_arcs.json", "w", encoding="utf-8") as f:
#         json.dump(links, f, indent=2)
#
#     print(f"[✓] Saved {len(links)} links for {report_name}")

import json
from pathlib import Path
from collections import defaultdict

# === Config ===
layer_order = ["tactic", "group", "cpe", "technique", "capec", "cwe", "cve"]
layer_index = {layer: i for i, layer in enumerate(layer_order)}

# # === Paths ===
# input_path = Path("../../data/entity_hits_v2")  # where entity .json files are
# output_path = Path("./linked_entities")
# output_path.mkdir(parents=True, exist_ok=True)

# === Paths ===
# data_dir = Path("../data/entity_hits_v2")
script_dir = Path(__file__).parent
input_path = script_dir.parent / "data" / "entity_hits_v2"
output_path = script_dir / "linked_entities"
output_path.mkdir(parents=True, exist_ok=True)

# === Helper to check valid link ===
def is_valid_link(from_layer, to_layer):
    return layer_index.get(to_layer, -1) == layer_index.get(from_layer, -1) + 1

# === Load sentence-aligned entities ===
def load_contextual_entities(file_path):
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    contexts = defaultdict(lambda: defaultdict(list))
    for layer, entities in data.items():
        for entity in entities:
            sentence = entity.get("sentence")
            if sentence:
                contexts[sentence][layer].append(entity)
    return contexts

# === Link entity pairs with justification ===
def link_entities(contexts):
    links = []
    for sentence, layer_entities in contexts.items():
        layers = list(layer_entities.keys())
        for from_layer in layers:
            for to_layer in layers:
                if not is_valid_link(from_layer, to_layer):
                    continue
                for e1 in layer_entities[from_layer]:
                    for e2 in layer_entities[to_layer]:
                        links.append({
                            "from": e1.get("original_id", e1.get("_id")),
                            "to": e2.get("original_id", e2.get("_id")),
                            "from_name": e1["name"],
                            "to_name": e2["name"],
                            "from_layer": from_layer,
                            "to_layer": to_layer,
                            "justification": f"Both entities appear in the same sentence: '{sentence.strip()}' which indicates a potential connection between a {from_layer} and a {to_layer}.",
                            "context": sentence.strip()
                        })
    return links

# === Main ===
for report_dir in input_path.glob("*/txt.json"):
    report_name = report_dir.parent.name
    print(f"[*] Linking entities in report: {report_name}")

    contextual_entities = load_contextual_entities(report_dir)
    linked_arcs = link_entities(contextual_entities)

    with open(output_path / f"{report_name}_arcs.json", "w", encoding="utf-8") as f:
        json.dump(linked_arcs, f, indent=2)

    print(f"[✓] {len(linked_arcs)} arcs saved for {report_name}")
