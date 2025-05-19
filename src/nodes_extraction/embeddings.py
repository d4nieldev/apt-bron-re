from sentence_transformers import SentenceTransformer
import json
from pathlib import Path
from nodes_extraction.constants import LAYER_DIR

sbert_model = SentenceTransformer("all-MiniLM-L6-v2")
output_path = Path(__file__).resolve().parents[2] / "data" / "embeddings" / "precomputed_node_embeddings.json"

result = {}


def get_node_embedding_candidates(node: dict, label: str) -> list[str]:
    fields = [node.get("name", ""), node.get("original_id", "")]
    if label == "group":
        for alias_field in ("MITRE_aliases", "malpedia_aliases"):
            fields.extend(node.get(alias_field, []))
    return [f for f in fields if f]


for layer_file in LAYER_DIR.glob("*.json"):
    label = layer_file.stem
    if label in {"cpe_unversioned", "cpe_versioned"}:
        continue

    with open(layer_file, encoding="utf-8") as f:
        nodes = json.load(f)

    result[label] = []
    for node in nodes:
        for text in get_node_embedding_candidates(node, label):
            emb = sbert_model.encode(text).tolist()
            result[label].append({
                "embedding": emb,
                "text": text,
                "node": node
            })

output_path.parent.mkdir(parents=True, exist_ok=True)

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print("finished computing embeddings for layers' nodes' names and ids")
