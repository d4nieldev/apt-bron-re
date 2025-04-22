import json
from pathlib import Path
from collections import defaultdict
from statistics import mean, stdev

# Choose directory for stats output (combined or basic)
input_dir = Path("../data/statistical_combined_entity_scores")
summary_file = Path("../data/statistical_summary.json")

summary = {
    "global_tactic_stats": {},
    # "per_document_summary": {}
}

all_tactic_data = defaultdict(list)

for file in input_dir.glob("*_tactic_stats.json"):
    data = json.loads(file.read_text(encoding="utf-8"))
    doc_name = file.stem.replace("_tactic_stats", "")
    tactic_data = data.get("tactics", data)  # handles both with or without __info__

    doc_summary = {
        "total_tactics": len(tactic_data),
        "total_mentions": 0,
        "top_tactics": []
    }

    top_scored = sorted(tactic_data.items(), key=lambda x: x[1]["score"], reverse=True)
    for name, details in tactic_data.items():
        count = details["count_in_doc"]
        score = details["score"]
        norm_freq = details["normalized_freq"]

        all_tactic_data[name].append({
            "count": count,
            "score": score,
            "normalized_freq": norm_freq
        })

        doc_summary["total_mentions"] += count

    # doc_summary["top_tactics"] = [
    #     {"name": name, "score": round(data["score"], 2)}
    #     for name, data in top_scored[:3]
    # ]
    # summary["per_document_summary"][doc_name] = doc_summary

# Global tactic stats
for tactic_name, entries in all_tactic_data.items():
    counts = [e["count"] for e in entries]
    scores = [e["score"] for e in entries]
    freqs = [e["normalized_freq"] for e in entries]

    summary["global_tactic_stats"][tactic_name] = {
        "total_mentions": sum(counts),
        "docs_mentioned": len(entries),
        "avg_score": round(mean(scores), 2),
        "avg_normalized_freq": round(mean(freqs), 4),
        "score_std_dev": round(stdev(scores), 2) if len(scores) > 1 else 0
    }

with open(summary_file, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print("[✓] Summary saved to:", summary_file)
