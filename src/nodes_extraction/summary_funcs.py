import json
from pathlib import Path
from collections import defaultdict
from statistics import mean, stdev
import matplotlib.pyplot as plt


def write_summary_counts(report_dir: Path):
    """
    compares between the outputs originating from both types of filetypes to which the report was converted,
    inserts the summary of that comparison into summary_counts.json, on the same report_dir (dir named after the report)
    """
    summary = {}
    for json_file in ["txt.json", "md.json"]:
        path = report_dir / json_file
        if path.exists():
            with open(path, encoding="utf-8") as j_file:
                data = json.load(j_file)
            summary_key = "txt_counts" if "txt" in json_file else "md_counts"
            summary[summary_key] = {category: len(entries) for category, entries in data.items()}
    if summary:
        with open(report_dir / "summary_counts.json", "w", encoding="utf-8") as sum_file:
            json.dump(summary, sum_file, indent=2)
    return summary


def write_summary_for_entity_hits_v3(base_dir: Path, summary_output_dir: Path):
    """
    writes a timestamped global summary of the nodes extraction, to compare with previous attempts
    to be inserted to entity_hits_v3/summaries, and also a summary/comparison between the number of entities
    in the reports, stored in entity_hits_v3/global_summary.json
    """
    global_summary = {}
    for report_dir in base_dir.iterdir():
        if report_dir.is_dir():
            summary = write_summary_counts(report_dir)
            if summary:
                global_summary[report_dir.name] = summary

    summary_txt = ["=== Total Entity Counts Across All Reports ===\n"]
    txt_totals = {}
    md_totals = {}

    for report in global_summary.values():
        for category, count in report.get("txt_counts", {}).items():
            txt_totals[category] = txt_totals.get(category, 0) + count
        for category, count in report.get("md_counts", {}).items():
            md_totals[category] = md_totals.get(category, 0) + count

    summary_txt.append("[TXT]")
    for category, count in sorted(txt_totals.items()):
        summary_txt.append(f"{category}: {count}")
    summary_txt.append("\n[MD]")
    for category, count in sorted(md_totals.items()):
        summary_txt.append(f"{category}: {count}")

    summary_output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = summary_output_dir / "summary_counts.txt"
    summary_path.write_text("\n".join(summary_txt), encoding="utf-8")
    global_summary_path = summary_output_dir / "global_summary.json"

    with open(global_summary_path, "w", encoding="utf-8") as global_file:
        json.dump(global_summary, global_file, indent=2)


def compare_differences(tables_json_path: Path, reports_json_path: Path, output_comparison_path: Path):
    """
    Compares entities between tables-only and full-reports, finding nodes
    that exist only in one of them (by original_id, regardless of name/index).
    Saves the differences to output_comparison_path as JSON.
    """
    try:
        with open(tables_json_path, encoding="utf-8") as fil:
            tables_data = json.load(fil)
        with open(reports_json_path, encoding="utf-8") as g:
            reports_data = json.load(g)
    except Exception as e:
        print(f"Failed to load input JSONs: {e}")
        return

    comparison = {}
    all_report_names = set(tables_data.keys()).union(reports_data.keys())

    for report_name in all_report_names:
        tables_report = tables_data.get(report_name, {})
        reports_report = reports_data.get(report_name, {})

        only_table = {}
        only_report = {}

        all_categories = set(tables_report.keys()).union(reports_report.keys())

        for category in all_categories:
            tables_nodes = tables_report.get(category, [])
            reports_nodes = reports_report.get(category, [])

            tables_ids = {entry.get("original_id", entry.get("value", "")).lower() for entry in tables_nodes}
            reports_ids = {entry.get("original_id", entry.get("value", "")).lower() for entry in reports_nodes}

            table_extras = tables_ids - reports_ids
            report_extras = reports_ids - tables_ids

            if table_extras:
                only_table[category] = sorted(list(table_extras))
            if report_extras:
                only_report[category] = sorted(list(report_extras))

        if only_table or only_report:
            comparison[report_name] = {
                "only table": only_table,
                "only report": only_report
            }

    output_comparison_path.write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    print(f"Differences saved to {output_comparison_path}")


def summarize_problematic_names(base_dir: Path, threshold=1.0, max_above_ratio=0.5, output_dir: Path = None):
    """
    Finds names for which more than 90% of their BM25 scores are under the threshold,
    and writes a summary including the few cases where they appear with higher scores.
    """

    # Structure: {label: {name: [("report_id", score), ...]}}
    score_map = defaultdict(lambda: defaultdict(list))

    # Gather all scores per name
    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue
        json_path = report_dir / "txt.json"
        if not json_path.exists():
            continue

        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)

            for label in ["group", "tactic", "technique", "software", "capec", "cwe"]:
                for entry in data.get(label, []):
                    name = entry.get("name", "").strip().lower()
                    score = entry.get("bm25_score", 0)
                    if name:
                        score_map[label][name].append((report_dir.name, score))
        except Exception as e:
            print(f"[!] Failed to read or parse {json_path}: {e}")

    # Analyze and write results
    lines = ["=== BM25 Problematic Names Summary ===\n"]
    for label in sorted(score_map.keys()):
        lines.append(f"\n>>> Category: {label.upper()}")
        for name, score_list in sorted(score_map[label].items()):
            total = len(score_list)
            under = sum(1 for _, s in score_list if s < threshold)
            ratio_under = under / total if total else 0

            if ratio_under >= (1 - max_above_ratio):
                lines.append(f"\n  - {name} ({under}/{total} under {threshold})")
                for report_id, s in score_list:
                    if s >= threshold:
                        lines.append(f"      [✓] Report: {report_id}, score: {s:.4f}")

    # Save summary
    output_path = output_dir if output_dir else Path("data/bm25_problematic_names_summary.txt")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[✓] Summary written to {output_path}")


def generate_bm25_statistics_and_histograms(base_dir: Path, min_occurrences: int = 5, threshold: float = 1.0, output_txt_path: Path = None, output_hist_dir: Path = None):
    """
    For each vertex type (group, tactic, etc.), calculates average BM25 and standard deviation,
    writes summary statistics sorted by mean score (descending), and generates histograms
    for entities that appear more than `min_occurrences` times.

    Output:
    - Text summary to 'data/bm25_statistics_summary.txt'
    - Histogram images in 'data/bm25_histograms/'
    """

    name_scores = defaultdict(lambda: defaultdict(list))  # {label: {name: [score1, score2, ...]}}
    stats_lines = ["=== BM25 Mean & Std Dev + Histograms ===\n"]

    hist_dir = output_hist_dir or Path("data/bm25_histograms")
    hist_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Collect BM25 scores from txt.json
    for report_dir in base_dir.iterdir():
        if not report_dir.is_dir():
            continue
        json_path = report_dir / "txt.json"
        if not json_path.exists():
            continue

        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)

            for label in ["group", "tactic", "technique", "software", "capec", "cwe"]:
                for entry in data.get(label, []):
                    name = entry.get("name", "").strip().lower()
                    score = entry.get("bm25_score", 0)
                    if name:
                        name_scores[label][name].append(score)
        except Exception as e:
            print(f"[!] Failed to read or parse {json_path}: {e}")

    # Step 2: Analyze and write stats
    for label in sorted(name_scores.keys()):
        stats_lines.append(f"\n>>> Category: {label.upper()}")

        sorted_items = sorted(
            name_scores[label].items(),
            key=lambda item: mean(item[1]),
            reverse=True
        )

        for name, scores in sorted_items:
            if len(scores) < 2:
                continue  # skip nodes with insufficient stats

            avg = mean(scores)
            std = stdev(scores)
            above = sum(1 for s in scores if s >= threshold)
            below = len(scores) - above
            ratio_above = above / len(scores)

            if ratio_above == 1:
                continue  # Skip if 100% are above threshold (i.e., always dominant)

            stats_lines.append(
                f"\n  - {name} (n={len(scores)}, μ={avg:.4f}, σ={std:.4f}, above {threshold}: {above}, below: {below}, ratio_above: {ratio_above:.1%})"
            )

            if len(scores) >= min_occurrences:
                safe_name = name.replace(" ", "_").replace("/", "_")
                plt.figure()
                plt.hist(scores, bins=20, alpha=0.7, edgecolor='black')
                plt.title(f"{label.upper()} - {name}")
                plt.xlabel("BM25 Score")
                plt.ylabel("Frequency")
                plt.grid(True)
                plt.tight_layout()
                plt.savefig(hist_dir / f"{label}_{safe_name}.png")
                plt.close()

    # Step 3: Save statistics summary
    output_path = output_txt_path or Path("data/bm25_statistics_summary.txt")
    output_path.write_text("\n".join(stats_lines), encoding="utf-8")
    print(f"[✓] Statistics written to {output_path}")
    print(f"[✓] Histograms saved to {hist_dir}")
