import json
from datetime import datetime
from pathlib import Path


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


def write_summary_for_entity_hits_v3(base_dir: Path):
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

    summary_dir = base_dir / "summaries"
    summary_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
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

    summary_path = summary_dir / f"{timestamp}_summary.txt"
    summary_path.write_text("\n".join(summary_txt), encoding="utf-8")

    global_summary_path = base_dir / "global_summary.json"
    with open(global_summary_path, "w", encoding="utf-8") as global_file:
        json.dump(global_summary, global_file, indent=2)