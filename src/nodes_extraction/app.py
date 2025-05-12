from pathlib import Path
from datetime import datetime

from basic import (
    process_folder,
    deduplicate_entity_hits,
    add_context_sentences_to_hits,
    add_bm25_score,
)
from summary_funcs import (
    write_summary_for_entity_hits_v3,
    summarize_problematic_names,
    generate_bm25_statistics_and_histograms,
)

# === Config ===
exact_match_score = 1.0
different_category_score = 0.5
untrained_categories_score = 0.75
char_len = 50

""" booleans to run or not the NER score, and bm25 score 
add_NER_score greatly worsens the runtime of the program, add_bm25_score doesn't have a great affect"""
add_NER_score = True
add_bm25_score_flag = True

""" booleans to run specific comparison and summary functions """
run_write_summary = True
run_problematic_summary = True
run_generate_histograms = True

# === Paths ===
summary_root = Path("data/summaries")
summary_root.mkdir(parents=True, exist_ok=True)
timestamp_dir = summary_root / datetime.now().strftime("%Y%m%d_%H%M")
timestamp_dir.mkdir(exist_ok=True)

text_dir = Path("data/converted_reports/texts")
md_dir = Path("data/converted_reports/markdown")
output_dir = Path("data/entity_hits_v3")

if __name__ == "__main__":
    process_folder(text_dir, "txt", add_NER_score, exact_match_score,
                   different_category_score, untrained_categories_score)
    process_folder(md_dir, "md", add_NER_score, exact_match_score, different_category_score, untrained_categories_score)
    deduplicate_entity_hits(output_dir)
    print("Finished extracting nodes from the reports, results are in:", output_dir)

    add_context_sentences_to_hits()
    print("Sentence context added to entity hits")

    if add_bm25_score_flag:
        add_bm25_score(output_dir)
        print("BM25 scores added to entities.")

    if run_write_summary:
        write_summary_for_entity_hits_v3(output_dir, timestamp_dir)
        print("Global and per-report summaries written to:", timestamp_dir)

    if run_problematic_summary:
        summarize_problematic_names(output_dir, output_dir=timestamp_dir / "bm25_problematic_names_summary.txt")

    if run_generate_histograms:
        generate_bm25_statistics_and_histograms(output_dir,
                                                output_txt_path=timestamp_dir / "bm25_statistics_summary.txt",
                                                output_hist_dir=timestamp_dir / "bm25_histograms")
