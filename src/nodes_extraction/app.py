from .basic import (
    process_folder,
    deduplicate_entity_hits,
    add_context_sentences_to_hits
)
from .summary_funcs import (
    write_summary_for_entity_hits_v3,
    summarize_problematic_names,
    generate_bm25_statistics_and_histograms,
)

from data_prep.statistics import add_bm25_score

from .constants import TEXT_DIR, MD_DIR, OUTPUT_DIR, TIMESTAMP_DIR

from .config import (
    NER_MATCH_SCORE, ADD_NER_SCORE, ADD_BM25_SCORE, CONTEXT_LENGTH, CPE_CHAR_RANGE,
    RUN_WRITE_SUMMARY, RUN_PROBLEMATIC_SUMMARY, RUN_GENERATE_HISTOGRAMS
)


if __name__ == "__main__":
    process_folder(TEXT_DIR, "txt", ADD_NER_SCORE, NER_MATCH_SCORE, CPE_CHAR_RANGE)
    process_folder(MD_DIR, "md", ADD_NER_SCORE, NER_MATCH_SCORE, CPE_CHAR_RANGE)
    deduplicate_entity_hits(OUTPUT_DIR)
    print("Finished extracting nodes from the reports, results are in:", OUTPUT_DIR)

    add_context_sentences_to_hits(CONTEXT_LENGTH)
    print("Sentence context added to entity hits")

    if ADD_BM25_SCORE:
        add_bm25_score(OUTPUT_DIR)
        print("BM25 scores added to entities.")

    if RUN_WRITE_SUMMARY:
        write_summary_for_entity_hits_v3(OUTPUT_DIR, TIMESTAMP_DIR)
        print("Global and per-report summaries written to:", TIMESTAMP_DIR)

    if RUN_PROBLEMATIC_SUMMARY:
        summarize_problematic_names(OUTPUT_DIR, output_dir=TIMESTAMP_DIR / "bm25_problematic_names_summary.txt")

    if RUN_GENERATE_HISTOGRAMS:
        generate_bm25_statistics_and_histograms(OUTPUT_DIR,
                                                output_txt_path=TIMESTAMP_DIR / "bm25_statistics_summary.txt",
                                                output_hist_dir=TIMESTAMP_DIR / "bm25_histograms")