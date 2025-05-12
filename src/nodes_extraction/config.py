# === Scoring Config ===
EXACT_MATCH_SCORE = 1.0
DIFFERENT_CATEGORY_SCORE = 0.5
UNTRAINED_CATEGORY_SCORE = 0.75

# === CPE Filtering ===
CPE_CHAR_RANGE = 75  # Radius for context window

# === Context sentence length ===
CONTEXT_LENGTH = 15  # How many words before/after hit

# === Feature toggles ===
ADD_NER_SCORE = True
ADD_BM25_SCORE = True
RUN_WRITE_SUMMARY = True
RUN_PROBLEMATIC_SUMMARY = True
RUN_GENERATE_HISTOGRAMS = True
