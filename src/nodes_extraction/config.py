# === Scoring Config ===
NER_MATCH_SCORE = 1.0

# === CPE Filtering ===
CPE_CHAR_RANGE = 75  # Radius for context window

# === Context sentence length ===
CONTEXT_LENGTH = 15  # How many words before/after hit

"""
similarity score for the comparison between NER and BRON nodes embeddings
1 is perfect match, 0.5 is "divided", under 0.5 is likely unrelated
"""
SIM_THRESHOLD = 0.8  #

# === Feature toggles ===
ADD_NER_SCORE = True
ADD_BM25_SCORE = True
RUN_WRITE_SUMMARY = True
RUN_PROBLEMATIC_SUMMARY = True
RUN_GENERATE_HISTOGRAMS = True
SEMANTIC_NER_INTERSECTION = True  # greatly affects runtime, uses LLM to find semantic distance
