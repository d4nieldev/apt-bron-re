from pathlib import Path
from datetime import datetime

TEXT_DIR = Path("data/converted_reports/texts")
MD_DIR = Path("data/converted_reports/markdown")
OUTPUT_DIR = Path("data/entity_hits_v3")
LAYER_DIR = Path("data/layers_nodes")

SUMMARY_ROOT = Path("data/summaries")
SUMMARY_ROOT.mkdir(parents=True, exist_ok=True)

TIMESTAMP_DIR = SUMMARY_ROOT / datetime.now().strftime("%Y%m%d_%H%M")
TIMESTAMP_DIR.mkdir(exist_ok=True)
