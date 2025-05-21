from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parents[2]
TEXT_DIR = REPO_ROOT / "data" / "converted_reports" / "texts"
MD_DIR = REPO_ROOT / "data" / "converted_reports" / "markdown"
OUTPUT_DIR = REPO_ROOT / "data" / "entity_hits_v3"
LAYER_DIR = REPO_ROOT / "data" / "layers_nodes"
SUMMARY_ROOT = REPO_ROOT / "data" / "summaries"

SUMMARY_ROOT.mkdir(parents=True, exist_ok=True)

TIMESTAMP_DIR = SUMMARY_ROOT / datetime.now().strftime("%Y%m%d_%H%M")
TIMESTAMP_DIR.mkdir(exist_ok=True)
