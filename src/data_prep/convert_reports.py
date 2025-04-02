import fitz  # PyMuPDF
from pathlib import Path
from tqdm import tqdm
from docling.document_converter import DocumentConverter
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Paths ===
base_dir = Path(__file__).resolve().parents[2]
pdf_root = base_dir / "data" / "pdf_reports"
text_dir = base_dir / "data" / "converted_reports" / "texts"
markdown_dir = base_dir / "data" / "converted_reports" / "markdown"

text_dir.mkdir(parents=True, exist_ok=True)
markdown_dir.mkdir(parents=True, exist_ok=True)

# === Gather PDFs ===
pdf_paths = list(pdf_root.glob("**/*.pdf"))

# === Shared converter instance
converter = DocumentConverter()


def process_pdf(pdf_path):
    pdf_filename = pdf_path.name
    filename_stem = pdf_path.stem

    txt_output = text_dir / f"{filename_stem}.txt"
    md_output = markdown_dir / f"{filename_stem}.md"

    # === Skip early if both files exist
    if txt_output.exists() and md_output.exists():
        return f"[→] Skipped (already converted): {pdf_filename}"

    try:
        # === Convert to .txt (if needed)
        if not txt_output.exists():
            with fitz.open(pdf_path) as doc:
                with txt_output.open("w", encoding="utf-8") as f:
                    for page in doc:
                        f.write(page.get_text())

        # === Convert to .md (if needed)
        if not md_output.exists():
            output = converter.convert(pdf_path)
            md_output.write_text(output.document.export_to_markdown(), encoding="utf-8")

        return f"[✓] Done: {pdf_filename}"

    except Exception as e:
        return f"[!] Failed {pdf_filename}: {e}"


# === Parallel processing with reduced workers
max_workers = 4
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(process_pdf, pdf) for pdf in pdf_paths]

    for f in tqdm(as_completed(futures), total=len(futures), desc="Converting PDFs"):
        result = f.result()
        if result:
            print(result)