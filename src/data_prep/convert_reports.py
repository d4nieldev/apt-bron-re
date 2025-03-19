import os
from pathlib import Path

from tqdm import tqdm
from docling.document_converter import DocumentConverter


PDF_REPORTS_DIR = Path(os.path.join('reports', 'pdf'))
MARKDOWN_REPORTS_DIR = Path(os.path.join('reports', 'markdown'))


total = 0
for year_dir in PDF_REPORTS_DIR.iterdir():
    for report_path in year_dir.iterdir():
        total += 1

progress_bar = tqdm(total=total, desc="Converting PDF reports to Markdown")
for year_dir in PDF_REPORTS_DIR.iterdir():
    for report_path in year_dir.iterdir():  
        source = report_path
        converter = DocumentConverter()
        output = converter.convert(source)
        result = output.document.export_to_markdown()
        output_path = MARKDOWN_REPORTS_DIR / year_dir.stem / report_path.with_suffix('.md').name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result)
        progress_bar.update(1)
